package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/samueltorres/ate-gress/internal/testpki"
)

const (
	serverName = "ate-gress.ate-gress.svc"
	envoyID    = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"
)

type fixture struct {
	servingCA, clientCA *testpki.CA
	cfg                 Config
	dir                 string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		servingCA: testpki.NewCA(t, "servicedns"),
		clientCA:  testpki.NewCA(t, "podidentity"),
		dir:       t.TempDir(),
	}
	f.cfg = Config{
		CredentialBundle: testpki.WriteFile(t, f.dir, "credential-bundle.pem", f.servingCA.Serving(t, serverName).Bundle(t)),
		ClientCAs:        testpki.WriteFile(t, f.dir, "trust-bundle.pem", f.clientCA.PEM()),
		AllowedClientIDs: []string{envoyID},
	}
	return f
}

// handshake runs a TLS handshake between srv and a client presenting client
// (if non-nil) and trusting rootCA, and returns the client's error.
func handshake(t *testing.T, srv *tls.Config, rootCA *x509.CertPool, client *tls.Certificate, maxVersion uint16) error {
	t.Helper()
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()

	done := make(chan error, 1)
	go func() {
		s := tls.Server(sc, srv)
		err := s.Handshake()
		if err == nil {
			// In TLS 1.3 the client finishes before the server has checked
			// its certificate; a read surfaces the server's verdict to it.
			_, err = s.Write([]byte{0})
		}
		sc.Close()
		done <- err
	}()

	cfg := &tls.Config{RootCAs: rootCA, ServerName: serverName, MaxVersion: maxVersion}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	c := tls.Client(cc, cfg)
	err := c.Handshake()
	if err == nil {
		_, err = c.Read(make([]byte, 1))
	}
	cc.Close()
	<-done
	return err
}

func TestServer(t *testing.T) {
	f := newFixture(t)
	srv, err := Server(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := testpki.NewCA(t, "other")
	envoy := f.clientCA.Client(t, envoyID).TLSCertificate()
	impostor := f.clientCA.Client(t, "spiffe://cluster.local/ns/default/sa/attacker").TLSCertificate()
	foreign := otherCA.Client(t, envoyID).TLSCertificate()
	multi := f.clientCA.Client(t, "spiffe://cluster.local/ns/x/sa/y", envoyID).TLSCertificate()

	tests := []struct {
		name       string
		client     *tls.Certificate
		maxVersion uint16
		wantErr    bool
	}{
		{name: "gateway identity", client: &envoy},
		{name: "allowed ID among several URI SANs", client: &multi},
		{name: "no client certificate", wantErr: true},
		{name: "wrong SPIFFE ID", client: &impostor, wantErr: true},
		{name: "right ID, untrusted CA", client: &foreign, wantErr: true},
		{name: "TLS 1.2", client: &envoy, maxVersion: tls.VersionTLS12, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handshake(t, srv, f.servingCA.Pool(), tt.client, tt.maxVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("handshake error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerPicksUpRotation(t *testing.T) {
	f := newFixture(t)
	srv, err := Server(f.cfg)
	if err != nil {
		t.Fatal(err)
	}

	// The client CA rotates: a client signed by the new CA is rejected until
	// the trust bundle names it, then accepted without rebuilding the config.
	newClientCA := testpki.NewCA(t, "podidentity-2")
	rotated := newClientCA.Client(t, envoyID).TLSCertificate()
	if err := handshake(t, srv, f.servingCA.Pool(), &rotated, 0); err == nil {
		t.Fatal("client from a CA not yet in the bundle was accepted")
	}
	testpki.WriteFile(t, f.dir, "trust-bundle.pem", append(f.clientCA.PEM(), newClientCA.PEM()...))
	if err := handshake(t, srv, f.servingCA.Pool(), &rotated, 0); err != nil {
		t.Fatalf("client from the newly published CA was rejected: %v", err)
	}

	// The serving certificate rotates to one from a new CA.
	newServingCA := testpki.NewCA(t, "servicedns-2")
	testpki.WriteFile(t, f.dir, "credential-bundle.pem", newServingCA.Serving(t, serverName).Bundle(t))
	if err := handshake(t, srv, newServingCA.Pool(), &rotated, 0); err != nil {
		t.Fatalf("handshake with the rotated serving certificate failed: %v", err)
	}
}

func TestServerFailsFast(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name   string
		mutate func(*Config)
		errSub string
	}{
		{name: "no allowed IDs", mutate: func(c *Config) { c.AllowedClientIDs = nil }, errSub: "client ID"},
		{name: "missing bundle", mutate: func(c *Config) { c.CredentialBundle += ".missing" }, errSub: "credential bundle"},
		{name: "missing CA", mutate: func(c *Config) { c.ClientCAs += ".missing" }, errSub: "client CA"},
		{name: "empty CA", mutate: func(c *Config) { c.ClientCAs = testpki.WriteFile(t, f.dir, "empty.pem", nil) }, errSub: "no certificates"},
		{name: "bundle without key", mutate: func(c *Config) { c.CredentialBundle = c.ClientCAs }, errSub: "parsing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := f.cfg
			tt.mutate(&cfg)
			if _, err := Server(cfg); err == nil || !strings.Contains(err.Error(), tt.errSub) {
				t.Errorf("Server() error = %v, want one mentioning %q", err, tt.errSub)
			}
		})
	}
}
