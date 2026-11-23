package tlsconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ate-tooling/ate-gress/internal/testpki"
)

func TestCertificateExpiryMetric(t *testing.T) {
	f := newFixture(t)
	reg := prometheus.NewRegistry()
	f.cfg.Registerer = reg
	expiry := func(notAfter time.Time) string {
		return fmt.Sprintf(`
# HELP ategress_tls_certificate_expiry_timestamp_seconds Not-after time of the serving certificate in the credential bundle, as the next handshake would load it, in seconds since the epoch. Absent while the bundle cannot be loaded.
# TYPE ategress_tls_certificate_expiry_timestamp_seconds gauge
ategress_tls_certificate_expiry_timestamp_seconds %d
`, notAfter.Unix())
	}

	first := f.servingCA.ServingUntil(t, time.Now().Add(2*time.Hour), serverName)
	testpki.WriteFile(t, f.dir, "credential-bundle.pem", first.Bundle(t))
	if _, err := Server(f.cfg); err != nil {
		t.Fatal(err)
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expiry(first.Cert.NotAfter)), "ategress_tls_certificate_expiry_timestamp_seconds"); err != nil {
		t.Error(err)
	}

	// The kubelet rotates the certificate. No handshake happens, as on a
	// gateway connection that stays open, and the metric still follows.
	rotated := f.servingCA.ServingUntil(t, time.Now().Add(48*time.Hour), serverName)
	testpki.WriteFile(t, f.dir, "credential-bundle.pem", rotated.Bundle(t))
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expiry(rotated.Cert.NotAfter)), "ategress_tls_certificate_expiry_timestamp_seconds"); err != nil {
		t.Error(err)
	}

	// A bundle no handshake could load has no expiry to report.
	testpki.WriteFile(t, f.dir, "credential-bundle.pem", f.clientCA.PEM())
	if n := testutil.CollectAndCount(reg, "ategress_tls_certificate_expiry_timestamp_seconds"); n != 0 {
		t.Errorf("%d expiry series for an unloadable bundle, want none", n)
	}
}

func TestReloadFailuresMetric(t *testing.T) {
	f := newFixture(t)
	reg := prometheus.NewRegistry()
	f.cfg.Registerer = reg
	srv, err := Server(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	envoy := f.clientCA.Client(t, envoyID).TLSCertificate()
	check := func(credentialBundle, clientCAs int) {
		t.Helper()
		want := fmt.Sprintf(`
# HELP ategress_tls_reload_failures_total Handshakes refused because TLS material could not be loaded, by file (credential_bundle, client_ca_bundle).
# TYPE ategress_tls_reload_failures_total counter
ategress_tls_reload_failures_total{file="client_ca_bundle"} %d
ategress_tls_reload_failures_total{file="credential_bundle"} %d
`, clientCAs, credentialBundle)
		if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "ategress_tls_reload_failures_total"); err != nil {
			t.Error(err)
		}
	}

	if err := handshake(t, srv, f.servingCA.Pool(), &envoy, 0); err != nil {
		t.Fatal(err)
	}
	check(0, 0)

	// The trust bundle is replaced by one with no certificates in it.
	trust := f.clientCA.PEM()
	testpki.WriteFile(t, f.dir, "trust-bundle.pem", []byte("not PEM\n"))
	if err := handshake(t, srv, f.servingCA.Pool(), &envoy, 0); err == nil {
		t.Fatal("handshake succeeded without client CAs")
	}
	check(0, 1)
	testpki.WriteFile(t, f.dir, "trust-bundle.pem", trust)

	// The credential bundle disappears.
	if err := os.Remove(f.cfg.CredentialBundle); err != nil {
		t.Fatal(err)
	}
	if err := handshake(t, srv, f.servingCA.Pool(), &envoy, 0); err == nil {
		t.Fatal("handshake succeeded without a serving certificate")
	}
	check(1, 1)

	// A client being refused is not a reload failure.
	testpki.WriteFile(t, f.dir, "credential-bundle.pem", f.servingCA.Serving(t, serverName).Bundle(t))
	if err := handshake(t, srv, f.servingCA.Pool(), nil, 0); err == nil {
		t.Fatal("handshake succeeded without a client certificate")
	}
	check(1, 1)
}

func TestServerRegistersOnce(t *testing.T) {
	f := newFixture(t)
	f.cfg.Registerer = prometheus.NewRegistry()
	if _, err := Server(f.cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Server(f.cfg); err == nil || !strings.Contains(err.Error(), "registering") {
		t.Errorf("second Server() with the same registry: error = %v, want one about registering", err)
	}
}
