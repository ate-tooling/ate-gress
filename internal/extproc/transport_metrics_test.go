package extproc

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ate-tooling/ate-gress/internal/testpki"
	"github.com/ate-tooling/ate-gress/internal/tlsconfig"
)

// eventuallyMetrics waits for the named metric to read want. The server
// counts a stream or a failed handshake on its own goroutine, after the
// client has seen the outcome.
func eventuallyMetrics(t *testing.T, h *harness, name, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := testutil.GatherAndCompare(h.reg, strings.NewReader(want), name)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestActiveStreamsMetric(t *testing.T) {
	h := newHarness(t)
	h.install(t)
	streams := func(n int) string {
		return fmt.Sprintf(`
# HELP ategress_active_streams ext_proc streams open. The gateway opens one for each HTTP request.
# TYPE ategress_active_streams gauge
ategress_active_streams %d
`, n)
	}
	eventuallyMetrics(t, h, "ategress_active_streams", streams(0))

	var open []extprocv3.ExternalProcessor_ProcessClient
	for range 3 {
		stream, err := h.client.Process(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(headersRequest(actorID, get("/repos/acme/a")...)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		open = append(open, stream)
	}
	eventuallyMetrics(t, h, "ategress_active_streams", streams(3))

	if err := open[0].CloseSend(); err != nil {
		t.Fatal(err)
	}
	eventuallyMetrics(t, h, "ategress_active_streams", streams(2))
	for _, stream := range open[1:] {
		if err := stream.CloseSend(); err != nil {
			t.Fatal(err)
		}
	}
	eventuallyMetrics(t, h, "ategress_active_streams", streams(0))
}

func handshakeFailures(clientCertificate, clientIdentity, other int) string {
	return fmt.Sprintf(`
# HELP ategress_tls_handshake_failures_total Connections refused in the TLS handshake, by reason (client_identity, client_certificate, other).
# TYPE ategress_tls_handshake_failures_total counter
ategress_tls_handshake_failures_total{reason="client_certificate"} %d
ategress_tls_handshake_failures_total{reason="client_identity"} %d
ategress_tls_handshake_failures_total{reason="other"} %d
`, clientCertificate, clientIdentity, other)
}

// TestHandshakeFailuresMetric runs handshakes against the server's
// credentials directly, with a client that presents its certificate whatever
// CAs the server names. Envoy does; Go's client would hold back a certificate
// the server's CAs did not sign.
func TestHandshakeFailuresMetric(t *testing.T) {
	servingCA, clientCA := testpki.NewCA(t, "servicedns"), testpki.NewCA(t, "podidentity")
	dir := t.TempDir()
	bundle := testpki.WriteFile(t, dir, "credential-bundle.pem", servingCA.Serving(t, serverName).Bundle(t))
	tlsCfg, err := tlsconfig.Server(tlsconfig.Config{
		CredentialBundle: bundle,
		ClientCAs:        testpki.WriteFile(t, dir, "trust-bundle.pem", clientCA.PEM()),
		AllowedClientIDs: []string{envoyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	creds := NewMetrics(reg).credentials(tlsCfg)

	// handshake reports whether the server accepted the client.
	handshake := func(client func(net.Conn)) bool {
		t.Helper()
		cc, sc := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer cc.Close()
			client(cc)
		}()
		conn, _, err := creds.ServerHandshake(sc)
		if err == nil {
			conn.Close()
		}
		sc.Close()
		<-done
		return err == nil
	}
	presenting := func(cert tls.Certificate) func(net.Conn) {
		return func(conn net.Conn) {
			c := tls.Client(conn, &tls.Config{
				RootCAs: servingCA.Pool(), ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
			})
			// In TLS 1.3 the client finishes first; the read waits for the
			// server's verdict.
			if c.Handshake() == nil {
				_, _ = c.Read(make([]byte, 1))
			}
		}
	}
	check := func(clientCertificate, clientIdentity, other int) {
		t.Helper()
		if err := testutil.GatherAndCompare(reg, strings.NewReader(handshakeFailures(clientCertificate, clientIdentity, other)), "ategress_tls_handshake_failures_total"); err != nil {
			t.Error(err)
		}
	}

	if !handshake(presenting(clientCA.Client(t, envoyID).TLSCertificate())) {
		t.Fatal("the gateway's certificate was refused")
	}
	check(0, 0, 0)

	// Signed by the client CA, but not the gateway.
	if handshake(presenting(clientCA.Client(t, "spiffe://cluster.local/ns/default/sa/attacker").TLSCertificate())) {
		t.Fatal("an impostor was accepted")
	}
	check(0, 1, 0)

	// The gateway's ID, from a CA the trust bundle does not hold.
	if handshake(presenting(testpki.NewCA(t, "other").Client(t, envoyID).TLSCertificate())) {
		t.Fatal("a certificate from an untrusted CA was accepted")
	}
	check(1, 1, 0)

	// No certificate at all.
	if handshake(presenting(tls.Certificate{})) {
		t.Fatal("a client without a certificate was accepted")
	}
	check(1, 1, 1)

	// Not TLS.
	if handshake(func(conn net.Conn) { _, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")) }) {
		t.Fatal("an HTTP client was accepted")
	}
	check(1, 1, 2)

	// TLS material ate-gress cannot load is its own failure, and is counted
	// as a reload failure as well.
	testpki.WriteFile(t, dir, "credential-bundle.pem", nil)
	if handshake(presenting(clientCA.Client(t, envoyID).TLSCertificate())) {
		t.Fatal("a handshake succeeded without a serving certificate")
	}
	check(1, 1, 3)

	// A port probe connects and hangs up. It was not refused, and a load
	// balancer doing that every few seconds must not look like an attack.
	if handshake(func(net.Conn) {}) {
		t.Fatal("a handshake with a closed connection succeeded")
	}
	check(1, 1, 3)
}

// TestHandshakeFailuresMetricOnServer checks that the gRPC server serves
// with the counting credentials.
func TestHandshakeFailuresMetricOnServer(t *testing.T) {
	h := newHarness(t)
	if _, err := h.roundTrip(t, headersRequest(actorID, get("/repos/acme/a")...)); err != nil {
		t.Fatal(err)
	}
	eventuallyMetrics(t, h, "ategress_tls_handshake_failures_total", handshakeFailures(0, 0, 0))

	conn, err := h.dial(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(t.Context())
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("the server accepted a client without a certificate")
	}
	eventuallyMetrics(t, h, "ategress_tls_handshake_failures_total", handshakeFailures(0, 0, 1))
}
