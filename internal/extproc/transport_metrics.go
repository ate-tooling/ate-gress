package extproc

import (
	"crypto/tls"
	"errors"
	"io"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/credentials"

	"github.com/ate-tooling/ate-gress/internal/tlsconfig"
)

// Why a handshake failed, as the reason label.
const (
	// handshakeClientIdentity: the client's certificate verified, but it is
	// not the gateway's. Something else in the cluster is calling ate-gress.
	handshakeClientIdentity = "client_identity"
	// handshakeClientCertificate: the client's certificate did not verify
	// against the client CA bundle. If the client is the gateway, its
	// certificate has expired or the bundle is out of date, and egress is
	// failing.
	handshakeClientCertificate = "client_certificate"
	// handshakeOther: everything else, including a client that presented no
	// certificate or does not speak TLS 1.3, a handshake that timed out, and
	// TLS material ate-gress could not load.
	handshakeOther = "other"
)

// transportMetrics describe the gRPC server beneath the request path.
type transportMetrics struct {
	streams           prometheus.Gauge
	handshakeFailures *prometheus.CounterVec
}

func newTransportMetrics(reg prometheus.Registerer) *transportMetrics {
	m := &transportMetrics{
		streams: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ategress_active_streams",
			Help: "ext_proc streams open. The gateway opens one for each HTTP request.",
		}),
		handshakeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ategress_tls_handshake_failures_total",
			Help: "Connections refused in the TLS handshake, by reason (client_identity, client_certificate, other).",
		}, []string{"reason"}),
	}
	// A failure counter that only appears with the first failure cannot be
	// told from one that is not exported.
	for _, reason := range []string{handshakeClientIdentity, handshakeClientCertificate, handshakeOther} {
		m.handshakeFailures.WithLabelValues(reason)
	}
	reg.MustRegister(m.streams, m.handshakeFailures)
	return m
}

func (m *transportMetrics) handshakeFailed(err error) {
	var unverified *tls.CertificateVerificationError
	reason := handshakeOther
	switch {
	case errors.Is(err, tlsconfig.ErrClientNotAllowed):
		reason = handshakeClientIdentity
	case errors.As(err, &unverified):
		reason = handshakeClientCertificate
	}
	m.handshakeFailures.WithLabelValues(reason).Inc()
}

// countingCredentials are transport credentials that count the server
// handshakes that fail. crypto/tls has no hook for a failed handshake, and
// gRPC only logs one, so the count is taken where gRPC asks for the
// handshake.
type countingCredentials struct {
	credentials.TransportCredentials
	metrics *transportMetrics
}

func (c countingCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	// A peer that connects and hangs up without a word is a port probe, not a
	// client that was refused; gRPC does not log those either.
	if err != nil && !errors.Is(err, io.EOF) {
		c.metrics.handshakeFailed(err)
	}
	return conn, info, err
}

func (c countingCredentials) Clone() credentials.TransportCredentials {
	return countingCredentials{TransportCredentials: c.TransportCredentials.Clone(), metrics: c.metrics}
}
