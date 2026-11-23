package tlsconfig

import (
	"crypto/x509"

	"github.com/prometheus/client_golang/prometheus"
)

// The files a handshake reloads, as the file label of the reload failures.
const (
	fileCredentialBundle = "credential_bundle"
	fileClientCAs        = "client_ca_bundle"
)

// metrics describe the TLS material. They are what warns before the gateway
// can no longer connect: a certificate that is not being rotated, or a
// projection that has stopped being readable.
type metrics struct {
	reloadFailures *prometheus.CounterVec
	expiry         *expiryCollector
}

func newMetrics(c Config) *metrics {
	m := &metrics{
		reloadFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ategress_tls_reload_failures_total",
			Help: "Handshakes refused because TLS material could not be loaded, by file (credential_bundle, client_ca_bundle).",
		}, []string{"file"}),
		expiry: &expiryCollector{bundle: c.CredentialBundle},
	}
	// A failure counter that only appears with the first failure cannot be
	// told from one that is not exported.
	m.reloadFailures.WithLabelValues(fileCredentialBundle)
	m.reloadFailures.WithLabelValues(fileClientCAs)
	return m
}

func (m *metrics) register(reg prometheus.Registerer) error {
	if err := reg.Register(m.reloadFailures); err != nil {
		return err
	}
	return reg.Register(m.expiry)
}

// expiryCollector reports when the serving certificate on disk expires.
//
// It reads the credential bundle at each scrape, not at each handshake. The
// bundle on disk is what the next handshake will serve, and handshakes can be
// days apart on long-lived ext_proc connections: a gauge set by the last
// handshake would report a certificate that has since been rotated, and
// alert on an expiry that is not going to happen.
type expiryCollector struct {
	bundle string
}

var expiryDesc = prometheus.NewDesc(
	"ategress_tls_certificate_expiry_timestamp_seconds",
	"Not-after time of the serving certificate in the credential bundle, as the next handshake would load it, in seconds since the epoch. Absent while the bundle cannot be loaded.",
	nil, nil,
)

// Describe implements prometheus.Collector.
func (c *expiryCollector) Describe(ch chan<- *prometheus.Desc) { ch <- expiryDesc }

// Collect implements prometheus.Collector.
func (c *expiryCollector) Collect(ch chan<- prometheus.Metric) {
	cert, err := loadKeyPair(c.bundle)
	if err != nil {
		return
	}
	leaf := cert.Leaf
	if leaf == nil {
		// X509KeyPair fills Leaf unless GODEBUG=x509keypairleaf=0.
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return
		}
	}
	ch <- prometheus.MustNewConstMetric(expiryDesc, prometheus.GaugeValue, float64(leaf.NotAfter.Unix()))
}
