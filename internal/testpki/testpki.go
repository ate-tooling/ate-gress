// Package testpki issues throwaway certificates for tests, shaped like the
// ones Substrate's pod-certificate signers issue: ECDSA P-256 leaves with DNS
// SANs for serving and SPIFFE URI SANs for clients.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA creates a fresh self-signed CA whose subject CommonName is name. It
// can only sign certificates, is valid from an hour ago to an hour from now,
// and fails t on any error.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, key: key}
}

// PEM returns the CA certificate in PEM form.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// Pool returns a pool holding only the CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Leaf is an issued certificate and its key.
type Leaf struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// Serving issues a server certificate for dnsNames.
func (ca *CA) Serving(t testing.TB, dnsNames ...string) *Leaf {
	t.Helper()
	return ca.issue(t, &x509.Certificate{DNSNames: dnsNames, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
}

// ServingUntil is Serving, for a certificate that expires at notAfter instead
// of in an hour.
func (ca *CA) ServingUntil(t testing.TB, notAfter time.Time, dnsNames ...string) *Leaf {
	t.Helper()
	return ca.issue(t, &x509.Certificate{DNSNames: dnsNames, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotAfter: notAfter})
}

// Client issues a client certificate carrying spiffeIDs as URI SANs.
func (ca *CA) Client(t testing.TB, spiffeIDs ...string) *Leaf {
	t.Helper()
	tmpl := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for _, id := range spiffeIDs {
		u, err := url.Parse(id)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	return ca.issue(t, tmpl)
}

func (ca *CA) issue(t testing.TB, tmpl *x509.Certificate) *Leaf {
	key := newKey(t)
	tmpl.SerialNumber = serial(t)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Leaf{Cert: cert, key: key}
}

// Bundle returns the key followed by the certificate, the layout of a
// podCertificate credential bundle.
func (l *Leaf) Bundle(t testing.TB) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(l.key)
	if err != nil {
		t.Fatal(err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.Cert.Raw})...)
}

// TLSCertificate returns l for use in a tls.Config.
func (l *Leaf) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{l.Cert.Raw}, PrivateKey: l.key, Leaf: l.Cert}
}

// WriteFile writes data to name under dir, atomically, as the kubelet updates
// projected volumes, and returns the path.
func WriteFile(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	return path
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
