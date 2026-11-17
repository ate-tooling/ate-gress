// Package tlsconfig builds the mutual-TLS server configuration ate-gress
// serves ext_proc with.
//
// The serving certificate and the client CA bundle are projected by the
// kubelet from pod-certificate and ClusterTrustBundle volumes and rotate in
// place. Both are re-read on every handshake, as Substrate's credential
// provider does, so a rotated certificate or a newly published CA takes effect
// without a restart. ext_proc connections are long-lived HTTP/2, so the cost is
// paid once per connection, not per request.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
)

// Config names the files and identities the server needs.
type Config struct {
	// CredentialBundle is a PEM file holding the private key and the
	// certificate chain, the layout a podCertificate projection writes.
	CredentialBundle string
	// ClientCAs is a PEM file of the CAs that sign acceptable clients.
	ClientCAs string
	// AllowedClientIDs are the URI SANs (SPIFFE IDs) a client certificate
	// must carry one of.
	AllowedClientIDs []string
}

// Server returns a TLS 1.3 server configuration that requires a client
// certificate chaining to c.ClientCAs and carrying one of c.AllowedClientIDs.
// It loads both files once up front, so a pod with a missing projection fails
// at startup rather than on the first connection.
func Server(c Config) (*tls.Config, error) {
	if len(c.AllowedClientIDs) == 0 {
		return nil, errors.New("at least one allowed client ID is required")
	}
	if _, err := loadKeyPair(c.CredentialBundle); err != nil {
		return nil, err
	}
	if _, err := loadPool(c.ClientCAs); err != nil {
		return nil, err
	}
	verify := verifyClientID(slices.Clone(c.AllowedClientIDs))
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert, err := loadKeyPair(c.CredentialBundle)
			if err != nil {
				return nil, err
			}
			pool, err := loadPool(c.ClientCAs)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:       tls.VersionTLS13,
				Certificates:     []tls.Certificate{cert},
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        pool,
				VerifyConnection: verify,
				NextProtos:       []string{"h2"},
			}, nil
		},
	}, nil
}

func loadKeyPair(path string) (tls.Certificate, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading credential bundle: %w", err)
	}
	// X509KeyPair takes the CERTIFICATE blocks from its first argument and the
	// key block from its second, skipping blocks of the other kind, so one
	// combined bundle serves as both.
	cert, err := tls.X509KeyPair(pem, pem)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing credential bundle %s: %w", path, err)
	}
	return cert, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client CA bundle %s holds no certificates", path)
	}
	return pool, nil
}

// verifyClientID returns a VerifyConnection callback, run after chain
// verification, that accepts only a leaf carrying one of allowed as a URI SAN.
func verifyClientID(allowed []string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("client certificate is required")
		}
		leaf := cs.PeerCertificates[0]
		for _, u := range leaf.URIs {
			if slices.Contains(allowed, u.String()) {
				return nil
			}
		}
		return fmt.Errorf("client certificate URI SANs %v include none of %v", leaf.URIs, allowed)
	}
}
