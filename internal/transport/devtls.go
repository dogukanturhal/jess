// SPDX-License-Identifier: AGPL-3.0-or-later

// Package transport provides the mTLS config for worker↔controller and
// operator↔controller links. PROD uses SPIFFE SVIDs (go-spiffe; wired in a
// later phase). DevCA here mints an in-process CA + leaf certs so the spine
// can run + be integration-tested locally without a SPIRE agent (ADR 0030 5a).
package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// DevCA is a self-signed CA for local/dev mTLS. NOT for production.
type DevCA struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
}

// NewDevCA mints a fresh ECDSA P-256 CA valid for 24h.
func NewDevCA() (*DevCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "jess-dev-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &DevCA{caCert: caCert, caKey: key, pool: pool}, nil
}

// leaf issues a CA-signed leaf cert usable for both client and server auth.
// CommonName carries the identity (e.g. the worker id); SANs cover local dials.
func (ca *DevCA) leaf(cn string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn, "localhost", "controller"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &key.PublicKey, ca.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// ServerConfig returns an mTLS server config requiring + verifying client certs.
func (ca *DevCA) ServerConfig(cn string) (*tls.Config, error) {
	cert, err := ca.leaf(cn)
	if err != nil {
		return nil, fmt.Errorf("devtls server cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientConfig returns an mTLS client config that verifies the server against
// the dev CA and presents a client cert with CommonName cn.
func (ca *DevCA) ClientConfig(cn, serverName string) (*tls.Config, error) {
	cert, err := ca.leaf(cn)
	if err != nil {
		return nil, fmt.Errorf("devtls client cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// PeerCommonName extracts the verified peer CommonName from a TLS server conn —
// the worker's identity in the dev model (SPIFFE ID in prod).
func PeerCommonName(conn *tls.Conn) (string, error) {
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	return st.PeerCertificates[0].Subject.CommonName, nil
}
