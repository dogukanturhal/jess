// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerConfig builds an mTLS server config from PEM files (prod/non-SPIFFE
// path; SPIFFE go-spiffe wiring lands later). Requires + verifies client certs.
func LoadServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadClientConfig builds an mTLS client config from PEM files.
func LoadClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// LoadServerTLS builds a server TLS config from a server keypair for the
// operator-facing listener. If caFile is non-empty it additionally requires +
// verifies client certs (mTLS — device/identity binding, defense in depth);
// otherwise the server only authenticates itself to the client (transport
// encryption), and the operator identity is still proven by the OIDC token
// carried inside the connection. Either way the bearer token no longer crosses
// the wire in cleartext.
func LoadServerTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load operator server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// LoadClientTLS builds a client TLS config that verifies the server against
// caFile (or the system roots if caFile is empty) and checks serverName. If
// certFile/keyFile are both set it also presents a client cert (operator mTLS);
// otherwise it is server-auth only. Used by jessctl for the operator link.
func LoadClientTLS(caFile, serverName, certFile, keyFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}
	if caFile != "" {
		pool, err := loadCAPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load operator client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certs parsed from %s", caFile)
	}
	return pool, nil
}

// AppendClientCAs adds extra PEM-encoded CA certs to a server tls.Config's
// ClientCAs pool. Used during the PKI migration: the controller's operator
// port trusts the file-mounted legacy CA (from caFile, set by
// LoadServerTLS) AND the runtime-fetched Vault PKI CA (passed here as
// extraPEM). Without this both old + new operator client certs can't
// validate simultaneously and the migration breaks live sessions.
//
// Idempotent and tolerant: returns an error only if extraPEM is non-empty
// but contains no parseable certs. Empty extraPEM is a no-op.
func AppendClientCAs(cfg *tls.Config, extraPEM []byte) error {
	if len(extraPEM) == 0 {
		return nil
	}
	if cfg.ClientCAs == nil {
		cfg.ClientCAs = x509.NewCertPool()
		// LoadServerTLS only enables ClientAuth when a caFile was passed.
		// If the caller is appending CAs to a config that started with no
		// caFile, enable ClientAuth here so the appended CAs actually
		// gate clients (otherwise this call would silently no-op).
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if !cfg.ClientCAs.AppendCertsFromPEM(extraPEM) {
		return fmt.Errorf("no certs parsed from extraPEM (len=%d)", len(extraPEM))
	}
	return nil
}
