// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// mintCA returns a self-signed CA cert as PEM bytes.
func mintCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestAppendClientCAsAppendsToExistingPool — the migration use case: file
// CA is already in ClientCAs, Vault PKI CA appended at runtime. Both must
// be trusted simultaneously so old + new operator certs validate.
func TestAppendClientCAsAppendsToExistingPool(t *testing.T) {
	legacyPEM := mintCA(t, "legacy-ca")
	pkiPEM := mintCA(t, "pki-ca")

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(legacyPEM) {
		t.Fatal("seed legacy CA failed")
	}
	cfg := &tls.Config{ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}

	if err := AppendClientCAs(cfg, pkiPEM); err != nil {
		t.Fatalf("AppendClientCAs: %v", err)
	}
	// Both subjects must be retrievable from the pool.
	subjects := cfg.ClientCAs.Subjects() //nolint:staticcheck // Subjects() is fine for tests
	if len(subjects) != 2 {
		t.Errorf("ClientCAs has %d subjects, want 2 (legacy + pki)", len(subjects))
	}
}

// TestAppendClientCAsBootstrapsEmptyPool — when LoadServerTLS was called
// without a caFile (no file-mount CA), AppendClientCAs must build a fresh
// pool AND enable RequireAndVerifyClientCert. Otherwise the appended CA
// would silently no-op.
func TestAppendClientCAsBootstrapsEmptyPool(t *testing.T) {
	pkiPEM := mintCA(t, "pki-only")
	cfg := &tls.Config{} // no ClientCAs, no ClientAuth

	if err := AppendClientCAs(cfg, pkiPEM); err != nil {
		t.Fatal(err)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs still nil after append")
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth=%v, want RequireAndVerifyClientCert (else appended CA silently no-ops)", cfg.ClientAuth)
	}
}

// TestAppendClientCAsEmptyExtraIsNoOp — defensive: passing nil/empty must
// not error. Called by the controller even when the Vault env isn't set.
func TestAppendClientCAsEmptyExtraIsNoOp(t *testing.T) {
	cfg := &tls.Config{}
	if err := AppendClientCAs(cfg, nil); err != nil {
		t.Errorf("nil extra should be no-op, got %v", err)
	}
	if err := AppendClientCAs(cfg, []byte{}); err != nil {
		t.Errorf("empty extra should be no-op, got %v", err)
	}
	if cfg.ClientCAs != nil {
		t.Error("nil/empty extra should not allocate ClientCAs")
	}
}

// TestAppendClientCAsRejectsGarbage — feeding bytes that look like PEM but
// don't parse as certs must error, not silently skip.
func TestAppendClientCAsRejectsGarbage(t *testing.T) {
	cfg := &tls.Config{}
	garbage := []byte("-----BEGIN CERTIFICATE-----\nnotacert\n-----END CERTIFICATE-----\n")
	if err := AppendClientCAs(cfg, garbage); err == nil {
		t.Error("garbage PEM should error")
	}
}
