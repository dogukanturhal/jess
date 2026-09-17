// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mintTestCert writes a self-signed cert PEM with the given NotAfter to
// the supplied path. Used to test certIsFresh against the three cases:
// fresh, near-expiry, missing.
func mintTestCert(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-operator"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCertIsFreshSkipsWhenStillValid — the fast-path: invoking `jessctl
// up` when the cert has plenty of headroom must return (true, ...) so
// the no-op shell-startup case stays fast (<50ms target).
func TestCertIsFreshSkipsWhenStillValid(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "operator.crt")
	mintTestCert(t, certPath, time.Now().Add(6*time.Hour))

	ok, exp, err := certIsFresh(certPath, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("fresh cert (6h left) reported stale; NotAfter=%v", exp)
	}
}

// TestCertIsFreshRemintsNearExpiry — the renewal trigger: with renewBefore
// = 30m and a cert expiring in 10m, we MUST re-mint, not silently use
// a cert that will expire mid-session.
func TestCertIsFreshRemintsNearExpiry(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "operator.crt")
	mintTestCert(t, certPath, time.Now().Add(10*time.Minute))

	ok, _, err := certIsFresh(certPath, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("cert with 10m left + renewBefore=30m should re-mint, not reuse")
	}
}

// TestCertIsFreshMissingFileTriggersRemint — first-run case (no cert
// yet). Must return (false, _, error) so caller mints.
func TestCertIsFreshMissingFileTriggersRemint(t *testing.T) {
	ok, _, err := certIsFresh(filepath.Join(t.TempDir(), "nope.crt"), time.Hour)
	if ok {
		t.Error("missing cert should NOT report fresh")
	}
	if err == nil {
		t.Error("missing cert should error so caller mints (not silently skip)")
	}
}

// TestCertIsFreshCorruptCertTriggersRemint — defensive: a half-written
// or zero-byte file MUST trigger re-mint, not crash.
func TestCertIsFreshCorruptCertTriggersRemint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "operator.crt")
	_ = os.WriteFile(certPath, []byte("nothing pem-shaped here"), 0o644)

	ok, _, err := certIsFresh(certPath, time.Hour)
	if ok {
		t.Error("garbage cert reported fresh")
	}
	if err == nil {
		t.Error("garbage cert should surface error so caller re-mints")
	}
}

// TestGenerateKeyAndCSRRoundtrips checks the CSR is valid + reproducibly
// uses the generated key (signature verifies). Pins the property the
// server depends on (CSR signature check before signing).
func TestGenerateKeyAndCSRRoundtrips(t *testing.T) {
	csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		t.Fatal(err)
	}
	if len(csrPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("empty csr or key")
	}
	csrBlock, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature self-check failed: %v", err)
	}
}
