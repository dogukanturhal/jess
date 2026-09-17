// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testPKI holds a self-signed CA and a signed EK leaf cert for chain tests.
type testPKI struct {
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caPool    *x509.CertPool
	ekKey     *ecdsa.PrivateKey
	ekCert    *x509.Certificate
	ekCertPEM []byte
	ekPubPEM  []byte
}

// newTestPKI builds:
//   - A self-signed CA cert (simulates pinned vendor root)
//   - An EK leaf cert signed by the CA with KeyEncipherment | DataEncipherment
//
// Both use ECDSA P-256 (real EK certs are RSA-2048 or P-256; test uses P-256
// for speed). The go-attestation ParseEKCertificate call requires the leaf
// to be a DER-encoded X.509 v3 cert — which x509.CreateCertificate produces.
func newTestPKI(t *testing.T, notBefore, notAfter time.Time) *testPKI {
	t.Helper()

	// Generate CA key + self-signed CA cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test TPM Vendor Root CA",
			Organization: []string{"Test Vendor Inc."},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Generate EK key + leaf cert signed by the CA.
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EK key: %v", err)
	}
	// KeyEncipherment is the KeyUsage required by TCG EK Credential Profile
	// v2.5 §3.2.7. For ECDSA (used in test), DataEncipherment also satisfies.
	// We use both to match the real EK cert profile.
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "TPM EK Test Leaf",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, ekTemplate, caCert, &ekKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create EK cert: %v", err)
	}
	ekCert, err := x509.ParseCertificate(ekDER)
	if err != nil {
		t.Fatalf("parse EK cert: %v", err)
	}

	ekCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekDER})

	ekPubDER, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal EK pub key: %v", err)
	}
	ekPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ekPubDER})

	return &testPKI{
		caKey:     caKey,
		caCert:    caCert,
		caPool:    caPool,
		ekKey:     ekKey,
		ekCert:    ekCert,
		ekCertPEM: ekCertPEM,
		ekPubPEM:  ekPubPEM,
	}
}

// -- tests ----------------------------------------------------------------

func TestChainVerifier_ValidChain_TIER_CORP(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pki.ekPubPEM,
		EKCertPEM:   pki.ekCertPEM,
		NonceClient: []byte("nonce"),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("valid chain verification failed: %v", err)
	}
	if resp.Path != "A_chain" {
		t.Errorf("Path = %q, want A_chain", resp.Path)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("Tier = %q, want TIER_CORP", resp.Tier)
	}
	if len(resp.Reasons) == 0 {
		t.Error("Reasons is empty")
	}
}

// TestChainVerifier_RequiresTOFU_Refused locks the anti-spoof guard:
// if the (manufacturer, kind) combination requires TOFU per the tier
// matrix, the chain verifier MUST refuse Path A even when a valid
// EK certificate is presented. This closes the downgrade vector where
// a malicious client claims an EK-cert-bearing platform (Intel/discrete)
// while really running an AMD consumer fTPM that doesn't factory-ship
// EK certs.
func TestChainVerifier_RequiresTOFU_Refused(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-24*time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	// AMD + firmware = RequiresTOFU(true) per tier_matrix.go.
	// Even with a fully valid EKCertPEM, chainVerifier must refuse.
	req := VerifyRequest{
		Platform:     "tpm2-linux",
		Manufacturer: "AMD",
		Kind:         "firmware",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("chain verifier accepted AMD/firmware request despite RequiresTOFU=true — anti-spoof guard absent")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("err = %v, want ErrVerification", err)
	}
	if !strings.Contains(err.Error(), "requires TOFU") {
		t.Errorf("err message does not mention requires TOFU: %v", err)
	}
}

func TestChainVerifier_ExpiredCert_Rejected(t *testing.T) {
	// Build a PKI where the EK cert is already expired at verify time.
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC) // 1 year after cert expired

	pki := newTestPKI(t, past, certNotAfter)

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pki.ekPubPEM,
		EKCertPEM:   pki.ekCertPEM,
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired EK cert")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_SelfSignedCert_Rejected(t *testing.T) {
	// Self-signed EK cert — not chained to our pinned CA pool.
	selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Self-Signed EK"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
	}
	selfDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &selfKey.PublicKey, selfKey)
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}
	selfCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfDER})

	selfPubDER, _ := x509.MarshalPKIXPublicKey(&selfKey.PublicKey)
	selfPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: selfPubDER})

	// Build a different pinned CA pool that does NOT contain the self-signed cert.
	otherPKI := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		otherPKI.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: selfPubPEM,
		EKCertPEM:   selfCertPEM,
		NonceClient: []byte("nonce"),
	}

	_, err = v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for self-signed cert not in pinned pool")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_WrongCA_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	// Build two separate PKIs. Present a cert from PKI-A but validate
	// against the pinned roots of PKI-B.
	pkiA := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	pkiB := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pkiB.caPool, // pool contains only PKI-B's root
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pkiA.ekPubPEM,
		EKCertPEM:   pkiA.ekCertPEM, // cert from PKI-A
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cert from wrong CA")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_EmptyCert_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pki.ekPubPEM,
		EKCertPEM:   nil, // missing — Path A requires it
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing EKCertPEM on Path A verifier")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_InvalidCertPEM_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pki.ekPubPEM,
		EKCertPEM:   []byte("not valid pem"),
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid EKCertPEM")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_EmptyEKPubKey_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: nil, // missing
		EKCertPEM:   pki.ekCertPEM,
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing EKPubKeyPEM on Path A verifier")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestChainVerifier_NoCertBlockType_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewChainVerifier(
		"tpm2-linux",
		pki.caPool,
		WithChainClock(func() time.Time { return now }),
	)

	// Valid PEM encoding but wrong block type (PUBLIC KEY instead of CERTIFICATE).
	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: pki.ekPubPEM,
		EKCertPEM:   pki.ekPubPEM, // public key PEM passed as cert
		NonceClient: []byte("nonce"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewChainVerifier_NilPool_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil vendorRoots")
		}
	}()
	NewChainVerifier("tpm2-linux", nil)
}

func TestSanitizeLabel(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Infineon OPTIGA TPM RSA Root CA", "infineon_optiga_tpm_rsa_root_ca"},
		{"", "unknown"},
		{"MSFT", "msft"},
		{"  leading-trailing  ", "leading_trailing"},
		{"123numeric456", "123numeric456"},
		{"camelCaseValue", "camelcasevalue"},
	}
	for _, tc := range cases {
		got := sanitizeLabel(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
