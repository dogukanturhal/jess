// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// appleTestPKI holds a root CA + a leaf "credCert" with the Apple nonce
// extension embedded, simulating the Apple App Attest certificate chain.
type appleTestPKI struct {
	rootKey      *ecdsa.PrivateKey
	rootCert     *x509.Certificate
	rootPool     *x509.CertPool
	leafKey      *ecdsa.PrivateKey
	leafCert     *x509.Certificate
	leafDER      []byte
	rootDER      []byte
	chainPEM     []byte
	challenge    []byte
	authData     []byte
	nonce        []byte // SHA-256(authData || SHA-256(challenge))
	credentialID []byte // SHA-256(SPKI of leafKey)
}

// newAppleTestPKI constructs a synthetic Apple App Attest certificate chain
// and authData, properly binding the nonce and key.
//
// The leaf certificate:
//   - Is signed by the root CA.
//   - Contains OID 1.2.840.113635.100.8.2 extension with the correct nonce.
//
// The authData:
//   - Contains the correct rpIdHash (from rpID).
//   - Contains the production AAGUID.
//   - Contains credentialID = SHA-256(SPKI of leaf key).
func newAppleTestPKI(t *testing.T, notBefore, notAfter time.Time, challenge []byte, allowDev bool) *appleTestPKI {
	t.Helper()

	// Root CA.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple App Attest Root CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Leaf (credCert) key.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	// Compute credentialID = SHA-256(SPKI bytes of leafKey).
	spkiDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal leaf SPKI: %v", err)
	}
	credIDHash := sha256.Sum256(spkiDER)
	credentialID := credIDHash[:]

	// Compute rpIdHash = SHA-256("teamID.bundleID" — use a test value).
	rpID := "TEAMID123.com.hexxlock.app"
	rpIDHashArr := sha256.Sum256([]byte(rpID))
	rpIDHash := rpIDHashArr[:]

	// Build authData.
	var aaguid []byte
	if allowDev {
		aaguid = appleAAGUIDDevelopment
	} else {
		aaguid = appleAAGUIDProduction
	}
	authData := buildAppleAuthDataForTest(rpIDHash, aaguid, credentialID)

	// Compute the composite nonce: SHA-256(authData || SHA-256(challenge)).
	clientDataHash := sha256.Sum256(challenge)
	compositeInput := make([]byte, 0, len(authData)+32)
	compositeInput = append(compositeInput, authData...)
	compositeInput = append(compositeInput, clientDataHash[:]...)
	compositeHash := sha256.Sum256(compositeInput)
	nonce := compositeHash[:]

	// Build the Apple nonce extension DER value.
	nonceExtDER, err := buildAppleNonceExtension(nonce)
	if err != nil {
		t.Fatalf("build Apple nonce extension: %v", err)
	}

	// Leaf cert with the Apple nonce extension.
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Apple App Attest Test Leaf"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidAppleAnonymousNonce,
				Critical: false,
				Value:    nonceExtDER,
			},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	// Build chain PEM: leaf first, root last.
	chainPEM := appendCertPEM(nil, leafDER)
	chainPEM = appendCertPEM(chainPEM, rootDER)

	return &appleTestPKI{
		rootKey:      rootKey,
		rootCert:     rootCert,
		rootPool:     rootPool,
		leafKey:      leafKey,
		leafDER:      leafDER,
		rootDER:      rootDER,
		chainPEM:     chainPEM,
		challenge:    challenge,
		authData:     authData,
		nonce:        nonce,
		credentialID: credentialID,
	}
}

// appendCertPEM PEM-encodes a DER certificate and appends it to buf.
func appendCertPEM(buf []byte, der []byte) []byte {
	return append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

// makeApplePayload builds AppleAppAttestPayload JSON for tests.
func makeApplePayload(t *testing.T, pki *appleTestPKI, challenge []byte, overrideChain []byte, allowDev bool) []byte {
	t.Helper()
	chain := pki.chainPEM
	if overrideChain != nil {
		chain = overrideChain
	}
	p := AppleAppAttestPayload{
		CertChainPEM:     chain,
		AuthData:         pki.authData,
		KeyID:            pki.credentialID,
		AllowDevelopment: allowDev,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal AppleAppAttestPayload: %v", err)
	}
	return b
}

// -- tests ------------------------------------------------------------------

func TestAppleAppAttest_ValidAttestation_TIER_CORP(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("server-challenge-apple-001")
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: makeApplePayload(t, pki, challenge, nil, false),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("valid Apple App Attest verification failed: %v", err)
	}
	if resp.Path != "A_chain" {
		t.Errorf("Path = %q, want A_chain", resp.Path)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("Tier = %q, want TIER_CORP", resp.Tier)
	}
	found := false
	for _, r := range resp.Reasons {
		if r == "apple_app_attest_verified" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'apple_app_attest_verified' in Reasons: %v", resp.Reasons)
	}
}

// TestAppleAppAttest_NonceMismatch_Rejected verifies that a stale or replayed
// challenge is rejected. This is the core replay-prevention check.
func TestAppleAppAttest_NonceMismatch_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("server-challenge-apple-original")
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	// Use a different nonce than what was embedded in the cert.
	differentChallenge := []byte("different-challenge-replay-attempt")
	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  differentChallenge, // mismatch
		PlatformBlob: makeApplePayload(t, pki, challenge, nil, false),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nonce (challenge) mismatch")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_WrongCA_Rejected verifies that a chain not rooted in the
// pinned Apple root pool is rejected.
func TestAppleAppAttest_WrongCA_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-wrong-ca-apple")
	pkiA := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)
	pkiB := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)

	// Use pkiB root but pkiA chain.
	v := NewAppleAppAttestVerifier(pkiB.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: makeApplePayload(t, pkiA, challenge, nil, false),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cert from wrong CA")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_ExpiredCert_Rejected verifies that an expired leaf cert
// causes verification to fail.
func TestAppleAppAttest_ExpiredCert_Rejected(t *testing.T) {
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	challenge := []byte("nonce-apple-expired")
	pki := newAppleTestPKI(t, past, certNotAfter, challenge, false)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: makeApplePayload(t, pki, challenge, nil, false),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_InvalidAAGUID_Rejected verifies that an authData blob
// with an unknown AAGUID is rejected.
func TestAppleAppAttest_InvalidAAGUID_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-apple-bad-aaguid")
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)

	// Modify authData to have an unknown AAGUID, then recompute composite nonce.
	badAAGUID := []byte("UNKNOWNAAGUID!!!")
	modAuthData := buildAppleAuthDataForTest(make([]byte, 32), badAAGUID, pki.credentialID)

	// Recompute nonce for the modified authData.
	clientDataHash := sha256.Sum256(challenge)
	compositeInput := append(modAuthData, clientDataHash[:]...)
	compositeHash := sha256.Sum256(compositeInput)
	badNonce := compositeHash[:]

	// Build a new leaf cert with the bad nonce embedded.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Bad AAGUID Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	badPool := x509.NewCertPool()
	badPool.AddCert(rootCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonceExtDER, _ := buildAppleNonceExtension(badNonce)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Bad AAGUID Leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: oidAppleAnonymousNonce, Value: nonceExtDER},
		},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	badChainPEM := appendCertPEM(nil, leafDER)
	badChainPEM = appendCertPEM(badChainPEM, rootDER)

	// Compute correct credentialID for this leaf.
	spkiDER, _ := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	credIDH := sha256.Sum256(spkiDER)

	p := AppleAppAttestPayload{
		CertChainPEM: badChainPEM,
		AuthData:     modAuthData,
		KeyID:        credIDH[:],
	}
	blob, _ := json.Marshal(p)

	v := NewAppleAppAttestVerifier(badPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: blob,
	}

	_, err = v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid AAGUID")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_DevelopmentAAGUID_WithFlag_Accepted verifies that the
// development AAGUID is accepted when AllowDevelopment=true.
func TestAppleAppAttest_DevelopmentAAGUID_WithFlag_Accepted(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-apple-dev-mode")
	// Build with development AAGUID.
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, true)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: makeApplePayload(t, pki, challenge, nil, true),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("valid development attestation failed: %v", err)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("Tier = %q, want TIER_CORP", resp.Tier)
	}
	// Verify development reason is recorded.
	found := false
	for _, r := range resp.Reasons {
		if r == "app_attest_allow_development_mode" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'app_attest_allow_development_mode' in Reasons: %v", resp.Reasons)
	}
}

// TestAppleAppAttest_MissingPlatformBlob_Rejected verifies guard condition.
func TestAppleAppAttest_MissingPlatformBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), []byte("n"), false)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:    "apple-app-attest",
		NonceClient: []byte("n"),
		// PlatformBlob: nil
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_MissingNonce_Rejected verifies guard condition.
func TestAppleAppAttest_MissingNonce_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce")
	pki := newAppleTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), challenge, false)

	v := NewAppleAppAttestVerifier(pki.rootPool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  nil,
		PlatformBlob: makeApplePayload(t, pki, challenge, nil, false),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing NonceClient")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleAppAttest_NoNonceExtension_Rejected verifies that a leaf cert
// without the OID 1.2.840.113635.100.8.2 extension is rejected.
func TestAppleAppAttest_NoNonceExtension_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-apple-no-ext")

	// Build a chain without the Apple nonce extension.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "No Nonce Apple Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "No Apple Nonce Ext"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// No ExtraExtensions — Apple nonce OID not present.
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)

	chainPEM := appendCertPEM(nil, leafDER)
	chainPEM = appendCertPEM(chainPEM, rootDER)

	spkiDER, _ := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	credIDH := sha256.Sum256(spkiDER)
	authData := buildAppleAuthDataForTest(make([]byte, 32), appleAAGUIDProduction, credIDH[:])

	p := AppleAppAttestPayload{
		CertChainPEM: chainPEM,
		AuthData:     authData,
		KeyID:        credIDH[:],
	}
	blob, _ := json.Marshal(p)

	v := NewAppleAppAttestVerifier(pool, WithAppleAppAttestClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "apple-app-attest",
		NonceClient:  challenge,
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing Apple nonce extension")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewAppleAppAttestVerifier_NilPool_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil rootPool")
		}
	}()
	NewAppleAppAttestVerifier(nil)
}

// TestAppleAuthDataParse_ShortData verifies parseAppleAuthData returns an
// error for truncated input.
func TestAppleAuthDataParse_ShortData(t *testing.T) {
	short := make([]byte, 20) // too short
	_, err := parseAppleAuthData(short)
	if err == nil {
		t.Fatal("expected error for short authenticatorData")
	}
}

// TestAppleNonceExtension_RoundTrip verifies that buildAppleNonceExtension +
// extractAppleNonce form a correct round-trip.
func TestAppleNonceExtension_RoundTrip(t *testing.T) {
	original := make([]byte, 32)
	for i := range original {
		original[i] = byte(i)
	}
	extDER, err := buildAppleNonceExtension(original)
	if err != nil {
		t.Fatalf("buildAppleNonceExtension: %v", err)
	}

	// Build a dummy cert with the extension to use extractAppleNonce.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Round Trip Test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidAppleAnonymousNonce, Value: extDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	extracted, err := extractAppleNonce(cert)
	if err != nil {
		t.Fatalf("extractAppleNonce: %v", err)
	}

	if len(extracted) != 32 {
		t.Errorf("extracted nonce length = %d, want 32", len(extracted))
	}
	for i, b := range extracted {
		if b != original[i] {
			t.Errorf("nonce byte %d: got %02x, want %02x", i, b, original[i])
		}
	}
}

// Ensure asn1 import is used (asn1.TagEnum etc. are referenced in Android tests).
var _ = asn1.TagEnum
