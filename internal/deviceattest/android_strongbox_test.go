// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// buildAndroidKeyDescription builds a DER-encoded KeyDescription SEQUENCE with
// the given attestationSecurityLevel and attestationChallenge.
//
// Schema (AOSP KeyAttestationTest.java):
//
//	KeyDescription ::= SEQUENCE {
//	  [0] INTEGER attestationVersion,
//	  [1] ENUMERATED attestationSecurityLevel,
//	  [2] INTEGER keymasterVersion,
//	  [3] ENUMERATED keymasterSecurityLevel,
//	  [4] OCTET STRING attestationChallenge,
//	  [5] OCTET STRING uniqueId,
//	  [6] AuthorizationList softwareEnforced,  -- SEQUENCE (empty in tests)
//	  [7] AuthorizationList teeEnforced        -- SEQUENCE (empty in tests)
//	}
func buildAndroidKeyDescription(t *testing.T, secLevel androidSecurityLevel, challenge []byte) []byte {
	t.Helper()

	// Helper: encode a value with a context-specific EXPLICIT tag.
	withContextTag := func(tag int, innerDER []byte) []byte {
		encoded, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tag,
			IsCompound: true,
			Bytes:      innerDER,
		})
		if err != nil {
			t.Fatalf("asn1.Marshal context tag [%d]: %v", tag, err)
		}
		return encoded
	}

	// Encode an INTEGER.
	encodeInt := func(v int) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("asn1.Marshal int(%d): %v", v, err)
		}
		return b
	}

	// Encode an ENUMERATED.
	encodeEnum := func(v int) []byte {
		b, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagEnum,
			Bytes: []byte{byte(v)},
		})
		if err != nil {
			t.Fatalf("asn1.Marshal enum(%d): %v", v, err)
		}
		return b
	}

	// Encode an OCTET STRING.
	encodeOctetString := func(b []byte) []byte {
		enc, err := asn1.Marshal(b)
		if err != nil {
			t.Fatalf("asn1.Marshal octet string: %v", err)
		}
		return enc
	}

	// Encode an empty SEQUENCE (for AuthorizationList fields [6] and [7]).
	encodeEmptySeq := func() []byte {
		b, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      []byte{},
		})
		if err != nil {
			t.Fatalf("asn1.Marshal empty sequence: %v", err)
		}
		return b
	}

	// Build the SEQUENCE body: fields [0]..[7].
	var body []byte
	body = append(body, withContextTag(0, encodeInt(200))...)               // attestationVersion = 200 (Android 11+)
	body = append(body, withContextTag(1, encodeEnum(int(secLevel)))...)    // attestationSecurityLevel
	body = append(body, withContextTag(2, encodeInt(100))...)               // keymasterVersion = 100
	body = append(body, withContextTag(3, encodeEnum(int(secLevel)))...)    // keymasterSecurityLevel
	body = append(body, withContextTag(4, encodeOctetString(challenge))...) // attestationChallenge
	body = append(body, withContextTag(5, encodeOctetString([]byte{}))...)  // uniqueId (empty)
	body = append(body, withContextTag(6, encodeEmptySeq())...)             // softwareEnforced
	body = append(body, withContextTag(7, encodeEmptySeq())...)             // teeEnforced

	// Wrap in outer SEQUENCE.
	outerDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	})
	if err != nil {
		t.Fatalf("asn1.Marshal outer SEQUENCE: %v", err)
	}
	return outerDER
}

// androidTestPKI holds a CA + a leaf cert with the Android Key Attestation
// extension injected. Mirrors the Google attestation chain:
//
//	leaf (device cert with KeyDescription ext) → rootCA
type androidTestPKI struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate
	rootPool *x509.CertPool
	leafCert *x509.Certificate
	chainPEM []byte
}

// newAndroidTestPKI builds a synthetic Android attestation chain.
// The leaf certificate contains the Android Key Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17) with the specified secLevel and challenge.
func newAndroidTestPKI(t *testing.T, notBefore, notAfter time.Time, secLevel androidSecurityLevel, challenge []byte) *androidTestPKI {
	t.Helper()

	// Root CA key + self-signed cert.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root CA key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Android Attestation Root CA"},
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

	// Build the KeyDescription extension DER value.
	kdDER := buildAndroidKeyDescription(t, secLevel, challenge)

	// Leaf key.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	// Leaf cert with the KeyDescription extension.
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Android Device Key Attestation"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidAndroidKeyAttestation,
				Critical: false,
				Value:    kdDER,
			},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Encode chain PEM: leaf first, then root.
	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)

	return &androidTestPKI{
		rootKey:  rootKey,
		rootCert: rootCert,
		rootPool: rootPool,
		leafCert: leafCert,
		chainPEM: chainPEM,
	}
}

// makeAndroidPayload marshals an AndroidKeyAttestPayload to JSON.
func makeAndroidPayload(t *testing.T, chainPEM []byte) []byte {
	t.Helper()
	p := AndroidKeyAttestPayload{CertChainPEM: chainPEM}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal AndroidKeyAttestPayload: %v", err)
	}
	return b
}

// -- tests ------------------------------------------------------------------

func TestAndroidStrongBox_ValidChain_TIER_CORP(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("server-issued-nonce-android-001")
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, challenge)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("valid Android StrongBox attestation failed: %v", err)
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
	// Verify "android_strongbox_attested" is in reasons.
	found := false
	for _, r := range resp.Reasons {
		if r == "android_strongbox_attested" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'android_strongbox_attested' in Reasons %v", resp.Reasons)
	}
}

// TestAndroidStrongBox_TEEOnly_Rejected verifies that a TEE-level attestation
// (security level 1, not StrongBox 2) is rejected.
func TestAndroidStrongBox_TEEOnly_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("server-nonce-tee-test")
	// Build a chain with TEE security level (not StrongBox).
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelTEE, challenge)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for TEE-only (non-StrongBox) attestation")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_SoftwareLevel_Rejected verifies software security level
// (level 0) is also rejected.
func TestAndroidStrongBox_SoftwareLevel_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("server-nonce-software-test")
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelSoftware, challenge)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for software-level attestation")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_NonceMismatch_Rejected verifies that a mismatched
// attestationChallenge (replay attack) is rejected.
func TestAndroidStrongBox_NonceMismatch_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	embeddedChallenge := []byte("original-server-nonce")
	differentNonce := []byte("different-nonce-replay")
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, embeddedChallenge)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  differentNonce, // different from embeddedChallenge
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nonce mismatch (replay attack)")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_WrongCA_Rejected verifies that a chain not rooting in
// the pinned root pool is rejected.
func TestAndroidStrongBox_WrongCA_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-wrong-ca")

	pkiA := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, challenge)
	pkiB := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, challenge)

	// Verifier uses pkiB's root; chain is from pkiA.
	v := NewAndroidStrongBoxVerifier(pkiB.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, pkiA.chainPEM), // pkiA's chain
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cert from wrong CA")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_ExpiredCert_Rejected verifies that an expired
// certificate is rejected.
func TestAndroidStrongBox_ExpiredCert_Rejected(t *testing.T) {
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	challenge := []byte("nonce-expired")
	pki := newAndroidTestPKI(t, past, certNotAfter, androidSecLevelStrongBox, challenge)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_MissingPlatformBlob_Rejected verifies that a request
// without PlatformBlob is rejected.
func TestAndroidStrongBox_MissingPlatformBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, []byte("nonce"))

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:    "android-strongbox",
		NonceClient: []byte("nonce"),
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

// TestAndroidStrongBox_MissingNonce_Rejected verifies that a request
// without NonceClient is rejected.
func TestAndroidStrongBox_MissingNonce_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, []byte("nonce"))

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  nil, // missing
		PlatformBlob: makeAndroidPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing NonceClient")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_NoKeyDescriptionExtension_Rejected verifies that a leaf
// cert without the OID extension is rejected.
func TestAndroidStrongBox_NoKeyDescriptionExtension_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-no-ext")

	// Build a chain but replace the leaf with a cert that has NO KeyDescription ext.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Android Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Leaf cert WITHOUT the KeyDescription extension.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "No KeyDescription"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)

	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...)

	v := NewAndroidStrongBoxVerifier(rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, chainPEM),
	}

	_, err = v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing KeyDescription extension")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_InvalidJSON_Rejected verifies that non-JSON PlatformBlob
// is rejected.
func TestAndroidStrongBox_InvalidJSON_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, []byte("nonce"))

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  []byte("nonce"),
		PlatformBlob: []byte("not json"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid JSON PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAndroidStrongBox_SingleCertChain_Rejected verifies that a chain with
// only one certificate (leaf == root, or just one cert) is rejected.
func TestAndroidStrongBox_SingleCertChain_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	challenge := []byte("nonce-single-cert")
	pki := newAndroidTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), androidSecLevelStrongBox, challenge)

	// Strip all but the leaf cert.
	block, _ := pem.Decode(pki.chainPEM)
	singleCertPEM := pem.EncodeToMemory(block)

	v := NewAndroidStrongBoxVerifier(pki.rootPool, WithAndroidStrongBoxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "android-strongbox",
		NonceClient:  challenge,
		PlatformBlob: makeAndroidPayload(t, singleCertPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for single-cert chain")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewAndroidStrongBoxVerifier_NilPool_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil rootPool")
		}
	}()
	NewAndroidStrongBoxVerifier(nil)
}
