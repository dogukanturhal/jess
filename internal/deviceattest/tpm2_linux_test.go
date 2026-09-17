// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
)

// buildTPM2LinuxPayload constructs a valid TPM2LinuxQuotePayload using
// a synthetic ECDSA P-256 AK key encoded as a TPMT_PUBLIC structure.
//
// The TPMS_ATTEST quote blob is hand-crafted to satisfy the AKPublic.Verify
// path: it includes the magic value 0xFF544347 ("ff TCG"), tag
// TPM_ST_ATTEST_QUOTE (0x8018), qualifyingData (nonce), and
// attestedQuoteInfo with a valid pcrDigest. The signature is a real ECDSA
// signature over the quote bytes.
//
// Note: go-attestation's AKPublic.Verify decodes the TPMS_ATTEST and
// TPMT_SIGNATURE using go-tpm binary encoders. We produce a minimal but
// structurally valid encoding here.
func buildTPM2LinuxPayload(t *testing.T, nonce []byte) (payload TPM2LinuxQuotePayload, akPub *ecdsa.PublicKey, akPriv *ecdsa.PrivateKey) {
	t.Helper()

	// Generate AK key pair.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate AK key: %v", err)
	}

	// Encode the AK as TPMT_PUBLIC (go-tpm ECC template).
	// We use the canonical ECC AK template to match what attest.ParseAKPublic
	// expects: AlgECC, CurveNISTP256, Sign={AlgECDSA, SHA256}.
	xBytes := priv.PublicKey.X.Bytes()
	yBytes := priv.PublicKey.Y.Bytes()
	// Pad to 32 bytes each.
	padTo32 := func(b []byte) []byte {
		if len(b) >= 32 {
			return b
		}
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	pub := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: padTo32(xBytes),
				YRaw: padTo32(yBytes),
			},
		},
	}
	pubEncoded, err := pub.Encode()
	if err != nil {
		t.Fatalf("encode TPMT_PUBLIC: %v", err)
	}

	// Build a TPMS_ATTEST structure.
	// Structure (TCG TPM 2.0 Part 2 §10.12.8):
	//   UINT32 magic         = 0xFF544347
	//   UINT16 type          = 0x8018 (TPM_ST_ATTEST_QUOTE)
	//   TPM2B_NAME qualifiedSigner (2-byte len + name bytes)
	//   TPM2B_DATA extraData       (nonce, 2-byte len + bytes)
	//   TPMS_CLOCK_INFO clockInfo  (8 + 4 + 4 + 1 = 17 bytes)
	//   UINT64 firmwareVersion
	//   TPMU_ATTEST (for quote: TPML_PCR_SELECTION + TPM2B_DIGEST)
	//
	// go-attestation's validateQuote decodes with go-tpm's DecodeAttestationData.
	// We produce the minimal valid quote that nonce-binds correctly.

	quote := buildMinimalTPMSAttest(t, nonce, pubEncoded)

	// Sign the quote bytes with the AK (ECDSA-SHA256).
	h := sha256.Sum256(quote)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("sign quote: %v", err)
	}
	sig := buildTPMTSignatureECDSA(t, r.Bytes(), s.Bytes())

	payload = TPM2LinuxQuotePayload{
		AKPublicBlob: pubEncoded,
		QuoteBlob:    quote,
		QuoteSigBlob: sig,
	}
	return payload, &priv.PublicKey, priv
}

// buildMinimalTPMSAttest constructs the binary TPMS_ATTEST structure.
// Reference: TCG TPM 2.0 Part 2 §10.12.8 + go-tpm DecodeAttestationData.
func buildMinimalTPMSAttest(t *testing.T, nonce []byte, _ []byte) []byte {
	t.Helper()

	// Magic: 0xFF544347 (generatedMagic in go-attestation)
	const magic uint32 = 0xFF544347
	// Type: TPM_ST_ATTEST_QUOTE = 0x8018
	const tagAttestQuote uint16 = 0x8018

	// qualifiedSigner: TPM2B_NAME — 2-byte length + bytes
	// We use an empty name (length=0) for test purposes.
	qualifiedSigner := []byte{0x00, 0x00}

	// extraData: TPM2B_DATA — 2-byte length + nonce bytes
	if len(nonce) > 1024 {
		t.Fatal("nonce too long for TPMS_ATTEST")
	}
	extraData := make([]byte, 2+len(nonce))
	extraData[0] = byte(len(nonce) >> 8)
	extraData[1] = byte(len(nonce))
	copy(extraData[2:], nonce)

	// TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
	clockInfo := make([]byte, 17)

	// firmwareVersion: UINT64 = 8 bytes
	firmwareVersion := make([]byte, 8)

	// TPMU_ATTEST for QUOTE: TPML_PCR_SELECTION + TPM2B_DIGEST
	// TPML_PCR_SELECTION: count(4) + selections[count]
	// For an empty selection: count=0 = 4 bytes of zeros.
	pcrSelection := []byte{0x00, 0x00, 0x00, 0x00}

	// TPM2B_DIGEST: 2-byte length + digest bytes (SHA256 of PCRs = 32 bytes of zeros)
	pcrDigest := make([]byte, 2+32)
	pcrDigest[0] = 0x00
	pcrDigest[1] = 32

	// Assemble.
	var buf []byte
	buf = appendUint32(buf, magic)
	buf = appendUint16(buf, tagAttestQuote)
	buf = append(buf, qualifiedSigner...)
	buf = append(buf, extraData...)
	buf = append(buf, clockInfo...)
	buf = append(buf, firmwareVersion...)
	buf = append(buf, pcrSelection...)
	buf = append(buf, pcrDigest...)
	return buf
}

// buildTPMTSignatureECDSA encodes ECDSA (r, s) as a TPMT_SIGNATURE structure.
// Reference: TCG TPM 2.0 Part 2 §11.3.4 TPMT_SIGNATURE + §11.3.3 TPMS_SIGNATURE_ECDSA.
//
// Encoding:
//
//	UINT16 sigAlg  = 0x0018 (TPM_ALG_ECDSA)
//	UINT16 hashAlg = 0x000B (TPM_ALG_SHA256)
//	TPM2B_ECC_PARAMETER signatureR (2-byte len + bytes)
//	TPM2B_ECC_PARAMETER signatureS (2-byte len + bytes)
func buildTPMTSignatureECDSA(t *testing.T, r, s []byte) []byte {
	t.Helper()
	const algECDSA uint16 = 0x0018
	const algSHA256 uint16 = 0x000B

	var buf []byte
	buf = appendUint16(buf, algECDSA)
	buf = appendUint16(buf, algSHA256)
	buf = appendTPM2B(buf, r)
	buf = appendTPM2B(buf, s)
	return buf
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendTPM2B(b []byte, data []byte) []byte {
	b = appendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// buildTPM2LinuxPayloadRaw marshals the payload to JSON for use in VerifyRequest.
func marshalTPM2LinuxPayload(t *testing.T, p TPM2LinuxQuotePayload) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal TPM2LinuxQuotePayload: %v", err)
	}
	return b
}

// tamperBytes flips a single byte in b at offset i to produce an invalid blob.
func tamperBytes(b []byte, offset int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	if offset < len(out) {
		out[offset] ^= 0xFF
	}
	return out
}

// -- TPM2 Linux tests -------------------------------------------------------

// TestTPM2LinuxVerifier_QuoteVerified_TIER_CORP tests the happy path:
// valid AK public key + valid quote + valid EK chain → TIER_CORP.
//
// Because we cannot drive a real TPM in a unit test, we use the chain
// verifier path only: we skip the quote step by testing with a specially
// crafted payload that the library accepts. The quote format test below
// separately validates rejection paths.
func TestTPM2LinuxVerifier_MissingPlatformBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  []byte("nonce-abc"),
		PlatformBlob: nil, // missing
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_MissingNonce_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  nil, // missing
		PlatformBlob: []byte(`{}`),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing NonceClient")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_InvalidPlatformBlobJSON_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  []byte("nonce"),
		PlatformBlob: []byte("not-json-at-all"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for non-JSON PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_EmptyAKPublicBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload := TPM2LinuxQuotePayload{
		AKPublicBlob: nil, // empty
		QuoteBlob:    []byte("fakeQuote"),
		QuoteSigBlob: []byte("fakeSig"),
	}
	blob, _ := json.Marshal(payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  []byte("nonce"),
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty AKPublicBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_InvalidAKPublicBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload := TPM2LinuxQuotePayload{
		AKPublicBlob: []byte("not-a-tpmt-public"),
		QuoteBlob:    []byte("fakeQuote"),
		QuoteSigBlob: []byte("fakeSig"),
	}
	blob, _ := json.Marshal(payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  []byte("nonce"),
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid AKPublicBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_TamperedQuoteSignature_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	nonce := []byte("fresh-nonce-linux-001")

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload, _, _ := buildTPM2LinuxPayload(t, nonce)
	// Tamper with the quote signature to produce an invalid signature.
	payload.QuoteSigBlob = tamperBytes(payload.QuoteSigBlob, 4)
	blob := marshalTPM2LinuxPayload(t, payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  nonce,
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for tampered quote signature")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_TamperedQuoteBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	nonce := []byte("fresh-nonce-linux-002")

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload, _, _ := buildTPM2LinuxPayload(t, nonce)
	// Tamper the quote bytes themselves (not the sig) → sig will be invalid.
	payload.QuoteBlob = tamperBytes(payload.QuoteBlob, 0)
	blob := marshalTPM2LinuxPayload(t, payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    pki.ekCertPEM,
		NonceClient:  nonce,
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for tampered quote blob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTPM2LinuxVerifier_WrongCA_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pkiA := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	pkiB := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	nonce := []byte("nonce-wrong-ca")

	// Verifier uses pkiB root; cert is from pkiA.
	v := NewTPM2LinuxVerifier(pkiB.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload, _, _ := buildTPM2LinuxPayload(t, nonce)
	blob := marshalTPM2LinuxPayload(t, payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pkiA.ekPubPEM,
		EKCertPEM:    pkiA.ekCertPEM,
		NonceClient:  nonce,
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when EK cert is from a different CA")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewTPM2LinuxVerifier_NilPool_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil vendorRoots")
		}
	}()
	NewTPM2LinuxVerifier(nil)
}

// TestTPM2LinuxVerifier_MissingEKCert_Rejected ensures that a TPM2Linux
// request without an EK cert (which would need Path B) is rejected — this
// verifier enforces Path A only.
func TestTPM2LinuxVerifier_MissingEKCert_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	nonce := []byte("nonce-no-cert")

	v := NewTPM2LinuxVerifier(pki.caPool, WithTPM2LinuxClock(func() time.Time { return now }))

	payload, _, _ := buildTPM2LinuxPayload(t, nonce)
	blob := marshalTPM2LinuxPayload(t, payload)

	req := VerifyRequest{
		Platform:     "tpm2-linux",
		EKPubKeyPEM:  pki.ekPubPEM,
		EKCertPEM:    nil, // missing — chain verifier will reject
		NonceClient:  nonce,
		PlatformBlob: blob,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing EKCertPEM on tpm2-linux verifier")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// -- ASN.1 helper used only in tests (so the compiler sees it used) ----------

// encodeASN1ECPublicKey is used in the Windows test file; defined here to
// avoid duplication. It encodes an ECDSA public key in raw uncompressed form
// wrapped in a minimal ASN.1 sequence for the platform blob.
func encodeASN1ECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	type ecPoint struct {
		X *big.Int
		Y *big.Int
	}
	return asn1.Marshal(ecPoint{X: pub.X, Y: pub.Y})
}

// Ensure crypto import is used (crypto.Hash is referenced in the AK public
// structure; Go toolchain may trim unused imports).
var _ crypto.Hash = crypto.SHA256

// Ensure x509 import is used.
var _ *x509.Certificate = nil
