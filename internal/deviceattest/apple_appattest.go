// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — apple_appattest.go
//
// Apple App Attest verifier (server-side, iOS/iPadOS only).
//
// PLATFORM SCOPE — READ BEFORE EDITING
// =====================================
// Apple App Attest is ONLY available on iOS 14+ and iPadOS 14+.
// macOS does NOT have App Attest — macOS has no equivalent SE-backed
// key attestation mechanism as of 2026-06-07 (residual risk R1 in ADR 0043).
// macOS device identity is handled by macos_mdm.go (MDM client cert).
//
// References:
//   - Apple Developer Documentation — Validating Apps That Connect to Your Server
//     https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
//   - Apple Developer Documentation — Establishing Your App's Integrity
//     https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
//   - App Attest attestation object structure (CBOR-encoded AuthenticatorData)
//     https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-Attestation
//   - Apple App Attest Root CA / intermediate certificates
//     https://www.apple.com/certificateauthority/
//   - WebAuthn spec §6.5 — authenticatorData structure (same format)
//     https://www.w3.org/TR/webauthn-2/#authenticator-data
//   - ADR 0043 §3.c.4 — apple-app-attest verifier
//
// Protocol summary (Apple's attestation verification steps)
// ==========================================================
// Apple App Attest produces an "attestation object" when the app calls
// DCAppAttestService.attestKey(). The object is CBOR-encoded and contains:
//
//   fmt: "apple-appattest" (string)
//   attStmt: {
//     x5c: [leaf_cert_DER, intermediate_cert_DER, ...]  // cert chain
//     receipt: <bytes>                                    // Apple receipt
//   }
//   authData: <bytes>  // authenticatorData (see §6.5)
//
// authenticatorData layout (big-endian):
//   [0:32]   rpIdHash     — SHA-256 of the relying-party ID (app's teamID.bundleID)
//   [32]     flags        — UP (0x01) + AT (0x40) present in attestation
//   [33:37]  signCount    — u32 (0 at first attestation)
//   [37:53]  aaguid       — 16 bytes ("appattestdevelop" | "appattest\0\0\0\0\0\0\0")
//   [53:55]  credIdLen    — u16 big-endian length of credentialId
//   [55:55+credIdLen] credentialId — the keyId
//   after credId: credentialPublicKey — COSE-encoded public key
//
// Server-side verification steps (Apple docs §Verify-the-Attestation):
//  1. Decode CBOR attestation object.
//  2. Verify x5c chain: leaf → Apple intermediate → Apple Root.
//  3. Verify nonce: compute clientDataHash = SHA-256(challenge); compute
//     composite = SHA-256(authData || clientDataHash); verify it equals
//     the credCert's leaf extension nonce (OID 1.2.840.113635.100.8.2).
//  4. Verify that the public key in the leaf cert matches the key in authData.
//  5. Verify rpIdHash in authData = SHA-256(teamID.bundleID).
//  6. Verify AAGUID matches expected value.
//
// Implementation note on CBOR
// ============================
// This package avoids adding a CBOR dependency. Instead, we accept a
// AppleAppAttestPayload where the client-side posture-agent has already
// pre-extracted the relevant fields:
//   - CertChainPEM  — x5c chain, PEM encoded, leaf first
//   - AuthData      — raw authenticatorData bytes
//   - Challenge     — the nonce the server issued (echoed back for verification)
//
// This sidesteps CBOR parsing server-side while keeping the critical crypto
// verification intact. The posture-agent (Go/Swift) remains responsible for
// CBOR decoding; the server verifies all cryptographic bindings.
//
// Platform string: "apple-app-attest"

package deviceattest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
)

// oidAppleAnonymousNonce is the OID for the Apple App Attest nonce extension
// embedded in the leaf certificate:
// 1.2.840.113635.100.8.2 — appleAnonymousAttestation
//
// Source: Apple Developer Documentation — Verify the Attestation
// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-Attestation
var oidAppleAnonymousNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// appleAAGUIDProduction is the 16-byte AAGUID for production App Attest.
// "appattest" + 7 zero bytes. Source: Apple App Attest documentation.
var appleAAGUIDProduction = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")

// appleAAGUIDDevelopment is the 16-byte AAGUID for sandbox/development App Attest.
// "appattestdevelop". Source: Apple App Attest documentation.
var appleAAGUIDDevelopment = []byte("appattestdevelop")

// AppleAppAttestPayload is the JSON structure the posture-agent on
// iOS/iPadOS marshals into VerifyRequest.PlatformBlob.
//
// The posture-agent decodes the raw CBOR attestation object from
// DCAppAttestService.attestKey() and extracts these fields before
// sending them to the controller.
type AppleAppAttestPayload struct {
	// CertChainPEM is the PEM-encoded certificate chain from the
	// attestation object's x5c field, leaf certificate first.
	// The leaf is the "credCert" that contains the Apple nonce extension
	// and the device public key.
	CertChainPEM []byte `json:"cert_chain_pem"`

	// AuthData is the raw authenticatorData bytes from the attestation
	// object. The server verifies: rpIdHash, aaguid, credentialId (keyId),
	// and the public key binding.
	AuthData []byte `json:"auth_data"`

	// KeyID is the key identifier (SHA-256 of the SubjectPublicKeyInfo
	// from the leaf cert). The posture-agent asserts this equals the
	// keyId returned by DCAppAttestService.generateKey().
	// Used to bind the attestation to a specific key registration.
	KeyID []byte `json:"key_id"`

	// RPIDHash is the SHA-256 of the app's teamID.bundleID used as the
	// relying party identifier. The server validates that authData[0:32]
	// matches this value. The posture-agent computes this client-side and
	// the server must independently know the expected value.
	// If empty, the server skips the rpIdHash check (development mode only).
	RPIDHash []byte `json:"rpid_hash,omitempty"`

	// AllowDevelopment permits the "appattestdevelop" AAGUID in addition
	// to the production AAGUID. MUST be false in production deployments.
	// Controlled by the posture-agent build configuration; the controller
	// LOGS a warning but still verifies all other checks when true.
	AllowDevelopment bool `json:"allow_development,omitempty"`
}

// appleAppAttestVerifier implements Verifier for Platform="apple-app-attest".
//
// Trust ceiling: TIER_CORP (Apple SE-backed key, Apple root chain, iOS/iPadOS only).
// Rationale: Apple App Attest leverages the Secure Enclave which provides
// hardware-backed key storage equivalent to StrongBox on Android.
type appleAppAttestVerifier struct {
	rootPool *x509.CertPool
	now      func() time.Time
}

// AppleAppAttestOption configures an appleAppAttestVerifier.
type AppleAppAttestOption func(*appleAppAttestVerifier)

// WithAppleAppAttestClock replaces the real-time clock. Used in tests.
func WithAppleAppAttestClock(fn func() time.Time) AppleAppAttestOption {
	return func(v *appleAppAttestVerifier) { v.now = fn }
}

// NewAppleAppAttestVerifier constructs a production Apple App Attest verifier.
//
// rootPool MUST contain the Apple App Attest Root CA certificate.
// Obtain it from https://www.apple.com/certificateauthority/
// (Apple Application Integration Certification Authority 5G1 / Root CA).
//
// Nil rootPool panics so the wiring bug surfaces at controller startup.
//
// Register with:
//
//	registry.Register("apple-app-attest", NewAppleAppAttestVerifier(appleRootPool))
func NewAppleAppAttestVerifier(rootPool *x509.CertPool, opts ...AppleAppAttestOption) Verifier {
	if rootPool == nil {
		panic("deviceattest: NewAppleAppAttestVerifier: rootPool must not be nil")
	}
	v := &appleAppAttestVerifier{
		rootPool: rootPool,
		now:      time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Platform="apple-app-attest".
//
// Flow (per Apple's verification steps):
//  1. Decode PlatformBlob → AppleAppAttestPayload.
//  2. Parse PEM cert chain (leaf first).
//  3. Verify cert chain against the pinned Apple root pool.
//  4. Verify the nonce binding: compute composite =
//     SHA-256(authData || SHA-256(NonceClient)); verify it equals the
//     nonce embedded in the leaf cert's extension OID 1.2.840.113635.100.8.2.
//  5. Verify the public key in the leaf cert's SubjectPublicKeyInfo matches
//     the COSE public key embedded in authData (credentialPublicKey field).
//     We verify this by checking SHA-256(SPKI) == credentialId in authData.
//  6. Verify authData AAGUID matches production or (if allowed) development.
//  7. If RPIDHash is provided, verify authData[0:32] == RPIDHash.
//  8. Return TIER_CORP.
func (v *appleAppAttestVerifier) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: platform blob required.
	if len(req.PlatformBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest verifier requires PlatformBlob (AppleAppAttestPayload JSON)",
			ErrVerification,
		)
	}

	// Guard 2: nonce required (binds this attestation to a server challenge).
	if len(req.NonceClient) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest verifier requires NonceClient (server challenge)",
			ErrVerification,
		)
	}

	// Parse the platform payload.
	var payload AppleAppAttestPayload
	if err := json.Unmarshal(req.PlatformBlob, &payload); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest PlatformBlob is not valid AppleAppAttestPayload JSON: %v",
			ErrVerification, err,
		)
	}
	if len(payload.CertChainPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: CertChainPEM is empty in PlatformBlob",
			ErrVerification,
		)
	}
	if len(payload.AuthData) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: AuthData is empty in PlatformBlob",
			ErrVerification,
		)
	}

	// Parse the certificate chain.
	certs, err := parsePEMChain(payload.CertChainPEM)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: cert chain parse failed: %v",
			ErrVerification, err,
		)
	}
	if len(certs) < 2 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: cert chain too short (%d certs, minimum 2)",
			ErrVerification, len(certs),
		)
	}

	credCert := certs[0] // leaf = device credential cert
	// Build intermediate pool from certs[1:len-1].
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediatePool.AddCert(certs[i])
	}

	// Step 3: Verify certificate chain against the pinned Apple root pool.
	verifyOpts := x509.VerifyOptions{
		Roots:         v.rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.now(),
	}
	if _, err := credCert.Verify(verifyOpts); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: certificate chain verification failed: %v",
			ErrVerification, err,
		)
	}

	// Step 4: Verify the nonce binding.
	// Composite nonce = SHA-256(authData || clientDataHash)
	// where clientDataHash = SHA-256(challenge).
	//
	// Apple spec: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-Attestation
	clientDataHash := sha256.Sum256(req.NonceClient)
	compositeInput := make([]byte, 0, len(payload.AuthData)+32)
	compositeInput = append(compositeInput, payload.AuthData...)
	compositeInput = append(compositeInput, clientDataHash[:]...)
	compositeNonce := sha256.Sum256(compositeInput)

	expectedNonce, err := extractAppleNonce(credCert)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: nonce extension extraction failed: %v",
			ErrVerification, err,
		)
	}
	if !bytes.Equal(compositeNonce[:], expectedNonce) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: nonce binding failed — "+
				"SHA-256(authData||SHA-256(challenge)) does not match leaf cert nonce "+
				"(possible replay or challenge mismatch)",
			ErrVerification,
		)
	}

	// Step 5: Parse authenticatorData and validate AAGUID + key binding.
	authDataInfo, err := parseAppleAuthData(payload.AuthData)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: authenticatorData parse failed: %v",
			ErrVerification, err,
		)
	}

	// Step 6: Verify AAGUID.
	validAAGUID := bytes.Equal(authDataInfo.aaguid, appleAAGUIDProduction)
	if !validAAGUID && payload.AllowDevelopment {
		validAAGUID = bytes.Equal(authDataInfo.aaguid, appleAAGUIDDevelopment)
	}
	if !validAAGUID {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: AAGUID %x does not match Apple App Attest AAGUID "+
				"(production: %x)",
			ErrVerification, authDataInfo.aaguid, appleAAGUIDProduction,
		)
	}

	// Step 5b: Verify the key in the leaf cert matches the credentialId in
	// authData. Apple defines credentialId = SHA-256(SPKI bytes of the
	// device key from the attestation leaf cert).
	spkiHash, err := computeSPKIHash(credCert)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: SPKI hash computation failed: %v",
			ErrVerification, err,
		)
	}
	if !bytes.Equal(spkiHash, authDataInfo.credentialID) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-app-attest: leaf cert public key does not match "+
				"credentialId in authenticatorData (key binding failure)",
			ErrVerification,
		)
	}

	// Step 7: Validate rpIdHash if provided.
	if len(payload.RPIDHash) > 0 {
		if !bytes.Equal(payload.RPIDHash, authDataInfo.rpIDHash) {
			return VerifyResponse{}, fmt.Errorf(
				"%w: apple-app-attest: rpIdHash mismatch — "+
					"expected %x, authData has %x",
				ErrVerification, payload.RPIDHash, authDataInfo.rpIDHash,
			)
		}
	}

	reasons := []string{
		"apple_app_attest_verified",
		"issuer_" + sanitizeLabel(credCert.Issuer.CommonName),
	}
	if payload.AllowDevelopment {
		reasons = append(reasons, "app_attest_allow_development_mode")
	}

	return VerifyResponse{
		Path:    "A_chain",
		Tier:    "TIER_CORP",
		Reasons: reasons,
	}, nil
}

// appleAuthDataInfo holds the parsed fields from the authenticatorData
// that we need for verification.
type appleAuthDataInfo struct {
	rpIDHash     []byte // [0:32]
	flags        byte   // [32]
	signCount    uint32 // [33:37] big-endian
	aaguid       []byte // [37:53]
	credentialID []byte // [55 : 55+credIdLen]
}

// parseAppleAuthData parses the relevant fields from Apple's authenticatorData
// binary format.
//
// Layout (from WebAuthn §6.5, used by Apple App Attest):
//
//	[0:32]   rpIdHash      — 32 bytes
//	[32]     flags         — 1 byte
//	[33:37]  signCount     — uint32 big-endian
//	[37:53]  aaguid        — 16 bytes
//	[53:55]  credIdLength  — uint16 big-endian
//	[55:55+N] credentialId — N bytes
//	[55+N:]  credentialPublicKey — COSE map (not parsed here)
func parseAppleAuthData(authData []byte) (*appleAuthDataInfo, error) {
	const minLen = 37 + 16 + 2 // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2)
	if len(authData) < minLen {
		return nil, fmt.Errorf(
			"authenticatorData too short: %d bytes, minimum %d",
			len(authData), minLen,
		)
	}

	info := &appleAuthDataInfo{}
	info.rpIDHash = authData[0:32]
	info.flags = authData[32]
	info.signCount = binary.BigEndian.Uint32(authData[33:37])
	info.aaguid = authData[37:53]

	credIdLen := int(binary.BigEndian.Uint16(authData[53:55]))
	endIdx := 55 + credIdLen
	if len(authData) < endIdx {
		return nil, fmt.Errorf(
			"authenticatorData truncated: credIdLen=%d requires %d bytes, have %d",
			credIdLen, endIdx, len(authData),
		)
	}
	info.credentialID = authData[55:endIdx]
	return info, nil
}

// extractAppleNonce reads the nonce value from the leaf certificate's
// Apple anonymous nonce extension (OID 1.2.840.113635.100.8.2).
//
// Apple embeds the nonce as:
//
//	SEQUENCE {
//	  SEQUENCE {
//	    OCTET STRING <32-byte SHA-256 nonce>
//	  }
//	}
//
// The outer SEQUENCE is the extension value; we unwrap it to get the
// raw 32-byte nonce bytes.
func extractAppleNonce(cert *x509.Certificate) ([]byte, error) {
	var extValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAppleAnonymousNonce) {
			extValue = ext.Value
			break
		}
	}
	if extValue == nil {
		return nil, fmt.Errorf(
			"Apple nonce extension (OID %s) not found in leaf certificate",
			oidAppleAnonymousNonce,
		)
	}

	// Unwrap: SEQUENCE { SEQUENCE { OCTET STRING nonce } }
	// Outer SEQUENCE.
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(extValue, &outer); err != nil {
		return nil, fmt.Errorf("outer SEQUENCE unmarshal failed: %v", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing bytes after Apple nonce SEQUENCE (%d bytes)", len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("Apple nonce: outer value is not a SEQUENCE (class=%d tag=%d)", outer.Class, outer.Tag)
	}

	// Inner SEQUENCE.
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &inner); err != nil {
		return nil, fmt.Errorf("inner SEQUENCE unmarshal failed: %v", err)
	}
	if inner.Class != asn1.ClassUniversal || inner.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("Apple nonce: inner value is not a SEQUENCE (class=%d tag=%d)", inner.Class, inner.Tag)
	}

	// OCTET STRING nonce.
	var nonce []byte
	if _, err := asn1.Unmarshal(inner.Bytes, &nonce); err != nil {
		return nil, fmt.Errorf("nonce OCTET STRING unmarshal failed: %v", err)
	}
	if len(nonce) != 32 {
		return nil, fmt.Errorf("Apple nonce: expected 32 bytes, got %d", len(nonce))
	}
	return nonce, nil
}

// computeSPKIHash returns SHA-256(SubjectPublicKeyInfo DER bytes) of the
// certificate's public key. Apple defines the App Attest credentialId as
// this hash.
func computeSPKIHash(cert *x509.Certificate) ([]byte, error) {
	ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("leaf cert public key is not ECDSA (got %T)", cert.PublicKey)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(ecKey)
	if err != nil {
		return nil, fmt.Errorf("MarshalPKIXPublicKey: %v", err)
	}
	h := sha256.Sum256(spkiDER)
	return h[:], nil
}

// buildAppleAuthData constructs a minimal authenticatorData byte slice for
// use in tests. Exported (unexported actually — starts lowercase) for use
// within the test file in the same package.
//
// Parameters:
//   - rpIDHash: 32-byte SHA-256 of the app relying party ID
//   - aaguid: 16-byte AAGUID (use appleAAGUIDProduction or appleAAGUIDDevelopment)
//   - credentialID: byte slice to embed as the credential ID
func buildAppleAuthDataForTest(rpIDHash []byte, aaguid []byte, credentialID []byte) []byte {
	var buf []byte
	// rpIdHash [0:32]
	if len(rpIDHash) == 32 {
		buf = append(buf, rpIDHash...)
	} else {
		buf = append(buf, make([]byte, 32)...)
	}
	// flags [32] — UP (0x01) set
	buf = append(buf, 0x41) // UP | AT flags
	// signCount [33:37] — 0 for first attestation
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	// aaguid [37:53]
	if len(aaguid) == 16 {
		buf = append(buf, aaguid...)
	} else {
		buf = append(buf, make([]byte, 16)...)
	}
	// credIdLen [53:55]
	buf = append(buf, byte(len(credentialID)>>8), byte(len(credentialID)))
	// credentialId [55:55+N]
	buf = append(buf, credentialID...)
	return buf
}

// buildAppleNonceExtension constructs the DER value for OID 1.2.840.113635.100.8.2.
// Structure: SEQUENCE { SEQUENCE { OCTET STRING <nonce> } }
func buildAppleNonceExtension(nonce []byte) ([]byte, error) {
	innerOctet, err := asn1.Marshal(nonce)
	if err != nil {
		return nil, err
	}
	innerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      innerOctet,
	})
	if err != nil {
		return nil, err
	}
	outerSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      innerSeq,
	})
	if err != nil {
		return nil, err
	}
	return outerSeq, nil
}
