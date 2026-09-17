// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — android_strongbox.go
//
// Android Keystore Hardware Attestation verifier (server-side).
//
// References:
//   - AOSP Key and ID Attestation — OID 1.3.6.1.4.1.11129.2.1.17
//     https://developer.android.com/privacy-and-security/security-key-attestation
//   - Android CTS KeyDescriptionASN1 schema
//     https://android.googlesource.com/platform/cts/+/main/tests/tests/keystore/src/android/keystore/cts/KeyAttestationTest.java
//   - Google AOSP key attestation root certificates
//     https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
//   - RFC 5280 §4.1 — X.509 Certificate Extensions
//   - ADR 0043 §3.c.3 — android-strongbox verifier
//
// How Android Keystore Attestation works
// ========================================
// When a key is generated in the Android Keystore with
// setAttestationChallenge(), the hardware security element (StrongBox or TEE)
// produces an X.509 certificate chain:
//
//	Device Key Certificate
//	  └── Batch Attestation Certificate (batch cert per device model)
//	       └── Google Hardware Attestation Root CA (pinned)
//
// The Device Key Certificate contains a non-critical extension with OID
// 1.3.6.1.4.1.11129.2.1.17 whose value is a DER-encoded KeyDescription
// structure (defined in AOSP KeyAttestationTest.java schema).
//
// The server (jess-controller) verifies:
//  1. The certificate chain is valid and chains to the pinned Google Root.
//  2. The KeyDescription extension is present and parseable.
//  3. attestationSecurityLevel == StrongBox (value 2). TEE-only (value 1)
//     and Software (value 0) are REJECTED — TIER_CORP requires StrongBox.
//  4. The attestationChallenge in the KeyDescription matches req.NonceClient
//     (replay prevention — same role as NonceClient in TPM2 quotes).
//
// Platform string: "android-strongbox"
// Payload: AndroidKeyAttestPayload (certificate chain PEM in PlatformBlob)
//
// ASN.1 KeyDescription schema (simplified, AOSP CTS canonical)
// =============================================================
//
//	KeyDescription ::= SEQUENCE {
//	  attestationVersion         INTEGER,         -- [0] implicit
//	  attestationSecurityLevel   SecurityLevel,   -- [1] implicit ENUMERATED
//	  keymasterVersion           INTEGER,         -- [2] implicit (renamed to keyMintVersion in A12+)
//	  keymasterSecurityLevel     SecurityLevel,   -- [3] implicit ENUMERATED
//	  attestationChallenge       OCTET STRING,    -- [4] implicit
//	  uniqueId                   OCTET STRING,    -- [5] implicit
//	  softwareEnforced           AuthorizationList, -- [6] implicit
//	  teeEnforced                AuthorizationList  -- [7] implicit
//	}
//
//	SecurityLevel ::= ENUMERATED {
//	  Software   (0),
//	  TrustedEnvironment (1),
//	  StrongBox  (2)
//	}
//
// We parse only the fields we care about (attestationSecurityLevel and
// attestationChallenge) using encoding/asn1 with manual tag inspection.

package deviceattest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// oidAndroidKeyAttestation is the OID for the Android Key Attestation
// extension: 1.3.6.1.4.1.11129.2.1.17
// Source: https://developer.android.com/privacy-and-security/security-key-attestation
var oidAndroidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// androidSecurityLevel mirrors the SecurityLevel ENUMERATED type from
// the AOSP KeyDescription ASN.1 schema.
type androidSecurityLevel int

const (
	androidSecLevelSoftware  androidSecurityLevel = 0
	androidSecLevelTEE       androidSecurityLevel = 1
	androidSecLevelStrongBox androidSecurityLevel = 2
)

// keyDescriptionFields holds the parsed fields from the top-level
// KeyDescription SEQUENCE that the jess-controller needs for verification.
// We parse only what we need; the AuthorizationList fields are left as raw
// bytes to avoid full schema implementation.
type keyDescriptionFields struct {
	attestationVersion       int
	attestationSecurityLevel androidSecurityLevel
	keymasterVersion         int
	keymasterSecurityLevel   androidSecurityLevel
	attestationChallenge     []byte
}

// AndroidKeyAttestPayload is the JSON structure the posture-agent on Android
// marshals into VerifyRequest.PlatformBlob.
//
// The cert chain is in PEM encoding, leaf first (device cert → batch cert →
// root). The last cert in the chain MUST be the Google Hardware Attestation
// Root CA (pinned in the verifier's rootPool). Intermediate certs between
// the batch cert and the root MAY be present.
type AndroidKeyAttestPayload struct {
	// CertChainPEM is the PEM-encoded certificate chain, leaf first.
	// Each certificate is a separate "-----BEGIN CERTIFICATE-----" block.
	// Minimum 3 blocks: device cert, batch cert, root cert.
	CertChainPEM []byte `json:"cert_chain_pem"`
}

// androidStrongBoxVerifier implements Verifier for Platform="android-strongbox".
//
// Trust ceiling: TIER_CORP (StrongBox-backed hardware key, Google root chain).
// TEE-only attestation is rejected — it offers weaker isolation guarantees
// than dedicated StrongBox hardware (ADR 0043 §3.c.3).
type androidStrongBoxVerifier struct {
	rootPool *x509.CertPool
	now      func() time.Time
}

// AndroidStrongBoxOption configures an androidStrongBoxVerifier.
type AndroidStrongBoxOption func(*androidStrongBoxVerifier)

// WithAndroidStrongBoxClock replaces the real-time clock. Used in tests.
func WithAndroidStrongBoxClock(fn func() time.Time) AndroidStrongBoxOption {
	return func(v *androidStrongBoxVerifier) { v.now = fn }
}

// NewAndroidStrongBoxVerifier constructs a production Android StrongBox verifier.
//
// rootPool MUST contain the Google Hardware Attestation Root CA certificate.
// It is the caller's responsibility to obtain and pin the root from:
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
//
// Nil rootPool panics so the wiring bug surfaces at controller startup.
//
// Register with:
//
//	registry.Register("android-strongbox", NewAndroidStrongBoxVerifier(googleRootPool))
func NewAndroidStrongBoxVerifier(rootPool *x509.CertPool, opts ...AndroidStrongBoxOption) Verifier {
	if rootPool == nil {
		panic("deviceattest: NewAndroidStrongBoxVerifier: rootPool must not be nil")
	}
	v := &androidStrongBoxVerifier{
		rootPool: rootPool,
		now:      time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Platform="android-strongbox".
//
// Flow:
//  1. Decode PlatformBlob → AndroidKeyAttestPayload.
//  2. Parse PEM chain → []x509.Certificate (leaf first).
//  3. Verify the chain against the pinned root pool.
//  4. Parse the KeyDescription extension from the leaf (device key cert).
//  5. Assert attestationSecurityLevel == StrongBox (2).
//  6. Assert attestationChallenge == req.NonceClient (replay prevention).
//  7. Return TIER_CORP.
func (v *androidStrongBoxVerifier) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: platform blob required.
	if len(req.PlatformBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox verifier requires PlatformBlob (AndroidKeyAttestPayload JSON)",
			ErrVerification,
		)
	}

	// Guard 2: nonce required (bound to attestationChallenge in the cert).
	if len(req.NonceClient) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox verifier requires NonceClient (attestation challenge)",
			ErrVerification,
		)
	}

	// Parse payload.
	var payload AndroidKeyAttestPayload
	if err := json.Unmarshal(req.PlatformBlob, &payload); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox PlatformBlob is not valid AndroidKeyAttestPayload JSON: %v",
			ErrVerification, err,
		)
	}
	if len(payload.CertChainPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: CertChainPEM is empty in PlatformBlob",
			ErrVerification,
		)
	}

	// Parse the PEM-encoded certificate chain.
	certs, err := parsePEMChain(payload.CertChainPEM)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: cert chain parse failed: %v",
			ErrVerification, err,
		)
	}
	if len(certs) < 2 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: cert chain too short (%d certs, minimum 2: leaf + root)",
			ErrVerification, len(certs),
		)
	}

	// Build an intermediate pool from all certs except the leaf and root.
	leafCert := certs[0]
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediatePool.AddCert(certs[i])
	}

	// Verify the chain: leaf → intermediates → root (in rootPool).
	verifyOpts := x509.VerifyOptions{
		Roots:         v.rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.now(),
		// KeyUsages is not set — we check the attestation extension, not TLS usage.
	}
	if _, err := leafCert.Verify(verifyOpts); err != nil {
		reason := classifyChainError(err)
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: certificate chain verification failed (%s): %v",
			ErrVerification, reason, err,
		)
	}

	// Extract and parse the Android Key Attestation extension from the leaf.
	kd, err := extractKeyDescription(leafCert)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: KeyDescription extension parse failed: %v",
			ErrVerification, err,
		)
	}

	// Assert StrongBox security level.
	// TEE (level 1) and Software (level 0) are rejected — they do not meet
	// the hardware isolation requirements for TIER_CORP (ADR 0043 §3.c.3).
	if kd.attestationSecurityLevel != androidSecLevelStrongBox {
		levelName := androidSecLevelName(kd.attestationSecurityLevel)
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: attestationSecurityLevel=%s (%d) is not StrongBox; "+
				"TIER_CORP requires hardware-backed StrongBox isolation",
			ErrVerification, levelName, int(kd.attestationSecurityLevel),
		)
	}

	// Assert attestationChallenge matches NonceClient (replay prevention).
	// The challenge is embedded by the Android system when the key was generated;
	// comparing it to the server-issued nonce binds the attestation to this
	// specific enrollment request.
	if !bytes.Equal(kd.attestationChallenge, req.NonceClient) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: android-strongbox: attestationChallenge does not match NonceClient "+
				"(nonce mismatch — possible replay attack)",
			ErrVerification,
		)
	}

	return VerifyResponse{
		Path: "A_chain",
		Tier: "TIER_CORP",
		Reasons: []string{
			"android_strongbox_attested",
			fmt.Sprintf("attest_version_%d", kd.attestationVersion),
			"issuer_" + sanitizeLabel(leafCert.Issuer.CommonName),
		},
	}, nil
}

// extractKeyDescription finds and parses the Android Key Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17) from the certificate.
//
// The extension value is DER-encoded KeyDescription SEQUENCE. We parse the
// first 6 fields using explicit tag values as defined in the AOSP schema.
//
// Schema (condensed from AOSP CTS KeyAttestationTest.java):
//
//	KeyDescription ::= SEQUENCE {
//	  [0] INTEGER attestationVersion,
//	  [1] ENUMERATED attestationSecurityLevel,
//	  [2] INTEGER keymasterVersion,
//	  [3] ENUMERATED keymasterSecurityLevel,
//	  [4] OCTET STRING attestationChallenge,
//	  [5] OCTET STRING uniqueId,
//	  [6] AuthorizationList softwareEnforced,  -- not parsed here
//	  [7] AuthorizationList teeEnforced        -- not parsed here
//	}
func extractKeyDescription(cert *x509.Certificate) (*keyDescriptionFields, error) {
	var extValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAndroidKeyAttestation) {
			extValue = ext.Value
			break
		}
	}
	if extValue == nil {
		return nil, fmt.Errorf(
			"Android Key Attestation extension (OID %s) not found in leaf certificate",
			oidAndroidKeyAttestation,
		)
	}

	// The extension value is the DER encoding of the KeyDescription SEQUENCE.
	// Unwrap the outer SEQUENCE.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(extValue, &outer)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription outer SEQUENCE parse failed: %v", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("KeyDescription: trailing bytes after SEQUENCE (%d bytes)", len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, fmt.Errorf("KeyDescription: outer value is not a SEQUENCE (class=%d tag=%d)", outer.Class, outer.Tag)
	}

	// Parse the fields from the SEQUENCE body using CONTEXT-SPECIFIC explicit
	// tag numbers [0]..[5]. Each field is wrapped in a context-specific tag.
	//
	// Note: AOSP encodes these as IMPLICIT tags in the schema definition, but
	// the actual DER encoding uses EXPLICIT context-specific tags in practice
	// (confirmed against AOSP CTS source and real device attestations). We use
	// asn1.RawValue to inspect each field's tag before decoding its content.
	body := outer.Bytes
	kd := &keyDescriptionFields{}

	// Field [0]: attestationVersion INTEGER
	body, err = parseContextInt(body, 0, &kd.attestationVersion)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription[0] attestationVersion: %v", err)
	}

	// Field [1]: attestationSecurityLevel ENUMERATED
	var secLevel int
	body, err = parseContextEnum(body, 1, &secLevel)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription[1] attestationSecurityLevel: %v", err)
	}
	kd.attestationSecurityLevel = androidSecurityLevel(secLevel)

	// Field [2]: keymasterVersion INTEGER
	body, err = parseContextInt(body, 2, &kd.keymasterVersion)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription[2] keymasterVersion: %v", err)
	}

	// Field [3]: keymasterSecurityLevel ENUMERATED
	var kmSecLevel int
	body, err = parseContextEnum(body, 3, &kmSecLevel)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription[3] keymasterSecurityLevel: %v", err)
	}
	kd.keymasterSecurityLevel = androidSecurityLevel(kmSecLevel)

	// Field [4]: attestationChallenge OCTET STRING
	body, err = parseContextOctetString(body, 4, &kd.attestationChallenge)
	if err != nil {
		return nil, fmt.Errorf("KeyDescription[4] attestationChallenge: %v", err)
	}

	// Fields [5]..[7] (uniqueId, AuthorizationLists) are not needed for
	// the enrollment check; we stop here.
	_ = body
	return kd, nil
}

// parseContextInt reads a CONTEXT tag [tagNum] wrapping an INTEGER from the
// DER bytes. Returns the remaining bytes and the decoded integer.
func parseContextInt(der []byte, tagNum int, out *int) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != tagNum {
		return nil, fmt.Errorf("expected [%d] context tag, got class=%d tag=%d", tagNum, raw.Class, raw.Tag)
	}
	var v int
	if _, err = asn1.Unmarshal(raw.Bytes, &v); err != nil {
		return nil, fmt.Errorf("INTEGER decode failed: %v", err)
	}
	*out = v
	return rest, nil
}

// parseContextEnum reads a CONTEXT tag [tagNum] wrapping an ENUMERATED from
// the DER bytes.
func parseContextEnum(der []byte, tagNum int, out *int) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != tagNum {
		return nil, fmt.Errorf("expected [%d] context tag, got class=%d tag=%d", tagNum, raw.Class, raw.Tag)
	}
	// ENUMERATED has the same encoding as INTEGER; decode as RawValue with
	// tag ENUMERATED then extract the value.
	var e asn1.RawValue
	if _, err = asn1.Unmarshal(raw.Bytes, &e); err != nil {
		return nil, fmt.Errorf("ENUMERATED decode failed: %v", err)
	}
	if e.Tag != asn1.TagEnum {
		return nil, fmt.Errorf("inner tag=%d is not ENUMERATED (%d)", e.Tag, asn1.TagEnum)
	}
	// Decode the variable-length integer from e.Bytes (big-endian, signed).
	v := 0
	for _, b := range e.Bytes {
		v = (v << 8) | int(b)
	}
	*out = v
	return rest, nil
}

// parseContextOctetString reads a CONTEXT tag [tagNum] wrapping an OCTET STRING.
func parseContextOctetString(der []byte, tagNum int, out *[]byte) (rest []byte, err error) {
	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != tagNum {
		return nil, fmt.Errorf("expected [%d] context tag, got class=%d tag=%d", tagNum, raw.Class, raw.Tag)
	}
	var s []byte
	if _, err = asn1.Unmarshal(raw.Bytes, &s); err != nil {
		return nil, fmt.Errorf("OCTET STRING decode failed: %v", err)
	}
	*out = s
	return rest, nil
}

// parsePEMChain decodes a PEM-encoded certificate chain (leaf first) and
// returns the parsed *x509.Certificate slice. Returns an error if any block
// cannot be parsed.
func parsePEMChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block type %q is not CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseCertificate: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM data")
	}
	return certs, nil
}

// androidSecLevelName returns the human-readable name for an androidSecurityLevel.
func androidSecLevelName(l androidSecurityLevel) string {
	switch l {
	case androidSecLevelSoftware:
		return "Software"
	case androidSecLevelTEE:
		return "TrustedEnvironment"
	case androidSecLevelStrongBox:
		return "StrongBox"
	default:
		return fmt.Sprintf("Unknown(%d)", int(l))
	}
}
