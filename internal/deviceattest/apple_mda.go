// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — apple_mda.go
//
// Apple Managed Device Attestation (MDA) verifier (server-side, macOS 14+).
//
// PLATFORM SCOPE — READ BEFORE EDITING
// =====================================
// Apple MDA is available on macOS 14+ (Sonoma), iOS 16+, iPadOS 16.1+,
// tvOS 16+, and watchOS 9+. For our ZTNA program, MDA on macOS is the
// primary path that closes residual risk R1 from ADR 0040 / ADR 0043.
//
// This file verifies the ATTESTATION CERTIFICATE chain issued by Apple's
// attestation servers during the ACME-DA (IETF RFC 9773) device enrollment
// flow. Distinguish from:
//
//   - apple_appattest.go  — iOS/iPadOS App Attest (App Store app, SE key,
//     WebAuthn-style attestation object). Platform="apple-app-attest".
//     Different root CA, different OID arc, different payload format.
//   - macos_mdm.go        — macOS MDM-issued CLIENT-AUTH certificate (Jamf/
//     Kandji SCEP/PKCS12 identity cert). No hardware attestation; TIER_BYOD
//     ceiling per ADR 0040 D-006.
//
// Apple MDA trust model
// ======================
// During ACME-DA enrollment an Apple device calls Apple's attestation servers
// which return an attestation certificate chain (leaf + intermediate) rooted
// in the Apple Enterprise Attestation Root CA. The leaf cert carries custom
// extensions (OID arc 1.2.840.113635.100.8.x) that encode hardware properties
// verified by the Secure Enclave:
//
//   - 1.2.840.113635.100.8.9.1  — Device Serial Number
//   - 1.2.840.113635.100.8.9.2  — Device UDID
//   - 1.2.840.113635.100.8.10.2 — Secure Enclave Processor (SEP) OS version
//   - 1.2.840.113635.100.8.11.1 — Freshness code (anti-replay nonce)
//
// A cert is accepted as a genuine Apple MDA attestation cert when:
//  1. Its chain verifies against the Apple Enterprise Attestation Root CA.
//  2. The leaf carries at least one device-identity OID (serial or UDID).
//  3. The leaf carries the freshness OID binding it to a specific request.
//  4. The cert is within its validity window.
//
// On macOS 14+, the Secure Enclave generates the key pair; the private key
// never leaves the Secure Enclave. This is the hardware-rooted binding that
// justifies TIER_CORP eligibility, equivalent to TPM Path A on Linux/Windows
// or App Attest on iOS.
//
// Root CA distinction
// ===================
// Apple MDA → Apple Enterprise Attestation Root CA
//   CN=Apple Enterprise Attestation Root CA, O=Apple Inc., C=US
//   SHA-256: CC:F5:9E:F8:FC:B3:01:7D:97:F8:B5:FA:6F:A9:0E:7A:3F:92:83:F7:6B:55:AC:6C:F6:ED:A8:B8:B9:49:F0:5B
//   https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem
//
// Apple App Attest (iOS/iPadOS) → Apple App Attestation Root CA (DIFFERENT root)
//   CN=Apple App Attestation Root CA, O=Apple Inc., ST=California
//   https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
//
// The roots MUST NOT be confused. An MDA cert verified against the App Attest
// root (or vice versa) will fail chain validation — this is correct behaviour.
//
// Payload format
// ==============
// The posture-agent (Swift/Go) on macOS receives the attestation certificate
// chain from the MDM's ACME solution and PEM-encodes it (leaf first). It
// marshals it into AppleMDAPayload which is carried in VerifyRequest.PlatformBlob.
// The posture-agent does NOT perform the chain verification — that happens here.
//
// Server-side verification steps (this verifier):
//  1. Decode PlatformBlob → AppleMDAPayload.
//  2. Parse PEM chain (leaf + optional intermediates).
//  3. Verify chain against the injected Apple Enterprise Attestation Root CA pool.
//  4. Validate the freshness OID (1.2.840.113635.100.8.11.1) matches the
//     server-issued nonce (req.NonceClient): per Apple docs, the freshness code
//     is the SHA-256 of the ACME token; the nonce stored in the cert is the
//     raw SHA-256 bytes, not further encoded.
//  5. Verify the leaf carries at least one device-identity OID (serial or UDID).
//  6. Verify the cert is within its validity window (handled implicitly by x509.Verify).
//  7. Return TIER_CORP with a reasons list carrying the extracted device properties.
//
// Note on ExtKeyUsage
// ===================
// Apple's MDA attestation leaf certificate does NOT include id-kp-clientAuth
// (1.3.6.1.5.5.7.3.2). It is an ATTESTATION certificate, not a client-auth
// certificate. The downstream ACME-issued certificate (signed by the MDM's
// own CA after the attestation is validated) is the TLS client certificate.
// This verifier validates the attestation layer only. We use ExtKeyUsageAny
// in x509.VerifyOptions so the Go x509 library does not reject the leaf.
// Reference: Smallstep open-source ACME CA (challenge.go doAppleAttestationFormat).
//
// Note on SAN / URI
// =================
// The Apple MDA attestation leaf cert does NOT carry a SPIFFE URI SAN. The
// device identity is encoded in the custom OID extensions (serial/UDID).
// The SPIFFE URI (spiffe://hexxlock.com/device/<uuid>) is stamped by jess
// into the device certificate that jess issues AFTER attestation succeeds —
// it is not present in the Apple-issued attestation cert.
//
// Platform string: "apple-mda"
// Tier: TIER_CORP (Secure Enclave-backed key, Apple Enterprise Attestation Root chain)
//
// References:
//   - Apple — Managed Device Attestation for Apple devices
//     https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web
//   - Apple — Managed device attestation security (OID table + validation steps)
//     https://support.apple.com/en-sa/guide/security/sec8a37b4cb2/web
//   - Smallstep — Managed Device Attestation: ACME as the bottom turtle
//     https://smallstep.com/blog/managed-device-attestation/
//   - Smallstep certificates (open source ACME CA reference implementation)
//     https://github.com/smallstep/certificates/blob/master/acme/challenge.go
//   - Apple Enterprise Attestation Root CA PEM
//     https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem
//   - IETF RFC 9773 — ACME Device Attestation Challenge
//     https://www.rfc-editor.org/rfc/rfc9773
//   - ADR 0040 D-006 (tier ceiling definitions), ADR 0043 §3.c.6, ADR 0040 R1 closure

package deviceattest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"time"
)

// Apple MDA OIDs — extensions embedded in the Apple-issued attestation leaf cert.
//
// Source: Apple security guide "Managed device attestation security" OID table
// https://support.apple.com/en-sa/guide/security/sec8a37b4cb2/web
// Cross-referenced against Smallstep open-source ACME CA implementation
// https://github.com/smallstep/certificates/blob/master/acme/challenge.go

// oidAppleMDASerialNumber is the device serial number embedded in the MDA leaf cert.
// OID: 1.2.840.113635.100.8.9.1
// Value encoding: UTF-8 string (raw extension value, not ASN.1 wrapped).
var oidAppleMDASerialNumber = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 1}

// oidAppleMDAUDID is the device UDID (Unique Device ID) embedded in the MDA leaf cert.
// On Mac, the UDID matches the provisioning UDID of the device.
// OID: 1.2.840.113635.100.8.9.2
// Value encoding: UTF-8 string (raw extension value, not ASN.1 wrapped).
// Note: omitted when using User Enrollment to protect user privacy.
var oidAppleMDAUDID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 9, 2}

// oidAppleMDASEPOSVersion is the Secure Enclave Processor OS version.
// OID: 1.2.840.113635.100.8.10.2
// Value encoding: UTF-8 string (version string, e.g. "16.0.0").
var oidAppleMDASEPOSVersion = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 10, 2}

// oidAppleMDAFreshnessCode is the freshness code binding the attestation to a
// specific request. Prevents replay of prior attestations.
// OID: 1.2.840.113635.100.8.11.1
// Value encoding: raw bytes (SHA-256 of the ACME token / DeviceAttestationNonce).
var oidAppleMDAFreshnessCode = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 11, 1}

// AppleMDAPayload is the JSON structure the posture-agent on macOS marshals
// into VerifyRequest.PlatformBlob.
//
// During ACME-DA enrollment the MDM (Jamf Pro, Intune, etc.) delivers the
// Apple attestation certificate chain to the posture-agent after the
// device-attest-01 challenge completes. The agent PEM-encodes this chain
// and sends it to the jess controller for server-side verification.
type AppleMDAPayload struct {
	// CertChainPEM is the PEM-encoded Apple attestation certificate chain,
	// leaf first. The chain comes from Apple's attestation servers during
	// the ACME-DA device-attest-01 challenge flow. It is rooted in the
	// Apple Enterprise Attestation Root CA.
	//
	// Minimum: leaf certificate. Recommended: leaf + any Apple intermediates.
	// The trust root (Enterprise Attestation Root CA) is NOT expected in this
	// chain — it is injected separately via the constructor rootPool.
	CertChainPEM []byte `json:"cert_chain_pem"`

	// DeviceSerial is the device serial number the posture-agent asserts for
	// this device. The verifier cross-checks this against the serial number
	// embedded in the leaf cert's OID 1.2.840.113635.100.8.9.1 extension.
	// Optional: if empty, the verifier skips the serial cross-check (the OID
	// extension presence check still applies).
	DeviceSerial string `json:"device_serial,omitempty"`

	// DeviceUDID is the device UDID the posture-agent asserts for this device.
	// Cross-checked against OID 1.2.840.113635.100.8.9.2 in the leaf cert.
	// Optional: if empty, the verifier skips the UDID cross-check.
	DeviceUDID string `json:"device_udid,omitempty"`
}

// appleMDAVerifier implements Verifier for Platform="apple-mda".
//
// Trust ceiling: TIER_CORP — Apple MDA binds the private key to the Secure
// Enclave; the attestation chain to the Apple Enterprise Attestation Root CA
// provides hardware-rooted trust equivalent to TPM Path A. This closes
// residual risk R1 from ADR 0040 / ADR 0043. See package doc for R1 rationale.
type appleMDAVerifier struct {
	rootPool *x509.CertPool
	now      func() time.Time
}

// AppleMDAOption configures an appleMDAVerifier.
type AppleMDAOption func(*appleMDAVerifier)

// WithAppleMDAClock replaces the real-time clock. Used in tests to simulate
// expired or future certificates without OS clock manipulation.
func WithAppleMDAClock(fn func() time.Time) AppleMDAOption {
	return func(v *appleMDAVerifier) { v.now = fn }
}

// NewAppleMDAVerifier constructs a production Apple MDA verifier.
//
// rootPool MUST contain the Apple Enterprise Attestation Root CA certificate.
// Obtain the PEM from:
//
//	https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem
//
// Load at controller startup from the vendor-root Kubernetes Secret:
//
//	pool := x509.NewCertPool()
//	if ok := pool.AppendCertsFromPEM(enterpriseAttestationRootPEM); !ok {
//	    return fmt.Errorf("no valid cert in apple-enterprise-attestation-root secret")
//	}
//	registry.Register("apple-mda", NewAppleMDAVerifier(pool))
//
// IMPORTANT: Do NOT pass the Apple App Attestation Root CA here — that root
// is for iOS App Attest (apple_appattest.go), not for macOS MDA.
//
// Nil rootPool panics at construction time so the wiring bug surfaces at
// controller startup, not silently at first attestation request.
func NewAppleMDAVerifier(rootPool *x509.CertPool, opts ...AppleMDAOption) Verifier {
	if rootPool == nil {
		panic("deviceattest: NewAppleMDAVerifier: rootPool must not be nil; " +
			"inject the Apple Enterprise Attestation Root CA " +
			"(https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem)")
	}
	v := &appleMDAVerifier{
		rootPool: rootPool,
		now:      time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Platform="apple-mda".
//
// The attestation request carries the Apple-issued attestation certificate
// chain (from the ACME-DA device-attest-01 flow) and the server-issued nonce.
//
// Verification flow:
//  1. Guard: PlatformBlob must be non-empty.
//  2. Guard: NonceClient must be non-empty (anti-replay binding).
//  3. Decode PlatformBlob → AppleMDAPayload.
//  4. Parse PEM cert chain (leaf first); minimum 1 cert required.
//  5. Verify cert chain against the injected Apple Enterprise Attestation Root
//     CA pool (x509.Verify with ExtKeyUsageAny; MDA attestation certs do not
//     carry id-kp-clientAuth — they are attestation certs, not client certs).
//  6. Verify freshness: OID 1.2.840.113635.100.8.11.1 must be present in
//     leaf extensions and its value must equal SHA-256(NonceClient). This
//     binds the attestation to the server's challenge and prevents replay.
//  7. Verify device identity: at least one of OID .8.9.1 (serial) or .8.9.2
//     (UDID) must be present — their presence proves the cert was issued to
//     a real Apple device by Apple's attestation servers, not a plain cert
//     that happens to chain to the Apple root.
//  8. If DeviceSerial is set in the payload, cross-check against .8.9.1.
//  9. If DeviceUDID is set in the payload, cross-check against .8.9.2.
//
// 10. Return TIER_CORP with diagnostic reasons.
func (v *appleMDAVerifier) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: platform blob required.
	if len(req.PlatformBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda verifier requires PlatformBlob (AppleMDAPayload JSON)",
			ErrVerification,
		)
	}

	// Guard 2: nonce required (binds the attestation to this server challenge).
	// Per Apple docs, the freshness code in the MDA cert is SHA-256(ACME token).
	// The server stores the raw ACME token as NonceClient; the verifier computes
	// SHA-256(NonceClient) and compares against the freshness OID value.
	if len(req.NonceClient) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda verifier requires NonceClient (ACME challenge token, "+
				"used to verify the MDA freshness code via SHA-256(token))",
			ErrVerification,
		)
	}

	// Parse the platform payload.
	var payload AppleMDAPayload
	if err := json.Unmarshal(req.PlatformBlob, &payload); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda PlatformBlob is not valid AppleMDAPayload JSON: %v",
			ErrVerification, err,
		)
	}
	if len(payload.CertChainPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: CertChainPEM is empty in PlatformBlob",
			ErrVerification,
		)
	}

	// Parse the certificate chain.
	certs, err := parsePEMChain(payload.CertChainPEM)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: cert chain parse failed: %v",
			ErrVerification, err,
		)
	}
	// Minimum: the leaf cert. Intermediates help x509.Verify build the chain
	// but are optional if the Apple intermediate is cached in the pool.
	// In practice the MDM always includes the intermediate.
	if len(certs) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: cert chain contains no parseable certificates",
			ErrVerification,
		)
	}

	leafCert := certs[0]

	// Build an intermediate pool from all certs between the leaf and root.
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediatePool.AddCert(certs[i])
	}

	// Step 5: Verify chain against the Apple Enterprise Attestation Root CA pool.
	//
	// ExtKeyUsageAny is required because Apple MDA attestation leaf certs do
	// NOT carry id-kp-clientAuth. They are attestation certs issued by Apple's
	// attestation servers — the downstream ACME-issued client cert (signed by
	// the MDM's CA) carries clientAuth, not the attestation cert.
	//
	// Reference: Smallstep challenge.go doAppleAttestationFormat uses
	// ExtKeyUsageAny for the same reason:
	// https://github.com/smallstep/certificates/blob/master/acme/challenge.go
	verifyOpts := x509.VerifyOptions{
		Roots:         v.rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leafCert.Verify(verifyOpts); err != nil {
		reason := classifyChainError(err)
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: attestation certificate chain verification failed (%s): %v "+
				"(ensure rootPool contains the Apple Enterprise Attestation Root CA, not "+
				"the App Attestation Root CA)",
			ErrVerification, reason, err,
		)
	}

	// Step 6: Verify the freshness code.
	//
	// Per Apple docs (https://support.apple.com/en-sa/guide/security/sec8a37b4cb2/web):
	//   "When using ACME attestation, the freshness code is the SHA-256 hash of
	//    the token from the device-attest-01 challenge."
	//
	// The jess controller stores the raw ACME token in req.NonceClient.
	// The cert contains SHA-256(token) as the raw value of OID .8.11.1.
	expectedFreshness := sha256.Sum256(req.NonceClient)
	freshnessValue, found := extractMDAExtension(leafCert, oidAppleMDAFreshnessCode)
	if !found {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: freshness OID (1.2.840.113635.100.8.11.1) not found in "+
				"leaf certificate extensions — cert may not be a genuine MDA attestation cert",
			ErrVerification,
		)
	}
	if !bytes.Equal(expectedFreshness[:], freshnessValue) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: freshness code mismatch — "+
				"SHA-256(NonceClient) does not match the value in OID 1.2.840.113635.100.8.11.1 "+
				"(possible replay attack or wrong challenge token)",
			ErrVerification,
		)
	}

	// Step 7: Verify device identity OIDs.
	//
	// At least one of serial (OID .8.9.1) or UDID (OID .8.9.2) MUST be present.
	// Their presence proves that Apple's attestation servers issued this cert to
	// a real enrolled Apple device — it is not merely a cert that happens to
	// chain to the Apple Enterprise Attestation Root CA (which Apple could
	// theoretically use for other purposes in the future).
	serialValue, hasSerial := extractMDAExtension(leafCert, oidAppleMDASerialNumber)
	udidValue, hasUDID := extractMDAExtension(leafCert, oidAppleMDAUDID)

	if !hasSerial && !hasUDID {
		return VerifyResponse{}, fmt.Errorf(
			"%w: apple-mda: leaf certificate has neither serial number OID "+
				"(1.2.840.113635.100.8.9.1) nor UDID OID (1.2.840.113635.100.8.9.2) — "+
				"cert is not a genuine Apple MDA device attestation certificate",
			ErrVerification,
		)
	}

	// Step 8: Cross-check client-asserted serial number against the OID value.
	if payload.DeviceSerial != "" && hasSerial {
		certSerial := string(serialValue)
		if payload.DeviceSerial != certSerial {
			return VerifyResponse{}, fmt.Errorf(
				"%w: apple-mda: DeviceSerial %q does not match serial number in "+
					"OID 1.2.840.113635.100.8.9.1 %q (identity cross-check failed)",
				ErrVerification, payload.DeviceSerial, certSerial,
			)
		}
	}

	// Step 9: Cross-check client-asserted UDID against the OID value.
	if payload.DeviceUDID != "" && hasUDID {
		certUDID := string(udidValue)
		if payload.DeviceUDID != certUDID {
			return VerifyResponse{}, fmt.Errorf(
				"%w: apple-mda: DeviceUDID %q does not match UDID in "+
					"OID 1.2.840.113635.100.8.9.2 %q (identity cross-check failed)",
				ErrVerification, payload.DeviceUDID, certUDID,
			)
		}
	}

	// Extract optional SEP OS version for audit reasons.
	sepOSVersion, hasSEP := extractMDAExtension(leafCert, oidAppleMDASEPOSVersion)

	// Step 10: Build diagnostic Reasons and return TIER_CORP.
	reasons := []string{
		"apple_mda_verified",
		"issuer_" + sanitizeLabel(leafCert.Issuer.CommonName),
	}
	if hasSerial {
		reasons = append(reasons, "mda_serial_"+sanitizeLabel(string(serialValue)))
	}
	if hasUDID {
		reasons = append(reasons, "mda_udid_present")
	}
	if hasSEP {
		reasons = append(reasons, "sep_os_"+sanitizeLabel(string(sepOSVersion)))
	}

	// TIER_CORP: MDA with Secure Enclave-backed key + Apple attestation chain
	// is equivalent to TPM Path A on Linux/Windows. Closes ADR 0040 R1.
	return VerifyResponse{
		Path:    "A_chain",
		Tier:    "TIER_CORP",
		Reasons: reasons,
	}, nil
}

// extractMDAExtension scans the certificate's raw Extensions and returns the
// raw (un-ASN.1-decoded) value bytes for the given OID, plus a found boolean.
//
// Apple MDA extension values are stored as raw bytes (UTF-8 string for serial/
// UDID/SEP-version; raw SHA-256 bytes for the freshness code). They are NOT
// wrapped in an additional ASN.1 SEQUENCE or OCTET STRING — the extension
// Value field IS the content directly.
//
// This differs from the Apple App Attest nonce extension (apple_appattest.go)
// which wraps the nonce in SEQUENCE { SEQUENCE { OCTET STRING } }.
//
// Reference: Smallstep challenge.go reads ext.Value directly for all four MDA OIDs.
func extractMDAExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value, true
		}
	}
	return nil, false
}

// buildAppleMDAFreshnessExtValue constructs the raw extension value for OID
// 1.2.840.113635.100.8.11.1 from the ACME token (for test PKI generation).
//
// Per Apple docs: freshness code = SHA-256(ACME token / DeviceAttestationNonce).
// The value stored in the extension is the raw 32 SHA-256 bytes (no ASN.1 wrapper).
func buildAppleMDAFreshnessExtValue(acmeToken []byte) []byte {
	sum := sha256.Sum256(acmeToken)
	return sum[:]
}
