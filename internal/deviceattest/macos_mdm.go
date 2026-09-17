// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — macos_mdm.go
//
// macOS MDM client certificate verifier (server-side).
//
// Residual risk R1 mitigation (ADR 0043 §3.c.5)
// =================================================
// macOS has no hardware-backed key attestation mechanism equivalent to
// Apple App Attest (iOS/iPadOS) or TPM EK certificate attestation. This
// is residual risk R1 in ADR 0043. The mitigation is MDM-issued identity:
//
//   "If the device is enrolled in a corporate MDM (Jamf, Kandji, Mosyle,
//    or similar), the MDM CA issues a client identity certificate during
//    enrollment. That certificate binds the device to the MDM inventory.
//    The jess-controller validates the client cert chain against the MDM
//    CA root that the org has deployed via a configuration profile."
//
// Trust ceiling: TIER_BYOD (not TIER_CORP) — per ADR 0040 D-006, MDM
// enrollment without hardware attestation is BYOD-ceiling. The device
// identity is administrative, not hardware-rooted. An admin with MDM
// access could theoretically issue a cert to a non-enrolled machine.
//
// This verifier does NOT enforce device serial number matching or MDM
// inventory lookup — those checks belong in the controller's device-
// registry layer (falcon-id iam_devices). This verifier's contract is:
//   "The client cert chain is valid and rooted in the org's MDM CA."
//
// MDM root injection
// ==================
// The MDM CA root is NEVER hardcoded in this package. The controller
// operator injects the *x509.CertPool at startup from a Kubernetes
// Secret mounted into the jess-controller Pod. No vendor-specific PEM
// is bundled here — this verifier works for Jamf, Kandji, Mosyle, and
// any other MDM that issues PKCS#12 identity certificates.
//
// MDM cert marker extension
// ==========================
// MDM identity certs from Jamf/Kandji/Mosyle include at least one of
// these markers that the verifier checks:
//
//  1. Extended Key Usage: id-kp-clientAuth (1.3.6.1.5.5.7.3.2) MUST be
//     present — this is the universal MDM identity cert marker.
//  2. Subject Common Name MUST be non-empty — MDM certs always set CN
//     to the device name or serial number.
//
// A plain self-signed cert (no EKU, generic CN) would pass chain
// validation against a custom CA pool but is rejected here because it
// lacks id-kp-clientAuth. This prevents misuse of the verifier with
// non-MDM certificates.
//
// Platform string: "macos-mdm"
// Payload: MacOSMDMPayload (client cert PEM in PlatformBlob)
//
// References:
//   - RFC 5280 §4.2.1.12 — Extended Key Usage extension
//   - RFC 5705 / MDM Protocol Reference — Apple MDM identity certificate
//     https://developer.apple.com/documentation/devicemanagement/implementing-device-management
//   - Jamf Pro MDM identity certificate profile
//     https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/SCEP_Proxy_Settings.html
//   - ADR 0043 §3.c.5 — macos-mdm verifier + R1 rationale

package deviceattest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

// MacOSMDMPayload is the JSON structure the posture-agent on macOS
// marshals into VerifyRequest.PlatformBlob.
//
// The posture-agent extracts the MDM identity certificate from the
// System Keychain (added by MDM enrollment) and PEM-encodes it.
// The chain SHOULD include the full path to the MDM CA root, but the
// verifier accepts leaf-only presentations too — x509.Verify walks
// the intermediate pool independently.
type MacOSMDMPayload struct {
	// ClientCertPEM is the PEM-encoded MDM identity certificate chain,
	// leaf first. At minimum one "-----BEGIN CERTIFICATE-----" block.
	// The leaf cert MUST have id-kp-clientAuth in its ExtKeyUsage.
	ClientCertPEM []byte `json:"client_cert_pem"`
}

// macOSMDMVerifier implements Verifier for Platform="macos-mdm".
//
// Trust ceiling: TIER_BYOD (ADR 0040 D-006 — MDM without hardware
// attestation is BYOD-ceiling; no EK-chain path to TIER_CORP).
type macOSMDMVerifier struct {
	mdmRootPool *x509.CertPool
	now         func() time.Time
}

// MacOSMDMOption configures a macOSMDMVerifier.
type MacOSMDMOption func(*macOSMDMVerifier)

// WithMacOSMDMClock replaces the real-time clock. Used in tests.
func WithMacOSMDMClock(fn func() time.Time) MacOSMDMOption {
	return func(v *macOSMDMVerifier) { v.now = fn }
}

// NewMacOSMDMVerifier constructs a production macOS MDM client-cert verifier.
//
// mdmRootPool MUST NOT be nil and MUST contain the org's MDM CA root
// certificate. Load it from a Kubernetes Secret at controller startup:
//
//	pool := x509.NewCertPool()
//	if ok := pool.AppendCertsFromPEM(mdmRootPEM); !ok {
//	    return fmt.Errorf("no valid MDM root CA cert in secret")
//	}
//	registry.Register("macos-mdm", NewMacOSMDMVerifier(pool))
//
// Nil mdmRootPool panics at construction time so the wiring bug surfaces
// at controller startup, not at request time.
func NewMacOSMDMVerifier(mdmRootPool *x509.CertPool, opts ...MacOSMDMOption) Verifier {
	if mdmRootPool == nil {
		panic("deviceattest: NewMacOSMDMVerifier: mdmRootPool must not be nil")
	}
	v := &macOSMDMVerifier{
		mdmRootPool: mdmRootPool,
		now:         time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Platform="macos-mdm".
//
// Flow:
//  1. Decode PlatformBlob → MacOSMDMPayload.
//  2. Parse PEM chain → []x509.Certificate (leaf first).
//  3. Assert leaf cert has id-kp-clientAuth in ExtKeyUsage.
//  4. Assert leaf cert Subject.CommonName is non-empty.
//  5. Verify chain against the injected MDM root pool.
//  6. Return TIER_BYOD (MDM-issued cert is BYOD ceiling per ADR 0040 D-006).
func (v *macOSMDMVerifier) Verify(_ context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: platform blob required.
	if len(req.PlatformBlob) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm verifier requires PlatformBlob (MacOSMDMPayload JSON)",
			ErrVerification,
		)
	}

	// Parse payload.
	var payload MacOSMDMPayload
	if err := json.Unmarshal(req.PlatformBlob, &payload); err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm PlatformBlob is not valid MacOSMDMPayload JSON: %v",
			ErrVerification, err,
		)
	}
	if len(payload.ClientCertPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: ClientCertPEM is empty in PlatformBlob",
			ErrVerification,
		)
	}

	// Parse the PEM-encoded certificate chain.
	certs, err := parsePEMChain(payload.ClientCertPEM)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: cert chain parse failed: %v",
			ErrVerification, err,
		)
	}
	if len(certs) == 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: ClientCertPEM contains no parseable certificates",
			ErrVerification,
		)
	}

	leafCert := certs[0]

	// Guard 3: id-kp-clientAuth (1.3.6.1.5.5.7.3.2) MUST be in ExtKeyUsage.
	// This is the universal MDM identity cert marker. A cert without
	// id-kp-clientAuth is not an MDM identity cert and is rejected, even
	// if it chains to the MDM CA root — the MDM CA might issue other cert
	// types (code-signing, server) that should not be accepted here.
	if !hasClientAuth(leafCert) {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: leaf certificate does not have id-kp-clientAuth "+
				"(OID 1.3.6.1.5.5.7.3.2) in ExtKeyUsage — "+
				"this is not an MDM identity certificate",
			ErrVerification,
		)
	}

	// Guard 4: Subject CommonName must be non-empty.
	// MDM certs always set CN to the device name or serial number.
	// An empty CN suggests the cert was not issued by an MDM enrollment flow.
	if leafCert.Subject.CommonName == "" {
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: leaf certificate Subject.CommonName is empty — "+
				"MDM identity certificates must have a non-empty CN",
			ErrVerification,
		)
	}

	// Build an intermediate pool from all certs between the leaf and root.
	intermediatePool := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediatePool.AddCert(certs[i])
	}

	// Guard 5: Verify chain against the MDM CA root pool.
	verifyOpts := x509.VerifyOptions{
		Roots:         v.mdmRootPool,
		Intermediates: intermediatePool,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leafCert.Verify(verifyOpts); err != nil {
		reason := classifyChainError(err)
		return VerifyResponse{}, fmt.Errorf(
			"%w: macos-mdm: MDM certificate chain verification failed (%s): %v",
			ErrVerification, reason, err,
		)
	}

	// Construct audit Reasons.
	deviceCN := sanitizeLabel(leafCert.Subject.CommonName)
	reasons := []string{
		"macos_mdm_cert_verified",
		"mdm_device_cn_" + deviceCN,
		"issuer_" + sanitizeLabel(leafCert.Issuer.CommonName),
	}

	// TIER_BYOD: MDM without hardware attestation = BYOD ceiling per ADR 0040 D-006.
	return VerifyResponse{
		Path:    "B_tofu", // MDM cert is administrative posture, not hardware chain
		Tier:    "TIER_BYOD",
		Reasons: reasons,
	}, nil
}

// hasClientAuth reports whether cert has id-kp-clientAuth (1.3.6.1.5.5.7.3.2)
// in its ExtKeyUsage list.
func hasClientAuth(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
