// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"errors"
	"time"
)

// Verifier validates one platform's attestation evidence. Implementations
// MUST NOT trust any field of the input outside their own signature or
// chain check — the request is operator-supplied and could be fabricated.
//
// Concrete implementations in this package:
//   - NewTOFUVerifier — Path B: EK pubkey TOFU + WebAuthn witness
//   - NewChainVerifier — Path A: EK cert chain to pinned vendor root
type Verifier interface {
	// Verify validates the presented attestation evidence. Returns
	// VerifyResponse on success or ErrVerification (possibly wrapped)
	// on any failure. Callers match on errors.Is(err, ErrVerification).
	Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error)
}

// VerifyRequest carries all attestation evidence from the device agent
// (ADR 0043 §3.b). One request flows from /device-cert into the
// appropriate Verifier based on Platform.
type VerifyRequest struct {
	// Platform names the hardware family: tpm2-linux, tpm2-windows,
	// android-strongbox, apple-app-attest, macos-mdm.
	Platform string

	// Manufacturer is the TPM2_PT_MANUFACTURER ASCII value (e.g. "AMD",
	// "INTC", "IFX", "MSFT"). Empty for non-TPM platforms.
	Manufacturer string

	// Kind is the TPM module classification: discrete | firmware | pluton.
	// Empty for non-TPM platforms.
	Kind string

	// SerialNumber, Model and SystemManufacturer are the system/machine
	// hardware identity (DMI/SMBIOS: chassis serial, product model, system
	// vendor — e.g. "PF2X9ABC", "Latitude 7440", "Dell Inc."). They ride in
	// the attest request's nested `hardware` block, carried by the enrollment
	// agent alongside (but distinct from) the TPM attestation evidence. Note
	// SystemManufacturer is the MACHINE vendor — NOT the TPM Manufacturer
	// above. All optional; empty when the agent could not read DMI (e.g. an
	// unprivileged probe). Persisted to the EnrolledDevice on first-enrollment.
	SerialNumber       string
	Model              string
	SystemManufacturer string

	// EKPubKeyPEM is the PEM-encoded EK public key extracted from the TPM.
	// Required for both Path A and Path B on TPM platforms.
	EKPubKeyPEM []byte

	// EKCertPEM is the PEM-encoded EK certificate from NV handles
	// 0x01C00002 (RSA) or 0x01C0000A (ECC). Required for Path A (chain
	// verification). MUST be nil for Path B — the presence of a cert
	// signals Path A eligibility; a non-nil cert on a RequiresTOFU
	// platform is rejected as an anti-spoof measure.
	EKCertPEM []byte // OPTIONAL — Path A requires; Path B = nil

	// UserSub is the Falcon-ID subject claim for the user requesting
	// device enrollment. Stamped into the EnrolledDevice record.
	UserSub string

	// DeviceUUID is the client-asserted UUIDv4 for the device
	// (spiffe://hexxlock.com/device/<uuid> SAN). The verifier validates
	// that this matches any prior enrollment for the same EK pubkey.
	DeviceUUID string

	// NonceClient is a freshness nonce from the controller, embedded
	// in the TPM2_MakeCredential / Certify challenge. Prevents replay.
	NonceClient []byte

	// Witness carries the Path B enrollment witness (WebAuthn-signed
	// operator assertion). Required on first enrollment for Path B;
	// nil on subsequent requests from an already-enrolled device.
	Witness *WitnessBundle // Path B only

	// PlatformBlob carries platform-specific attestation evidence that does
	// not fit the generic EK cert / pubkey model. Each platform verifier
	// defines its own JSON payload structure that it marshals into this field:
	//   - tpm2-linux:         TPM2LinuxQuotePayload  (AK public + quote + sig)
	//   - tpm2-windows:       TPM2WindowsQuotePayload (AK public + quote + sig)
	//   - android-strongbox:  AndroidKeyAttestPayload (leaf cert chain PEM)
	//   - apple-app-attest:   AppleAppAttestPayload   (cbor attestation object)
	//   - macos-mdm:          MacOSMDMPayload         (MDM leaf cert PEM)
	// Verifiers that do not need platform-specific data leave this nil.
	PlatformBlob []byte
}

// VerifyResponse is the verified claims surviving attestation. The
// controller stamps these into the audit row and the issued device-cert
// Subject Alternative Name (SPIFFE URI per ADR 0040 D-005).
type VerifyResponse struct {
	// Path is the trust model used: "A_chain" or "B_tofu".
	Path string // A_chain | B_tofu

	// Tier is the access tier this device qualifies for:
	// TIER_CORP, TIER_BYOD, or TIER_BREAKGLASS.
	Tier string // TIER_CORP | TIER_BYOD | TIER_BREAKGLASS

	// Reasons is a slice of stable diagnostic strings recorded in the
	// audit row. Each entry is machine-readable (Prometheus label safe).
	// Examples: "path_b_tofu_enrollment", "witness_ops@example.com",
	// "ek_chain_infineon_root_match".
	Reasons []string
}

// WitnessBundle is the Path B enrollment witness — an operator WebAuthn-
// signed assertion over the device's metadata (hostname, MAC, platform
// UUID). An operator with WebAuthn credentials must physically witness
// the device enrollment; this prevents automated mass-enrollment of
// untrusted hardware via the Path B path.
//
// The SignedJWS is verified by the injected WitnessVerifier interface;
// the concrete implementation in jess-controller uses the operator's
// WebAuthn credential (stored in Falcon-ID) to verify the JWS.
type WitnessBundle struct {
	// AdminSub is the Falcon-ID sub of the operator who witnessed the
	// enrollment. Extracted from the signed JWS — do NOT trust the
	// raw field; the WitnessVerifier validates it.
	AdminSub string

	// SignedJWS is the compact-serialized JWS signed with the operator's
	// WebAuthn credential bound key. Payload includes device metadata
	// (hostname, MAC, platform UUID, device_uuid) + iat claim to
	// bound the freshness window.
	SignedJWS []byte

	// IssuedAt is the iat claim from the decoded (pre-verify) JWS header.
	// Used for freshness rejection before the JWS signature is verified
	// (fast-path to avoid expensive crypto on expired witnesses).
	IssuedAt time.Time
}

// ErrVerification is the canonical sentinel — every verifier failure
// path wraps this via fmt.Errorf("%w: ...", ErrVerification, ...).
// Callers match on errors.Is(err, ErrVerification) so the controller
// HTTP response stays uniform regardless of which validation rule fired.
var ErrVerification = errors.New("deviceattest: verification failed")

// Registry is controller-side dispatch from platform name → Verifier.
// Built at controller startup; immutable thereafter (no locks needed).
type Registry struct {
	verifiers map[string]Verifier
}

// NewRegistry constructs an empty Registry. Register each Verifier
// during controller startup.
func NewRegistry() *Registry {
	return &Registry{verifiers: make(map[string]Verifier)}
}

// Register adds a verifier for the given platform. Calling twice for
// the same platform overwrites the previous — controller wiring is
// single-threaded at startup so this is intentional.
func (r *Registry) Register(platform string, v Verifier) {
	r.verifiers[platform] = v
}

// VerifierFor returns the registered Verifier for platform, or nil if
// not registered. Callers MUST treat nil as "platform not enabled" —
// MUST NOT fall back to a looser posture.
func (r *Registry) VerifierFor(platform string) Verifier {
	return r.verifiers[platform]
}

// Enabled returns the list of registered platform names. Used by admin
// status endpoint and audit rows for "unknown platform" rejections.
func (r *Registry) Enabled() []string {
	out := make([]string, 0, len(r.verifiers))
	for p := range r.verifiers {
		out = append(out, p)
	}
	return out
}
