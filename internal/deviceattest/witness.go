// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
)

// WitnessVerifier verifies a Path B enrollment witness. The concrete
// implementation in jess-controller uses the operator's WebAuthn
// credential (stored in Falcon-ID) to verify the compact-serialized
// JWS in WitnessBundle.SignedJWS.
//
// The witness is an operator-signed assertion over the device's metadata
// (hostname, MAC addresses, platform UUID, device_uuid, iat). An
// operator with WebAuthn credentials must physically co-sign the
// enrollment — this prevents automated mass-enrollment of untrusted
// hardware through the Path B path.
type WitnessVerifier interface {
	// Verify validates the WitnessBundle for the given deviceUUID.
	// On success the returned WitnessResult describes how the human was
	// verified, and the caller may trust bundle.AdminSub as the verified
	// operator identity.
	//
	// ekHash is the EK hash the verifier computed for this enrollment (see
	// EKHashOf); bearerSub is the Falcon-ID sub of the authenticated
	// enrollment caller. Both are inputs to the witness binding checks.
	//
	// Implementations MUST:
	//   - Verify the JWS signature against the operator's bound key
	//   - Extract and validate the iat claim within the freshness window
	//     (default: 5 minutes — prevents witness replay)
	//   - Assert the device_uuid claim inside the JWS matches deviceUUID
	//     to prevent cross-device witness replay
	//   - Return an error wrapping ErrVerification on any failure
	Verify(ctx context.Context, bundle WitnessBundle, deviceUUID, ekHash, bearerSub string) (WitnessResult, error)
}

// Witness methods recorded in WitnessResult.Method / EnrolledDevice.WitnessMethod.
const (
	// WitnessMethodPasskey is a WebAuthn passkey witness (amr "hwk").
	WitnessMethodPasskey = "passkey"
	// WitnessMethodOTP is the authenticator-app TOTP fallback (amr "otp").
	WitnessMethodOTP = "otp"
)

// WitnessResult is the outcome of a successful WitnessVerifier.Verify.
type WitnessResult struct {
	// Method is WitnessMethodPasskey or WitnessMethodOTP.
	Method string
	// Sub is the verified JWS subject (the witnessing user).
	Sub string
	// EKHash is the ek_pubkey_hash claim when the JWS carried one, else
	// empty (legacy JWS). When non-empty it already equals the EK hash jess
	// computed.
	EKHash string
}

// EKHashOf returns the EK hash encoding used everywhere (TOFU anchor,
// iam_devices.ek_pubkey_hash, the witness ek_pubkey_hash claim):
// lowercase hex of SHA-256 over the raw ek_pubkey_pem bytes exactly as the
// client sent them (no PEM decode, no re-encoding, no trimming).
func EKHashOf(ekPubKeyPEM []byte) string {
	sum := sha256.Sum256(ekPubKeyPEM)
	return hex.EncodeToString(sum[:])
}
