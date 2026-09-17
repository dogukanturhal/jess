// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import "context"

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
	// On success, nil is returned and the caller may trust
	// bundle.AdminSub as the verified operator identity.
	//
	// Implementations MUST:
	//   - Verify the JWS signature against the operator's bound key
	//   - Extract and validate the iat claim within the freshness window
	//     (default: 5 minutes — prevents witness replay)
	//   - Assert the device_uuid claim inside the JWS matches deviceUUID
	//     to prevent cross-device witness replay
	//   - Return an error wrapping ErrVerification on any failure
	Verify(ctx context.Context, bundle WitnessBundle, deviceUUID string) error
}
