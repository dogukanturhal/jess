// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// tofuVerifier implements Verifier for Path B: EK pubkey TOFU + operator
// WebAuthn-signed enrollment witness. Used when EK certificate is absent
// (AMD consumer fTPM and other unprovisioned TPMs per ADR 0043 §3.c.0).
//
// Trust model: the EK key is still hardware-rooted (PSP-fuse-derived,
// unique per CPU) — TOFU preserves key uniqueness but without a
// manufacturer-signed cert chain. The TIER_BYOD ceiling (ADR 0040 D-006)
// reflects the reduced trust compared to Path A.
//
// Security properties:
//   - Anti-replay: NonceClient must be present in req; witness iat is
//     validated by the injected WitnessVerifier.
//   - Anti-impersonation: device_uuid drift (same EK pubkey, different
//     device_uuid between enrollment and re-verification) is rejected
//     with a specific error surfaced in the audit row.
//   - Idempotency: duplicate first-enrollment requests with the same
//     EK pubkey and device_uuid succeed without creating duplicate rows
//     (delegated to EnrollmentStore.Register idempotency guarantee).
type tofuVerifier struct {
	store    EnrollmentStore
	witness  WitnessVerifier
	platform string
	now      func() time.Time
}

// TOFUOption configures a tofuVerifier. Apply with NewTOFUVerifier.
type TOFUOption func(*tofuVerifier)

// WithTOFUClock replaces the real-time clock with fn. Used in tests.
func WithTOFUClock(fn func() time.Time) TOFUOption {
	return func(v *tofuVerifier) { v.now = fn }
}

// NewTOFUVerifier constructs a production Path B verifier.
//
// platform must be one of the recognized platform strings (e.g.
// "tpm2-linux", "tpm2-windows"). store and witness MUST NOT be nil —
// Path B without persistence and witness verification would silently
// accept unauthenticated hardware. Nil arguments panic immediately so
// the bug surfaces at controller startup, not at request time.
func NewTOFUVerifier(platform string, store EnrollmentStore, witness WitnessVerifier, opts ...TOFUOption) Verifier {
	if store == nil {
		panic("deviceattest: NewTOFUVerifier: store must not be nil")
	}
	if witness == nil {
		panic("deviceattest: NewTOFUVerifier: witness must not be nil")
	}
	v := &tofuVerifier{
		platform: platform,
		store:    store,
		witness:  witness,
		now:      time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements Verifier for Path B.
//
// Flow:
//  1. Guard: reject if EKCertPEM is non-empty (Path B is only valid when
//     the EK certificate is absent — the caller must route to chainVerifier
//     when a cert is present).
//  2. Parse and hash EKPubKeyPEM → SHA-256 hex anchor.
//  3. Look up prior enrollment by EK pubkey hash.
//     4a. Returning device: assert device_uuid matches the enrolled record.
//     Verify the AK Certify nonce (NonceClient must be present even on
//     re-verification to prevent stale-nonce replay). Return TIER_BYOD.
//     4b. First-time enrollment: require WitnessBundle. Verify the witness
//     JWS against the injected WitnessVerifier. Mint and persist the
//     EnrolledDevice record. Return TIER_BYOD.
//  5. EK pubkey matches prior but device_uuid differs → impersonation
//     attempt, reject with wrapped ErrVerification.
func (v *tofuVerifier) Verify(ctx context.Context, req VerifyRequest) (VerifyResponse, error) {
	// Guard 1: Path B only applies when no EK cert is present.
	// If EKCertPEM is set, the caller must use chainVerifier (Path A).
	// Receiving a cert here could mean a misconfigured client or an
	// attempt to force TIER_BYOD on hardware that should be TIER_CORP.
	if len(req.EKCertPEM) > 0 {
		return VerifyResponse{}, fmt.Errorf(
			"%w: Path B verifier received a non-empty EKCertPEM; "+
				"use chainVerifier (Path A) when EK certificate is present",
			ErrVerification,
		)
	}

	// Guard 2: EK public key must be present.
	if len(req.EKPubKeyPEM) == 0 {
		return VerifyResponse{}, fmt.Errorf("%w: EKPubKeyPEM is required for Path B", ErrVerification)
	}

	// Guard 3: nonce must be present AND of sufficient length (freshness
	// anchor, replay defense). The substrate verifier ONLY checks
	// presence + minimum entropy; cryptographic BINDING of NonceClient
	// to a TPM2_Certify quote ExtraData field is the responsibility of
	// the per-platform verifier (tpm2-linux, tpm2-windows, etc.) that
	// ships in stacked MRs and chains into this Path B base. That
	// binding is what makes the nonce a real freshness defense.
	//
	// The 32-byte floor here is a soft entropy guard: a NonceClient
	// shorter than 32 bytes cannot encode the 256-bit challenge a TPM
	// quote uses (TCG TPM 2.0 Part 3 §32.2 — the AttestationData
	// ExtraData carries up to 32 bytes of caller-supplied nonce). Any
	// shorter input is unambiguously a programming/test fixture, not a
	// real challenge.
	const minNonceLength = 32
	if len(req.NonceClient) < minNonceLength {
		return VerifyResponse{}, fmt.Errorf(
			"%w: NonceClient is required for Path B and MUST be >= %d bytes "+
				"(TPM2_Certify ExtraData length); got %d bytes",
			ErrVerification, minNonceLength, len(req.NonceClient),
		)
	}

	// Parse EK public key PEM to validate it is well-formed before hashing.
	block, rest := pem.Decode(req.EKPubKeyPEM)
	if block == nil {
		return VerifyResponse{}, fmt.Errorf("%w: EKPubKeyPEM is not valid PEM", ErrVerification)
	}
	if len(rest) > 0 {
		if extra, _ := pem.Decode(rest); extra != nil {
			return VerifyResponse{}, fmt.Errorf("%w: EKPubKeyPEM contains multiple PEM blocks; expected exactly one", ErrVerification)
		}
	}
	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" && block.Type != "EC PUBLIC KEY" {
		return VerifyResponse{}, fmt.Errorf("%w: EKPubKeyPEM block type %q is not a recognized public key type", ErrVerification, block.Type)
	}

	// Compute the TOFU anchor: SHA-256 of the canonical PEM bytes.
	// Using the raw input bytes (not re-encoded) so the hash is stable
	// across verifier calls with the same key.
	sum := sha256.Sum256(req.EKPubKeyPEM)
	ekHash := hex.EncodeToString(sum[:])

	// Look up prior enrollment.
	prior, err := v.store.GetByEKPubkeyHash(ctx, ekHash)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("%w: enrollment store lookup failed: %v", ErrVerification, err)
	}

	if prior.DeviceUUID != "" {
		// Returning-device path: EK pubkey was enrolled previously.
		return v.verifyReturning(ctx, req, prior)
	}

	// First-enrollment path: EK pubkey is new.
	return v.verifyFirstEnrollment(ctx, req, ekHash)
}

// verifyReturning handles the case where the EK pubkey has a prior
// enrollment record. The presented device_uuid must match the enrolled
// record; any drift is an impersonation signal.
func (v *tofuVerifier) verifyReturning(
	_ context.Context,
	req VerifyRequest,
	prior EnrolledDevice,
) (VerifyResponse, error) {
	// Device UUID drift: same EK pubkey, different device_uuid.
	// This suggests the requester is using a legitimate EK key (from
	// the enrolled device's TPM) but claiming to be a different device.
	// Could be EK export + replay or deliberate impersonation.
	if req.DeviceUUID != "" && req.DeviceUUID != prior.DeviceUUID {
		return VerifyResponse{}, fmt.Errorf(
			"%w: device_uuid mismatch for enrolled EK pubkey: "+
				"enrolled=%q presented=%q — possible impersonation attempt",
			ErrVerification, prior.DeviceUUID, req.DeviceUUID,
		)
	}

	reasons := []string{
		"path_b_tofu_returning_device",
		"witness_" + prior.WitnessAdminSub,
	}

	return VerifyResponse{
		Path:    "B_tofu",
		Tier:    "TIER_BYOD",
		Reasons: reasons,
	}, nil
}

// verifyFirstEnrollment handles the case where the EK pubkey is seen for
// the first time. A valid WitnessBundle from an authorized operator is
// required — without it, any device could self-enroll into Path B.
func (v *tofuVerifier) verifyFirstEnrollment(
	ctx context.Context,
	req VerifyRequest,
	ekHash string,
) (VerifyResponse, error) {
	if req.Witness == nil {
		return VerifyResponse{}, fmt.Errorf(
			"%w: first enrollment requires a WitnessBundle "+
				"(operator WebAuthn-signed assertion) — re-run agent through witnessed enrollment",
			ErrVerification,
		)
	}

	// Freshness check on the witness before expensive JWS crypto.
	// WitnessVerifier enforces its own freshness window (5 min default),
	// but we pre-check here to return a clean error before the JWS parse.
	if req.Witness.IssuedAt.IsZero() {
		return VerifyResponse{}, fmt.Errorf(
			"%w: WitnessBundle.IssuedAt is zero (witness clock not set)",
			ErrVerification,
		)
	}
	age := v.now().Sub(req.Witness.IssuedAt)
	// Forward-dated witnesses (clock-skew or attacker-supplied future
	// timestamps) must be rejected with a small tolerance for honest
	// NTP slop. Without this guard a witness with IssuedAt 1h in the
	// future would have negative `age` and silently pass both this
	// pre-check and the upstream WitnessVerifier's "age > window"
	// comparison — the JWS would then sit valid for an hour into the
	// future, defeating freshness entirely.
	const clockSkewTolerance = 30 * time.Second
	if age < -clockSkewTolerance {
		return VerifyResponse{}, fmt.Errorf(
			"%w: WitnessBundle.IssuedAt is in the future (skew=%v > %v tolerance)",
			ErrVerification, age.Round(time.Second), clockSkewTolerance,
		)
	}
	if age > 10*time.Minute {
		return VerifyResponse{}, fmt.Errorf(
			"%w: WitnessBundle is too old (%v > 10m freshness window)",
			ErrVerification, age.Round(time.Second),
		)
	}

	// Verify the operator's WebAuthn-signed JWS.
	if err := v.witness.Verify(ctx, *req.Witness, req.DeviceUUID); err != nil {
		return VerifyResponse{}, fmt.Errorf("%w: witness JWS verification failed: %v", ErrVerification, err)
	}

	// Persist the enrollment. The store is responsible for idempotency
	// (UNIQUE constraint on ek_pubkey_hash at the DB layer).
	now := v.now()
	row := EnrolledDevice{
		DeviceUUID:      req.DeviceUUID,
		UserSub:         req.UserSub,
		Platform:        req.Platform,
		AttestationPath: "B_tofu",
		Tier:            "TIER_BYOD",
		EKPubkeyHash:    ekHash,
		TPMManufacturer: req.Manufacturer,
		TPMKind:         req.Kind,
		// System/machine hardware identity from the attest request's hardware
		// block (distinct from the TPM fields above). Empty when undetected.
		SerialNumber:    req.SerialNumber,
		Model:           req.Model,
		Manufacturer:    req.SystemManufacturer,
		WitnessAdminSub: req.Witness.AdminSub,
		EnrolledAt:      now,
	}
	if err := v.store.Register(ctx, row); err != nil {
		return VerifyResponse{}, fmt.Errorf("%w: enrollment store write failed: %v", ErrVerification, err)
	}

	return VerifyResponse{
		Path: "B_tofu",
		Tier: "TIER_BYOD",
		Reasons: []string{
			"path_b_tofu_enrollment",
			"witness_" + req.Witness.AdminSub,
		},
	}, nil
}
