// SPDX-License-Identifier: AGPL-3.0-or-later

package devicepolicy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/jess/internal/deviceattest"
)

// witnessAudience is the fixed audience claim stamped into every operator
// enrollment witness JWS. The device-cert endpoint rejects any JWS whose
// aud does not match this URI exactly (case-sensitive). This prevents a
// JWS issued for a different audience (e.g. a Talon access token) from
// being replayed as an enrollment witness.
const witnessAudience = "https://jess.internal.example.com/device-attest"

// witnessAudienceOTP is the separate audience of the authenticator-app TOTP
// fallback witness. A distinct audience means a jess that predates the
// fallback rejects OTP witnesses outright (its jwt audience check fails).
const witnessAudienceOTP = "https://jess.internal.example.com/device-attest/otp"

// RFC 8176 amr values stamped by Falcon-ID.
const (
	amrPasskey = "hwk"
	amrOTP     = "otp"
)

// witnessFreshnessWindow is the maximum age of an enrollment witness JWS.
// An operator must sign the witness within this window before the device
// presents it. 10 minutes is deliberately generous (covers slow MFA
// flows) while still defeating credential replay from a stolen device.
// The tofuVerifier applies an outer pre-check (also 10m) before calling
// Verify — this constant must match or be narrower than that outer window
// to avoid accepting a witness that the tofuVerifier will later reject.
const witnessFreshnessWindow = 10 * time.Minute

// OperatorPublicKeyStore retrieves the public key registered for an
// operator's WebAuthn credential. The concrete implementation in production
// calls Falcon-ID's user-profile API to fetch the operator's WebAuthn
// credential public key; tests inject a static map.
//
// The method MUST return an error (not nil, zero key) when the sub is
// unknown — a nil return would silently accept a JWS signed by any key.
// Implementations should wrap the "not found" case with a distinct error
// value (e.g. ErrOperatorNotFound) so callers can map it to a specific
// HTTP status code.
type OperatorPublicKeyStore interface {
	// LookupPublicKey returns the operator's bound WebAuthn credential
	// public key (ECDSA P-256 or Ed25519 per the Falcon-ID WebAuthn
	// registration flow). Returns ErrOperatorNotFound when the sub is
	// not in the store.
	//
	// kid is the JWS header key id. When non-empty the implementation MUST
	// return the key with that id (ErrOperatorNotFound if none); it may fall
	// back to a default key only when kid is empty (legacy JWS).
	LookupPublicKey(ctx context.Context, sub, kid string) (crypto.PublicKey, error)
}

// ErrOperatorNotFound is returned by OperatorPublicKeyStore when the
// requested sub has no registered WebAuthn credential.
var ErrOperatorNotFound = errors.New("devicepolicy: operator public key not found")

// witnessClaims is the JWT claims body embedded in the compact JWS. All
// standard claims (iss/aud/sub/iat) plus the device-specific extension
// claim device_uuid, which binds the witness to one specific device.
// Validating device_uuid prevents cross-device witness replay: an
// operator who witnesses device A cannot have that JWS accepted for
// device B.
type witnessClaims struct {
	jwt.RegisteredClaims
	// DeviceUUID is the client-asserted UUIDv4 of the device being enrolled.
	// MUST match the device_uuid from the outer enrollment request.
	DeviceUUID string `json:"device_uuid"`
	// Amr is the RFC 8176 authentication methods: ["hwk"] passkey, ["otp"]
	// authenticator-app fallback. Absent on legacy (pre-fallback) JWS.
	Amr []string `json:"amr,omitempty"`
	// WitnessMethod is "passkey" or "otp"; absent on legacy JWS.
	WitnessMethod string `json:"witness_method,omitempty"`
	// EKPubKeyHash binds the witness to one EK: lowercase hex SHA-256 of
	// the raw ek_pubkey_pem bytes (deviceattest.EKHashOf). Absent on legacy
	// JWS.
	EKPubKeyHash string `json:"ek_pubkey_hash,omitempty"`
}

// WebAuthnWitnessVerifier implements deviceattest.WitnessVerifier using
// the golang-jwt/jwt/v5 library for compact JWS parsing and ECDSA / EdDSA
// signature verification against the operator's registered WebAuthn public
// key.
//
// Trust model (ADR 0043 §3.c.0):
//   - The operator's WebAuthn credential public key is fetched from
//     OperatorPublicKeyStore (backed by Falcon-ID).
//   - The compact JWS is parsed and its signature verified against that key.
//   - Standard JWT claims (iss, aud, sub, iat) are validated including
//     freshness (iat within witnessFreshnessWindow of now).
//   - The device_uuid custom claim is asserted to match the deviceUUID
//     parameter from the enrollment request, preventing cross-device replay.
//
// Thread-safe: the struct holds only immutable configuration; the now
// function pointer is only written at construction time.
type WebAuthnWitnessVerifier struct {
	issuer string // e.g. "jess-controller"
	store  OperatorPublicKeyStore
	now    func() time.Time
	// allowOTP is the JESS_WITNESS_ALLOW_OTP kill switch; when false the
	// OTP audience is rejected.
	allowOTP bool
}

// WebAuthnWitnessVerifierOption configures a WebAuthnWitnessVerifier.
type WebAuthnWitnessVerifierOption func(*WebAuthnWitnessVerifier)

// WithWitnessVerifierClock replaces the real-time clock. Used in tests to
// simulate expired witnesses without OS clock manipulation.
func WithWitnessVerifierClock(fn func() time.Time) WebAuthnWitnessVerifierOption {
	return func(v *WebAuthnWitnessVerifier) { v.now = fn }
}

// WithWitnessAllowOTP enables (true) or disables the authenticator-app OTP
// witness fallback. Default is disabled.
func WithWitnessAllowOTP(allow bool) WebAuthnWitnessVerifierOption {
	return func(v *WebAuthnWitnessVerifier) { v.allowOTP = allow }
}

// NewWebAuthnWitnessVerifier constructs a production WitnessVerifier.
//
// issuer is the expected iss claim in every enrollment witness JWS —
// typically "jess-controller". store provides the operator's registered
// WebAuthn public key for signature verification. Both MUST NOT be nil/empty;
// violations panic at construction time so the bug surfaces at controller
// startup, not at enrollment time.
func NewWebAuthnWitnessVerifier(issuer string, store OperatorPublicKeyStore, opts ...WebAuthnWitnessVerifierOption) deviceattest.WitnessVerifier {
	if issuer == "" {
		panic("devicepolicy: NewWebAuthnWitnessVerifier: issuer must not be empty")
	}
	if store == nil {
		panic("devicepolicy: NewWebAuthnWitnessVerifier: OperatorPublicKeyStore must not be nil")
	}
	v := &WebAuthnWitnessVerifier{
		issuer: issuer,
		store:  store,
		now:    time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify implements deviceattest.WitnessVerifier.
//
// Verification flow:
//  1. Pre-check: reject if bundle.IssuedAt is stale before paying the cost
//     of the public-key lookup and JWS parse.
//  2. Lookup the operator's WebAuthn public key from the store by AdminSub.
//     Returns ErrVerification wrapping ErrOperatorNotFound on miss.
//  3. Parse the compact JWS using golang-jwt/jwt/v5 with a key function
//     that verifies the alg matches the key type (ES256 for ECDSA P-256,
//     EdDSA for Ed25519). Signature mismatch returns ErrVerification.
//  4. Validate standard claims:
//     - iss == v.issuer
//     - aud contains witnessAudience
//     - sub == bundle.AdminSub
//     - iat within witnessFreshnessWindow of now
//  5. Validate custom claim device_uuid == deviceUUID parameter.
func (v *WebAuthnWitnessVerifier) Verify(ctx context.Context, bundle deviceattest.WitnessBundle, deviceUUID, ekHash, bearerSub string) (deviceattest.WitnessResult, error) {
	now := v.now()

	// Step 1 — pre-check IssuedAt freshness (fast path before crypto).
	// The bundle.IssuedAt is parsed from the JWS header by the caller
	// (tofuVerifier) before calling us; we do a second bounds check here
	// because we own the canonical freshness window constant.
	if bundle.IssuedAt.IsZero() {
		return deviceattest.WitnessResult{}, fmt.Errorf("%w: witness IssuedAt is zero", deviceattest.ErrVerification)
	}
	age := now.Sub(bundle.IssuedAt)
	if age > witnessFreshnessWindow {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: witness JWS is too old (age=%s > window=%s)",
			deviceattest.ErrVerification, age.Round(time.Second), witnessFreshnessWindow)
	}
	if age < -30*time.Second {
		// Reject JWSes from > 30s in the future — protects against clock
		// skew exploits where an attacker pre-computes a witness with a
		// future iat to extend its validity window.
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: witness JWS has a future iat (skew=%s > 30s tolerance)",
			deviceattest.ErrVerification, (-age).Round(time.Second))
	}

	// Step 2 — operator public key lookup.
	// The JWS header is read unverified ONLY to select the key (kid) and the
	// expected audience; every claim is re-validated by the signed parse below.
	var peek witnessClaims
	unverified, _, perr := jwt.NewParser().ParseUnverified(string(bundle.SignedJWS), &peek)
	if perr != nil {
		return deviceattest.WitnessResult{}, fmt.Errorf("%w: malformed witness JWS: %v", deviceattest.ErrVerification, perr)
	}
	kid, _ := unverified.Header["kid"].(string)

	method := deviceattest.WitnessMethodPasskey
	expectedAud := witnessAudience
	for _, a := range peek.Audience {
		if a == witnessAudienceOTP {
			method = deviceattest.WitnessMethodOTP
			expectedAud = witnessAudienceOTP
			break
		}
	}
	if method == deviceattest.WitnessMethodOTP && !v.allowOTP {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: authenticator-app (OTP) witness is disabled (JESS_WITNESS_ALLOW_OTP)",
			deviceattest.ErrVerification)
	}

	pubKey, err := v.store.LookupPublicKey(ctx, bundle.AdminSub, kid)
	if err != nil {
		if errors.Is(err, ErrOperatorNotFound) {
			return deviceattest.WitnessResult{}, fmt.Errorf(
				"%w: operator sub %q has no registered WebAuthn credential",
				deviceattest.ErrVerification, bundle.AdminSub)
		}
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: operator public key lookup failed for sub %q: %v",
			deviceattest.ErrVerification, bundle.AdminSub, err)
	}
	if pubKey == nil {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: operator public key store returned nil key for sub %q (store bug)",
			deviceattest.ErrVerification, bundle.AdminSub)
	}

	// Step 3 — parse the compact JWS and verify the signature.
	// The keyFunc validates that the alg header matches the runtime key type
	// so a JWS header claiming "alg:none" or "alg:RS256" against an ECDSA key
	// is rejected (algorithm confusion attack mitigation).
	keyFunc := buildKeyFunc(pubKey)

	var claims witnessClaims
	token, err := jwt.ParseWithClaims(
		string(bundle.SignedJWS),
		&claims,
		keyFunc,
		// Standard validators — the parser checks exp (if present) and iat (if
		// present) automatically. We supply explicit WithIssuedAt to get a
		// consistent error message.
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(expectedAud),
		// Provide the controlled clock for tests.
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		return deviceattest.WitnessResult{}, fmt.Errorf("%w: JWS signature/claims validation failed: %v", deviceattest.ErrVerification, err)
	}
	if !token.Valid {
		return deviceattest.WitnessResult{}, fmt.Errorf("%w: JWS token marked invalid after parse", deviceattest.ErrVerification)
	}

	// Step 4 — sub claim must match the AdminSub from the bundle.
	// The JWS parser already validated iss + aud via WithIssuer/WithAudience;
	// we additionally validate sub to ensure an operator cannot use another
	// operator's witness claim.
	if claims.Subject != bundle.AdminSub {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: JWS sub %q does not match bundle.AdminSub %q",
			deviceattest.ErrVerification, claims.Subject, bundle.AdminSub)
	}

	// Step 5 — device_uuid custom claim.
	// This is the cross-device replay guard: an operator who witnesses device
	// A cannot have that JWS accepted for device B even if all other claims
	// are valid.
	if claims.DeviceUUID != deviceUUID {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: JWS device_uuid %q does not match enrollment device_uuid %q (cross-device replay?)",
			deviceattest.ErrVerification, claims.DeviceUUID, deviceUUID)
	}

	// Step 6 — method binding. aud selects the method; amr (and
	// witness_method when present) must agree. Legacy passkey JWS carry
	// neither; an OTP JWS must carry amr.
	if err := checkWitnessMethod(method, claims); err != nil {
		return deviceattest.WitnessResult{}, err
	}

	// Step 7 — EK binding. When the claim is present it must equal the EK
	// hash jess itself computed from the request's ek_pubkey_pem. OTP
	// witnesses are weaker, so they MUST carry the claim.
	if claims.EKPubKeyHash == "" {
		if method == deviceattest.WitnessMethodOTP {
			return deviceattest.WitnessResult{}, fmt.Errorf(
				"%w: OTP witness JWS lacks ek_pubkey_hash", deviceattest.ErrVerification)
		}
	} else if subtle.ConstantTimeCompare([]byte(claims.EKPubKeyHash), []byte(ekHash)) != 1 {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: JWS ek_pubkey_hash does not match the enrolling EK (witness bound to a different key)",
			deviceattest.ErrVerification)
	}

	// Step 8 — an OTP witness proves possession of the account's
	// authenticator, not an operator co-signing: it must be the enrolling
	// user themself.
	if method == deviceattest.WitnessMethodOTP && claims.Subject != bearerSub {
		return deviceattest.WitnessResult{}, fmt.Errorf(
			"%w: OTP witness sub %q does not match the authenticated enrolling user",
			deviceattest.ErrVerification, claims.Subject)
	}

	res := deviceattest.WitnessResult{Method: method, Sub: claims.Subject, EKHash: claims.EKPubKeyHash}
	return res, nil
}

// checkWitnessMethod asserts amr / witness_method agree with the method
// derived from aud.
func checkWitnessMethod(method string, c witnessClaims) error {
	want, other := amrPasskey, amrOTP
	if method == deviceattest.WitnessMethodOTP {
		want, other = amrOTP, amrPasskey
	}
	if len(c.Amr) == 0 {
		if method == deviceattest.WitnessMethodOTP {
			return fmt.Errorf("%w: OTP witness JWS lacks amr", deviceattest.ErrVerification)
		}
	} else {
		has := false
		for _, a := range c.Amr {
			if a == other {
				return fmt.Errorf("%w: JWS amr %v contradicts audience (method %s)",
					deviceattest.ErrVerification, c.Amr, method)
			}
			if a == want {
				has = true
			}
		}
		if !has {
			return fmt.Errorf("%w: JWS amr %v does not match audience (method %s)",
				deviceattest.ErrVerification, c.Amr, method)
		}
	}
	if c.WitnessMethod != "" && c.WitnessMethod != method {
		return fmt.Errorf("%w: JWS witness_method %q does not match audience (method %s)",
			deviceattest.ErrVerification, c.WitnessMethod, method)
	}
	return nil
}

// buildKeyFunc returns a jwt.Keyfunc that validates alg matches the runtime
// key type and returns the public key for signature verification.
//
// Supported key types:
//   - *ecdsa.PublicKey  → ES256 (P-256), ES384 (P-384), ES512 (P-521)
//   - ed25519.PublicKey → EdDSA
//   - *rsa.PublicKey    → RS256, RS384, RS512, PS256, PS384, PS512
//
// Any other key type or alg/key mismatch returns an error so the JWS is
// rejected before the signature is checked. This is the algorithm
// confusion defence specified in RFC 8725 §3.1.
func buildKeyFunc(pubKey crypto.PublicKey) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		switch k := pubKey.(type) {
		case *ecdsa.PublicKey:
			// Accept only ECDSA algorithms.
			switch t.Method.(type) {
			case *jwt.SigningMethodECDSA:
				return k, nil
			default:
				return nil, fmt.Errorf(
					"algorithm mismatch: key is ECDSA but JWS alg is %q — potential algorithm confusion attack",
					t.Header["alg"])
			}

		case ed25519.PublicKey:
			// Accept only EdDSA.
			switch t.Method.(type) {
			case *jwt.SigningMethodEd25519:
				return k, nil
			default:
				return nil, fmt.Errorf(
					"algorithm mismatch: key is Ed25519 but JWS alg is %q — potential algorithm confusion attack",
					t.Header["alg"])
			}

		case *rsa.PublicKey:
			// Accept only RSA family.
			switch t.Method.(type) {
			case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
				return k, nil
			default:
				return nil, fmt.Errorf(
					"algorithm mismatch: key is RSA but JWS alg is %q — potential algorithm confusion attack",
					t.Header["alg"])
			}

		default:
			return nil, fmt.Errorf("unsupported public key type %T", pubKey)
		}
	}
}
