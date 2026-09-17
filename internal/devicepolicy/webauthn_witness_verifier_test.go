// SPDX-License-Identifier: AGPL-3.0-or-later

package devicepolicy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dogukanturhal/jess/internal/deviceattest"
)

const (
	testIssuer     = "jess-controller"
	testAdminSub   = "ops_alice"
	testDeviceUUID = "aaaabbbb-0000-4000-8000-ccccddddeeee"
)

// staticOperatorKeyStore is a test-only OperatorPublicKeyStore backed by
// an in-memory map.
type staticOperatorKeyStore struct {
	keys map[string]crypto.PublicKey
}

func (s *staticOperatorKeyStore) LookupPublicKey(_ context.Context, sub string) (crypto.PublicKey, error) {
	k, ok := s.keys[sub]
	if !ok {
		return nil, ErrOperatorNotFound
	}
	return k, nil
}

// generateOperatorKey returns a fresh ECDSA P-256 keypair suitable for use
// as an operator's WebAuthn credential in tests.
func generateOperatorKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate operator ECDSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

// signWitness signs a witnessClaims payload with the given private key
// and returns the compact JWS bytes.
func signWitness(t *testing.T, priv *ecdsa.PrivateKey, claims witnessClaims) []byte {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign witness JWS: %v", err)
	}
	return []byte(signed)
}

// buildValidClaims builds a witnessClaims that passes all verifier checks
// when signed by the operator key and verified at time `now`.
func buildValidClaims(now time.Time) witnessClaims {
	return witnessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   testIssuer,
			Subject:  testAdminSub,
			Audience: jwt.ClaimStrings{witnessAudience},
			IssuedAt: jwt.NewNumericDate(now),
			// ExpiresAt required by WithExpirationRequired
			ExpiresAt: jwt.NewNumericDate(now.Add(witnessFreshnessWindow)),
		},
		DeviceUUID: testDeviceUUID,
	}
}

// buildBundle builds a WitnessBundle from the signed JWS bytes and iat.
func buildBundle(signedJWS []byte, iat time.Time) deviceattest.WitnessBundle {
	return deviceattest.WitnessBundle{
		AdminSub:  testAdminSub,
		SignedJWS: signedJWS,
		IssuedAt:  iat,
	}
}

// TestWebAuthnWitnessVerifier_HappyPath tests that a freshly signed witness
// JWS with all valid claims passes verification.
func TestWebAuthnWitnessVerifier_HappyPath(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	jws := signWitness(t, priv, claims)
	bundle := buildBundle(jws, now)

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))

	if err := v.Verify(context.Background(), bundle, testDeviceUUID); err != nil {
		t.Fatalf("happy path: unexpected error: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_ExpiredWitness tests that a witness with iat
// > 10 minutes ago is rejected.
func TestWebAuthnWitnessVerifier_ExpiredWitness(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	// Sign 15 minutes ago.
	iat := time.Now().UTC().Add(-15 * time.Minute)
	claims := buildValidClaims(iat)
	jws := signWitness(t, priv, claims)
	bundle := buildBundle(jws, iat)

	// Verify at "now" (real clock).
	v := NewWebAuthnWitnessVerifier(testIssuer, store)
	err := v.Verify(context.Background(), bundle, testDeviceUUID)
	if err == nil {
		t.Fatal("expected error for expired witness, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_WrongAudience tests that a JWS whose aud
// does not contain witnessAudience is rejected.
func TestWebAuthnWitnessVerifier_WrongAudience(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	// Override audience with a wrong value.
	claims.Audience = jwt.ClaimStrings{"https://other.example.com/not-device-attest"}
	jws := signWitness(t, priv, claims)
	bundle := buildBundle(jws, now)

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))
	err := v.Verify(context.Background(), bundle, testDeviceUUID)
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_WrongDeviceUUID tests that a JWS signed for
// device A is rejected when presented for device B (cross-device replay guard).
func TestWebAuthnWitnessVerifier_WrongDeviceUUID(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	// JWS was issued for testDeviceUUID.
	jws := signWitness(t, priv, claims)
	bundle := buildBundle(jws, now)

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))
	// But we present it for a DIFFERENT device.
	wrongDevice := "zzzz0000-0000-4000-8000-ffffaaaabbbb"
	err := v.Verify(context.Background(), bundle, wrongDevice)
	if err == nil {
		t.Fatal("expected error for wrong device_uuid, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_TamperedSignature tests that modifying the JWS
// payload after signing causes the signature verification to fail.
func TestWebAuthnWitnessVerifier_TamperedSignature(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	jws := signWitness(t, priv, claims)

	// Tamper: flip the last character of the compact JWS signature part.
	// Compact JWS has form: header.payload.signature — mutate the signature.
	raw := string(jws)
	raw = raw[:len(raw)-2] + "xx"
	bundle := buildBundle([]byte(raw), now)

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))
	err := v.Verify(context.Background(), bundle, testDeviceUUID)
	if err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_UnknownAdminSub tests that a JWS whose
// AdminSub has no registered public key is rejected.
func TestWebAuthnWitnessVerifier_UnknownAdminSub(t *testing.T) {
	priv, _ := generateOperatorKey(t)
	// Store has no entry for testAdminSub.
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	jws := signWitness(t, priv, claims)
	bundle := buildBundle(jws, now)

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))
	err := v.Verify(context.Background(), bundle, testDeviceUUID)
	if err == nil {
		t.Fatal("expected error for unknown admin sub, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// TestWebAuthnWitnessVerifier_ZeroIssuedAt tests that a bundle whose
// IssuedAt is zero is rejected before any crypto is attempted.
func TestWebAuthnWitnessVerifier_ZeroIssuedAt(t *testing.T) {
	priv, pub := generateOperatorKey(t)
	store := &staticOperatorKeyStore{keys: map[string]crypto.PublicKey{testAdminSub: pub}}

	now := time.Now().UTC()
	claims := buildValidClaims(now)
	jws := signWitness(t, priv, claims)
	// Intentionally set IssuedAt to zero value.
	bundle := deviceattest.WitnessBundle{
		AdminSub:  testAdminSub,
		SignedJWS: jws,
		IssuedAt:  time.Time{},
	}

	v := NewWebAuthnWitnessVerifier(testIssuer, store,
		WithWitnessVerifierClock(func() time.Time { return now }))
	err := v.Verify(context.Background(), bundle, testDeviceUUID)
	if err == nil {
		t.Fatal("expected error for zero IssuedAt, got nil")
	}
	if !isDeviceAttestVerificationErr(err) {
		t.Errorf("expected ErrVerification wrapping, got: %v", err)
	}
}

// isDeviceAttestVerificationErr reports whether err wraps
// deviceattest.ErrVerification. Uses errors.Is equivalent via string check
// since the error is always wrapped with %w.
func isDeviceAttestVerificationErr(err error) bool {
	return err != nil && isErrVerification(err)
}
