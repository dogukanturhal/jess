// SPDX-License-Identifier: AGPL-3.0-or-later

package pdp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://id.test.hexxlock.com"

// mintToken signs an RS256 JWT (go-oidc's StaticKeySet default alg, matching
// Falcon-ID) with the given audiences and returns the raw token plus the
// public key to seed a static-keyset verifier.
func mintToken(t *testing.T, auds ...string) (raw string, pub crypto.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    testIssuer,
		Subject:   "user-123",
		Audience:  jwt.ClaimStrings(auds),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed, priv.Public()
}

// TestMultiAudience_AcceptsAnyAllowlisted — an operator token from either jess
// client (svc-jess id/access token OR svc-jess-web id_token) is accepted.
func TestMultiAudience_AcceptsAnyAllowlisted(t *testing.T) {
	accepted := []string{"svc-jess", "svc-jess-web"}
	cases := [][]string{
		{"svc-jess"},     // jessctl id_token
		{"svc-jess-web"}, // browser SPA id_token (the failing case)
		{"svc-jess", "https://api.hexxlock.com", "hexxlock-services"}, // jessctl access token (multi-aud)
		{"svc-jess-web", "https://api.hexxlock.com"},                  // browser access token
	}
	for _, aud := range cases {
		raw, pub := mintToken(t, aud...)
		v := NewVerifierFromKeySetMulti(testIssuer, accepted, []crypto.PublicKey{pub})
		id, err := v.Verify(context.Background(), raw)
		if err != nil {
			t.Errorf("aud=%v: unexpected error: %v", aud, err)
			continue
		}
		if id.Subject != "user-123" {
			t.Errorf("aud=%v: subject=%q, want user-123", aud, id.Subject)
		}
	}
}

// TestMultiAudience_RejectsNonAllowlisted — a token whose aud shares nothing
// with the allowlist is rejected even though its signature is valid.
func TestMultiAudience_RejectsNonAllowlisted(t *testing.T) {
	raw, pub := mintToken(t, "svc-other", "https://api.hexxlock.com")
	v := NewVerifierFromKeySetMulti(testIssuer, []string{"svc-jess", "svc-jess-web"}, []crypto.PublicKey{pub})
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected rejection for non-allowlisted audience, got nil")
	}
}

// TestSingleAudience_StillStrict — the original single-audience constructor is
// unchanged: a svc-jess-web token is NOT accepted by an svc-jess verifier.
func TestSingleAudience_StillStrict(t *testing.T) {
	raw, pub := mintToken(t, "svc-jess-web")
	v := NewVerifierFromKeySet(testIssuer, "svc-jess", []crypto.PublicKey{pub})
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("expected single-aud verifier to reject svc-jess-web, got nil")
	}
}

func TestAudienceAccepted(t *testing.T) {
	cases := []struct {
		tok, acc []string
		want     bool
	}{
		{[]string{"svc-jess-web"}, []string{"svc-jess", "svc-jess-web"}, true},
		{[]string{"svc-jess"}, []string{"svc-jess", "svc-jess-web"}, true},
		{[]string{"a", "b", "svc-jess"}, []string{"svc-jess"}, true},
		{[]string{"x"}, []string{"svc-jess", "svc-jess-web"}, false},
		{nil, []string{"svc-jess"}, false},
		{[]string{"svc-jess"}, nil, false},
	}
	for _, c := range cases {
		if got := audienceAccepted(c.tok, c.acc); got != c.want {
			t.Errorf("audienceAccepted(%v,%v)=%v want %v", c.tok, c.acc, got, c.want)
		}
	}
}
