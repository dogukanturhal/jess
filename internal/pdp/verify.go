// SPDX-License-Identifier: AGPL-3.0-or-later

package pdp

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dogukanturhal/jess/internal/devicepolicy"
)

// FalconIDVerifier verifies Falcon-ID OIDC tokens (signature via JWKS, plus
// issuer/audience/expiry) and extracts the operator Identity.
//
// When acceptedAuds is non-empty the underlying go-oidc verifier is built with
// SkipClientIDCheck (it cannot express "any of N audiences") and this type
// enforces audience membership itself: the token is accepted if its aud array
// intersects acceptedAuds. When acceptedAuds is nil the go-oidc verifier does
// the single-audience check as before.
type FalconIDVerifier struct {
	v            *oidc.IDTokenVerifier
	acceptedAuds []string
}

// NewFalconIDVerifier fetches Falcon-ID's discovery + JWKS from issuer (network
// at construction) and verifies tokens whose audience is clientID (the Jess
// OAuth client).
func NewFalconIDVerifier(ctx context.Context, issuer, clientID string) (*FalconIDVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("pdp: oidc discovery for %s: %w", issuer, err)
	}
	return &FalconIDVerifier{v: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

// NewFalconIDVerifierMulti is NewFalconIDVerifier for a resource reached by
// several first-party OAuth clients: the token is accepted if its aud contains
// ANY of audiences (membership, per Falcon-ID's documented multi-audience
// contract). The jess controller admin chain uses it because operator tokens
// arrive as svc-jess (jessctl id/access token) AND svc-jess-web (the browser
// SPA's id_token). This is an explicit allowlist of jess operator clients —
// deliberately NOT the broad platform-API audience, since the admin chain is
// the critical ADR-0030 privileged-broker surface.
func NewFalconIDVerifierMulti(ctx context.Context, issuer string, audiences []string) (*FalconIDVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("pdp: oidc discovery for %s: %w", issuer, err)
	}
	return &FalconIDVerifier{
		v:            provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		acceptedAuds: audiences,
	}, nil
}

// NewVerifierFromKeySet builds a verifier from explicit public keys (offline;
// used in tests and air-gapped setups where JWKS is provisioned out of band).
func NewVerifierFromKeySet(issuer, clientID string, keys []crypto.PublicKey) *FalconIDVerifier {
	ks := &oidc.StaticKeySet{PublicKeys: keys}
	return &FalconIDVerifier{v: oidc.NewVerifier(issuer, ks, &oidc.Config{ClientID: clientID})}
}

// NewVerifierFromKeySetMulti is the offline (static-keyset) multi-audience
// counterpart to NewVerifierFromKeySet — used in tests.
func NewVerifierFromKeySetMulti(issuer string, audiences []string, keys []crypto.PublicKey) *FalconIDVerifier {
	ks := &oidc.StaticKeySet{PublicKeys: keys}
	return &FalconIDVerifier{
		v:            oidc.NewVerifier(issuer, ks, &oidc.Config{SkipClientIDCheck: true}),
		acceptedAuds: audiences,
	}
}

// audienceAccepted reports whether tokenAuds intersects accepted. Only
// consulted when acceptedAuds is non-empty (multi-audience mode).
func audienceAccepted(tokenAuds, accepted []string) bool {
	for _, want := range accepted {
		for _, got := range tokenAuds {
			if got == want {
				return true
			}
		}
	}
	return false
}

// Verify checks the token and returns the trusted Identity.
func (f *FalconIDVerifier) Verify(ctx context.Context, raw string) (Identity, error) {
	id, _, err := f.VerifyDevice(ctx, raw)
	return id, err
}

// VerifyDevice implements DeviceClaimsVerifier (Phase 5h-5) — same as
// Verify but also extracts the device-posture subset of claims for the
// devicepolicy evaluator. Returned map keys are drawn from
// devicepolicy.CanonicalClaimNames; values stringified by the
// devicepolicy.Stringify rules.
func (f *FalconIDVerifier) VerifyDevice(ctx context.Context, raw string) (Identity, map[string]string, error) {
	id, device, _, err := f.VerifySession(ctx, raw)
	return id, device, err
}

// VerifySession implements SessionClaimsVerifier (P2.5) — one token
// verification yielding the Identity, the device-posture claim subset, AND the
// step-up freshness claims (auth_time). It is the single extraction path;
// VerifyDevice and Verify delegate to it.
func (f *FalconIDVerifier) VerifySession(ctx context.Context, raw string) (Identity, map[string]string, StepUpClaims, error) {
	tok, err := f.v.Verify(ctx, raw)
	if err != nil {
		return Identity{}, nil, StepUpClaims{}, fmt.Errorf("pdp: token verification failed: %w", err)
	}
	// Multi-audience mode: go-oidc skipped the aud check (it can't express
	// "any of N"), so enforce membership here. Error string mirrors go-oidc's
	// single-aud message for log/operator familiarity.
	if len(f.acceptedAuds) > 0 && !audienceAccepted(tok.Audience, f.acceptedAuds) {
		return Identity{}, nil, StepUpClaims{}, fmt.Errorf("pdp: token verification failed: oidc: expected audience in %q got %q", f.acceptedAuds, tok.Audience)
	}
	var c struct {
		Email  string   `json:"email"`
		Roles  []string `json:"roles"`
		Groups []string `json:"groups"`
		AMR    []string `json:"amr"`
	}
	_ = tok.Claims(&c)
	id := Identity{
		Subject: tok.Subject,
		Email:   c.Email,
		Roles:   c.Roles,
		Groups:  c.Groups,
		AMR:     c.AMR,
	}
	// Device-claim extraction (5h-5) + step-up freshness (P2.5). Read the JWT
	// as a generic map and pull each canonical device claim if present. Missing
	// keys stay ABSENT from the returned map so policy.Evaluate can fail-closed
	// on missing.
	var allClaims map[string]any
	_ = tok.Claims(&allClaims)
	device := map[string]string{}
	for _, k := range devicepolicy.CanonicalClaimNames {
		if v, ok := allClaims[k]; ok {
			if s := devicepolicy.Stringify(v); s != "" {
				device[k] = s
			}
		}
	}
	var su StepUpClaims
	if v, ok := allClaims["auth_time"]; ok {
		if secs, ok := claimUnixSeconds(v); ok {
			su.AuthTime = time.Unix(secs, 0)
		}
	}
	return id, device, su, nil
}

// claimUnixSeconds coerces a JWT numeric-date claim (RFC 7519 NumericDate) to
// unix seconds. JSON numbers decode to float64; json.Number and integer forms
// are handled for robustness across decoders.
func claimUnixSeconds(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return 0, false
}
