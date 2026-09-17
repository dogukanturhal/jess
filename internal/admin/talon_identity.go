// SPDX-License-Identifier: AGPL-3.0-or-later

// talon_identity.go — Phase 2 closure for jess↔talon SSH bridge (task #140).
//
// Verifies the X-Talon-Identity-Token JWT that Talon's edge mTLS verifier
// stamps onto every authenticated request flowing downstream. The token
// carries the verified posture-tier + device-UUID extracted from the
// client's mTLS device certificate, so jess admin endpoints can trust
// those claims without re-validating the device cert themselves.
//
// Before this MR: jess's SSH-cert handler trusted the bare
// X-Talon-Device-UUID header. Any caller who could reach the admin
// port could forge a device-UUID claim (modulo the port's network ACL).
// After this MR: the device UUID is sourced from the JWT signature,
// which is verifiable against Talon's published JWKS — only Talon's
// iap-identity-key can mint a token jess accepts.
//
// JWT contract (ADR 0040 §Phase 4):
//
//	{
//	  "iss":  "https://internal.example.com",
//	  "aud":  "jess",
//	  "sub":  "spiffe://hexxlock.com/device/<device-uuid>",
//	  "iat":  …,
//	  "exp":  …,        # talon-side TTL, typically 60s
//	  "tier": "TIER_CORP" | "TIER_BYOD" | "TIER_BREAKGLASS",
//	  "device_uuid": "01HZZ…",
//	  "posture_iat": "2026-06-09T11:15:23Z"
//	}

package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TalonIdentityVerifier verifies the X-Talon-Identity-Token header.
type TalonIdentityVerifier struct {
	v *oidc.IDTokenVerifier
}

// TalonIdentityClaims is the verified subset of the token surfaced to
// admin route handlers.
type TalonIdentityClaims struct {
	// Subject is the SPIFFE URI from the device cert
	// (spiffe://hexxlock.com/device/<uuid>).
	Subject string
	// DeviceUUID is the explicit device_uuid claim — the same UUID
	// the SPIFFE Subject encodes, but extracted up-front so handlers
	// don't have to re-parse the SPIFFE URI.
	DeviceUUID string
	// Tier is the access tier the device qualifies for at the moment
	// Talon issued this token.
	Tier string
	// PostureIAT is the wall-clock timestamp Talon recorded for the
	// posture state used to compute the tier. RFC3339.
	PostureIAT string
}

// NewTalonIdentityVerifier fetches the Talon JWKS via OIDC discovery
// against `issuer` and returns a verifier that accepts tokens whose
// audience contains `audience` (typically "jess").
//
// Network at construction: one HTTPS GET to
// <issuer>/.well-known/openid-configuration. Subsequent token
// verifications use the cached JWKS until the key rotates.
func NewTalonIdentityVerifier(ctx context.Context, issuer, audience string) (*TalonIdentityVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("talon identity: oidc discovery for %s: %w", issuer, err)
	}
	return &TalonIdentityVerifier{
		v: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

// Verify parses + validates the X-Talon-Identity-Token from the request
// header. Returns (claims, nil) on success; (zero, err) on missing
// header, malformed JWT, signature failure, or audience mismatch.
//
// Callers that REQUIRE the token (e.g. ssh-cert handler in enforce
// mode) check `errors.Is(err, ErrNoTalonIdentityToken)` to distinguish
// "header missing" from "header present but invalid". Audit log
// rationale: missing = client didn't send anything (could be a
// pre-Phase-4 client), invalid = active forgery attempt.
func (t *TalonIdentityVerifier) Verify(ctx context.Context, r *http.Request) (TalonIdentityClaims, error) {
	raw := r.Header.Get("X-Talon-Identity-Token")
	if raw == "" {
		return TalonIdentityClaims{}, ErrNoTalonIdentityToken
	}
	tok, err := t.v.Verify(ctx, raw)
	if err != nil {
		return TalonIdentityClaims{}, fmt.Errorf("talon identity: verify: %w", err)
	}
	var c struct {
		DeviceUUID string `json:"device_uuid"`
		Tier       string `json:"tier"`
		PostureIAT string `json:"posture_iat"`
	}
	if err := tok.Claims(&c); err != nil {
		return TalonIdentityClaims{}, fmt.Errorf("talon identity: decode claims: %w", err)
	}
	if c.DeviceUUID == "" {
		// SPIFFE Subject is the fallback if the explicit claim is
		// missing. spiffe://hexxlock.com/device/<uuid>
		const spiffePrefix = "spiffe://hexxlock.com/device/"
		if strings.HasPrefix(tok.Subject, spiffePrefix) {
			c.DeviceUUID = strings.TrimPrefix(tok.Subject, spiffePrefix)
		}
	}
	return TalonIdentityClaims{
		Subject:    tok.Subject,
		DeviceUUID: c.DeviceUUID,
		Tier:       c.Tier,
		PostureIAT: c.PostureIAT,
	}, nil
}

// ErrNoTalonIdentityToken is the sentinel returned when the request
// carries no X-Talon-Identity-Token header. Distinct from a verification
// failure so the SSH-cert + future device-claim handlers can degrade
// gracefully in non-enforce mode.
var ErrNoTalonIdentityToken = errors.New("talon identity: header X-Talon-Identity-Token missing")

// WithTalonIdentityVerifier mounts the verifier so downstream handlers
// (currently /ssh-cert, future device-management) can read the
// cryptographically-verified device claims.
func (h *Handler) WithTalonIdentityVerifier(v *TalonIdentityVerifier) *Handler {
	h.talonIdentity = v
	return h
}
