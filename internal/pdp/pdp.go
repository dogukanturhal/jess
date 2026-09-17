// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pdp is the Policy Decision Point: it verifies the operator's
// Falcon-ID token into a trusted Identity (TokenVerifier) and decides
// allow/deny from that Identity + the target's required roles (Authorizer).
// The "shared brain" of the L4 PEP (ADR 0030 Phase 5b).
//
// Identity is a type alias to the shared
// github.com/dogukanturhal/hexx-pep-core/pkg/identity.Identity
// (ADR 0031); jess.pdp keeps the alias so existing callers
// (spine.Controller, RoleAuthorizer) compile unchanged.
package pdp

import (
	"context"
	"time"

	"github.com/dogukanturhal/hexx-pep-core/pkg/identity"
)

// Identity is the authenticated operator, derived ONLY from a verified token.
// Aliased to the shared hexx-pep-core type so Jess and Talon converge on the
// same six-claim shape (Subject, Email, Roles, Groups, Region, AMR).
type Identity = identity.Identity

// Request is a per-session authorization request.
type Request struct {
	Identity      Identity
	TargetID      string
	Protocol      string
	Region        string
	RequiredRoles []string // from the target; access requires an intersecting role
}

// Decision is the PDP verdict. DecisionID is propagated into every audit event.
type Decision struct {
	Allow      bool
	Reason     string
	DecisionID string
	TTL        time.Duration
}

// Authorizer decides allow/deny for a verified Identity against a target.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// TokenVerifier turns a raw operator token into a verified Identity. A failed
// verification MUST deny — the controller never trusts a client-supplied subject.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (Identity, error)
}

// DeviceClaimsVerifier is the optional Phase 5h-5 extension: alongside the
// hexx-pep-core Identity (Subject/Email/Roles/Groups/Region/AMR), the
// FalconIDVerifier can also extract the device-posture subset of claims
// (device_compliant, device_managed_by_mdm, …) into a flat string map.
//
// The shared identity.Identity stays narrow on purpose (one shape across
// all HexxLock PEPs); device-posture is a per-product extension wired via
// this optional interface so older Verify impls in tests / dev brokers
// still satisfy TokenVerifier.
//
// Returned claims map keys MUST be drawn from devicepolicy.CanonicalClaimNames;
// values are stringified per Talon's stringifyClaim semantics so the two
// PEPs read identical strings against the same JWT.
type DeviceClaimsVerifier interface {
	TokenVerifier
	VerifyDevice(ctx context.Context, rawToken string) (Identity, map[string]string, error)
}

// StepUpClaims carries the RFC 9068 freshness claims used by the per-session
// MFA step-up gate (ADR 0037, P2.5). The `amr` factor set already rides on
// Identity; this adds the freshness anchor the step-up policy needs.
type StepUpClaims struct {
	// AuthTime is the token's `auth_time` claim (RFC 9068 §2.2) — the instant
	// the operator's authentication factors were verified. Zero when the claim
	// is absent, which the step-up gate treats as "freshness unprovable" and
	// fails closed for any non-none tier.
	AuthTime time.Time
}

// SessionClaimsVerifier is the P2.5 superset of DeviceClaimsVerifier: a single
// token verification that also yields the step-up freshness claims. The
// controller prefers it over DeviceClaimsVerifier so it can evaluate per-session
// MFA step-up without a second verify. Optional — older Verify/VerifyDevice
// impls (tests, dev brokers) remain valid TokenVerifiers.
type SessionClaimsVerifier interface {
	DeviceClaimsVerifier
	VerifySession(ctx context.Context, rawToken string) (Identity, map[string]string, StepUpClaims, error)
}

// RoleAuthorizer allows iff the identity carries at least one of the target's
// RequiredRoles. Empty RequiredRoles => DENY (zero-trust default-deny).
type RoleAuthorizer struct{}

// Authorize implements Authorizer.
func (RoleAuthorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	if len(req.RequiredRoles) == 0 {
		return Decision{Allow: false, Reason: "target has no required roles (default-deny)", DecisionID: decisionID()}, nil
	}
	want := make(map[string]struct{}, len(req.RequiredRoles))
	for _, r := range req.RequiredRoles {
		want[r] = struct{}{}
	}
	for _, have := range req.Identity.Roles {
		if _, ok := want[have]; ok {
			return Decision{Allow: true, Reason: "role:" + have, DecisionID: decisionID(), TTL: 15 * time.Minute}, nil
		}
	}
	return Decision{Allow: false, Reason: "identity lacks a required role", DecisionID: decisionID()}, nil
}
