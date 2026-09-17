// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stepup implements per-session MFA step-up policy evaluation — the
// P2.5 generalization of the admin-direct-connect AMR gate into a per-target,
// freshness-bounded, phishing-resistant re-auth requirement (ADR 0037).
//
// Where the pre-P2.5 broker only checked a token's `amr` claim on the
// admin-direct-connect fast-path, this package lets ANY sensitive target/tier
// demand a FRESH strong-auth assertion — both at session-open AND continuously
// through the session (the controller's grant-watch re-evaluates freshness so a
// session whose step-up has aged out is torn down mid-flight, forcing re-auth).
//
// Two invariants, per NIST SP 800-63B-4 §3.2.5 + RFC 9068 (auth_time/acr) +
// RFC 9470 (step-up challenge shape) and OMB M-22-09 (application-layer MFA):
//
//  1. FACTOR: the token's `amr` must contain an accepted factor. For the
//     `elevated` tier the accepted set is phishing-resistant ONLY
//     (hwk/webauthn/piv/cac) — OTP/TOTP/generic "mfa" are refused.
//  2. FRESHNESS: the token's `auth_time` (RFC 9068) must be within the tier's
//     max-age window (standard 1h, elevated 5min, per-target overridable). A
//     token with no auth_time cannot prove freshness and is REFUSED — the static
//     8h-stale `amr` weakness ADR 0037 calls out is closed.
//
// Every path fails CLOSED: an unknown policy string, a missing auth_time, a
// stale assertion, or no acceptable factor all deny.
package stepup

import (
	"fmt"
	"strings"
	"time"
)

// Policy is the per-target step-up tier (ADR 0037 §Decision 1).
type Policy string

const (
	// PolicyNone preserves pre-P2.5 behaviour: no step-up required.
	PolicyNone Policy = "none"
	// PolicyStandard requires a fresh assertion with amr ∈
	// {mfa,otp,totp,hwk,webauthn,piv,cac} within the (default 1h) window.
	PolicyStandard Policy = "standard"
	// PolicyElevated requires a fresh PHISHING-RESISTANT assertion with amr ∈
	// {hwk,webauthn,piv,cac} within a tighter (default 5min) window. For prod
	// DB targets, root-shell SSH, infra control planes.
	PolicyElevated Policy = "elevated"
)

// Freshness-window defaults per tier (ADR 0037 §Decision 1; open-question #5).
const (
	defaultStandardMaxAge = time.Hour
	defaultElevatedMaxAge = 5 * time.Minute
)

// SkewTolerance is the clock-skew allowance applied to the auth_time freshness
// comparison. Matches the JWT-validation skew in internal/falconid and ADR 0037
// failure-mode #4 (±2min; both ends run NTP).
const SkewTolerance = 2 * time.Minute

// Parse maps a catalog string to a Policy. Empty ⇒ PolicyNone (no gate). A
// non-empty UNKNOWN value is an error so the caller fails closed rather than
// silently disabling step-up on a typo (the CRD admission webhook validates the
// enum upstream; this is the belt-and-suspenders decode).
func Parse(s string) (Policy, error) {
	switch Policy(strings.ToLower(strings.TrimSpace(s))) {
	case "", PolicyNone:
		return PolicyNone, nil
	case PolicyStandard:
		return PolicyStandard, nil
	case PolicyElevated:
		return PolicyElevated, nil
	default:
		return PolicyNone, fmt.Errorf("unknown step-up policy %q (want none|standard|elevated)", s)
	}
}

// RequiredFactors returns the accepted amr set for the tier (nil for none).
func (p Policy) RequiredFactors() []string {
	switch p {
	case PolicyStandard:
		return []string{"mfa", "otp", "totp", "hwk", "webauthn", "piv", "cac"}
	case PolicyElevated:
		return []string{"hwk", "webauthn", "piv", "cac"}
	default:
		return nil
	}
}

// PhishingResistantOnly reports whether the tier accepts phishing-resistant
// factors only (elevated).
func (p Policy) PhishingResistantOnly() bool { return p == PolicyElevated }

// DefaultMaxAge is the tier's freshness window when no per-target override is
// set (0 for none).
func (p Policy) DefaultMaxAge() time.Duration {
	switch p {
	case PolicyStandard:
		return defaultStandardMaxAge
	case PolicyElevated:
		return defaultElevatedMaxAge
	default:
		return 0
	}
}

// EffectiveMaxAge resolves the freshness window: a positive per-target override
// (seconds) wins, else the tier default.
func (p Policy) EffectiveMaxAge(overrideSeconds int) time.Duration {
	if overrideSeconds > 0 {
		return time.Duration(overrideSeconds) * time.Second
	}
	return p.DefaultMaxAge()
}

// AcrValues returns the RFC 9470 acr_values the broker advertises to the AS for
// the tier's factor set (urn:falcon-id:<factor>). Used to populate the step-up
// challenge; empty for none.
func (p Policy) AcrValues() []string {
	fs := p.RequiredFactors()
	if len(fs) == 0 {
		return nil
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, "urn:falcon-id:"+f)
	}
	return out
}

// IsPhishingResistant is the canonical NIST SP 800-63B-4 §3.2.5 allowlist: only
// channel binding (PIV/CAC) and verifier name binding (WebAuthn/FIDO2) qualify.
// This is the single source of truth for the phishing-resistant AMR set across
// the broker (spine + jess-controller delegate here).
func IsPhishingResistant(amr string) bool {
	switch strings.ToLower(strings.TrimSpace(amr)) {
	case "hwk", "webauthn", "piv", "cac":
		return true
	}
	return false
}

// Satisfied reports whether a token's amr + auth_time satisfy the tier at `now`,
// given the effective maxAge window. Returns (true,"") when satisfied, or
// (false, reason) — fail-closed — otherwise. PolicyNone is always satisfied.
//
// Checks, in order (all must hold for a non-none tier):
//   - auth_time present (non-zero) — else the assertion's freshness is unprovable;
//   - auth_time within [now-maxAge-skew, now+skew] — fresh, not future-dated;
//   - amr intersects RequiredFactors (phishing-resistant-filtered for elevated).
func Satisfied(tokenAMR []string, authTime, now time.Time, maxAge time.Duration, p Policy) (bool, string) {
	if p == PolicyNone {
		return true, ""
	}
	if authTime.IsZero() {
		return false, "token carries no auth_time — cannot prove step-up freshness"
	}
	age := now.Sub(authTime)
	if age > maxAge+SkewTolerance {
		return false, fmt.Sprintf("step-up stale: auth_time age %s exceeds max-age %s", age.Truncate(time.Second), maxAge)
	}
	if age < -SkewTolerance {
		return false, "auth_time is in the future beyond skew tolerance"
	}
	prOnly := p.PhishingResistantOnly()
	have := make(map[string]struct{}, len(tokenAMR))
	for _, a := range tokenAMR {
		have[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	for _, want := range p.RequiredFactors() {
		if _, ok := have[want]; !ok {
			continue
		}
		if prOnly && !IsPhishingResistant(want) {
			continue
		}
		return true, ""
	}
	return false, "no acceptable step-up factor in token amr (need one of " + strings.Join(p.RequiredFactors(), ",") + ")"
}
