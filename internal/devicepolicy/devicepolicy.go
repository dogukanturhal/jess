// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devicepolicy enforces device-posture claims from the
// Falcon-ID JWT on session-open. Phase 5h-5 of ADR 0030 Phase 5 —
// jess-side mirror of Talon's RequireDeviceClaims, so the same
// device-posture wall sits in front of L4 brokering (this package)
// as already sits in front of L7 admin UIs (Talon).
//
// Wire shape mirrors talon/internal/router/perhost.go::evaluate device
// step: every Requirement in the policy AND-combined; missing keys
// FAIL-CLOSED (no "trust me, the device is fine" leaks).
//
// Sources
//   - Microsoft Entra Conditional Access publishes device_compliant,
//     device_managed_by_mdm, device_id, device_tpm_attested.
//   - Okta Device Trust exposes the same shape under different names —
//     normalised by the IdP-side broker (Falcon-ID).
//   - Our IdP (Falcon-ID) publishes the canonical claim names from
//     gatewayv1alpha1.AllowedDeviceClaimNames so both PEPs read the
//     same key strings.
//
// Why a separate package (vs shoving into pdp): the policy is target-
// specific — Targets in the catalog carry their own RequireDeviceClaims
// (5h-5 catalog extension). pdp.Identity stays Falcon-ID-shape; this
// package is the evaluator that takes Identity claims + target policy
// and yields allow/deny + audit reason.
package devicepolicy

import (
	"fmt"
	"strings"
)

// Requirement is one claim/value pair. AND-combined across the
// slice — every requirement MUST be satisfied for the session to
// open. ValuesAnyOf is OR-combined within the requirement (so
// "device_compliant in [true]" or "device_os_version in [13,14]").
type Requirement struct {
	Claim       string
	ValuesAnyOf []string
}

// Claims is the device-claim subset extracted from the verified
// Falcon-ID JWT. Identity-shape kept narrow on purpose — every
// member is a string for trivial comparison; the verifier is in
// charge of stringifying bool/number/JSON via the same rules
// Talon uses (talon/internal/oidc/rp.go::stringifyClaim).
//
// Missing claim → key absent from the map (NOT empty string). The
// evaluator must distinguish "claim not in token" (fail-closed for
// privacy + audit reason) from "claim present with value ” "
// (rare but legal).
type Claims map[string]string

// Verdict is the evaluator's allow/deny result.
type Verdict struct {
	Allow bool
	// Reason is a stable string suitable for audit + Prometheus
	// label. One of:
	//   ""                            (allow)
	//   "device_claim_missing:<key>"  (claim absent)
	//   "device_claim_mismatch:<key>" (claim present but value not in ValuesAnyOf)
	//   "no_device_claim_required"    (empty policy → trivially allow)
	Reason string
}

// Evaluate runs the policy against the operator's device claims.
//
// Posture is FAIL-CLOSED for the explicit-policy branch: if any
// requirement's claim is missing from the operator's token, the
// session is denied. Empty policy = no device gate (allow). This
// matches Talon's perhost.go evaluation — same semantics so an
// operator with a non-compliant laptop cannot bypass the wall by
// switching from a Talon-fronted admin UI to a jess SSH/RDP/DB
// brokered session.
func Evaluate(operator Claims, policy []Requirement) Verdict {
	if len(policy) == 0 {
		return Verdict{Allow: true, Reason: "no_device_claim_required"}
	}
	for _, req := range policy {
		got, present := operator[req.Claim]
		if !present {
			return Verdict{Allow: false, Reason: "device_claim_missing:" + req.Claim}
		}
		if !contains(req.ValuesAnyOf, got) {
			return Verdict{
				Allow:  false,
				Reason: fmt.Sprintf("device_claim_mismatch:%s=%s", req.Claim, got),
			}
		}
	}
	return Verdict{Allow: true}
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// CanonicalClaimNames is the local mirror of Talon's
// allowedDeviceClaimNames. Kept in sync with that variable; both
// PEPs read the same Falcon-ID claim keys.
var CanonicalClaimNames = []string{
	"device_id",
	"device_compliant",
	"device_managed_by_mdm",
	"device_tpm_attested",
	"device_os_version",
	"device_attestation_chain",
}

// Stringify normalises an arbitrary JWT claim value into the string
// form Evaluate compares against. Mirrors talon/internal/oidc/rp.go
// ::stringifyClaim exactly so the two PEPs read identical strings:
//
//	string → unchanged
//	bool   → "true" / "false"
//	number → decimal string (no exponent for int values)
//	other  → empty (caller drops)
func Stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// Avoid scientific notation for whole numbers — Talon's
		// stringifier picks the integer form when the float has
		// no fractional component; mirror that.
		if t == float64(int64(t)) {
			return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.0f", t), "0"), ".")
		}
		return fmt.Sprintf("%g", t)
	case int, int32, int64, uint, uint32, uint64:
		return fmt.Sprintf("%d", t)
	}
	return ""
}
