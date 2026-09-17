// SPDX-License-Identifier: AGPL-3.0-or-later

// Package riskscore evaluates a JIT-grant request against a policy and
// returns an auto-approval decision. Phase 5h-4.
//
// Design:
//
//   - Evaluator is the policy interface. Default implementation is
//     rules-based (no external dependency); an OPA-backed Evaluator
//     lands in 5h-4b that consumes the same Decision shape.
//   - The evaluator is INFORMATION-ONLY — it never persists state and
//     never holds locks. The caller (admin request handler) decides
//     what to do with the Decision (mint a grant, leave pending, etc).
//   - Decisions are deterministic given the same Input. The fields on
//     Input enumerate every signal the policy can consider — adding a
//     new signal means adding a field + bumping a regression test.
package riskscore

import (
	"context"
	"strings"
	"time"
)

// Decision is the policy outcome for one JIT request.
type Decision string

const (
	// AutoApprove — the policy is confident enough to mint a grant
	// inline. Audit still records "approve.auto" so SOC 2 evidence
	// distinguishes auto from human approvals.
	AutoApprove Decision = "auto_approve"
	// RequireHuman — leave the request Pending; admin queue picks
	// it up via the existing approve/deny flow.
	RequireHuman Decision = "require_human"
	// AutoDeny — the policy explicitly forbids this request. Caller
	// flips state to Denied with the policy reason. Rare; used for
	// hard-blocked combos (e.g. operator's grant frequency exceeds
	// rate-limit window).
	AutoDeny Decision = "auto_deny"
)

// Input is the bag of signals the evaluator sees. Fields are
// individually optional — implementations should tolerate empty values
// (the policy author decides whether the empty case is "default-safe"
// or "require-human" per signal).
type Input struct {
	// Subject is the verified Falcon-ID sub of the requester.
	Subject string

	// SubjectRoles is the verified role set on the requester's token.
	// Empty for operators without admin/editor/viewer assignments.
	SubjectRoles []string

	// SubjectGroups likewise — empty when the token carries no groups
	// claim or when the operator is in none.
	SubjectGroups []string

	// TargetID + TargetCriticality + TargetTags from the catalog at
	// request time. Critical: this is the LIVE catalog snapshot, not
	// what the operator typed — so retroactive criticality bumps via
	// a catalog edit affect any in-flight requests.
	TargetID          string
	TargetCriticality string
	TargetTags        []string
	TargetProtocol    string

	// RequestedAt is the wall-clock time the request was submitted.
	// Evaluator's business-hours check uses time.Hour buckets in the
	// CONTROLLER's timezone (env TZ); operators in distant timezones
	// will see different auto-approval cutoffs.
	RequestedAt time.Time

	// RequestReason — free-form text the operator supplies. Evaluator
	// MAY pattern-match keywords (e.g. "incident", "INC-") to influence
	// the decision, but should not gate on absence (operator might
	// genuinely have no incident link).
	RequestReason string

	// RecentApprovalCount is how many of the operator's requests in
	// the last 30d were approved. High count + low criticality is
	// the canonical "operator does this routinely" auto-approval
	// signal. 0 = first-time-requester (default-conservative).
	RecentApprovalCount int

	// RecentDenialCount is the same window for denied requests. Any
	// recent denial taints the operator — auto-approval requires a
	// clean record. 0 means "no recent denials".
	RecentDenialCount int
}

// Output is the Decision plus a human-readable reason + the optional
// TTL the evaluator wants for the auto-minted grant (caller may clamp
// to system defaults).
type Output struct {
	Decision Decision      `json:"decision"`
	Reason   string        `json:"reason"`
	GrantTTL time.Duration `json:"grant_ttl,omitempty"`
	// PolicyVersion is a free-form tag the evaluator stamps on its
	// decision so the audit log can attribute outcomes to a specific
	// policy version. Default rules emit "rules-v1"; OPA backend
	// would emit the bundle digest.
	PolicyVersion string `json:"policy_version"`
}

// Evaluator is the policy interface. nil-safe at the call site —
// callers MUST handle a nil Evaluator (interpret as "no auto-approval
// configured; every request requires human review").
type Evaluator interface {
	Evaluate(ctx context.Context, in Input) (Output, error)
}

// DefaultRulesEvaluator is the conservative built-in. Rules:
//
//  1. Critical-criticality target  → RequireHuman (always).
//  2. Operator has any recent denial → RequireHuman.
//  3. Operator has < 3 prior approvals → RequireHuman (new operator).
//  4. Out-of-business-hours (default UTC 06:00–18:00) → RequireHuman.
//  5. Reason references an incident (regex /INC-\d+/i) → AutoApprove
//     with shorter TTL — operator is responding to a paging signal.
//  6. Low-criticality + ≥ 3 approvals + business-hours → AutoApprove.
//  7. Medium-criticality + ≥ 10 approvals + business-hours → AutoApprove.
//  8. Anything else → RequireHuman.
//
// The default never AutoDeny — that's reserved for explicit policy
// rules (OPA bundle) or hard rate limits. The default is conservative
// by design; production deployments override with an OPA bundle that
// codifies per-team / per-target rules.
type DefaultRulesEvaluator struct {
	// BusinessHoursStart / End in cluster TZ. 0 == use defaults (6-18).
	BusinessHoursStart int
	BusinessHoursEnd   int
	// DefaultTTL is the grant TTL the evaluator suggests on AutoApprove.
	// Caller (handleApprove inline path) may clamp.
	DefaultTTL time.Duration
	// IncidentTTL is the (shorter) TTL when the reason matches the
	// incident pattern — break-glass shouldn't grant 8h of access.
	IncidentTTL time.Duration
}

// NewDefaultRules returns a fully-defaulted evaluator. Override fields
// after construction to customize.
func NewDefaultRules() *DefaultRulesEvaluator {
	return &DefaultRulesEvaluator{
		BusinessHoursStart: 6,
		BusinessHoursEnd:   18,
		DefaultTTL:         1 * time.Hour,
		IncidentTTL:        30 * time.Minute,
	}
}

func (e *DefaultRulesEvaluator) Evaluate(_ context.Context, in Input) (Output, error) {
	out := Output{PolicyVersion: "rules-v1", Decision: RequireHuman}
	crit := strings.ToLower(in.TargetCriticality)
	if crit == "" {
		crit = "medium"
	}

	// Rule 1: critical-criticality always requires human.
	if crit == "critical" {
		out.Reason = "critical-criticality targets require human approval"
		return out, nil
	}

	// Rule 2: any recent denial taints the operator.
	if in.RecentDenialCount > 0 {
		out.Reason = "operator has recent denials in 30d window"
		return out, nil
	}

	// Rule 3: new operator (< 3 prior approvals) requires human review.
	// Phishing-protection: a freshly-compromised account can't grind
	// out auto-approvals before its first review.
	if in.RecentApprovalCount < 3 {
		out.Reason = "operator has < 3 prior approvals (new operator review)"
		return out, nil
	}

	// Rule 5: incident reference shortcuts to AutoApprove with shorter TTL.
	// Operators paging through INC-* numbers in the reason get fast-tracked.
	if containsIncidentRef(in.RequestReason) {
		out.Decision = AutoApprove
		out.Reason = "reason references incident ticket — break-glass auto-approve"
		out.GrantTTL = e.IncidentTTL
		return out, nil
	}

	// Rule 4: out-of-business-hours fails through to human review.
	// Business-hours check uses the controller's TZ (env TZ).
	if !inBusinessHours(in.RequestedAt, e.BusinessHoursStart, e.BusinessHoursEnd) {
		out.Reason = "out of business hours — human review required"
		return out, nil
	}

	// Rule 6: low-criticality + tenured operator + business-hours → auto.
	if crit == "low" {
		out.Decision = AutoApprove
		out.Reason = "low-criticality target, tenured operator, business hours"
		out.GrantTTL = e.DefaultTTL
		return out, nil
	}

	// Rule 7: medium-criticality requires more history (10+ approvals).
	if crit == "medium" && in.RecentApprovalCount >= 10 {
		out.Decision = AutoApprove
		out.Reason = "medium-criticality target, well-tenured operator, business hours"
		out.GrantTTL = e.DefaultTTL
		return out, nil
	}

	// Rule 8: default fall-through.
	out.Reason = "no rule matched for auto-approval (high-criticality or insufficient tenure)"
	return out, nil
}

// containsIncidentRef returns true when the reason text references a
// recognised incident-tracker pattern. Conservative — only matches
// `INC-<digits>` (Linear/Atlassian-style); future patterns added via
// policy override.
func containsIncidentRef(reason string) bool {
	low := strings.ToLower(reason)
	for i := 0; i+4 < len(low); i++ {
		if low[i:i+4] == "inc-" {
			// at least one digit must follow
			if i+4 < len(low) && low[i+4] >= '0' && low[i+4] <= '9' {
				return true
			}
		}
	}
	return false
}

func inBusinessHours(t time.Time, start, end int) bool {
	if start == 0 && end == 0 {
		start, end = 6, 18
	}
	h := t.Hour()
	return h >= start && h < end
}
