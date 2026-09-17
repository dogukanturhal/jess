// SPDX-License-Identifier: AGPL-3.0-or-later

package riskscore

import (
	"context"
	"strings"
	"testing"
	"time"
)

// sample policy used by the OPA evaluator tests. Mirrors the rules-v1
// semantics so callers see the same behaviour either backend.
const samplePolicy = `
package jess.risk

default decision := "require_human"
default reason := "no rule matched for auto-approval"
default grant_ttl_seconds := 3600
policy_version := "opa-test-v1"

decision := "require_human" if {
    input.target_criticality == "critical"
}

decision := "auto_approve" if {
    input.target_criticality == "low"
    input.recent_approval_count >= 3
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
}

reason := "low-criticality tenured operator, business hours" if {
    input.target_criticality == "low"
    input.recent_approval_count >= 3
    input.recent_denial_count == 0
    input.requested_hour >= 6
    input.requested_hour < 18
}

reason := "critical-criticality always requires human" if {
    input.target_criticality == "critical"
}

grant_ttl_seconds := 1800 if {
    contains(input.request_reason, "INC-")
}
`

func TestOPAEvaluator_CompilesAndEvaluates(t *testing.T) {
	e, err := NewOPAEvaluator(context.Background(), samplePolicy)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if e == nil {
		t.Fatalf("nil evaluator on non-empty module")
	}
	out, err := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RecentApprovalCount: 5,
		RequestedAt:         time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if out.Decision != AutoApprove {
		t.Errorf("decision = %v, want %v", out.Decision, AutoApprove)
	}
	if out.PolicyVersion != "opa-test-v1" {
		t.Errorf("policy_version = %q, want opa-test-v1", out.PolicyVersion)
	}
	if !strings.Contains(out.Reason, "low-criticality") {
		t.Errorf("reason = %q, want low-criticality match", out.Reason)
	}
}

func TestOPAEvaluator_CriticalRequiresHuman(t *testing.T) {
	e, _ := NewOPAEvaluator(context.Background(), samplePolicy)
	out, err := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "critical",
		RecentApprovalCount: 100,
		RequestedAt:         time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if out.Decision != RequireHuman {
		t.Errorf("critical → %v, want %v", out.Decision, RequireHuman)
	}
	if !strings.Contains(out.Reason, "critical") {
		t.Errorf("reason = %q, want critical reference", out.Reason)
	}
}

func TestOPAEvaluator_EmptyModuleReturnsNil(t *testing.T) {
	e, err := NewOPAEvaluator(context.Background(), "")
	if err != nil {
		t.Fatalf("empty module err: %v", err)
	}
	if e != nil {
		t.Fatalf("empty module → non-nil evaluator")
	}
}

func TestOPAEvaluator_RejectsMalformedRegoAtCompile(t *testing.T) {
	_, err := NewOPAEvaluator(context.Background(), `this is not rego at all { unclosed`)
	if err == nil {
		t.Fatalf("expected compile error on malformed Rego")
	}
}

func TestOPAEvaluator_RejectsUnknownDecisionValue(t *testing.T) {
	bad := `
package jess.risk
decision := "lgtm"
reason := "policy author typo"
policy_version := "v1"
`
	e, err := NewOPAEvaluator(context.Background(), bad)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	_, err = e.Evaluate(context.Background(), Input{
		TargetCriticality: "low",
		RequestedAt:       time.Now(),
	})
	if err == nil || !strings.Contains(err.Error(), "unknown decision") {
		t.Fatalf("expected unknown-decision error, got %v", err)
	}
}

func TestOPAEvaluator_IncidentTTLOverride(t *testing.T) {
	e, _ := NewOPAEvaluator(context.Background(), samplePolicy)
	out, err := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RecentApprovalCount: 5,
		RequestedAt:         time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
		RequestReason:       "INC-7741 debug urgent",
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if out.GrantTTL != 30*time.Minute {
		t.Errorf("incident TTL = %v, want 30m", out.GrantTTL)
	}
}
