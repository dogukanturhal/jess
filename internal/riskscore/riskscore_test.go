// SPDX-License-Identifier: AGPL-3.0-or-later

package riskscore

import (
	"context"
	"testing"
	"time"
)

// businessTime returns 2026-06-01 14:00 (Monday, mid-day) — comfortably
// inside the default business-hours window across reasonable TZs.
func businessTime() time.Time { return time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC) }
func afterHours() time.Time   { return time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC) }

func TestDefaultRules_CriticalAlwaysRequiresHuman(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		Subject:             "u",
		TargetCriticality:   "critical",
		RequestedAt:         businessTime(),
		RecentApprovalCount: 100, // even very tenured operator
		RequestReason:       "INC-4421 incident response",
	})
	if out.Decision != RequireHuman {
		t.Fatalf("critical target → got %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_RecentDenialTaints(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RequestedAt:         businessTime(),
		RecentApprovalCount: 50,
		RecentDenialCount:   1,
	})
	if out.Decision != RequireHuman {
		t.Fatalf("recent denial → got %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_NewOperatorRequiresHuman(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RequestedAt:         businessTime(),
		RecentApprovalCount: 2, // less than 3
	})
	if out.Decision != RequireHuman {
		t.Fatalf("new operator → got %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_IncidentShortcutsAutoApprove(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "medium",
		RequestedAt:         afterHours(), // even out-of-hours
		RecentApprovalCount: 5,
		RequestReason:       "INC-7741 debug OOM on node-app-01",
	})
	if out.Decision != AutoApprove {
		t.Fatalf("incident ref → got %v, want %v", out.Decision, AutoApprove)
	}
	if out.GrantTTL != 30*time.Minute {
		t.Fatalf("incident TTL = %v, want 30m", out.GrantTTL)
	}
}

func TestDefaultRules_OutOfHoursRequiresHuman(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RequestedAt:         afterHours(),
		RecentApprovalCount: 50,
		RequestReason:       "weekly maintenance window",
	})
	if out.Decision != RequireHuman {
		t.Fatalf("out-of-hours non-incident → got %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_LowCriticalityTenuredBusinessHours_AutoApprove(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "low",
		RequestedAt:         businessTime(),
		RecentApprovalCount: 5,
		RequestReason:       "routine config check",
	})
	if out.Decision != AutoApprove {
		t.Fatalf("low tenured biz-hours → got %v, want %v", out.Decision, AutoApprove)
	}
	if out.GrantTTL != 1*time.Hour {
		t.Fatalf("default TTL = %v, want 1h", out.GrantTTL)
	}
}

func TestDefaultRules_MediumCriticalityNeedsMoreTenure(t *testing.T) {
	e := NewDefaultRules()
	tcs := []struct {
		approvals int
		want      Decision
	}{
		{approvals: 5, want: RequireHuman}, // not tenured enough for medium
		{approvals: 10, want: AutoApprove}, // crosses the 10-approval gate
		{approvals: 20, want: AutoApprove},
	}
	for _, c := range tcs {
		out, _ := e.Evaluate(context.Background(), Input{
			TargetCriticality:   "medium",
			RequestedAt:         businessTime(),
			RecentApprovalCount: c.approvals,
			RequestReason:       "routine debug",
		})
		if out.Decision != c.want {
			t.Errorf("medium @ %d approvals → %v, want %v (reason=%q)",
				c.approvals, out.Decision, c.want, out.Reason)
		}
	}
}

func TestDefaultRules_HighCriticalityAlwaysHuman(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "high",
		RequestedAt:         businessTime(),
		RecentApprovalCount: 100,
		RequestReason:       "routine task",
	})
	if out.Decision != RequireHuman {
		t.Fatalf("high criticality non-incident → %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_EmptyCriticalityDefaultsToMedium(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{
		TargetCriticality:   "", // not set in catalog → defaults to medium
		RequestedAt:         businessTime(),
		RecentApprovalCount: 5, // not yet tenured for medium
	})
	if out.Decision != RequireHuman {
		t.Fatalf("empty criticality + medium-tenure → %v, want %v", out.Decision, RequireHuman)
	}
}

func TestDefaultRules_PolicyVersionAlwaysStamped(t *testing.T) {
	e := NewDefaultRules()
	out, _ := e.Evaluate(context.Background(), Input{TargetCriticality: "critical", RequestedAt: businessTime()})
	if out.PolicyVersion != "rules-v1" {
		t.Fatalf("PolicyVersion = %q, want %q", out.PolicyVersion, "rules-v1")
	}
}

func TestContainsIncidentRef(t *testing.T) {
	cases := map[string]bool{
		"INC-4421 debug":                    true,
		"inc-4421 lowercase":                true,
		"see ticket inc-99 today":           true,
		"reference number INC- with no num": false, // dash but no digit
		"INCREDIBLE not an incident":        false,
		"":                                  false,
		"jira PROJ-123 ticket":              false,
	}
	for input, want := range cases {
		if got := containsIncidentRef(input); got != want {
			t.Errorf("containsIncidentRef(%q) = %v, want %v", input, got, want)
		}
	}
}
