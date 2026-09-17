// SPDX-License-Identifier: AGPL-3.0-or-later

package devicepolicy

import (
	"testing"
)

func TestEvaluate_EmptyPolicy_Allows(t *testing.T) {
	v := Evaluate(Claims{}, nil)
	if !v.Allow {
		t.Fatalf("empty policy → deny? %+v", v)
	}
	if v.Reason != "no_device_claim_required" {
		t.Errorf("reason = %q, want no_device_claim_required", v.Reason)
	}
}

func TestEvaluate_MissingClaim_FailsClosed(t *testing.T) {
	v := Evaluate(Claims{}, []Requirement{
		{Claim: "device_compliant", ValuesAnyOf: []string{"true"}},
	})
	if v.Allow {
		t.Fatalf("missing claim must deny: %+v", v)
	}
	if v.Reason != "device_claim_missing:device_compliant" {
		t.Errorf("reason = %q, want device_claim_missing:device_compliant", v.Reason)
	}
}

func TestEvaluate_MismatchClaim_Denies(t *testing.T) {
	v := Evaluate(Claims{"device_compliant": "false"}, []Requirement{
		{Claim: "device_compliant", ValuesAnyOf: []string{"true"}},
	})
	if v.Allow {
		t.Fatalf("mismatched claim must deny: %+v", v)
	}
	if v.Reason != "device_claim_mismatch:device_compliant=false" {
		t.Errorf("reason = %q, want device_claim_mismatch:device_compliant=false", v.Reason)
	}
}

func TestEvaluate_AllSatisfied_Allows(t *testing.T) {
	v := Evaluate(
		Claims{
			"device_compliant":      "true",
			"device_managed_by_mdm": "true",
		},
		[]Requirement{
			{Claim: "device_compliant", ValuesAnyOf: []string{"true"}},
			{Claim: "device_managed_by_mdm", ValuesAnyOf: []string{"true"}},
		},
	)
	if !v.Allow {
		t.Fatalf("all satisfied must allow: %+v", v)
	}
}

func TestEvaluate_ValuesAnyOf_ORWithin(t *testing.T) {
	// device_os_version in {"13","14"} — operator on 14 satisfies.
	v := Evaluate(Claims{"device_os_version": "14"}, []Requirement{
		{Claim: "device_os_version", ValuesAnyOf: []string{"13", "14"}},
	})
	if !v.Allow {
		t.Fatalf("OR-within failed: %+v", v)
	}
}

func TestEvaluate_FirstFailingRequirementReported(t *testing.T) {
	// Multiple failing requirements — reason names the FIRST one
	// so the audit log doesn't enumerate every miss (rate-limiter
	// friendly + privacy: don't leak the full posture set).
	v := Evaluate(Claims{}, []Requirement{
		{Claim: "device_compliant", ValuesAnyOf: []string{"true"}},
		{Claim: "device_managed_by_mdm", ValuesAnyOf: []string{"true"}},
	})
	if v.Allow {
		t.Fatalf("expected deny: %+v", v)
	}
	if v.Reason != "device_claim_missing:device_compliant" {
		t.Errorf("reason = %q, want first-failing-requirement only", v.Reason)
	}
}

func TestStringify_AllTypes(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string passthrough", "true", "true"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"float64 integer", float64(14), "14"},
		{"float64 fractional", float64(14.5), "14.5"},
		{"int", 14, "14"},
		{"int64", int64(14), "14"},
		{"nil", nil, ""},
		{"map → empty", map[string]any{"k": "v"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Stringify(c.in)
			if got != c.want {
				t.Errorf("Stringify(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
