// SPDX-License-Identifier: AGPL-3.0-or-later

package pending

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Test the Rego policy evaluator in isolation — no informer / dynamic
// client. Exercises the default policy in docs/policy/jess/discovery.rego.

const testPolicy = `
package jess.discovery
import rego.v1

default allow := false
default reason := "default-deny"

allow if {
	input.candidate.source == "k8s-services"
	input.candidate.criticality != "critical"
}
reason := "auto-promote: k8s-services + non-critical" if {
	input.candidate.source == "k8s-services"
	input.candidate.criticality != "critical"
}

allow if {
	"jess:auto-promote" in input.candidate.tags
}
reason := "auto-promote: explicit tag" if {
	"jess:auto-promote" in input.candidate.tags
}
`

func evalOnly(t *testing.T, policy string, candidate map[string]any) Decision {
	t.Helper()
	r, err := New(context.Background(), Config{
		// Use a no-op stub client to satisfy nil check; we don't run informers.
		Client:     stubClient{},
		RegoModule: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.evaluate(context.Background(), candidate)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return d
}

func TestRego_AllowsK8sServicesNonCritical(t *testing.T) {
	d := evalOnly(t, testPolicy, map[string]any{
		"source":      "k8s-services",
		"criticality": "low",
	})
	if !d.Allow {
		t.Fatalf("expected allow, got %#v", d)
	}
	if !strings.Contains(d.Reason, "non-critical") {
		t.Errorf("expected reason mentions non-critical, got %q", d.Reason)
	}
}

func TestRego_DeniesK8sServicesCritical(t *testing.T) {
	d := evalOnly(t, testPolicy, map[string]any{
		"source":      "k8s-services",
		"criticality": "critical",
	})
	if d.Allow {
		t.Fatalf("expected deny, got %#v", d)
	}
	if d.Reason != "default-deny" {
		t.Errorf("expected default-deny reason, got %q", d.Reason)
	}
}

func TestRego_AllowsExplicitTagOverride(t *testing.T) {
	d := evalOnly(t, testPolicy, map[string]any{
		"source":      "ldap",
		"criticality": "critical", // would normally deny
		"tags":        []any{"jess:auto-promote"},
	})
	if !d.Allow {
		t.Fatalf("expected allow via tag override, got %#v", d)
	}
	if !strings.Contains(d.Reason, "explicit tag") {
		t.Errorf("expected explicit-tag reason, got %q", d.Reason)
	}
}

func TestRego_DefaultDeny(t *testing.T) {
	d := evalOnly(t, testPolicy, map[string]any{
		"source":      "unknown-source",
		"criticality": "medium",
	})
	if d.Allow {
		t.Fatalf("expected deny, got %#v", d)
	}
}

// loadRealPolicy reads a policy file shipped under docs/policy/jess so the tests
// guard the ACTUAL deployed Rego, not just an inline copy. Test cwd is the
// package dir (internal/lifecycle/pending) → up three to the repo root.
func loadRealPolicy(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "policy", "jess", name))
	if err != nil {
		t.Fatalf("read policy %s: %v", name, err)
	}
	return string(b)
}

// ADR 0052 Tier-0 RDP hard-guard (layer 2): the REAL default policy must deny
// rdp+critical EVEN WITH the jess:auto-promote tag — the tag override must NOT
// reach a Tier-0 DC's RDP. This test guards against a future edit deleting the
// hard_deny block.
func TestRego_Tier0RDPHardDeny_BeatsAutoPromoteTag(t *testing.T) {
	d := evalOnly(t, loadRealPolicy(t, "discovery.rego"), map[string]any{
		"source":      "ldap",
		"protocol":    "rdp",
		"criticality": "critical",
		"tags":        []any{"jess:auto-promote"},
	})
	if d.Allow {
		t.Fatalf("Tier-0 RDP must be denied even with jess:auto-promote tag, got allow: %#v", d)
	}
	if !strings.Contains(d.Reason, "HARD-DENY") {
		t.Errorf("expected HARD-DENY reason, got %q", d.Reason)
	}
}

func TestRego_Tier0RDPHardDeny_NoTag(t *testing.T) {
	d := evalOnly(t, loadRealPolicy(t, "discovery.rego"), map[string]any{
		"source":      "ldap",
		"protocol":    "rdp",
		"criticality": "critical",
	})
	if d.Allow {
		t.Fatalf("Tier-0 RDP must be denied, got %#v", d)
	}
}

// The guard is RDP-specific: SSH to a critical host (the legitimate dc01 SSH
// admin path) is still promotable via the explicit tag.
func TestRego_SSHToCriticalHost_TagStillPromotes(t *testing.T) {
	d := evalOnly(t, loadRealPolicy(t, "discovery.rego"), map[string]any{
		"source":      "ldap",
		"protocol":    "ssh",
		"criticality": "critical",
		"tags":        []any{"jess:auto-promote"},
	})
	if !d.Allow {
		t.Fatalf("SSH to critical host with auto-promote tag should allow, got %#v", d)
	}
}

func TestRego_DefaultPolicy_PromotesNonCriticalK8sServices(t *testing.T) {
	d := evalOnly(t, loadRealPolicy(t, "discovery.rego"), map[string]any{
		"source":      "k8s-services",
		"protocol":    "ssh",
		"criticality": "low",
	})
	if !d.Allow {
		t.Fatalf("expected promote for non-critical k8s-services, got %#v", d)
	}
}

// ADR 0052 option (b): the strict initial-rollout policy holds EVERYTHING for
// manual review — even a normally auto-promoted candidate — and still hard-denies
// Tier-0 RDP.
func TestRego_StrictPolicy_EverythingManual(t *testing.T) {
	pol := loadRealPolicy(t, "discovery-strict.rego")
	d := evalOnly(t, pol, map[string]any{
		"source":      "k8s-services",
		"protocol":    "ssh",
		"criticality": "low",
	})
	if d.Allow {
		t.Fatalf("strict policy must hold everything for manual review, got %#v", d)
	}
	dc := evalOnly(t, pol, map[string]any{
		"protocol":    "rdp",
		"criticality": "critical",
	})
	if dc.Allow || !strings.Contains(dc.Reason, "HARD-DENY") {
		t.Fatalf("strict policy must hard-deny Tier-0 RDP, got %#v", dc)
	}
}

func TestNew_RejectsMalformedRego(t *testing.T) {
	_, err := New(context.Background(), Config{
		Client:     stubClient{},
		RegoModule: "this is not valid rego at all { unclosed",
	})
	if err == nil {
		t.Fatal("expected compile error on malformed Rego")
	}
}

func TestNew_RejectsEmptyRego(t *testing.T) {
	_, err := New(context.Background(), Config{
		Client:     stubClient{},
		RegoModule: "",
	})
	if err == nil {
		t.Fatal("expected error on empty Rego (default-deny policy required)")
	}
}

func TestStripPendingFields_RemovesProvenance(t *testing.T) {
	in := map[string]any{
		"protocol":      "ssh",
		"address":       "host:22",
		"source":        "ldap",
		"source_ref":    "CN=dc01,DC=corp",
		"discovered_at": "2026-06-06T00:00:00Z",
		"criticality":   "high",
	}
	out := stripPendingFields(in)
	if _, has := out["source"]; has {
		t.Error("source should be stripped")
	}
	if _, has := out["source_ref"]; has {
		t.Error("source_ref should be stripped")
	}
	if _, has := out["discovered_at"]; has {
		t.Error("discovered_at should be stripped")
	}
	if out["protocol"] != "ssh" || out["criticality"] != "high" {
		t.Errorf("non-provenance fields should pass through, got %#v", out)
	}
}

// --- minimal stub dynamic.Interface so New() can validate config without
// touching the API server. The reconciler doesn't call any client methods
// in evaluate() — we only test the Rego path here.

type stubClient struct{}

func (stubClient) Resource(_ schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	panic("stubClient.Resource called — not expected in evaluate-only tests")
}
