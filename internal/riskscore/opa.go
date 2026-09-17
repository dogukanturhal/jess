// SPDX-License-Identifier: AGPL-3.0-or-later

package riskscore

// Phase 5h-4b — OPA-backed Evaluator.
//
// Same Evaluator interface as DefaultRulesEvaluator; swap in by setting
// JESS_RISK_OPA_POLICY_FILE (an absolute path to a .rego file) at
// controller startup. Policy author writes a Rego module that exposes
// `decision`, `reason`, `grant_ttl_seconds`, and `policy_version` —
// the evaluator marshals Input as `input.*` and reads those four keys
// back.
//
// Rego module contract:
//
//	package jess.risk
//
//	default decision := "require_human"
//	default reason   := "no rule matched"
//	default grant_ttl_seconds := 3600
//	policy_version := "opa-bundle-v1"
//
//	decision := "auto_approve" if {
//	    input.target_criticality == "low"
//	    input.recent_approval_count >= 3
//	    # ... etc
//	}
//
// The same module can be evolved + signed + verified via Kyverno (the
// platform's existing supply chain). Operators rotate policy by
// re-deploying the controller with a new policy file mounted from a
// ConfigMap — no jess binary change.
//
// Why we don't poll the bundle for hot-reload: Rego policies are
// rotated like code (GitOps + verified images), not like config. A
// stale evaluator after deploy lasts at most one pod restart.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

// numericFromAny extracts a positive integer from a Rego-returned value.
// OPA's pipeline can surface numbers as float64 (default), int / int64
// (some optimisation paths), or json.Number (the "preserve precision"
// path). Any non-numeric value returns 0 so the caller treats it as
// "field absent".
func numericFromAny(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int64:
		return n
	case json.Number:
		i, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil {
			return 0
		}
		return i
	default:
		return 0
	}
}

// OPAEvaluator wraps a compiled, prepared Rego query for the
// data.jess.risk decision rule.
type OPAEvaluator struct {
	query rego.PreparedEvalQuery
}

// NewOPAEvaluator compiles the Rego module + prepares the query at
// construction time so a malformed module fails the controller at
// startup, not on the first JIT request. Empty module string returns
// (nil, nil) — caller treats nil as "no OPA configured; fall back".
func NewOPAEvaluator(ctx context.Context, module string) (*OPAEvaluator, error) {
	if module == "" {
		return nil, nil
	}
	q, err := rego.New(
		rego.Query("data.jess.risk"),
		rego.Module("jess_risk.rego", module),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("riskscore: opa compile: %w", err)
	}
	return &OPAEvaluator{query: q}, nil
}

// LoadOPAEvaluator reads a .rego file from disk + compiles. Convenience
// wrapper around NewOPAEvaluator for the common controller-startup
// pattern. Returns (nil, nil) when path is empty (opt-out).
func LoadOPAEvaluator(ctx context.Context, path string) (*OPAEvaluator, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("riskscore: opa read %s: %w", path, err)
	}
	return NewOPAEvaluator(ctx, string(b))
}

// Evaluate marshals the Input as `input.*` (snake_case keys to match
// Rego conventions), queries `data.jess.risk`, and reads back the
// four decision fields. Errors surface — caller's fail-CLOSED posture
// in handleSubmit treats any error as "leave request Pending".
func (e *OPAEvaluator) Evaluate(ctx context.Context, in Input) (Output, error) {
	if e == nil {
		return Output{}, errors.New("riskscore: nil OPAEvaluator")
	}
	regoInput := map[string]any{
		"subject":               in.Subject,
		"subject_roles":         in.SubjectRoles,
		"subject_groups":        in.SubjectGroups,
		"target_id":             in.TargetID,
		"target_criticality":    in.TargetCriticality,
		"target_tags":           in.TargetTags,
		"target_protocol":       in.TargetProtocol,
		"requested_at":          in.RequestedAt.Unix(),
		"requested_hour":        in.RequestedAt.Hour(),
		"request_reason":        in.RequestReason,
		"recent_approval_count": in.RecentApprovalCount,
		"recent_denial_count":   in.RecentDenialCount,
	}
	rs, err := e.query.Eval(ctx, rego.EvalInput(regoInput))
	if err != nil {
		return Output{}, fmt.Errorf("riskscore: opa eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Output{}, errors.New("riskscore: opa query returned no result")
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Output{}, fmt.Errorf("riskscore: opa query returned %T, expected object", rs[0].Expressions[0].Value)
	}
	out := Output{
		Decision:      RequireHuman, // safe default if module omits the field
		PolicyVersion: "opa-unspecified",
	}
	if v, ok := m["decision"].(string); ok {
		switch Decision(v) {
		case AutoApprove, RequireHuman, AutoDeny:
			out.Decision = Decision(v)
		default:
			return Output{}, fmt.Errorf("riskscore: opa returned unknown decision %q", v)
		}
	}
	if v, ok := m["reason"].(string); ok {
		out.Reason = v
	}
	// Numbers from Rego v1 may surface as float64, int, int64, or
	// json.Number depending on the OPA pipeline. Handle each cleanly
	// — a stale type assertion would silently zero the TTL.
	if secs := numericFromAny(m["grant_ttl_seconds"]); secs > 0 {
		out.GrantTTL = time.Duration(secs) * time.Second
	}
	if v, ok := m["policy_version"].(string); ok && v != "" {
		out.PolicyVersion = v
	}
	return out, nil
}
