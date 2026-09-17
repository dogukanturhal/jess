// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5h-4a — wire the rules-based risk-score evaluator into the
// admin requests handler. Adapter pattern: the admin package
// intentionally has its own narrow interfaces (Evaluator, TargetLookup,
// AuditEmitter, RiskMetricsEmitter) so it doesn't import internal/riskscore
// or internal/catalog directly. cmd/jess-controller constructs the
// adapter glue here.
//
// Auto-approval is OPT-IN via JESS_RISK_AUTO_APPROVAL=true. Default off
// so existing clusters don't change behaviour at deploy. When enabled,
// every Submit() runs through the rules-v1 evaluator.

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/dogukanturhal/jess/internal/admin"
	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/metrics"
	"github.com/dogukanturhal/jess/internal/riskscore"
)

// catalogAdapter satisfies admin.TargetLookup by deferring to the
// catalog.Catalog already wired on the controller.
type catalogAdapter struct {
	cat catalog.Catalog
}

func (c catalogAdapter) Lookup(ctx context.Context, id string) (admin.TargetSummary, error) {
	t, err := c.cat.Lookup(ctx, id)
	if err != nil {
		return admin.TargetSummary{}, err
	}
	return admin.TargetSummary{
		ID:          t.ID,
		Criticality: t.Criticality,
		Tags:        t.Tags,
		Protocol:    string(t.Protocol),
	}, nil
}

// riskEvalAdapter wraps a riskscore.Evaluator as an admin.Evaluator.
// Both shapes carry the same data; the adapter only re-keys.
type riskEvalAdapter struct {
	inner riskscore.Evaluator
}

func (a riskEvalAdapter) Evaluate(ctx context.Context, in admin.EvalInput) (admin.EvalOutput, error) {
	out, err := a.inner.Evaluate(ctx, riskscore.Input{
		Subject:             in.Subject,
		SubjectRoles:        in.SubjectRoles,
		SubjectGroups:       in.SubjectGroups,
		TargetID:            in.TargetID,
		TargetCriticality:   in.TargetCriticality,
		TargetTags:          in.TargetTags,
		TargetProtocol:      in.TargetProtocol,
		RequestedAt:         in.RequestedAt,
		RequestReason:       in.RequestReason,
		RecentApprovalCount: in.RecentApprovalCount,
		RecentDenialCount:   in.RecentDenialCount,
	})
	if err != nil {
		return admin.EvalOutput{}, err
	}
	return admin.EvalOutput{
		Decision:      string(out.Decision),
		Reason:        out.Reason,
		GrantTTL:      out.GrantTTL,
		PolicyVersion: out.PolicyVersion,
	}, nil
}

// auditAdapter satisfies admin.AuditEmitter by emitting through the
// existing audit.Sink with action="approve.auto" — distinct from
// "approve" so the audit log differentiates auto from human decisions.
type auditAdapter struct {
	sink audit.Sink
}

func (a auditAdapter) EmitApproveAuto(ctx context.Context, requestID, subject, targetID, reason, policyVersion string) {
	if a.sink == nil {
		return
	}
	_ = a.sink.Emit(ctx, audit.Event{
		Time:     time.Now(),
		Action:   "approve.auto",
		Subject:  "system:risk-score-" + policyVersion,
		TargetID: targetID,
		Err:      "auto-approved request " + requestID + " for " + subject + ": " + reason,
	})
}

// metricsAdapter satisfies admin.RiskMetricsEmitter.
type metricsAdapter struct {
	m *metrics.Metrics
}

func (a metricsAdapter) RequestAutoDecision(decision string) {
	a.m.RequestAutoDecision(decision)
}

// maybeWireRiskScore checks the env flag and returns the four adapter
// instances on success. Returns nil if disabled — the caller leaves
// the requests handler at its pre-5h-4a (every request require human)
// behaviour.
//
// Backend selection (Phase 5h-4b):
//   - JESS_RISK_OPA_POLICY_FILE non-empty → load Rego module from path,
//     compile at startup. Malformed module fail-fast at boot.
//   - Otherwise → fall back to the built-in DefaultRulesEvaluator
//     (rules-v1). Same semantics, no external dependency.
//
// The Evaluator interface is identical across both; the admin handler
// is unaware which backend it's using.
func maybeWireRiskScore(cat catalog.Catalog, sink audit.Sink, m *metrics.Metrics) (
	admin.Evaluator, admin.TargetLookup, admin.AuditEmitter, admin.RiskMetricsEmitter, bool,
) {
	if os.Getenv("JESS_RISK_AUTO_APPROVAL") != "true" {
		return nil, nil, nil, nil, false
	}
	var eval riskscore.Evaluator = riskscore.NewDefaultRules()
	if path := os.Getenv("JESS_RISK_OPA_POLICY_FILE"); path != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		opa, err := riskscore.LoadOPAEvaluator(ctx, path)
		if err != nil {
			// Fail-fast at startup: a malformed policy file in
			// production would silently fall back to default rules
			// otherwise — and operators authoring policy expect
			// authoring errors to surface immediately.
			log.Fatalf("jess-controller: risk-score OPA policy load failed: %v", err)
		}
		if opa != nil {
			eval = opa
			log.Printf("jess-controller: risk-score auto-approval ENABLED (OPA bundle from %s)", path)
		} else {
			log.Printf("jess-controller: JESS_RISK_OPA_POLICY_FILE pointed at empty file; falling back to rules-v1")
		}
	} else {
		log.Printf("jess-controller: risk-score auto-approval ENABLED (rules-v1; set JESS_RISK_OPA_POLICY_FILE to load an OPA bundle)")
	}
	return riskEvalAdapter{inner: eval},
		catalogAdapter{cat: cat},
		auditAdapter{sink: sink},
		metricsAdapter{m: m},
		true
}
