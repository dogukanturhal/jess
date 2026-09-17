// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase E (auto-discovery program) — wiring for the JessPendingTarget
// reconciler. Discovery providers write candidates as JessPendingTarget
// CRs; the reconciler evaluates a Rego policy and promotes
// (→ JessTarget CR + deletes Pending) or rejects (→ status.rejected).
//
// Default: OFF. Enable via env so an unconfigured controller stays
// identical to the pre-Phase-E shape.
//
//   JESS_PENDING_RECONCILER_ENABLED=true
//   JESS_PENDING_REGO_FILE=/etc/jess/policy/discovery.rego
//
// Operators mount the Rego file from a ConfigMap; the default policy
// docs/policy/jess/discovery.rego implements the four allow-rules
// recommended by the deep-research synthesis (2026-06-06).

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/lifecycle/pending"
)

// startPendingReconciler returns a shutdown func. nil-safe: if the
// reconciler isn't enabled, returns a no-op.
func startPendingReconciler(sink audit.Sink) func() {
	if os.Getenv("JESS_PENDING_RECONCILER_ENABLED") != "true" {
		return func() {}
	}
	policyPath := os.Getenv("JESS_PENDING_REGO_FILE")
	if policyPath == "" {
		log.Fatal("jess-controller: JESS_PENDING_RECONCILER_ENABLED=true requires JESS_PENDING_REGO_FILE (path to Rego policy)")
	}
	module, err := pending.LoadRegoModule(policyPath)
	if err != nil {
		log.Fatalf("jess-controller: %v", err)
	}
	client, err := pending.NewInCluster()
	if err != nil {
		log.Fatalf("jess-controller: pending reconciler in-cluster client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	resync := 5 * time.Minute
	if d, ok := tryDuration(os.Getenv("JESS_PENDING_RESYNC")); ok && d > 0 {
		resync = d
	}
	r, err := pending.New(ctx, pending.Config{
		Client:         client,
		RegoModule:     module,
		ResyncInterval: resync,
		Audit:          pendingAuditBridge{sink: sink},
	})
	if err != nil {
		cancel()
		log.Fatalf("jess-controller: pending reconciler init: %v", err)
	}
	go func() {
		if err := r.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("jess-controller: pending reconciler exited: %v", err)
		}
	}()
	log.Printf("jess-controller: JessPendingTarget reconciler ENABLED (policy=%s, resync=%s)", policyPath, resync)
	return cancel
}

func tryDuration(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}

// pendingAuditBridge maps the reconciler's DiscoveryEvent into the
// existing audit.Sink. Action shape mirrors catalogAudit:
//
//	discovery.<phase>  — promoted | rejected | etc.
type pendingAuditBridge struct {
	sink audit.Sink
}

func (a pendingAuditBridge) EmitDiscoveryEvent(ctx context.Context, providerName, phase, targetID, reason string) {
	if a.sink == nil {
		return
	}
	_ = a.sink.Emit(ctx, audit.Event{
		Time:     time.Now(),
		Action:   "discovery." + phase,
		Subject:  "system:pending-reconciler",
		TargetID: targetID,
		Err:      "provider=" + providerName + " reason=" + reason,
	})
}
