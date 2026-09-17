// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5f-9 — RDP probe-sweep monitor.
//
// Periodic background tick (5min default) runs the same probe sweep
// the admin /rdp-probe/sweep endpoint exposes. Updates Prometheus
// metrics (jess_rdp_*) and emits a structured audit Event on every
// per-target transition reachable ↔ failed (not on every sustained
// failure — that would spam the audit log).
//
// Mirrors cmd/jess-controller/chain_monitor.go pattern exactly:
// initial-run-at-boot, then 5min ticker, hard timeout per call so a
// stuck probe can't pile up goroutines. Same cadence as chain
// monitor + requests-expirer — keeps the controller's background
// goroutine surface uniform.

import (
	"context"
	"log"
	"time"

	"github.com/dogukanturhal/jess/internal/admin"
	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/metrics"
)

const rdpSweepInterval = 5 * time.Minute

// rdpSweeper is the narrow surface the monitor needs from the admin
// handler — keeps the goroutine de-coupled from the full handler.
type rdpSweeper interface {
	RunRDPSweep(ctx context.Context) (admin.SweepResponse, error)
}

func runRDPSweepMonitor(s rdpSweeper, m *metrics.Metrics, sink audit.Sink) {
	prev := map[string]bool{} // last-known reachability per target_id
	doRDPSweep(s, m, sink, prev)
	t := time.NewTicker(rdpSweepInterval)
	defer t.Stop()
	for range t.C {
		doRDPSweep(s, m, sink, prev)
	}
}

func doRDPSweep(s rdpSweeper, m *metrics.Metrics, sink audit.Sink, prev map[string]bool) {
	// Hard cap = sweep's own ceiling + small buffer. Catalogs of <80
	// targets stay well under this even if every probe times out
	// (8 concurrent * 5s = 5s per round; 80 targets = 10 rounds = 50s).
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := s.RunRDPSweep(ctx)
	if err != nil {
		log.Printf("rdp-sweep-monitor: %v", err)
		// Don't fudge metrics on backend error — last-known values stay.
		// Operational alert path is jess_up / pg_connect_errors_total.
		return
	}
	perTarget := make(map[string]bool, len(rep.Results))
	for _, r := range rep.Results {
		ok := r.Probe.Reachable && r.Probe.FailureCode == 0
		perTarget[r.TargetID] = ok
	}
	m.RDPSweepResult(rep.Reachable, rep.Failed, rep.Total, float64(rep.ElapsedMs)/1000.0, perTarget)

	// Transition-aware audit: emit only when a target FLIPS state
	// (reachable→failed OR failed→reachable). Sustained state is
	// captured by Prometheus; the audit log carries the moments
	// that matter for incident reconstruction.
	if sink != nil {
		for id, ok := range perTarget {
			wasOK, seen := prev[id]
			if !seen {
				// First sight — only audit if it's already failed
				// (operator should know they came up with broken targets).
				if !ok {
					_ = sink.Emit(context.Background(), audit.Event{
						Time:     time.Now(),
						Action:   "rdp.target.unreachable",
						Subject:  "system:rdp-sweep-monitor",
						TargetID: id,
						Err:      reasonOf(rep, id),
					})
				}
				continue
			}
			if wasOK != ok {
				action := "rdp.target.recovered"
				if !ok {
					action = "rdp.target.unreachable"
				}
				_ = sink.Emit(context.Background(), audit.Event{
					Time:     time.Now(),
					Action:   action,
					Subject:  "system:rdp-sweep-monitor",
					TargetID: id,
					Err:      reasonOf(rep, id),
				})
			}
		}
		// Drop entries from prev for targets that have left the catalog.
		for id := range prev {
			if _, stillThere := perTarget[id]; !stillThere {
				delete(prev, id)
			}
		}
	}
	// Update prev AFTER emitting transitions.
	for id, ok := range perTarget {
		prev[id] = ok
	}

	if rep.Failed > 0 {
		log.Printf("rdp-sweep-monitor: %d/%d reachable in %dms; failures: %s",
			rep.Reachable, rep.Total, rep.ElapsedMs, joinFailedIDs(rep))
	}
}

// reasonOf returns a compact human description of a target's most
// recent probe outcome, for inclusion in audit Event.Err.
func reasonOf(rep admin.SweepResponse, id string) string {
	for _, r := range rep.Results {
		if r.TargetID != id {
			continue
		}
		switch {
		case !r.Probe.Reachable && r.Probe.Error != "":
			return "unreachable: " + r.Probe.Error
		case r.Probe.FailureCode != 0:
			return r.Probe.FailureReason
		case r.Probe.Reachable:
			return "reachable: " + r.Probe.NegotiatedProto
		}
	}
	return ""
}

func joinFailedIDs(rep admin.SweepResponse) string {
	var b []byte
	first := true
	for _, r := range rep.Results {
		if r.Probe.Reachable && r.Probe.FailureCode == 0 {
			continue
		}
		if !first {
			b = append(b, ',')
		}
		b = append(b, r.TargetID...)
		first = false
	}
	return string(b)
}
