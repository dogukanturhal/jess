// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5e-18 — cross-session WORM chain integrity monitor.
//
// Periodic background tick (5min default) calls SessionStore.VerifyChain;
// on break, emits a structured audit Event AND updates Prometheus
// so the SRE alert fires within minutes of any tampering.
//
// Why a background tick and not "verify on every read":
//   - VerifyChain is O(N) on every row — fine at hundreds-thousands
//     but pointless on every HTTP request.
//   - Tampering is rare; a 5min window is well within SOC 2 detection
//     SLAs (24h is the typical bar; 5min is two orders of magnitude
//     better).
//   - Decouples cost from request rate — load spikes don't amplify
//     verify cost.

import (
	"context"
	"log"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/metrics"
)

// chainMonitorInterval is the verify cadence. 5min picked to match the
// requests-expirer cadence — same goroutine pattern, same operational
// expectation (background work, not user-facing).
const chainMonitorInterval = 5 * time.Minute

func runChainMonitor(verifier jit.ChainVerifier, m *metrics.Metrics, sink audit.Sink) {
	// Initial verify at startup so jess_chain_intact reflects reality
	// from minute 1 instead of sitting at -1 (unverified) for 5min.
	doChainVerify(verifier, m, sink)
	t := time.NewTicker(chainMonitorInterval)
	defer t.Stop()
	for range t.C {
		doChainVerify(verifier, m, sink)
	}
}

func doChainVerify(verifier jit.ChainVerifier, m *metrics.Metrics, sink audit.Sink) {
	// Hard cap per-verify wall time so a frozen DB connection doesn't
	// pile up goroutines. The verify itself is bound by the store's
	// own query timeout, but we belt-and-brace at 30s.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := verifier.VerifyChain(ctx)
	if err != nil {
		log.Printf("chain-monitor: verify failed: %v", err)
		// Do NOT set chain_intact on error — the previous value stays.
		// "DB unreachable" is operational, not a tampering signal;
		// jess_up / jess_pg_connect_errors_total covers that path.
		return
	}
	m.ChainVerifyResult(rep.OK, rep.Total, len(rep.Breaks))
	if rep.OK {
		// Quiet on the happy path — operators don't need a "still
		// fine" line every 5min in the controller log. Prometheus
		// has the timeseries if anyone wants to chart it.
		return
	}
	// BREAK detected — log + audit + (Prometheus already bumped above).
	log.Printf("chain-monitor: ALERT — %d break(s) across %d session rows; first: session=%s reason=%s",
		len(rep.Breaks), rep.Total, firstSession(rep), firstReason(rep))
	if sink != nil {
		// Stamp one audit event per break (capped at 10 in the report
		// payload so a runaway tamper doesn't write a million events).
		// Each event lives in the same tamper-evident chain Talon /
		// Falcon-ID use, so even the alert itself is anchored.
		for i, b := range rep.Breaks {
			if i >= 10 {
				break
			}
			_ = sink.Emit(context.Background(), audit.Event{
				Time:    time.Now(),
				Action:  "chain.break",
				Subject: "system:chain-monitor",
				Err:     b.Reason + " on session " + b.SessionID,
			})
		}
	}
}

func firstSession(rep jit.ChainReport) string {
	if len(rep.Breaks) == 0 {
		return ""
	}
	return rep.Breaks[0].SessionID
}

func firstReason(rep jit.ChainReport) string {
	if len(rep.Breaks) == 0 {
		return ""
	}
	return rep.Breaks[0].Reason
}
