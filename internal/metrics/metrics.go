// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics exposes Jess control-plane Prometheus metrics on a private
// registry (not the global default, so tests stay isolated). All methods are
// nil-safe, so a Controller with no Metrics simply records nothing.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the controller collectors.
type Metrics struct {
	reg            *prometheus.Registry
	authz          *prometheus.CounterVec
	sessionsOpened prometheus.Counter
	sessionsActive prometheus.Gauge
	// Phase 5e-18 — cross-session WORM chain monitor.
	chainBreaks prometheus.Counter
	chainIntact prometheus.Gauge // 1 when latest verify returned ok=true; 0 otherwise; -1 unverified
	chainTotal  prometheus.Gauge // total rows observed on most recent verify (operational visibility)
	// Phase 5f-9 — RDP probe-sweep monitor.
	rdpReachable       prometheus.Gauge
	rdpFailed          prometheus.Gauge
	rdpTotal           prometheus.Gauge
	rdpSweepDuration   prometheus.Gauge     // most recent sweep wall time in seconds (Gauge not Histogram — sweep cadence is 5min so one sample/5min, histograms add noise)
	rdpTargetReachable *prometheus.GaugeVec // labeled by target_id; 1=reachable, 0=failed
	// Phase 5g-5 — session-open SLO surface.
	sessionOpenOutcome  *prometheus.CounterVec // labels: result = ok|authn|authz|jit|no_worker|pool
	sessionOpenDuration prometheus.Histogram   // wall time from request decode to bridge-ready, in seconds
	// Phase 5g-6 — continuous grant verification kill counter.
	sessionRevocations *prometheus.CounterVec // labels: reason = grant_revoked|grant_expired|grant_target_mismatch|grant_check_failed
	// Phase 5h-4a — risk-score auto-approval outcomes.
	requestAutoDecisions *prometheus.CounterVec // labels: decision = auto_approve|require_human|auto_deny
	// Phase 5h-5 — device-posture wall denials at session-open.
	sessionDeviceClaimDenies *prometheus.CounterVec // labels: reason = device_claim_missing:<key>|device_claim_mismatch:<key>=<got>
	// Phase 5h-6 — CAEP subscriber telemetry.
	caepEventsReceived    *prometheus.CounterVec // labels: type = session_revoked|password_changed|mfa_revoked|role_revoked|credential_compromised|ip_changed|account_locked|...
	caepGrantsRevoked     *prometheus.CounterVec // labels: type = same; value = count of grants terminated per event
	caepReconnects        prometheus.Counter
	caepSubscribeFailures *prometheus.CounterVec // labels: reason = token_mint|dial|http_<code>
	// Phase 4 full — operator-cert CRL enforcement.
	operatorCertRevocationChecks *prometheus.CounterVec // labels: result = accepted|revoked|no_chain
	operatorCertCRLRefreshes     *prometheus.CounterVec // labels: result = success|failure
	operatorCertCRLLastRefresh   prometheus.Gauge       // unix seconds of last successful fetch
	operatorCertCRLRevokedCount  prometheus.Gauge       // size of revoked-set on last successful fetch
	// Phase 5j-1 — admin lock primitive (ADR 0034 #4+#7).
	jitLocksInserted   *prometheus.CounterVec // labels: target_type, mode = inserted|replaced
	jitLocksRemoved    prometheus.Counter
	jitLocksExpired    prometheus.Counter
	jitLocksActive     *prometheus.GaugeVec   // labels: target_type — snapshot from the 5-min poller
	jitLockCheckErrors *prometheus.CounterVec // labels: surface = session_open|grant_watch
}

// New builds and registers the collectors on a fresh registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		authz: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_authz_decisions_total",
			Help: "Authorization decisions made by the controller (PDP + JIT gate).",
		}, []string{"result"}),
		sessionsOpened: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "jess_sessions_opened_total",
			Help: "Total brokered sessions opened.",
		}),
		sessionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_sessions_active",
			Help: "Currently active brokered sessions.",
		}),
		chainBreaks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "jess_chain_breaks_total",
			Help: "Cross-session WORM chain breaks detected (Phase 5e-18). Increments by len(report.breaks) on every observed broken verify — alert on rate>0.",
		}),
		chainIntact: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_chain_intact",
			Help: "1 when latest VerifyChain returned ok=true; 0 when ok=false; -1 when no verify has run yet (Phase 5e-18). Page on jess_chain_intact == 0.",
		}),
		chainTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_chain_total_rows",
			Help: "Total session rows observed on the most recent VerifyChain (Phase 5e-18). Operational visibility for chain growth.",
		}),
		rdpReachable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_rdp_targets_reachable",
			Help: "Count of RDP catalog targets that responded to the most recent sweep with a valid Connection Confirm (Phase 5f-9).",
		}),
		rdpFailed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_rdp_targets_failed",
			Help: "Count of RDP catalog targets that did NOT respond to the most recent sweep (Phase 5f-9). Alert on > 0.",
		}),
		rdpTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_rdp_targets_total",
			Help: "Total RDP-protocol entries in the catalog observed on the most recent sweep (Phase 5f-9).",
		}),
		rdpSweepDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_rdp_sweep_last_duration_seconds",
			Help: "Wall-time of the most recent RDP probe sweep in seconds (Phase 5f-9). Sweep is bounded at ceil(targets/8) * 5s; sustained values near the ceiling indicate target/network degradation.",
		}),
		rdpTargetReachable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jess_rdp_target_reachable",
			Help: "Per-target RDP reachability on the most recent sweep (Phase 5f-9): 1 = Connection Confirm + valid negotiation, 0 = failure of any kind. Labeled by catalog target_id.",
		}, []string{"target_id"}),
		sessionOpenOutcome: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_session_open_outcome_total",
			Help: "Session-open attempts by outcome (Phase 5g-5 SLO). result ∈ {ok, authn, authz, jit, no_worker, pool, locked}. SLO success = ok / total. `locked` (Phase 5j-1) is distinct from `authz` so dashboards can chart admin-issued kills separately from policy denies.",
		}, []string{"result"}),
		requestAutoDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_request_auto_decisions_total",
			Help: "JIT request submissions classified by the risk-score evaluator (Phase 5h-4a). decision ∈ {auto_approve, require_human, auto_deny}. SOC 2 evidence + capacity-planning signal: auto_approve trends correlate with admin queue load (more auto = less human work).",
		}, []string{"decision"}),
		sessionDeviceClaimDenies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_session_device_claim_denies_total",
			Help: "Session-open attempts denied by the device-posture wall (Phase 5h-5). reason mirrors devicepolicy.Verdict.Reason — device_claim_missing:<key> or device_claim_mismatch:<key>=<got>. Spike on device_claim_missing rate indicates Falcon-ID broken claim emission OR operator JWTs minted before posture rollout; spike on mismatch indicates non-compliant devices attempting access.",
		}, []string{"reason"}),
		caepEventsReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_caep_events_received_total",
			Help: "CAE events received from Falcon-ID's SSE stream (Phase 5h-6). Labeled by type (session_revoked, password_changed, mfa_revoked, role_revoked, credential_compromised, ip_changed, account_locked). Sustained 0 with high jess_caep_reconnects_total = subscriber failing to consume; alert.",
		}, []string{"type"}),
		caepGrantsRevoked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_caep_grants_revoked_total",
			Help: "Grants terminated by the CAEP subscriber (Phase 5h-6). value = count per event so sum() over time = total revocation propagation through this channel. Compare against jess_session_revocations_total{reason=grant_revoked} to see how many were caught by CAEP vs by the 10s continuous-grant tick.",
		}, []string{"type"}),
		caepReconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "jess_caep_reconnects_total",
			Help: "CAEP SSE subscriber reconnect attempts (Phase 5h-6). Steady-state low/zero; spike correlates with falcon-id deploy / network partition. Watch alongside jess_caep_subscribe_failures_total.",
		}),
		caepSubscribeFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_caep_subscribe_failures_total",
			Help: "CAEP SSE connect attempts that failed (Phase 5h-6). reason = token_mint (svctoken refresh broken) | dial (network) | http_<code> (Falcon-ID rejected). Persistent token_mint or http_401 = svctoken pipeline broken; alert.",
		}, []string{"reason"}),
		sessionRevocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_session_revocations_total",
			Help: "Live sessions killed by the continuous grant verifier (Phase 5g-6). reason ∈ {grant_revoked, grant_expired, grant_target_mismatch, grant_check_failed}. Alert on rate > 0 — operators don't see these unless something rotated underneath them. grant_check_failed specifically tracks tolerance-exceeded transient errors; rate > 0 there indicates DB/network degradation, not security event.",
		}, []string{"reason"}),
		operatorCertRevocationChecks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_operator_cert_revocation_checks_total",
			Help: "Operator client cert revocation checks at the operator-port + admin-port mTLS layer (Phase 4 full). result ∈ {accepted, revoked, no_chain}. accepted = cert valid + not in CRL; revoked = cert serial found on CRL (handshake rejected); no_chain = dev-mode plaintext path (TLS chain wasn't built). Alert on revoked > 0 — every revoke MUST be intentional.",
		}, []string{"result"}),
		operatorCertCRLRefreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_operator_cert_crl_refreshes_total",
			Help: "CRL fetch attempts (Phase 4 full). result ∈ {success, failure}. Sustained failure > 1 refresh interval = Vault PKI unreachable; controller still accepts pre-cached revocations but new ones won't propagate. Page on (failure rate × 100 / success rate) > 25%.",
		}, []string{"result"}),
		operatorCertCRLLastRefresh: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_operator_cert_crl_last_refresh_timestamp_seconds",
			Help: "Unix seconds of the last successful CRL fetch (Phase 4 full). 0 when never fetched. Combine with time() to compute staleness; alert on staleness > 3 × refresh_interval.",
		}),
		operatorCertCRLRevokedCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "jess_operator_cert_crl_revoked_count",
			Help: "Number of revoked operator-cert serials on the last successful CRL fetch (Phase 4 full). Operational signal — sudden jump = mass revocation event (e.g. compromised operator), should correlate with audit log.",
		}),
		jitLocksInserted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_jit_locks_inserted_total",
			Help: "Admin locks created via POST /locks (Phase 5j-1, ADR 0034 #4+#7). target_type ∈ {subject, target, cert_serial, mfa_device}; mode ∈ {inserted, replaced} — inserted = brand-new lock on (target_type, target_value), replaced = upsert overwrote an existing lock. Sustained nonzero rate on `replaced` for the same target_type may indicate operator UX confusion or a kill-script in a tight loop; correlate with the controller audit log.",
		}, []string{"target_type", "mode"}),
		jitLocksRemoved: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "jess_jit_locks_removed_total",
			Help: "Admin locks deleted via DELETE /locks/{id} (Phase 5j-1). Idempotent — counts every request, not just ones that found a row. Compared against jess_jit_locks_inserted_total gives net active growth.",
		}),
		jitLocksExpired: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "jess_jit_locks_expired_total",
			Help: "Past-expiry lock rows garbage-collected by the controller's 5-min expirer goroutine (Phase 5j-1). High value is fine; sustained zero with a growing jit_locks table indicates the expirer goroutine has stalled.",
		}),
		jitLocksActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "jess_jit_locks_active",
			Help: "Currently-active locks per target_type (Phase 5j-1). Snapshot refreshed by the controller every 5 min on the same cadence as the expirer. Operational view (\"how many admin-issued kills are in effect right now\"). Sustained jess_jit_locks_active{target_type=\"subject\"} > 0 for >24h is worth a non-paging awareness alert: someone got locked out and was never let back in.",
		}, []string{"target_type"}),
		jitLockCheckErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "jess_jit_lock_check_errors_total",
			Help: "Lock-store IsLockedAny calls that errored at runtime (Phase 5j-1). surface ∈ {session_open, grant_watch} — session_open = the pre-catalog gate in spine.handleOperator; grant_watch = the continuous re-check in the per-grant watcher tick. The controller fails OPEN on these (don't lock out every operator on a Postgres blip per the CRLCache pattern) — so a sustained rate > 0 means kills are silently bypassed. Page on rate > 0 for 5m.",
		}, []string{"surface"}),
		sessionOpenDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "jess_session_open_duration_seconds",
			Help: "Wall time from operator request decode to bridge-ready (or deny) in seconds (Phase 5g-5 SLO). Buckets sized for the 99.9% / 2s p99 SLO budget.",
			// Bucket boundaries straddle the 2s p99 target (5g-5 SLO)
			// and the controller's 5s per-stage timeouts. Le=+Inf
			// implicit. Auth + JIT + catalog lookups should land
			// well under 100ms; the 2-5s tail is the worker dial.
			Buckets: []float64{0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}),
	}
	// chain_intact starts at -1 so monitoring can distinguish 'never
	// verified' (controller just booted) from 'verified intact'. Alert
	// rules should ignore -1 — only page on 0 (genuine break).
	m.chainIntact.Set(-1)
	reg.MustRegister(
		m.authz, m.sessionsOpened, m.sessionsActive,
		m.chainBreaks, m.chainIntact, m.chainTotal,
		m.rdpReachable, m.rdpFailed, m.rdpTotal, m.rdpSweepDuration, m.rdpTargetReachable,
		m.sessionOpenOutcome, m.sessionOpenDuration,
		m.sessionRevocations,
		m.requestAutoDecisions,
		m.sessionDeviceClaimDenies,
		m.caepEventsReceived,
		m.caepGrantsRevoked,
		m.caepReconnects,
		m.caepSubscribeFailures,
		m.operatorCertRevocationChecks,
		m.operatorCertCRLRefreshes,
		m.operatorCertCRLLastRefresh,
		m.operatorCertCRLRevokedCount,
		m.jitLocksInserted,
		m.jitLocksRemoved,
		m.jitLocksExpired,
		m.jitLocksActive,
		m.jitLockCheckErrors,
	)
	return m
}

// RequestAutoDecision records one risk-score evaluator outcome
// (Phase 5h-4a). Called by the admin requests handler after
// Evaluate() returns. Includes require_human (the no-op case) so a
// sudden drop in auto-approval rate is observable.
func (m *Metrics) RequestAutoDecision(decision string) {
	if m == nil {
		return
	}
	m.requestAutoDecisions.WithLabelValues(decision).Inc()
}

// CAEPEventReceived records one CAE event received from Falcon-ID
// (Phase 5h-6). Counted on every parsed event, actionable or not.
func (m *Metrics) CAEPEventReceived(eventType string) {
	if m == nil {
		return
	}
	m.caepEventsReceived.WithLabelValues(eventType).Inc()
}

// CAEPRevocation records one set of grants terminated by the CAEP
// subscriber. n is the number of jit_grants rows affected; the
// counter is bumped by n (not by 1) so sum() over time = total
// grants revoked through this channel.
func (m *Metrics) CAEPRevocation(eventType string, n int) {
	if m == nil {
		return
	}
	if n <= 0 {
		return
	}
	m.caepGrantsRevoked.WithLabelValues(eventType).Add(float64(n))
}

// CAEPReconnect records one CAEP-subscriber reconnect attempt.
func (m *Metrics) CAEPReconnect() {
	if m == nil {
		return
	}
	m.caepReconnects.Inc()
}

// CAEPSubscribeFailure records one CAEP connect failure by category.
func (m *Metrics) CAEPSubscribeFailure(reason string) {
	if m == nil {
		return
	}
	m.caepSubscribeFailures.WithLabelValues(reason).Inc()
}

// SessionDeviceClaimDeny records one session-open denial by the
// Phase 5h-5 device-posture wall. Called inline in the controller
// after Evaluate() returns Allow=false.
func (m *Metrics) SessionDeviceClaimDeny(reason string) {
	if m == nil {
		return
	}
	m.sessionDeviceClaimDenies.WithLabelValues(reason).Inc()
}

// SessionRevoked records one continuous-grant-verifier kill (Phase 5g-6).
// Called from spine.Controller.recordRevocation when the watcher terminates
// a live session.
func (m *Metrics) SessionRevoked(reason string) {
	if m == nil {
		return
	}
	m.sessionRevocations.WithLabelValues(reason).Inc()
}

// SessionOpenOutcome records one session-open attempt by outcome label.
// Phase 5g-5 SLO surface. Called from spine.Controller.handleOperator
// on every terminal path (success OR each deny layer).
func (m *Metrics) SessionOpenOutcome(result string) {
	if m == nil {
		return
	}
	m.sessionOpenOutcome.WithLabelValues(result).Inc()
}

// SessionOpenDuration observes the wall-time of one session-open
// attempt. Phase 5g-5 SLO surface — paired with SessionOpenOutcome
// so the SLO can be expressed as "p99 ok-latency < 2s AND error
// ratio < 0.1%".
func (m *Metrics) SessionOpenDuration(d time.Duration) {
	if m == nil {
		return
	}
	m.sessionOpenDuration.Observe(d.Seconds())
}

// ChainVerifyResult records the outcome of one VerifyChain run.
// Called by the chain monitor goroutine on each tick.
func (m *Metrics) ChainVerifyResult(ok bool, total int, breakCount int) {
	if m == nil {
		return
	}
	if ok {
		m.chainIntact.Set(1)
	} else {
		m.chainIntact.Set(0)
	}
	m.chainTotal.Set(float64(total))
	if breakCount > 0 {
		m.chainBreaks.Add(float64(breakCount))
	}
}

// RDPSweepResult records the outcome of one probe-sweep run.
// Phase 5f-9. perTarget is a map[target_id]reachable so the monitor
// can both update the GaugeVec AND clean up labels for targets that
// have left the catalog (otherwise stale rows accumulate forever).
func (m *Metrics) RDPSweepResult(reachable, failed, total int, durationSec float64, perTarget map[string]bool) {
	if m == nil {
		return
	}
	m.rdpReachable.Set(float64(reachable))
	m.rdpFailed.Set(float64(failed))
	m.rdpTotal.Set(float64(total))
	m.rdpSweepDuration.Set(durationSec)
	// Reset the per-target gauge to drop labels for any target that's
	// no longer in the catalog. Then re-publish the current state.
	m.rdpTargetReachable.Reset()
	for id, ok := range perTarget {
		v := 0.0
		if ok {
			v = 1.0
		}
		m.rdpTargetReachable.WithLabelValues(id).Set(v)
	}
}

// Allow records an allowed authorization decision.
func (m *Metrics) Allow() {
	if m != nil {
		m.authz.WithLabelValues("allow").Inc()
	}
}

// Deny records a denied authorization decision.
func (m *Metrics) Deny() {
	if m != nil {
		m.authz.WithLabelValues("deny").Inc()
	}
}

// SessionOpened records a session start.
func (m *Metrics) SessionOpened() {
	if m != nil {
		m.sessionsOpened.Inc()
		m.sessionsActive.Inc()
	}
}

// SessionClosed records a session end.
func (m *Metrics) SessionClosed() {
	if m != nil {
		m.sessionsActive.Dec()
	}
}

// RegisterWorkerGauge adds a gauge reporting the number of connected workers.
func (m *Metrics) RegisterWorkerGauge(f func() float64) {
	if m == nil {
		return
	}
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "jess_workers_connected",
		Help: "Workers currently connected to this controller.",
	}, f))
}

// OperatorCertRevocationCheck records one mTLS-layer revocation decision
// (Phase 4 full). Called by admin.CRLCache.VerifyPeerCertificate. result ∈
// {accepted, revoked, no_chain}. nil-safe.
func (m *Metrics) OperatorCertRevocationCheck(result string) {
	if m == nil {
		return
	}
	m.operatorCertRevocationChecks.WithLabelValues(result).Inc()
}

// OperatorCertCRLRefresh records one CRL fetch attempt (Phase 4 full). On
// success, also bumps the last-refresh timestamp gauge and the revoked-count
// gauge. nil-safe.
func (m *Metrics) OperatorCertCRLRefresh(success bool, revokedCount int) {
	if m == nil {
		return
	}
	if success {
		m.operatorCertCRLRefreshes.WithLabelValues("success").Inc()
		m.operatorCertCRLLastRefresh.SetToCurrentTime()
		m.operatorCertCRLRevokedCount.Set(float64(revokedCount))
		return
	}
	m.operatorCertCRLRefreshes.WithLabelValues("failure").Inc()
}

// JITLockInserted records one admin-lock insert/replace (Phase 5j-1).
// mode ∈ {inserted, replaced}; targetType is the LockTargetType string.
func (m *Metrics) JITLockInserted(targetType, mode string) {
	if m == nil {
		return
	}
	m.jitLocksInserted.WithLabelValues(targetType, mode).Inc()
}

// JITLockRemoved records one admin-lock delete (Phase 5j-1). DELETE is
// idempotent so every request counts, not just ones that found a row.
func (m *Metrics) JITLockRemoved() {
	if m == nil {
		return
	}
	m.jitLocksRemoved.Inc()
}

// JITLocksExpired records the count of past-expiry lock rows GC'd by
// the 5-min expirer goroutine (Phase 5j-1). Pass the return value of
// ExpireOldLocks. n<=0 is a no-op.
func (m *Metrics) JITLocksExpired(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.jitLocksExpired.Add(float64(n))
}

// JITLocksActive sets the per-target_type active-lock counts. Caller
// passes the FULL snapshot every call (the gauge resets first so
// target_types that disappear from the snapshot drop to zero). Wire
// from the controller's 5-min refresher; cheap because ListLocks is
// a single indexed SELECT.
func (m *Metrics) JITLocksActive(perType map[string]int) {
	if m == nil {
		return
	}
	m.jitLocksActive.Reset()
	for t, n := range perType {
		m.jitLocksActive.WithLabelValues(t).Set(float64(n))
	}
}

// JITLockCheckError records one IsLockedAny call that errored, by the
// hot-path surface that called it (Phase 5j-1). surface ∈
// {session_open, grant_watch}. Fail-OPEN behaviour is in effect, so
// each increment is a silent bypass — alert on rate > 0.
func (m *Metrics) JITLockCheckError(surface string) {
	if m == nil {
		return
	}
	m.jitLockCheckErrors.WithLabelValues(surface).Inc()
}

// Handler serves the metrics from this registry.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
