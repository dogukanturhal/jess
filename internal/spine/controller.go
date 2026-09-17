// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spine wires the Jess control plane (Controller) and data-plane worker
// runtime (WorkerRuntime) together over the reverse-tunnel fabric — the Phase 5a
// "spine": controller + worker + yamux/SPIFFE tunnel + raw-TCP brokering + JIT
// gate + audit. SSH/DB brokering (5b/5c) and jess-web rendering (5e) plug in as
// additional worker behavior; the spine here is protocol-agnostic plumbing.
package spine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/devicepolicy"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/metrics"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/stepup"
	"github.com/dogukanturhal/jess/internal/tunnel"
	"github.com/dogukanturhal/jess/internal/wire"
)

// Controller is the Jess control plane: it VERIFIES the operator's Falcon-ID
// token (subject + roles come only from the verified token), authorizes via the
// PDP (role-based) + the JIT grant gate, then opens a session into an
// outbound-connected worker and bridges the operator to it.
type Controller struct {
	Pool     *tunnel.YamuxPool
	Cat      catalog.Catalog
	JIT      jit.GrantStore
	PDP      pdp.Authorizer
	Verifier pdp.TokenVerifier // verifies the operator's Falcon-ID token
	Audit    audit.Sink
	Metrics  *metrics.Metrics // optional (nil-safe)

	// Sessions is the per-session persistence log (Phase 5e-6). Optional
	// — when nil, the controller still works but no session rows are
	// persisted (dev-mode w/o postgres). When non-nil, every successful
	// Pool.Open is followed by Sessions.OpenSession; bridge teardown
	// (graceful close OR grant revocation OR worker err) calls
	// Sessions.CloseSession with a structured reason. Failures here are
	// LOGGED but do NOT fail-close the session — observability shouldn't
	// gate the broker's hot path.
	Sessions jit.SessionStore

	// Locks is the Phase 5j-1 admin kill primitive. When non-nil, every
	// session-open consults IsLockedAny(subject, target) before grant
	// validation; matched sessions never open and the operator sees a
	// deny reason of `locked_<axis>: <reason>`. The continuous grant
	// watcher (Phase 5g-6) also calls IsLockedAny each tick so lock
	// drops kill live sessions within the watcher interval (default 10s).
	// Nil = locks disabled (lock store wiring at the controller startup
	// type-asserts and only sets this when the GrantStore implements
	// jit.LockStore — PostgresStore + MemoryBroker both do).
	Locks jit.LockStore

	// RecordingOverrides is the per-target admin recording-override store.
	// When non-nil, session-open resolves the EFFECTIVE recorded value
	// (override-if-present, else the catalog target's static `recorded`
	// default) and propagates it to the worker via SessionHeader.Recorded
	// so the admin's runtime toggle is authoritative end-to-end. Nil = no
	// override store wired (dev / custom GrantStore that doesn't implement
	// jit.RecordingOverrideStore) — the controller + worker fall back to
	// the catalog default unconditionally, exactly as before. Read-only on
	// the hot path; the admin handler is the only writer.
	RecordingOverrides jit.RecordingOverrideStore

	// ControllerID is the pod identity persisted into jit_sessions.controller_id
	// so cross-controller analytics ("which pod brokered this session?")
	// is possible. Defaults to "" — typically wired to HOSTNAME by main.
	ControllerID string

	// AdminAutoGrantRole is the role that bypasses the JIT request/grant
	// workflow when an OperatorRequest arrives without a grant_id. When
	// the verified caller holds this role, the controller auto-mints a
	// short-lived self-approved grant inline (no approver round-trip).
	//
	// What admin-direct-connect IS:
	//   - bypass of the approval queue ("admin doesn't ask permission
	//     for routine break-glass / on-call work")
	//
	// What it is NOT:
	//   - bypass of audit / recording — every admin session still goes
	//     through OpenSession → SetRecordingPath → bridge → CloseSession,
	//     same as any operator session
	//   - bypass of RBAC — Target.RequiredRoles still gates which
	//     targets the admin can reach
	//   - bypass of revocation — the auto-minted grant has a TTL and
	//     can be revoked via the admin port like any other grant
	//
	// Empty string disables the feature: every connect needs a pre-
	// existing grant_id, no exceptions. Production deploys typically
	// set this to "platform_admin" via env JESS_ADMIN_DIRECT_CONNECT_ROLE.
	AdminAutoGrantRole string

	// AdminAutoGrantTTL bounds the auto-grant lifetime (default 1h if
	// zero). Match this to your tier-1 admin-session ceiling.
	AdminAutoGrantTTL time.Duration

	// AdminAutoGrantRequireAMR lists OIDC amr (RFC 8176) values that
	// satisfy the step-up gate for admin-direct-connect. The verified
	// token's amr claim must contain AT LEAST ONE entry from this list,
	// otherwise the connect is denied with reason "step_up_required"
	// and the operator must re-authenticate with MFA before retrying.
	//
	// Default (when nil OR empty): NO admin-direct-connect — the role
	// check alone isn't enough; configure this list explicitly. Tier-1
	// production should set ["mfa","otp","totp","hwk","webauthn"].
	//
	// What this prevents: a stolen long-lived session cookie that
	// happens to carry the platform_admin role can't open new sessions
	// without re-asserting strong auth. The auth bar is RAISED for
	// admin-direct-connect, NOT lowered.
	AdminAutoGrantRequireAMR []string

	// AdminAutoGrantPhishingResistantOnly forces the require-amr gate
	// to reject any AMR value that doesn't meet NIST SP 800-63B-4
	// §3.2.5 (Final, 2025-07-31) phishing-resistant criteria — only
	// channel binding (PIV / CAC) and verifier name binding (WebAuthn
	// / FIDO2) qualify; OTP / TOTP / generic "mfa" are denied. The env
	// + AMR-list filter at jess-controller startup already drops
	// non-PR values from AdminAutoGrantRequireAMR when this is set,
	// but the runtime gate enforces the same rule per-request so a
	// future token-introspection path that adds an OTP-only AMR
	// can't slip past.
	//
	// Empty (default): the literal AdminAutoGrantRequireAMR list is
	// the gate, no per-request PR filter.
	AdminAutoGrantPhishingResistantOnly bool

	// DefaultStepUpPolicy is the fleet-wide per-session MFA step-up floor
	// (ADR 0037, P2.5) applied to any target whose own RequireSessionMFA is
	// empty/none. Empty (default) = no global floor: only targets that set
	// RequireSessionMFA are gated. Wired from JESS_STEP_UP_DEFAULT_POLICY. A
	// target's explicit tier always wins over this default (a target may not be
	// weakened below the floor — a stronger explicit tier is honoured; an
	// explicit "none" is treated as unset and thus takes the floor).
	DefaultStepUpPolicy stepup.Policy

	// SessionIdleTimeout bounds the per-session inactivity window for
	// the AAL3 inactivity-timeout enforcement (gap audit #6 — NIST SP
	// 800-63B-4 §AAL3 inactivity SHOULD ≤15 minutes). Zero or
	// negative disables the check entirely. Worker must implement
	// jit.SessionActivityStore for this to take effect (MemoryBroker
	// + PostgresStore both do); MemoryBroker tests stay deterministic
	// because the worker only touches when a real byte transfer
	// happens.
	SessionIdleTimeout time.Duration

	// draining is the gap audit #12 graceful-shutdown flag. When set
	// via Drain(), handleOperator denies new session-opens with
	// reason="draining" while watchGrant + idle-timeout + lock-check
	// continue running for IN-FLIGHT sessions. Used by SIGTERM
	// handler in cmd/jess-controller to allow a pod bounce without
	// dropping live sessions: kill new opens immediately, let
	// existing sessions reach their own close on their own terms.
	draining atomic.Bool
}

// Drain flips the controller into drain mode (gap audit #12 — Boundary
// + Teleport pattern). New session-opens are denied with a clear
// reason; in-flight sessions are unaffected. Idempotent.
func (c *Controller) Drain() {
	c.draining.Store(true)
}

// IsDraining reports whether the controller is in drain mode.
func (c *Controller) IsDraining() bool {
	return c.draining.Load()
}

// adminAutoGrantTTL returns the configured TTL with a 1h default.
func (c *Controller) adminAutoGrantTTL() time.Duration {
	if c.AdminAutoGrantTTL > 0 {
		return c.AdminAutoGrantTTL
	}
	return time.Hour
}

// AdminAutoGrantTTLOrDefault is the exported variant for boot-log
// printing — same semantics as adminAutoGrantTTL but accessible
// outside the package.
func (c *Controller) AdminAutoGrantTTLOrDefault() time.Duration {
	return c.adminAutoGrantTTL()
}

// sessionIdleTimeout returns the configured AAL3 inactivity ceiling.
// Zero/negative disables the check.
func (c *Controller) sessionIdleTimeout() time.Duration {
	if c.SessionIdleTimeout > 0 {
		return c.SessionIdleTimeout
	}
	return 0
}

// satisfiesStepUp reports whether the verified token's amr claim
// contains at least one of the required strong-auth methods. Empty
// required list means the gate is DISABLED — return false so callers
// fail closed when not explicitly configured. RFC 8176 standard amr
// values include: mfa, otp, totp, hwk (hardware key), pwd, pin,
// webauthn (vendor-specific but common).
//
// When phishingResistantOnly is true (gap audit #3 — NIST SP 800-63B-4
// §3.2.5), the function additionally requires that the MATCHED AMR
// value is itself phishing-resistant — only `hwk`, `webauthn`, `piv`,
// `cac` qualify. A token whose only matches are `mfa` / `otp` / `totp`
// returns false even if those strings appear in requiredAny.
func satisfiesStepUp(tokenAMR, requiredAny []string, phishingResistantOnly bool) bool {
	if len(requiredAny) == 0 {
		return false // fail closed: gate must be explicitly configured
	}
	have := make(map[string]struct{}, len(tokenAMR))
	for _, a := range tokenAMR {
		have[a] = struct{}{}
	}
	for _, want := range requiredAny {
		if _, ok := have[want]; !ok {
			continue
		}
		if phishingResistantOnly && !isPhishingResistantAMRValue(want) {
			continue
		}
		return true
	}
	return false
}

// isPhishingResistantAMRValue delegates to the canonical NIST SP 800-63B-4
// §3.2.5 allowlist in internal/stepup so the admin-direct gate and the
// per-session step-up gate share ONE source of truth (P2.5).
func isPhishingResistantAMRValue(amr string) bool {
	return stepup.IsPhishingResistant(amr)
}

// stepUpWatch is the per-session MFA step-up assertion captured at session-open
// so the continuous grant-watch can re-evaluate its freshness each tick (P2.5).
// nil when the target's tier is none.
type stepUpWatch struct {
	amr      []string
	authTime time.Time
	policy   stepup.Policy
	maxAge   time.Duration
}

// stale reports whether the step-up assertion has aged out of the tier's
// freshness window at `now`. A nil / none watch is never stale.
func (w *stepUpWatch) stale(now time.Time) (bool, string) {
	if w == nil || w.policy == stepup.PolicyNone {
		return false, ""
	}
	ok, reason := stepup.Satisfied(w.amr, w.authTime, now, w.maxAge, w.policy)
	return !ok, reason
}

// resolveStepUp resolves the effective per-session step-up tier + freshness
// window for a target: the target's explicit RequireSessionMFA, or the
// controller's DefaultStepUpPolicy floor when the target leaves it unset/none.
// Returns an error on an unparseable target tier so the caller fails closed.
func (c *Controller) resolveStepUp(target *catalog.Target) (stepup.Policy, time.Duration, error) {
	pol, err := stepup.Parse(target.RequireSessionMFA)
	if err != nil {
		return stepup.PolicyNone, 0, err
	}
	if pol == stepup.PolicyNone && c.DefaultStepUpPolicy != "" && c.DefaultStepUpPolicy != stepup.PolicyNone {
		pol = c.DefaultStepUpPolicy
	}
	return pol, pol.EffectiveMaxAge(target.StepUpTTLSeconds), nil
}

// ServeWorkers runs the worker-facing accept loop (mTLS listener l; idFn derives
// the worker identity from the TLS peer cert / SPIFFE ID).
func (c *Controller) ServeWorkers(l net.Listener, idFn func(net.Conn) (string, error)) error {
	return c.Pool.ServeWorkers(l, idFn)
}

// ServeOperators runs the operator-facing accept loop.
func (c *Controller) ServeOperators(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go c.handleOperator(conn)
	}
}

func (c *Controller) handleOperator(conn net.Conn) {
	defer conn.Close()
	ctx := context.Background()

	// Phase 5g-5 SLO: stamp the session-open attempt with wall-time +
	// terminal outcome. The result is mutated as the control flow
	// traverses each gate (authn → authz → jit → pool → ok).
	openStarted := time.Now()
	openResult := "ok"
	defer func() {
		c.Metrics.SessionOpenDuration(time.Since(openStarted))
		c.Metrics.SessionOpenOutcome(openResult)
	}()

	// Gap audit #12: drain mode. New session-opens denied early so
	// SIGTERM-initiated controller bounces don't drop in-flight
	// sessions. Pre-decode so even malformed requests during drain
	// get the "draining" outcome label.
	if c.IsDraining() {
		openResult = "draining"
		return
	}

	dec := json.NewDecoder(conn)
	var req wire.OperatorRequest
	if err := dec.Decode(&req); err != nil {
		openResult = "authn" // decode failure = malformed request; same SLO bucket as token-rejected
		return
	}

	// 1. AUTHENTICATE: the identity comes ONLY from the verified token.
	// Phase 5h-5: if the verifier exposes DeviceClaimsVerifier, also
	// pull the device-posture claim subset alongside Identity so the
	// per-target RequireDeviceClaims wall can evaluate.
	var ident pdp.Identity
	var deviceClaims map[string]string
	var stepUpClaims pdp.StepUpClaims
	var err error
	switch v := c.Verifier.(type) {
	case pdp.SessionClaimsVerifier:
		// P2.5: single verify yields device-posture AND step-up freshness claims.
		ident, deviceClaims, stepUpClaims, err = v.VerifySession(ctx, req.Token)
	case pdp.DeviceClaimsVerifier:
		ident, deviceClaims, err = v.VerifyDevice(ctx, req.Token)
	default:
		ident, err = c.Verifier.Verify(ctx, req.Token)
	}
	if err != nil {
		openResult = "authn"
		c.deny(ctx, audit.Event{Action: "deny", TargetID: req.TargetID, Err: "token: " + err.Error()})
		return
	}

	// Phase 5j-1 lock gate — admin kill primitive. Runs BEFORE target
	// lookup so a subject-lock doesn't reveal target existence in the
	// deny message. Target-axis is also checked here against the raw
	// req.TargetID (operator-supplied) — if that's also locked the
	// caller learns "locked" but not "target valid". A non-nil Locks
	// store wired at controller startup is the opt-in; nil = legacy
	// behaviour (no lock check, pre-Phase-5j-1).
	if c.Locks != nil {
		if locked, reason, lerr := c.Locks.IsLockedAny(ctx, ident.Subject, req.TargetID); lerr != nil {
			// Storage failure on the hot path: fail-OPEN (don't lock out
			// every operator if Postgres blips). Audit + log loudly so
			// SRE notices. Mirrors the CRLCache soft-fail posture from
			// Phase 4 full — security primitives that depend on external
			// state degrade open, never silently closed. The metric
			// makes the silent-bypass observable; alert on rate > 0.
			log.Printf("jess-controller: locks IsLockedAny error (fail-open): subject=%s target=%s err=%v", ident.Subject, req.TargetID, lerr)
			c.Metrics.JITLockCheckError("session_open")
		} else if locked {
			// Distinct outcome label so the SLO surface separates
			// admin-issued kills from policy-deny — operators expect
			// to see exactly which one denied them, and dashboards
			// expect to chart them independently.
			openResult = "locked"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: req.TargetID, Err: reason})
			return
		}
	}

	target, err := c.Cat.Lookup(ctx, req.TargetID)
	if err != nil {
		openResult = "authz" // catalog miss = caller asked for a target that doesn't exist; an authz-shape failure
		c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: req.TargetID, Err: err.Error()})
		return
	}

	// Resolve the EFFECTIVE recording decision: the per-target admin
	// recording override (runtime, controller DB) beats the catalog's
	// static `recorded` default (GitOps). This is the single resolution
	// point — both the controller's recording-path computation below AND
	// the worker (via SessionHeader.Recorded) honour this value, so the
	// admin's console toggle is authoritative end-to-end without a Git
	// round-trip. A store error fails OPEN to the catalog default (an
	// observability/override-store blip must not change the broker's
	// security posture in an unpredictable direction — the GitOps default
	// is the safe, declared baseline) and is logged loudly.
	effectiveRecorded := c.resolveEffectiveRecorded(ctx, target)

	// 2a. DEVICE POSTURE (Phase 5h-5): if the target carries a
	// RequireDeviceClaims policy, evaluate the operator's JWT
	// device claims against it. Missing claim FAILS CLOSED. Same
	// semantics as Talon's per-host gate so the operator sees the
	// identical wall on L4 and L7.
	if len(target.RequireDeviceClaims) > 0 {
		policy := make([]devicepolicy.Requirement, 0, len(target.RequireDeviceClaims))
		for _, r := range target.RequireDeviceClaims {
			policy = append(policy, devicepolicy.Requirement{
				Claim:       r.Claim,
				ValuesAnyOf: r.ValuesAnyOf,
			})
		}
		v := devicepolicy.Evaluate(devicepolicy.Claims(deviceClaims), policy)
		if !v.Allow {
			openResult = "authz"
			c.Metrics.SessionDeviceClaimDeny(v.Reason)
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region, Err: "device_posture: " + v.Reason})
			return
		}
	}

	// 2. AUTHORIZE (RBAC): identity roles must intersect the target's required roles.
	d, err := c.PDP.Authorize(ctx, pdp.Request{
		Identity: ident, TargetID: target.ID, Protocol: string(target.Protocol),
		Region: target.Region, RequiredRoles: target.RequiredRoles,
	})
	if err != nil || !d.Allow {
		reason := "authorization denied"
		if d.Reason != "" {
			reason = d.Reason
		}
		openResult = "authz"
		c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), Region: target.Region, Err: reason})
		return
	}

	// 3. JIT GATE: an active grant must exist AND belong to this operator.
	//
	// Admin direct-connect: when the operator holds AdminAutoGrantRole
	// AND no grant_id was supplied, the controller mints a self-approved
	// grant inline. This is the "admin doesn't wait for approval for
	// routine on-call / break-glass work" path. Audit + recording still
	// run end-to-end; only the request/approve queue is bypassed.
	var grant *jit.Grant
	if req.GrantID == "" && c.AdminAutoGrantRole != "" && ident.HasRole(c.AdminAutoGrantRole) {
		// Step-up gate: admin-direct-connect requires a strong-auth
		// assertion in the verified token's amr claim. A long-lived
		// session cookie with platform_admin alone is NOT enough;
		// the operator must have completed MFA / OTP / WebAuthn
		// recently (auth ladder raised, not lowered).
		if !satisfiesStepUp(ident.AMR, c.AdminAutoGrantRequireAMR, c.AdminAutoGrantPhishingResistantOnly) {
			openResult = "jit"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "step_up_required: admin-direct-connect needs MFA in token amr"})
			return
		}
		issuer, ok := c.JIT.(jit.GrantIssuer)
		if !ok {
			openResult = "jit"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "admin-direct-connect requested but grant store cannot issue (custom JIT impl)"})
			return
		}
		g, ierr := issuer.IssueGrant(ctx, ident.Subject, target.ID, c.adminAutoGrantTTL())
		if ierr != nil {
			openResult = "jit"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "admin-direct-connect mint: " + ierr.Error()})
			return
		}
		// Stamp the request's GrantID so downstream logging + session
		// row + worker SessionHeader all see the freshly-minted grant
		// as if the operator had supplied it.
		req.GrantID = g.ID
		grant = &g
		c.emit(ctx, audit.Event{Action: "authorize", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "admin-auto-grant " + g.ID})
	} else {
		g, err := c.JIT.AssertActiveID(ctx, req.GrantID, req.TargetID)
		if err != nil {
			openResult = "jit"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: err.Error()})
			return
		}
		if g.Subject != ident.Subject {
			openResult = "jit"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "grant does not belong to this operator"})
			return
		}
		grant = g
	}

	// 3b. PER-SESSION MFA STEP-UP (ADR 0037, P2.5). A sensitive target/tier
	// requires a FRESH phishing-resistant re-auth — not just the admin-direct
	// bypass's amr check. Evaluated here for EVERY grant path (admin-direct AND
	// regular), and re-evaluated continuously by watchGrant so a session whose
	// step-up ages out is torn down mid-flight. Composes with (never weakens)
	// the admin-direct amr gate above. Fail-closed: a misconfigured tier, a
	// missing auth_time, a stale assertion, or no acceptable factor all deny.
	stepPolicy, stepMaxAge, spErr := c.resolveStepUp(target)
	if spErr != nil {
		openResult = "step_up"
		c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "step_up_misconfigured: " + spErr.Error()})
		return
	}
	var suw *stepUpWatch
	if stepPolicy != stepup.PolicyNone {
		if ok, reason := stepup.Satisfied(ident.AMR, stepUpClaims.AuthTime, time.Now(), stepMaxAge, stepPolicy); !ok {
			openResult = "step_up"
			c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Err: "step_up_required: " + reason})
			return
		}
		suw = &stepUpWatch{amr: ident.AMR, authTime: stepUpClaims.AuthTime, policy: stepPolicy, maxAge: stepMaxAge}
	}

	workers := c.Pool.Workers()
	if len(workers) == 0 {
		openResult = "no_worker"
		c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Err: "no worker available"})
		return
	}
	// Phase 5e-6: persist the session row BEFORE Pool.Open so the row id
	// can be propagated to the worker (Phase 5e-7 wire change) and the
	// recording bundle key matches jit_sessions.id. Nil-safe: dev mode
	// w/o postgres skips. Failure is observed but does NOT fail-close —
	// the broker hot path can't be gated on observability storage.
	var sessionRowID, sessionRowHash string
	if c.Sessions != nil {
		if row, sErr := c.Sessions.OpenSession(ctx, ident.Subject, target.ID, req.GrantID, string(target.Protocol), c.ControllerID); sErr != nil {
			log.Printf("jess-controller: persist OpenSession failed: %v", sErr)
		} else {
			sessionRowID = row.ID
			// Phase 5e-20: propagate the chain link to the worker so
			// the recording bundle's manifest pins the chain position.
			// Empty when the store doesn't implement the chain.
			sessionRowHash = row.RowHash
		}
	}

	// Phase 5e-7: if the target is recorded, the bundle key is
	// deterministic from sessionRowID + protocol — controller can
	// populate jit_sessions.recording_path BEFORE the bridge starts
	// so the SPA can show the path even on a live (still-recording)
	// session. Per-protocol extension matches internal/recording/
	// bundle.go contentKey() conventions.
	if sessionRowID != "" && effectiveRecorded && c.Sessions != nil {
		if path := computeRecordingPath(sessionRowID, target.Protocol); path != "" {
			if rerr := c.Sessions.SetRecordingPath(ctx, sessionRowID, path); rerr != nil {
				log.Printf("jess-controller: SetRecordingPath failed: %v", rerr)
			}
		}
	}

	// 5a: pick the first worker. 5e/multi-region: pick by region + capability.
	// 5e-7: SessionID propagates the controller's jit_sessions.id so the
	// worker's recorder uses it for the bundle storage key.
	// Recorded propagates the controller-resolved EFFECTIVE recording
	// decision (override-or-default) so the worker honours the admin toggle
	// rather than its own static catalog flag.
	effRec := effectiveRecorded
	sess, err := c.Pool.Open(ctx, workers[0], tunnel.SessionHeader{
		TargetID:       target.ID,
		Protocol:       string(target.Protocol),
		GrantID:        req.GrantID,
		Subject:        ident.Subject,
		SessionID:      sessionRowID,
		SessionRowHash: sessionRowHash,
		Recorded:       &effRec,
	})
	if err != nil {
		openResult = "pool"
		c.deny(ctx, audit.Event{Action: "deny", Subject: ident.Subject, TargetID: target.ID, Err: err.Error()})
		// The session row was inserted before Pool.Open; mark it closed
		// with the dial failure reason so the SPA doesn't show a stuck
		// "active" row that never tore down.
		if sessionRowID != "" && c.Sessions != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = c.Sessions.CloseSession(closeCtx, sessionRowID, "pool_open_err")
		}
		return
	}
	defer sess.Close()

	c.Metrics.Allow()
	c.Metrics.SessionOpened()
	defer c.Metrics.SessionClosed()
	c.emit(ctx, audit.Event{Action: "open", Subject: ident.Subject, TargetID: target.ID, Protocol: string(target.Protocol), DecisionID: d.DecisionID, Region: target.Region})
	closeReason := "ok"
	defer func() {
		if sessionRowID == "" {
			return
		}
		// Use background ctx — the request ctx is likely cancelled by
		// this point (that's the whole reason the bridge tore down).
		// A 3s budget bounds the close write so a slow Postgres can't
		// stall the goroutine on shutdown.
		closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if cErr := c.Sessions.CloseSession(closeCtx, sessionRowID, closeReason); cErr != nil {
			log.Printf("jess-controller: persist CloseSession failed: %v", cErr)
		}
	}()

	// Continuous authorization (Phase 5g-6): the session is hard-capped at
	// the grant's expiry (zero-standing-privilege) and re-checked periodically
	// so a revoked grant kills the LIVE session, not just future ones.
	// Closing sess+conn unblocks the bridge copies below.
	//
	// revocationReason is set atomically by watchGrant when it detects the
	// grant has been revoked or expired upstream — read by the close-reason
	// refinement block after the bridge tears down. Without it, the close
	// reason was a guess based on (time.Now < ExpiresAt); now it's authoritative.
	sessCtx, sessCancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer sessCancel()
	revocationReason := &atomic.Pointer[string]{}
	go c.watchGrant(sessCtx, sessCancel, req.GrantID, req.TargetID, ident.Subject, target.ID, sessionRowID, revocationReason, suw)
	go func() {
		<-sessCtx.Done()
		_ = sess.Close()
		_ = conn.Close()
	}()

	// Bridge operator <-> worker session. dec.Buffered() carries any payload
	// bytes the JSON decoder read ahead, so we don't lose the start of stream.
	//
	// Phase 5e-10: countingWriter wrappers capture per-direction byte
	// totals so the SessionStore can persist them on close. Goroutines
	// touch the atomics, so reads at teardown see the final value
	// (synchronized by the channel rendezvous below).
	opReader := io.MultiReader(dec.Buffered(), conn)
	cwIn := &countingWriter{w: sess}  // operator → worker
	cwOut := &countingWriter{w: conn} // worker → operator
	// Gap audit #6: AAL3 inactivity touch. When the session-store
	// implements SessionActivityStore, wire the countingWriters to
	// call TouchSessionActivity on every byte transfer. The watcher
	// then enforces idle > policy in its tick loop. Throttled to
	// ≤ 1 touch / 5s so a chatty terminal doesn't hammer Postgres
	// — the AAL3 spec is minutes-grained, the 5s floor is more than
	// fine.
	if idleStore, ok := c.Sessions.(jit.SessionActivityStore); ok && c.SessionIdleTimeout > 0 && sessionRowID != "" {
		touch := newActivityToucher(idleStore, sessionRowID, 5*time.Second)
		cwIn.onWrite = touch
		cwOut.onWrite = touch
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(cwIn, opReader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(cwOut, sess); done <- struct{}{} }()
	<-done
	_ = sess.Close()
	_ = conn.Close()
	<-done

	// Refine the close reason after bridge teardown. Phase 5g-6: prefer
	// the authoritative reason from watchGrant (set on revocation/expiry
	// detection) over the time-based heuristic. Heuristic stays as the
	// fallback for the case where sessCtx was cancelled by some other path.
	if sessCtx.Err() != nil {
		if r := revocationReason.Load(); r != nil {
			closeReason = *r
		} else if time.Now().Before(grant.ExpiresAt) {
			closeReason = "grant_revoked"
		} else {
			closeReason = "grant_expired"
		}
	}
	// Phase 5e-10: persist final byte counts. Same nil-safe + log-on-fail
	// posture as CloseSession (observability storage can't gate the hot
	// path). Best-effort with a short ctx budget.
	if sessionRowID != "" && c.Sessions != nil {
		bytesCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if bErr := c.Sessions.RecordBytes(bytesCtx, sessionRowID, cwIn.n.Load(), cwOut.n.Load()); bErr != nil {
			log.Printf("jess-controller: persist RecordBytes failed: %v", bErr)
		}
	}
	c.emit(ctx, audit.Event{
		Action: "close", Subject: ident.Subject, TargetID: target.ID,
		Protocol: string(target.Protocol), DecisionID: d.DecisionID,
		Bytes: cwIn.n.Load() + cwOut.n.Load(),
	})
}

// countingWriter is a tiny io.Writer wrapper that counts bytes written.
// Used by handleOperator to capture per-direction totals on the bridge
// without changing the io.Copy semantics or perf characteristics. The
// counter is atomic so the close-time read is race-free vs. the bridge
// goroutine even if the rendezvous channel had a window where one
// goroutine kept writing post-signal (defence-in-depth; in practice
// the channel-receive blocks until the writer exits).
type countingWriter struct {
	w       io.Writer
	n       atomic.Int64
	onWrite func() // optional — fired on every non-empty write for activity tracking
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n.Add(int64(n))
		if c.onWrite != nil {
			c.onWrite()
		}
	}
	return n, err
}

// newActivityToucher returns a closure that calls
// SessionActivityStore.TouchSessionActivity at most once per
// throttle window. Throttling avoids hammering Postgres on chatty
// terminal output — the AAL3 inactivity ceiling is minutes-grained
// so a 5s floor is generous. The store call uses
// context.Background() with a 1s ceiling because the bridge hot
// path must not block on a slow DB write; a failed touch defers
// to the next tick.
func newActivityToucher(store jit.SessionActivityStore, sessionID string, throttle time.Duration) func() {
	var lastAt atomic.Int64
	return func() {
		now := time.Now().UnixNano()
		last := lastAt.Load()
		if last != 0 && time.Duration(now-last) < throttle {
			return
		}
		if !lastAt.CompareAndSwap(last, now) {
			return // lost the race; another writer just touched
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_ = store.TouchSessionActivity(ctx, sessionID)
		}()
	}
}

// resolveEffectiveRecorded returns the EFFECTIVE recording decision for a
// target: the per-target admin recording override (controller DB, runtime)
// if one exists, else the catalog target's static `recorded` default
// (GitOps). When no override store is wired (dev / a GrantStore that doesn't
// implement jit.RecordingOverrideStore) the catalog default is returned
// unchanged — zero behaviour change vs. pre-override.
//
// Fail-OPEN to the catalog default on a store error: an override-store blip
// must not silently change the broker's declared baseline posture in an
// unpredictable way. The error is logged loudly so SRE notices a degraded
// override store. (The catalog default is itself the safe, reviewed value.)
func (c *Controller) resolveEffectiveRecorded(ctx context.Context, target *catalog.Target) bool {
	if c.RecordingOverrides == nil {
		return target.Recorded
	}
	ov, found, err := c.RecordingOverrides.GetRecordingOverride(ctx, target.ID)
	if err != nil {
		log.Printf("jess-controller: recording-override lookup failed (fail-open to catalog default=%v): target=%s err=%v", target.Recorded, target.ID, err)
		return target.Recorded
	}
	return jit.EffectiveRecorded(target.Recorded, ov, found)
}

// computeRecordingPath returns the WORM bundle key the worker-side
// recorder will write to, given the persisted session id + protocol.
// The extension matches internal/recording/bundle.go contentKey() —
// asciicast for terminal SSH (the only recorded protocol today),
// drawing-format for future graphical (RDP/VNC). Empty string for
// unrecorded protocols (TCP/Postgres/MySQL).
//
// This MUST stay in sync with recording.ext() — the controller's
// computed path needs to equal the worker's actual storage key for
// the audit hand-off (operator/SOC follows the path in the SPA to
// the MinIO WORM bucket and finds the bundle there).
func computeRecordingPath(sessionID string, protocol catalog.Protocol) string {
	switch protocol {
	case catalog.ProtoSSH:
		return sessionID + "/recording.cast"
	default:
		// TCP / Postgres / MySQL are not recorded today. Future graphical
		// protocols (RDP/VNC — Phase 5f) would extend this switch.
		return ""
	}
}

// watchGrant re-checks the JIT grant on an interval and cancels the session
// if it is revoked or expired before the session-context deadline (the
// deadline itself is enforced by sessCtx). Builds toward CAEP/SSF push-based
// revocation (Phase 6).
//
// Phase 5g-6 hardening over the original 10s-tick-and-kill-on-any-error:
//
//  1. **Transient-error tolerance.** A single DB hiccup (network blip,
//     reconnect window, brief CNPG failover) used to terminate the session.
//     Now: distinguish ErrNoGrant / "not for target" / "expired" (kill
//     immediately) from arbitrary query errors (tolerate up to
//     maxTransientFailures consecutive). The latter still kills if the
//     DB stays unreachable for the full window — fail-closed is
//     non-negotiable — but a 1s glitch no longer drops live operator
//     sessions.
//
//  2. **Reason transmission.** Stores the authoritative reason (revoked
//     vs expired vs grant_check_failed) in the shared atomic the caller
//     reads after teardown. Replaces the (time.Now < ExpiresAt) heuristic
//     that was wrong by 1ns at the boundary.
//
//  3. **Audit emission.** When the watcher kills the session it emits an
//     audit.Event{Action:"revoke", Err:reason} so SOC + SOC 2 audit have
//     a record of WHY the operator's connection dropped (not just the
//     "close" event that fires regardless).
//
//  4. **Prometheus.** Bumps jess_session_revocations_total{reason=...}
//     so SRE can chart revocation rates and alert on anomalies.
//
//  5. **Configurable interval.** Reads JESS_GRANT_WATCH_INTERVAL_SECONDS
//     env at controller startup via Controller.grantWatchInterval();
//     default 10s. Set to 30s for low-criticality, 2s for tier-0
//     destructive targets.
func (c *Controller) watchGrant(ctx context.Context, cancel context.CancelFunc,
	grantID, targetID, subject, targetIDForAudit, sessionID string, reasonOut *atomic.Pointer[string], suw *stepUpWatch) {
	interval := c.grantWatchInterval()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	// Tolerate up to N consecutive transient query failures before
	// killing. With default interval=10s and N=3, a 30s PG outage during
	// failover doesn't drop the session.
	const maxTransientFailures = 3
	transientFailures := 0
	idleStore, _ := c.Sessions.(jit.SessionActivityStore)
	idleLimit := c.sessionIdleTimeout()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Phase 5j-1 lock re-check — runs alongside the grant
			// AssertActiveID call so a lock dropped between session-open
			// and now kills the session within the watcher interval
			// (default 10s). Fail-OPEN on storage error per the
			// session-open path (don't kill every session on a Postgres
			// blip; SRE sees the log).
			if c.Locks != nil {
				if locked, reason, lerr := c.Locks.IsLockedAny(ctx, subject, targetID); lerr != nil {
					log.Printf("jess-controller: grant-watch locks check error (fail-open): grant=%s err=%v", grantID, lerr)
					c.Metrics.JITLockCheckError("grant_watch")
				} else if locked {
					c.recordRevocation(ctx, reason, subject, targetIDForAudit, grantID, errors.New(reason))
					reasonOut.Store(&reason)
					cancel()
					return
				}
			}
			// P2.5: per-session MFA step-up freshness re-check (ADR 0037).
			// The token's step-up assertion was fresh at session-open; here
			// we re-evaluate it against the tier's max-age window each tick so
			// a session whose assertion ages out mid-flight is torn down
			// (continuous verification), forcing the operator to reconnect with
			// a fresh phishing-resistant re-auth. No state changes between ticks
			// (auth_time is fixed for the session), so this fires deterministically
			// once now-auth_time exceeds the window — that is the enforcement.
			if suw != nil {
				if stale, reason := suw.stale(time.Now()); stale {
					r := "step_up_expired"
					c.recordRevocation(ctx, r, subject, targetIDForAudit, grantID, errors.New(reason))
					reasonOut.Store(&r)
					cancel()
					return
				}
			}
			// Gap audit #6: AAL3 inactivity-timeout enforcement. NIST
			// SP 800-63B-4 §AAL3 inactivity SHOULD ≤15min. When
			// idleLimit > 0 AND the session-store implements
			// SessionActivityStore AND we have a sessionID,
			// SessionIdleFor reports how long since the worker last
			// emitted a byte-transfer touch. Idle > policy → kill
			// with reason="idle_timeout".
			if idleStore != nil && idleLimit > 0 && sessionID != "" {
				if idle, found, ierr := idleStore.SessionIdleFor(ctx, sessionID); ierr != nil {
					log.Printf("jess-controller: grant-watch idle check error (fail-open): session=%s err=%v", sessionID, ierr)
				} else if found && idle > idleLimit {
					reason := "idle_timeout"
					c.recordRevocation(ctx, reason, subject, targetIDForAudit, grantID, errors.New(reason))
					reasonOut.Store(&reason)
					cancel()
					return
				}
			}
			_, err := c.JIT.AssertActiveID(ctx, grantID, targetID)
			if err == nil {
				transientFailures = 0
				continue
			}
			// Permanent-revocation signals: kill immediately.
			reason, permanent := classifyGrantError(err)
			if permanent {
				c.recordRevocation(ctx, reason, subject, targetIDForAudit, grantID, err)
				reasonOut.Store(&reason)
				cancel()
				return
			}
			// Transient: log + count + tolerate up to N consecutive.
			transientFailures++
			log.Printf("jess-controller: grant-watch transient err %d/%d (grant=%s): %v",
				transientFailures, maxTransientFailures, grantID, err)
			if transientFailures >= maxTransientFailures {
				reason := "grant_check_failed"
				c.recordRevocation(ctx, reason, subject, targetIDForAudit, grantID, err)
				reasonOut.Store(&reason)
				cancel()
				return
			}
		}
	}
}

// classifyGrantError returns (close_reason, isPermanent). Permanent errors
// kill the session immediately; transient errors are tolerated up to N
// consecutive failures before kill.
//
// Today's classifier is conservative: ONLY recognises the explicit
// ErrNoGrant sentinel + the two error-string patterns AssertActiveID
// emits for "not for target" / "expired". Anything else falls through
// to transient so a PG outage doesn't masquerade as revocation.
//
// Future: when AssertActiveID grows typed errors (ErrGrantWrongTarget,
// ErrGrantExpired), switch to errors.Is checks. The string match is
// the bridge until then; tests guard against drift.
func classifyGrantError(err error) (reason string, permanent bool) {
	if errors.Is(err, jit.ErrNoGrant) {
		return "grant_revoked", true
	}
	msg := err.Error()
	if strings.Contains(msg, "is not for target") {
		// Caller is asserting against a grant that exists but belongs
		// to a different target — treat as revocation (operator can't
		// reuse a stale grant cross-target).
		return "grant_target_mismatch", true
	}
	if strings.Contains(msg, "expired") {
		return "grant_expired", true
	}
	return "", false
}

// recordRevocation emits the SOC-2-grade audit event + bumps Prometheus
// when the watcher kills a session. Called once per terminated session.
func (c *Controller) recordRevocation(ctx context.Context, reason, subject, targetID, grantID string, cause error) {
	c.Metrics.SessionRevoked(reason)
	if c.Audit != nil {
		_ = c.Audit.Emit(ctx, audit.Event{
			Action:   "revoke",
			Subject:  subject,
			TargetID: targetID,
			Err:      reason + ": " + cause.Error(),
		})
	}
	log.Printf("jess-controller: revocation killed live session grant=%s subject=%s target=%s reason=%s err=%v",
		grantID, subject, targetID, reason, cause)
}

// grantWatchInterval returns the watcher tick cadence. Reads
// JESS_GRANT_WATCH_INTERVAL_SECONDS env on first call (default 10s).
// Bounded to [1, 300] — tighter is operationally pointless (DB hammered)
// and longer than 5min defeats the continuous-verification goal.
func (c *Controller) grantWatchInterval() time.Duration {
	const defaultSec = 10
	v := os.Getenv("JESS_GRANT_WATCH_INTERVAL_SECONDS")
	if v == "" {
		return defaultSec * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 300 {
		return defaultSec * time.Second
	}
	return time.Duration(n) * time.Second
}

// deny records a denial in metrics + audit.
func (c *Controller) deny(ctx context.Context, ev audit.Event) {
	c.Metrics.Deny()
	c.emit(ctx, ev)
}

func (c *Controller) emit(ctx context.Context, ev audit.Event) {
	if c.Audit != nil {
		_ = c.Audit.Emit(ctx, ev)
	}
}
