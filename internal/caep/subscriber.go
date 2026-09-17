// SPDX-License-Identifier: AGPL-3.0-or-later

// Package caep is the jess-side Continuous Access Evaluation Profile
// receiver. Subscribes to Falcon-ID's CAE SSE stream at
// /api/v1/cae/events and, on relevant events (session_revoked,
// password_changed, mfa_revoked, role_revoked,
// credential_compromised), invokes the configured Revoker to
// terminate every active grant held by the affected subject.
//
// This closes the gap between IdP-side revocation and jess-side
// session liveness. Pre-5h-6 a subject whose password was rotated
// (or whose admin role was removed) kept active brokered sessions
// until the next 10s continuous-grant-watch tick OR until the
// session token expired (default 1h). With CAEP, propagation drops
// to ~1 second (network + SSE flush + revoke SQL).
//
// Wire shape:
//
//	falcon-id /api/v1/cae/events (SSE)
//	  ↓  Bearer <svctoken> (Phase 5+ Falcon-ID JWT)
//	  ↓
//	jess-controller [Subscriber.Run]
//	  ↓  parse "event: cae" / "data: <json>" frames
//	  ↓
//	handleEvent(CAEEvent)
//	  ↓  switch on Type → relevant subjects to revoke
//	  ↓
//	GrantRevoker.RevokeBySubject(ctx, sub)
//	  → 10s continuous-grant watch picks up expires_at=now() →
//	  → session bridge torn down with reason "grant_revoked"
//
// Falcon-ID side (already in production today):
//
//	internal/services/cae_service.go — publishes to
//	  "hexxlock:cae:events" (legacy) AND
//	  "caep:events:{tenant_id}" (tenant-scoped) Redis pub/sub.
//	internal/handlers/cae_handler.go — SSE handler at
//	  GET /api/v1/cae/events that fans the Redis pub/sub channel to
//	  bearer-authenticated subscribers.
//
// Reconnect: exponential backoff capped at 30s. Loses no audit
// trail; missed events on disconnect WILL leak through to the next
// 10s continuous-auth tick (the existing 5g-6 safety net), so this
// is a latency optimisation, not a correctness foundation.
package caep

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// GrantRevoker is the narrow interface this package needs from
// internal/jit (so caep doesn't import jit and vice versa — avoids
// dep cycles and keeps the wire shape testable).
type GrantRevoker interface {
	RevokeBySubject(ctx context.Context, subject string) (int, error)
}

// TokenSource mints a Bearer token for the SSE connection. Wired to
// the jess-controller's existing Falcon-ID svctoken sidecar via the
// file watcher pattern used for the credential exchange (talon!63).
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// MetricsSink reports received + acted-on events. Optional — nil
// disables.
type MetricsSink interface {
	CAEPEventReceived(eventType string)
	CAEPRevocation(eventType string, revokedCount int)
	CAEPReconnect()
	CAEPSubscribeFailure(reason string)
}

// AuditEmitter writes one audit row per actioned revocation so the
// SOC2 trail names CAEP as the trigger (vs the existing 5g-6 cron
// watch).
type AuditEmitter interface {
	EmitCAEPRevoke(ctx context.Context, eventType, subject string, revokedCount int)
}

// Subscriber is the long-lived SSE client. Run blocks until ctx is
// cancelled; reconnect loop is internal.
type Subscriber struct {
	EndpointURL string        // e.g. https://id.hexxlock.com/api/v1/cae/events
	Token       TokenSource   // Bearer source — refreshed per connect attempt
	HTTPClient  *http.Client  // optional; defaults to http.DefaultClient with 0 timeout
	Revoker     GrantRevoker  // jit.PostgresStore in production
	Metrics     MetricsSink   // optional
	Audit       AuditEmitter  // optional
	Backoff     time.Duration // initial reconnect backoff; default 1s. Capped at 30s exponential.
	Logger      *log.Logger   // optional

	// ExpectedIssuer is the iss value declared in the SSF Stream
	// Configuration (SSF 1.0 §4.1.6 — published 2025-08-29). When set,
	// every incoming SET MUST carry an `iss` claim matching this
	// EXACTLY; any SET with a missing OR mismatched iss is dropped as
	// anti-spoofing (a spoofed SET cannot bypass the check by simply
	// omitting iss). Empty disables the check — but the controller now
	// REQUIRES this to be set by default and only leaves it empty under
	// the explicit JESS_CAEP_ALLOW_ANY_ISSUER=1 dev/legacy opt-out
	// (see cmd/jess-controller/main.go). Production sets it to the
	// Falcon-ID OIDC issuer URL.
	ExpectedIssuer string
}

// caeEvent mirrors falcon-id/internal/services/cae_service.go::CAEEvent.
// Kept narrow — we only read the fields jess acts on. CAEP 1.0 Final
// (published 2025-08-29) added an `iss` field on the wire-level SET
// envelope which receivers MUST validate against the
// Stream Configuration per SSF 1.0 §4.1.6.
type caeEvent struct {
	Type      string            `json:"type"`
	UserID    string            `json:"user_id"`
	TenantID  string            `json:"tenant_id"`
	Timestamp time.Time         `json:"timestamp"`
	Iss       string            `json:"iss,omitempty"` // CAEP 1.0 + SSF 1.0 §4.1.6
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Event types we ACT on. CAEP 1.0 Final (2025-08-29) added
// `session-established` + `session-presented` as inventory signals
// (we log + emit metric but do not revoke). RISC vocabulary events
// (account-disabled, identifier-changed, account-purged) ALSO act
// like session_revoked — they indicate the IdP-side identity is
// no longer trustworthy. ip_changed remains receive-only (no
// IP-binding posture gate).
//
// Gap audit #5 — gap closed: jess receiver now handles the CAEP 1.0
// Final event-type universe + the RISC vocabulary.
var actionableTypes = map[string]struct{}{
	// CAEP 0.x baseline (original Falcon-ID wire shape).
	"session_revoked":        {},
	"password_changed":       {},
	"mfa_revoked":            {},
	"role_revoked":           {},
	"credential_compromised": {},
	// RISC vocabulary — same hard-revoke semantics; identity is gone.
	"account-disabled":   {},
	"identifier-changed": {},
	"account-purged":     {},
}

// inventoryTypes are CAEP 1.0 Final event types that the receiver
// logs + emits a metric for but does NOT terminate sessions on. They
// represent session-inventory signals (a new login was established at
// the IdP; an existing session was presented to a resource server).
// Used for visibility into IdP-side session state, not for revocation.
var inventoryTypes = map[string]struct{}{
	"session-established": {},
	"session-presented":   {},
}

// Run blocks until ctx is cancelled. On every disconnect (network
// blip, Falcon-ID restart, deploy-time pod rotation), reconnects
// after exponential backoff. No state is preserved across reconnect
// — every CAE event is independent; missed events are caught by the
// 5g-6 continuous-grant-watch at the next 10s tick.
func (s *Subscriber) Run(ctx context.Context) {
	if s.Backoff <= 0 {
		s.Backoff = time.Second
	}
	if s.HTTPClient == nil {
		s.HTTPClient = http.DefaultClient
	}
	backoff := s.Backoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := s.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		s.log("caep: subscriber disconnected: %v; reconnecting in %s", err, backoff)
		if s.Metrics != nil {
			s.Metrics.CAEPReconnect()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// connectOnce mints a token, opens the SSE stream, and pumps events
// until the stream closes or the context cancels. Returns the
// disconnection cause to drive reconnect logging.
func (s *Subscriber) connectOnce(ctx context.Context) error {
	tok, err := s.Token.Token(ctx)
	if err != nil {
		if s.Metrics != nil {
			s.Metrics.CAEPSubscribeFailure("token_mint")
		}
		return fmt.Errorf("token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", s.EndpointURL, nil)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		if s.Metrics != nil {
			s.Metrics.CAEPSubscribeFailure("dial")
		}
		return fmt.Errorf("dial: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if s.Metrics != nil {
			s.Metrics.CAEPSubscribeFailure(fmt.Sprintf("http_%d", resp.StatusCode))
		}
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	s.log("caep: connected to %s", s.EndpointURL)
	return s.pump(ctx, resp.Body)
}

// pump reads SSE frames off the stream. SSE frames are blank-line-
// delimited; within a frame, lines starting "data: " carry the JSON
// payload (single-line per Falcon-ID's emitter). We tolerate but
// ignore "event:", "id:", "retry:" lines for forward-compat.
func (s *Subscriber) pump(ctx context.Context, body io.Reader) error {
	scanner := bufio.NewScanner(body)
	// Bumped buffer cap — default 64KiB is tight for stuffed-metadata
	// events (e.g. credential_compromised carries the full WebAuthn
	// authenticator chain).
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		var evt caeEvent
		if err := json.Unmarshal([]byte(payload), &evt); err != nil {
			s.log("caep: bad event payload: %v (raw=%q)", err, payload)
			continue
		}
		s.handleEvent(ctx, evt)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("stream closed")
}

// handleEvent applies one CAE event. Non-actionable types log + metric
// only. Actionable types call Revoker.RevokeBySubject — fail-closed
// posture: a revoke error logs but does NOT swallow the trigger (we
// still emit the audit event so the SOC2 trail records the attempt).
//
// Gap audit #5 / ASVS L2 V10: SSF 1.0 Final §4.1.6 — receivers MUST
// validate that the SET's `iss` matches the iss in the Stream
// Configuration. When ExpectedIssuer is non-empty, an event whose `iss`
// is MISSING or does not match is dropped with a warning log. The prior
// `evt.Iss != ""` guard was an anti-spoof HOLE: a forged SET that simply
// omitted iss bypassed validation entirely and could drive a revocation
// (or, for an inventory event, pollute session state). Empty
// ExpectedIssuer skips the check — only reachable under the controller's
// explicit JESS_CAEP_ALLOW_ANY_ISSUER=1 dev/legacy opt-out.
func (s *Subscriber) handleEvent(ctx context.Context, evt caeEvent) {
	if s.Metrics != nil {
		s.Metrics.CAEPEventReceived(evt.Type)
	}
	if s.ExpectedIssuer != "" && evt.Iss != s.ExpectedIssuer {
		s.log("caep: SSF iss validation FAILED (anti-spoof) — expected=%q got=%q type=%s; dropping", s.ExpectedIssuer, evt.Iss, evt.Type)
		return
	}
	if _, inv := inventoryTypes[evt.Type]; inv {
		// CAEP 1.0 Final inventory signal — log + metric only,
		// don't terminate. Useful for "operator just signed in
		// somewhere else" visibility.
		s.log("caep: inventory event type=%s user=%s (no action; CAEP 1.0 Final inventory signal)", evt.Type, evt.UserID)
		return
	}
	if _, action := actionableTypes[evt.Type]; !action {
		s.log("caep: ignored event type=%s user=%s (not actionable)", evt.Type, evt.UserID)
		return
	}
	// The IdP-side iam_users.id is the canonical subject — same field
	// the JWT `sub` claim carries — so this is a direct match against
	// jit_grants.subject.
	if evt.UserID == "" {
		s.log("caep: actionable event with empty user_id, skipping: type=%s", evt.Type)
		return
	}
	revokeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := s.Revoker.RevokeBySubject(revokeCtx, evt.UserID)
	if err != nil {
		s.log("caep: revoke failed type=%s user=%s err=%v", evt.Type, evt.UserID, err)
		// Fall through — still emit metric + audit so the trail records
		// the attempt; the 10s continuous-auth tick is the safety net.
	}
	if s.Metrics != nil {
		s.Metrics.CAEPRevocation(evt.Type, n)
	}
	if s.Audit != nil {
		s.Audit.EmitCAEPRevoke(ctx, evt.Type, evt.UserID, n)
	}
	s.log("caep: revoked %d grants type=%s user=%s", n, evt.Type, evt.UserID)
}

func (s *Subscriber) log(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}
