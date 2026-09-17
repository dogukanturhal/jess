// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"errors"
	"time"
)

// Session is one brokered operator session — the period between the
// controller accepting an OperatorRequest and the bridge tearing down
// (graceful close OR grant revocation OR worker error). ADR 0030
// Phase 5e-6 adds this persistence layer; pre-5e-6 the controller
// emitted only ephemeral audit events without a queryable session log.
//
// Lifecycle:
//
//	OpenSession  → INSERT row, EndedAt nil, CloseReason "" (active)
//	CloseSession → UPDATE row, set EndedAt + CloseReason
//
// What this enables:
//
//   - Operator self-service "recent sessions" view on jess-web (Phase
//     5e-6 SPA card).
//   - Admin audit queries ("who connected to node-app-01 last week?")
//     against a structured table rather than the loki/tempo event
//     funnel — the audit log is still authoritative for forensics,
//     this is the indexed projection for fast operational lookups.
//   - Foundation for recording-path lookup (Phase 5e-7+) by joining
//     session.id to the WORM bundle key.
//
// What this is NOT:
//
//   - Replacement for the audit Sink (which is tamper-evident hash-
//     chained). The audit log stays authoritative.
//   - Bytes counters / recording_path — both need protocol-handler
//     integration (worker-side; spine doesn't see them today).
//     Phase 5e-7 follow-ups.
type Session struct {
	ID            string
	Subject       string
	TargetID      string
	GrantID       string
	Protocol      string
	StartedAt     time.Time
	EndedAt       *time.Time // nil while active
	CloseReason   string     // "" while active; "ok" | "grant_revoked" | "operator_disconnect" | "worker_err" | …
	RecordingPath string     // empty until Phase 5e-7 wires it from the worker-side recorder
	ControllerID  string     // pod identity for cross-controller analytics; "" if unset

	// Bytes counters per direction, populated by spine.Controller via
	// SessionStore.RecordBytes on bridge teardown (Phase 5e-10).
	// BytesIn  = operator → worker (keystrokes, paste bursts)
	// BytesOut = worker → operator (terminal output, MySQL/PG result sets)
	BytesIn  int64
	BytesOut int64

	// LastActivityAt tracks the most recent byte-transfer event for
	// AAL3 inactivity-timeout enforcement (gap audit #6 — NIST SP
	// 800-63B-4 §AAL3 inactivity SHOULD ≤15min, overall reauth SHALL
	// ≤12h). Populated by the worker on every multiplexer flush via
	// SessionActivityStore.TouchSessionActivity; the grant-watcher
	// reads this on each tick and kills sessions idle > policy.
	//
	// Zero value (un-set) means "no activity tracked yet" — caller
	// treats as "no idle check" rather than "infinite idle". Stores
	// that don't implement SessionActivityStore leave this at zero
	// throughout the session lifecycle.
	LastActivityAt time.Time

	// Phase 5e-16: cross-session WORM audit chain. Each row carries
	// its own canonical hash (RowHash) + a pointer to the previous
	// row's hash (PrevRowHash). Together they form a Merkle-ish chain
	// across all sessions: mutating, deleting, inserting, or reordering
	// any row breaks the chain and surfaces in
	// /audit/chain/verify with a typed reason.
	//
	// RowHash is computed at OpenSession from canonical(row) (id,
	// subject, target_id, started_at, prev_row_hash) — see
	// jit.ComputeRowHash. Empty string in MemoryBroker; populated
	// in PostgresStore on insert.
	//
	// PrevRowHash is "" for the very first session row written to the
	// store (the chain's genesis). After that, every new row reads the
	// most-recent row's RowHash and pins it here.
	RowHash     string
	PrevRowHash string
}

// SessionStore is the durable per-session log used by:
//
//	spine/controller.go (write path: open/close + recording-path)
//	internal/admin/sessions.go (read path: admin + ?mine=true list)
//
// Implemented by MemoryBroker (dev/tests) and PostgresStore (prod).
// Optional for the controller — if Sessions is nil on the controller,
// the spine still works (no log written, no list endpoint visible).
type SessionStore interface {
	OpenSession(ctx context.Context, subject, targetID, grantID, protocol, controllerID string) (Session, error)
	CloseSession(ctx context.Context, sessionID, reason string) error
	ListSessions(ctx context.Context, subject string, limit int) ([]Session, error)
	GetSession(ctx context.Context, sessionID string) (Session, error)

	// SetRecordingPath — Phase 5e-7. Called by the controller right
	// after a session opens, once it knows whether the target is
	// recorded (catalog.Target.Recorded + protocol determines the
	// bundle file extension). Idempotent: a second call with the
	// same path is a no-op; a call on an unknown id is a no-op +
	// nil error (same teardown-race posture as CloseSession).
	SetRecordingPath(ctx context.Context, sessionID, path string) error

	// RecordBytes — Phase 5e-10. Called by the controller on bridge
	// teardown with the final byte counts per direction. Unknown id
	// is a no-op + nil err. The counters are absolute totals (not
	// deltas) so the call is idempotent — a re-tried teardown writes
	// the same value rather than double-counting.
	RecordBytes(ctx context.Context, sessionID string, in, out int64) error
}

// SessionActivityStore is the optional surface a SessionStore exposes
// when it supports the AAL3 inactivity-timeout primitive (gap audit
// #6, NIST SP 800-63B-4 §AAL3 inactivity timeout SHOULD ≤15 minutes).
// The worker calls TouchSessionActivity on every byte-transfer event
// to keep last_activity_at current; the grant-watcher tick uses
// SessionIdleFor on each live session to detect idle > policy
// threshold + kill the session. Stores that don't implement this
// (MemoryBroker today) — the grant-watcher just skips the check.
type SessionActivityStore interface {
	// TouchSessionActivity bumps last_activity_at to now() for the
	// session. Unknown id is a no-op + nil err so a race on session
	// close doesn't error-log the worker.
	TouchSessionActivity(ctx context.Context, sessionID string) error

	// SessionIdleFor returns the duration since last_activity_at for
	// the given session. Unknown id returns (0, false, nil) — caller
	// treats as "no tracked activity, skip idle check".
	SessionIdleFor(ctx context.Context, sessionID string) (idle time.Duration, found bool, err error)
}

// ChainVerifier is the optional surface a SessionStore exposes if it
// supports the Phase 5e-16 cross-session WORM audit chain. Stores that
// don't (MemoryBroker today) simply don't implement it — the admin
// /audit/chain/verify endpoint surfaces 501 in that case so dev mode
// without postgres doesn't appear "broken".
//
// VerifyChain walks the entire session log in started_at order,
// recomputes each row's expected RowHash from current field values,
// and reports breaks: row_hash mismatches (mutation), prev_row_hash
// points to a missing row (deletion or reordering), or prev_row_hash
// pointing at the wrong row (insertion or row swap).
//
// Returns ChainReport with the full break list (capped at a safe N)
// and a summary count so admins can spot a single localized issue vs
// systemic tampering at a glance.
type ChainVerifier interface {
	VerifyChain(ctx context.Context) (ChainReport, error)
}

// ChainReport is the verified-chain summary returned to the admin
// endpoint. OK=true means every row's RowHash recomputes to the
// stored value AND every PrevRowHash matches the previous (by
// started_at) row's RowHash.
type ChainReport struct {
	OK          bool         `json:"ok"`
	Total       int          `json:"total"`
	GenesisHash string       `json:"genesis_hash,omitempty"`
	HeadHash    string       `json:"head_hash,omitempty"`
	Breaks      []ChainBreak `json:"breaks,omitempty"`
}

// ChainBreak names one inconsistency in the session chain.
type ChainBreak struct {
	SessionID string `json:"session_id"`
	Position  int    `json:"position"` // 0-indexed; matches order in the report
	Reason    string `json:"reason"`   // "row_hash_mismatch" | "prev_row_hash_mismatch" | "prev_row_hash_orphan"
	Expected  string `json:"expected,omitempty"`
	Got       string `json:"got,omitempty"`
}

// ErrNoSession is returned by SessionStore.GetSession when the id is
// unknown. CloseSession on an unknown id is a no-op + no error
// (idempotency for retries from a flaky network path).
var ErrNoSession = errors.New("jess/jit: session not found")
