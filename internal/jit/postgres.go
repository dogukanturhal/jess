// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is a durable, shared JIT-grant store (ADR 0030 Phase 5d / HA).
// Multiple stateless controllers and workers point at the same Postgres, so
// grant state survives restarts and is consistent across the fleet — the
// prerequisite for running >1 controller behind a load balancer.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects (and pings) the pool.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("jit: postgres connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("jit: postgres ping: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases the pool.
func (s *PostgresStore) Close() { s.pool.Close() }

// Ping checks the database is reachable (used by the readiness probe).
func (s *PostgresStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate creates the grants + sessions tables if absent (idempotent).
//
// jit_sessions (Phase 5e-6): one row per brokered operator session;
// EndedAt nullable while the session is live so the SPA / admin can
// show currently-open sessions. The (subject, started_at DESC) index
// powers the operator's "recent sessions" view in O(log n + k).
//
// recording_path is included for forward-compatibility with Phase 5e-7
// (worker-side recorder integration). Today the column is always
// empty; SPA renders "n/a" for it.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS jit_grants (
			id          text PRIMARY KEY,
			subject     text NOT NULL,
			target_id   text NOT NULL,
			approved_by text NOT NULL DEFAULT '',
			issued_at   timestamptz NOT NULL DEFAULT now(),
			expires_at  timestamptz NOT NULL
		);
		CREATE INDEX IF NOT EXISTS jit_grants_expires_at_idx ON jit_grants (expires_at);

		CREATE TABLE IF NOT EXISTS jit_sessions (
			id             text PRIMARY KEY,
			subject        text NOT NULL,
			target_id      text NOT NULL,
			grant_id       text NOT NULL DEFAULT '',
			protocol       text NOT NULL DEFAULT '',
			started_at     timestamptz NOT NULL DEFAULT now(),
			ended_at       timestamptz,
			close_reason   text NOT NULL DEFAULT '',
			recording_path text NOT NULL DEFAULT '',
			controller_id  text NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS jit_sessions_subject_started_idx
			ON jit_sessions (subject, started_at DESC);
		CREATE INDEX IF NOT EXISTS jit_sessions_active_idx
			ON jit_sessions (ended_at) WHERE ended_at IS NULL;
		-- Phase 5e-10: bytes counters per direction. Additive ALTER so
		-- this migration is safe to run against pre-5e-10 deployments
		-- where the table already exists without these columns. Default
		-- 0 so the column constraint is met for existing closed rows
		-- (no backfill — those sessions predate the counters).
		ALTER TABLE jit_sessions ADD COLUMN IF NOT EXISTS bytes_in  bigint NOT NULL DEFAULT 0;
		ALTER TABLE jit_sessions ADD COLUMN IF NOT EXISTS bytes_out bigint NOT NULL DEFAULT 0;
		-- Phase 5e-16: cross-session WORM audit chain.
		-- row_hash is this row's canonical hash; prev_row_hash points
		-- at the previous session's row_hash (chain link). Both default
		-- to '' so pre-5e-16 rows survive the additive ALTER unbroken
		-- (those rows appear as "pre-chain" entries in /audit/chain/verify
		-- — recognisable by row_hash='').
		ALTER TABLE jit_sessions ADD COLUMN IF NOT EXISTS row_hash      text NOT NULL DEFAULT '';
		ALTER TABLE jit_sessions ADD COLUMN IF NOT EXISTS prev_row_hash text NOT NULL DEFAULT '';

		-- Gap audit #6: AAL3 inactivity-timeout tracking. NIST SP
		-- 800-63B-4 §AAL3 inactivity SHOULD ≤15 minutes. The worker
		-- bumps this on every byte-transfer event via
		-- SessionActivityStore.TouchSessionActivity; the grant-
		-- watcher reads it on each tick. NULL = no activity tracked
		-- yet (caller skips idle check rather than treating as
		-- infinite idle). EXCLUDED from row_hash by design — the
		-- chain pins immutable session shape (id + subject +
		-- target_id + started_at + prev_row_hash); activity is a
		-- mutable field that legitimately changes throughout the
		-- session lifecycle.
		ALTER TABLE jit_sessions ADD COLUMN IF NOT EXISTS last_activity_at timestamptz;

		-- Phase 5j-1 (Phase 4 follow-on, item #4 + #7 of ADR 0034): admin
		-- lock primitive. Composes with the JIT grant substrate so admins
		-- can kill all sessions for a subject / to a target / by cert
		-- serial / by MFA device without revoking individual grants.
		-- target_type values: subject | target | cert_serial | mfa_device.
		-- expires_at NULL = indefinite (the common case for "compromised
		-- account, lock until investigation completes"). UNIQUE on
		-- (target_type, target_value) means re-locking the same axis is
		-- an UPSERT, not a duplicate row; admin handler chooses Insert vs
		-- Replace semantics per call.
		CREATE TABLE IF NOT EXISTS jit_locks (
			id           text PRIMARY KEY,
			target_type  text NOT NULL CHECK (target_type IN ('subject','target','cert_serial','mfa_device')),
			target_value text NOT NULL,
			reason       text NOT NULL,
			locked_by    text NOT NULL,
			locked_at    timestamptz NOT NULL DEFAULT now(),
			expires_at   timestamptz,
			UNIQUE (target_type, target_value)
		);
		CREATE INDEX IF NOT EXISTS jit_locks_expires_idx ON jit_locks (expires_at);
		CREATE INDEX IF NOT EXISTS jit_locks_type_value_idx ON jit_locks (target_type, target_value);

		-- Per-target admin recording override (runtime-override-on-GitOps-
		-- default design). The catalog target recorded flag is the GitOps
		-- DEFAULT (ConfigMap/CRD/discovery annotation); this table is the
		-- operational RUNTIME override a platform_admin sets from the
		-- console. EFFECTIVE recorded = override if a row exists here, else
		-- the catalog default. updated_by stamps the verified caller for the
		-- security-relevant audit trail; clearing the override (DELETE)
		-- reverts the target to its catalog default. One row per target_id.
		CREATE TABLE IF NOT EXISTS target_recording_overrides (
			target_id  text PRIMARY KEY,
			recorded   boolean NOT NULL,
			updated_by text NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now()
		);`)
	if err != nil {
		return fmt.Errorf("jit: migrate: %w", err)
	}
	return nil
}

// OpenSession persists a fresh active session row. Caller stores the
// returned session.ID and passes it to CloseSession at teardown.
//
// Phase 5e-16: also chains the row into the cross-session WORM audit
// chain. Picks the previous row's row_hash (newest session at insert
// time, by started_at DESC then id DESC tiebreak — the tiebreaker
// keeps the chain stable when two controllers open sessions in the
// same instant) and computes THIS row's row_hash from the canonical
// form. Insertion happens in a single SQL statement with the chain
// link selected inside a CTE — atomic under the row-level lock so two
// concurrent OpenSessions can't both pick the same predecessor.
func (s *PostgresStore) OpenSession(ctx context.Context, subject, targetID, grantID, protocol, controllerID string) (Session, error) {
	sess := Session{
		ID:       id("sess"),
		Subject:  subject,
		TargetID: targetID,
		GrantID:  grantID,
		Protocol: protocol,
		// Truncate to microseconds to match Postgres `timestamptz`
		// (µs resolution). ComputeRowHash formats StartedAt as
		// RFC3339Nano, so hashing the full-nanosecond time.Now() here
		// would NOT match VerifyChain's recompute from the µs-truncated
		// value read back from the DB — a false-positive
		// row_hash_mismatch for any session whose clock carried sub-µs
		// nanoseconds (Phase 5e-16 chain-monitor bug). Truncating before
		// both the hash and the INSERT keeps write == read-back.
		StartedAt:    time.Now().Truncate(time.Microsecond),
		ControllerID: controllerID,
	}
	// Two-step under a transaction so the predecessor lookup + insert
	// observe a consistent snapshot. SERIALIZABLE would be heavier
	// than needed (we don't read-then-decide); REPEATABLE READ is
	// already given by pgx's default txn isolation. The SELECT FOR
	// UPDATE on the last row ensures concurrent OpenSession calls
	// serialize on the chain head.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Session{}, fmt.Errorf("jit: open session begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var prevHash string
	if err := tx.QueryRow(ctx,
		`SELECT row_hash FROM jit_sessions
		  ORDER BY started_at DESC, id DESC
		  LIMIT 1
		  FOR UPDATE`).Scan(&prevHash); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, fmt.Errorf("jit: read prev chain head: %w", err)
	}
	sess.PrevRowHash = prevHash
	sess.RowHash = ComputeRowHash(sess.ID, sess.Subject, sess.TargetID, sess.StartedAt, sess.PrevRowHash)
	if _, err := tx.Exec(ctx,
		`INSERT INTO jit_sessions (id, subject, target_id, grant_id, protocol, started_at, controller_id, row_hash, prev_row_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		sess.ID, sess.Subject, sess.TargetID, sess.GrantID, sess.Protocol, sess.StartedAt, sess.ControllerID, sess.RowHash, sess.PrevRowHash); err != nil {
		return Session{}, fmt.Errorf("jit: insert session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, fmt.Errorf("jit: open session commit: %w", err)
	}
	return sess, nil
}

// VerifyChain — Phase 5e-16. Walks every session in started_at order
// (with id as the tiebreaker matching the OpenSession ORDER BY) and
// reports any row whose recomputed row_hash doesn't match the stored
// value, or whose prev_row_hash doesn't match the actual previous
// row's row_hash.
//
// Pre-5e-16 rows (row_hash=”) are skipped — they exist before the
// chain was introduced and can't be retrospectively verified. The
// report's `total` count covers ALL sessions; chain coverage starts
// at the first row with a non-empty row_hash.
func (s *PostgresStore) VerifyChain(ctx context.Context) (ChainReport, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject, target_id, started_at, row_hash, prev_row_hash
		   FROM jit_sessions
		  ORDER BY started_at ASC, id ASC`)
	if err != nil {
		return ChainReport{}, fmt.Errorf("jit: verify chain: %w", err)
	}
	defer rows.Close()
	rep := ChainReport{OK: true}
	const maxBreaks = 200
	var prev struct {
		hash string
		seen bool
	}
	pos := 0
	for rows.Next() {
		var rid, rsub, rtgt, rh, prh string
		var startedAt time.Time
		if err := rows.Scan(&rid, &rsub, &rtgt, &startedAt, &rh, &prh); err != nil {
			return ChainReport{}, fmt.Errorf("jit: verify scan: %w", err)
		}
		rep.Total++
		if rh == "" {
			// Pre-5e-16 row — outside the chain coverage.
			continue
		}
		if rep.GenesisHash == "" {
			rep.GenesisHash = rh
		}
		rep.HeadHash = rh
		expected := ComputeRowHash(rid, rsub, rtgt, startedAt, prh)
		if expected != rh {
			rep.OK = false
			if len(rep.Breaks) < maxBreaks {
				rep.Breaks = append(rep.Breaks, ChainBreak{
					SessionID: rid,
					Position:  pos,
					Reason:    "row_hash_mismatch",
					Expected:  expected,
					Got:       rh,
				})
			}
		}
		if prev.seen {
			if prh != prev.hash {
				rep.OK = false
				if len(rep.Breaks) < maxBreaks {
					rep.Breaks = append(rep.Breaks, ChainBreak{
						SessionID: rid,
						Position:  pos,
						Reason:    "prev_row_hash_mismatch",
						Expected:  prev.hash,
						Got:       prh,
					})
				}
			}
		} else if prh != "" {
			// First chained row claims a predecessor that doesn't exist
			// in our scan — the genesis row was deleted.
			rep.OK = false
			if len(rep.Breaks) < maxBreaks {
				rep.Breaks = append(rep.Breaks, ChainBreak{
					SessionID: rid,
					Position:  pos,
					Reason:    "prev_row_hash_orphan",
					Expected:  "(no row before genesis)",
					Got:       prh,
				})
			}
		}
		prev.hash = rh
		prev.seen = true
		pos++
	}
	return rep, nil
}

// CloseSession marks a session ended. Idempotent: a second close (or a
// close on an unknown id) is a no-op + nil error — the bridge teardown
// path is racey by nature (deadline + grant-watcher + bridge-EOF can
// all fire close in quick succession) and we don't want spurious errors
// in the controller log every time.
func (s *PostgresStore) CloseSession(ctx context.Context, sessionID, reason string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE jit_sessions
		    SET ended_at = now(), close_reason = $2
		  WHERE id = $1 AND ended_at IS NULL`,
		sessionID, reason)
	if err != nil {
		return fmt.Errorf("jit: close session: %w", err)
	}
	return nil
}

// SetRecordingPath stamps the recording_path column. Called by the
// controller right after OpenSession when the target is recorded
// (Phase 5e-7). Idempotent — running it twice with the same path is
// a no-op; calling it on an unknown id is a no-op + nil err.
func (s *PostgresStore) SetRecordingPath(ctx context.Context, sessionID, path string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE jit_sessions SET recording_path = $2 WHERE id = $1`,
		sessionID, path)
	if err != nil {
		return fmt.Errorf("jit: set recording_path: %w", err)
	}
	return nil
}

// RecordBytes stamps the bytes counters at bridge teardown (Phase 5e-10).
// Absolute totals, not deltas — a re-tried close writes the same value
// rather than double-counting. Unknown id is no-op + nil err.
func (s *PostgresStore) RecordBytes(ctx context.Context, sessionID string, in, out int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE jit_sessions SET bytes_in = $2, bytes_out = $3 WHERE id = $1`,
		sessionID, in, out)
	if err != nil {
		return fmt.Errorf("jit: record bytes: %w", err)
	}
	return nil
}

// TouchSessionActivity stamps last_activity_at to now() for the given
// session. Called by the worker on every byte-transfer event. Unknown
// id is no-op + nil err. Part of SessionActivityStore (gap audit #6).
func (s *PostgresStore) TouchSessionActivity(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE jit_sessions SET last_activity_at = NOW() WHERE id = $1 AND ended_at IS NULL`,
		sessionID)
	if err != nil {
		return fmt.Errorf("jit: touch session activity: %w", err)
	}
	return nil
}

// SessionIdleFor returns time since last_activity_at for the given
// session. Unknown id or NULL last_activity_at returns (0, false,
// nil) — caller treats as "no idle check".
func (s *PostgresStore) SessionIdleFor(ctx context.Context, sessionID string) (time.Duration, bool, error) {
	var last *time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT last_activity_at FROM jit_sessions WHERE id = $1 AND ended_at IS NULL`,
		sessionID).Scan(&last)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("jit: session idle for: %w", err)
	}
	if last == nil {
		return 0, false, nil
	}
	return time.Since(*last), true, nil
}

// ListSessions returns the most recent sessions for the optional
// subject filter. Empty subject = all sessions (admin path; the admin
// handler enforces the role gate). Capped at min(limit, 200) — same
// safety ceiling List uses for grants.
func (s *PostgresStore) ListSessions(ctx context.Context, subject string, limit int) ([]Session, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	q := `SELECT id, subject, target_id, grant_id, protocol, started_at, ended_at,
	             close_reason, recording_path, controller_id, bytes_in, bytes_out,
	             row_hash, prev_row_hash
	      FROM jit_sessions`
	args := []any{}
	if subject != "" {
		q += ` WHERE subject = $1`
		args = append(args, subject)
	}
	q += ` ORDER BY started_at DESC LIMIT ` + iitoa(limit)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("jit: list sessions: %w", err)
	}
	defer rows.Close()
	out := make([]Session, 0, 16)
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.Subject, &sess.TargetID, &sess.GrantID,
			&sess.Protocol, &sess.StartedAt, &sess.EndedAt, &sess.CloseReason,
			&sess.RecordingPath, &sess.ControllerID, &sess.BytesIn, &sess.BytesOut,
			&sess.RowHash, &sess.PrevRowHash); err != nil {
			return nil, fmt.Errorf("jit: scan session: %w", err)
		}
		out = append(out, sess)
	}
	return out, nil
}

// GetSession is the single-row read path. Used by the per-id admin GET
// (Phase 5e-7+); included now for completeness so the SessionStore
// surface is symmetric with the requests one and tests can verify
// writes without doing a full ListSessions+filter.
func (s *PostgresStore) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject, target_id, grant_id, protocol, started_at, ended_at,
		        close_reason, recording_path, controller_id, bytes_in, bytes_out,
		        row_hash, prev_row_hash
		 FROM jit_sessions WHERE id = $1`, sessionID).
		Scan(&sess.ID, &sess.Subject, &sess.TargetID, &sess.GrantID,
			&sess.Protocol, &sess.StartedAt, &sess.EndedAt, &sess.CloseReason,
			&sess.RecordingPath, &sess.ControllerID, &sess.BytesIn, &sess.BytesOut,
			&sess.RowHash, &sess.PrevRowHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("jit: query session: %w", err)
	}
	return sess, nil
}

// iitoa is a tiny int → decimal-string helper to inline LIMIT in the
// query string. pgx does NOT allow $N for LIMIT/OFFSET in all drivers
// (depends on prepared-statement caching mode). Hard-cap is already
// applied at the call site so this can't be operator-supplied.
func iitoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Issue persists an already-approved, time-boxed grant (admin/5d entry point).
func (s *PostgresStore) Issue(ctx context.Context, subject, targetID string, ttl time.Duration) (Grant, error) {
	g := Grant{
		ID:         id("grant"),
		Subject:    subject,
		TargetID:   targetID,
		ApprovedBy: "system:issue",
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO jit_grants (id, subject, target_id, approved_by, issued_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		g.ID, g.Subject, g.TargetID, g.ApprovedBy, g.IssuedAt, g.ExpiresAt)
	if err != nil {
		return Grant{}, fmt.Errorf("jit: insert grant: %w", err)
	}
	return g, nil
}

// List returns active grants (expires_at > now). When targetID is non-empty
// the result is filtered to a single target. Ordered newest-first by
// issued_at. Pagination is not implemented yet — the demo dataset is small
// and a `LIMIT 200` ceiling caps the response so a runaway accumulation
// cannot blow up the admin CLI's terminal.
//
// Admin/SOC tooling consumes this; the operator session path uses
// AssertActiveID and never lists.
func (s *PostgresStore) List(ctx context.Context, targetID string) ([]Grant, error) {
	const limit = 200
	q := `SELECT id, subject, target_id, approved_by, issued_at, expires_at
	      FROM jit_grants
	      WHERE expires_at > now()`
	args := []any{limit}
	if targetID != "" {
		q += ` AND target_id = $2`
		args = append(args, targetID)
	}
	q += ` ORDER BY issued_at DESC LIMIT $1`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("jit: list grants: %w", err)
	}
	defer rows.Close()
	out := make([]Grant, 0, 16)
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.Subject, &g.TargetID, &g.ApprovedBy, &g.IssuedAt, &g.ExpiresAt); err != nil {
			return nil, fmt.Errorf("jit: scan grant: %w", err)
		}
		out = append(out, g)
	}
	return out, nil
}

// Revoke ends an active grant by setting expires_at = now(). Soft delete on
// purpose: subsequent AssertActiveID calls fail-closed (the existing
// "grant expired" check rejects), and audit trails over the table still
// reference the row. Returns ErrNoGrant when the grant doesn't exist.
//
// Live brokered sessions referencing the grant continue until the next
// continuous-auth re-check (spine.Controller fires every 10s; the session
// dies within the next tick because the grant's expires_at is now in the
// past).
func (s *PostgresStore) Revoke(ctx context.Context, grantID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE jit_grants SET expires_at = now() WHERE id = $1 AND expires_at > now()`,
		grantID)
	if err != nil {
		return fmt.Errorf("jit: revoke grant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// either no such grant, or already expired — caller treats both as no-op
		// success for idempotency from the admin CLI.
		return ErrNoGrant
	}
	return nil
}

// RevokeBySubject ends every active grant held by a specific operator subject.
// Used by the CAEP receiver (Phase 5h-6 — Continuous Access Evaluation push
// from Falcon-ID) on session_revoked / password_changed / mfa_revoked /
// role_revoked / credential_compromised events. Returns the number of grants
// terminated; 0 with nil error is the common case (operator has no live
// grants) and is NOT an error.
//
// Soft-delete pattern identical to Revoke — expires_at = now(); next 10s
// continuous-auth tick on any in-flight session kills the bridge. The
// CAEP signal accelerates revocation propagation from session-token-TTL
// (default 1h) to ~10s.
func (s *PostgresStore) RevokeBySubject(ctx context.Context, subject string) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE jit_grants SET expires_at = now() WHERE subject = $1 AND expires_at > now()`,
		subject)
	if err != nil {
		return 0, fmt.Errorf("jit: revoke grants by subject: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// IsLockedAny implements LockStore. Single indexed query — empty
// arguments skip that axis. Returns the first matching active lock's
// reason (subject takes precedence on multi-match, see lock.go header).
func (s *PostgresStore) IsLockedAny(ctx context.Context, subject, targetID string) (bool, string, error) {
	if subject == "" && targetID == "" {
		return false, "", nil
	}
	// Build the WHERE list dynamically so we only fire the OR branches
	// the caller actually asked about. Avoids matching unintended rows
	// when one of the axes is empty.
	var (
		clauses []string
		args    []any
	)
	if subject != "" {
		args = append(args, subject)
		clauses = append(clauses, fmt.Sprintf("(target_type = 'subject' AND target_value = $%d)", len(args)))
	}
	if targetID != "" {
		args = append(args, targetID)
		clauses = append(clauses, fmt.Sprintf("(target_type = 'target' AND target_value = $%d)", len(args)))
	}
	q := `SELECT target_type, reason FROM jit_locks
	      WHERE (` + strings.Join(clauses, " OR ") + `)
	        AND (expires_at IS NULL OR expires_at > now())
	      ORDER BY CASE target_type WHEN 'subject' THEN 0 ELSE 1 END, locked_at DESC
	      LIMIT 1`
	var tt, reason string
	err := s.pool.QueryRow(ctx, q, args...).Scan(&tt, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("jit: IsLockedAny: %w", err)
	}
	return true, "locked_" + tt + ": " + reason, nil
}

// LookupLock implements LockStore — fetches the (still-active) lock on
// the given axis or returns (nil, nil) for not-found.
func (s *PostgresStore) LookupLock(ctx context.Context, t LockTargetType, value string) (*Lock, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("jit: LookupLock: invalid target_type %q", t)
	}
	var l Lock
	var tt string
	err := s.pool.QueryRow(ctx,
		`SELECT id, target_type, target_value, reason, locked_by, locked_at, expires_at
		   FROM jit_locks
		  WHERE target_type = $1 AND target_value = $2
		    AND (expires_at IS NULL OR expires_at > now())`,
		string(t), value).
		Scan(&l.ID, &tt, &l.TargetVal, &l.Reason, &l.LockedBy, &l.LockedAt, &l.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("jit: LookupLock: %w", err)
	}
	l.TargetType = LockTargetType(tt)
	return &l, nil
}

// InsertLock writes a new lock; returns ErrLockExists when the
// (target_type, target_value) tuple already has an active row. Use
// ReplaceLock for upsert semantics.
func (s *PostgresStore) InsertLock(ctx context.Context, l Lock) (Lock, error) {
	if !l.TargetType.Valid() {
		return Lock{}, fmt.Errorf("jit: InsertLock: invalid target_type %q", l.TargetType)
	}
	if l.TargetVal == "" {
		return Lock{}, errors.New("jit: InsertLock: target_value required")
	}
	if l.LockedBy == "" {
		return Lock{}, errors.New("jit: InsertLock: locked_by required (verified Falcon-ID subject)")
	}
	if l.ID == "" {
		l.ID = id("lock")
	}
	if l.LockedAt.IsZero() {
		l.LockedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO jit_locks (id, target_type, target_value, reason, locked_by, locked_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		l.ID, string(l.TargetType), l.TargetVal, l.Reason, l.LockedBy, l.LockedAt, l.ExpiresAt)
	if err != nil {
		// pgx unique-violation surfaces as SQLSTATE 23505. Map it to
		// the typed sentinel so admin handlers can branch cleanly.
		if strings.Contains(err.Error(), "jit_locks_target_type_target_value_key") || strings.Contains(err.Error(), "duplicate key") {
			return Lock{}, ErrLockExists
		}
		return Lock{}, fmt.Errorf("jit: InsertLock: %w", err)
	}
	return l, nil
}

// ReplaceLock upserts — overwrites any existing active lock on the same
// (target_type, target_value). Returns the resulting row with its
// (possibly pre-existing) ID. Used by `jessctl admin lock --replace`.
func (s *PostgresStore) ReplaceLock(ctx context.Context, l Lock) (Lock, error) {
	if !l.TargetType.Valid() {
		return Lock{}, fmt.Errorf("jit: ReplaceLock: invalid target_type %q", l.TargetType)
	}
	if l.TargetVal == "" {
		return Lock{}, errors.New("jit: ReplaceLock: target_value required")
	}
	if l.LockedBy == "" {
		return Lock{}, errors.New("jit: ReplaceLock: locked_by required")
	}
	if l.ID == "" {
		l.ID = id("lock")
	}
	if l.LockedAt.IsZero() {
		l.LockedAt = time.Now().UTC()
	}
	// ON CONFLICT keeps the existing id (won't update it) so external
	// references to that lock ID remain valid; updates the mutable fields.
	row := s.pool.QueryRow(ctx,
		`INSERT INTO jit_locks (id, target_type, target_value, reason, locked_by, locked_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (target_type, target_value) DO UPDATE
		   SET reason = EXCLUDED.reason,
		       locked_by = EXCLUDED.locked_by,
		       locked_at = EXCLUDED.locked_at,
		       expires_at = EXCLUDED.expires_at
		 RETURNING id, target_type, target_value, reason, locked_by, locked_at, expires_at`,
		l.ID, string(l.TargetType), l.TargetVal, l.Reason, l.LockedBy, l.LockedAt, l.ExpiresAt)
	var out Lock
	var tt string
	if err := row.Scan(&out.ID, &tt, &out.TargetVal, &out.Reason, &out.LockedBy, &out.LockedAt, &out.ExpiresAt); err != nil {
		return Lock{}, fmt.Errorf("jit: ReplaceLock: %w", err)
	}
	out.TargetType = LockTargetType(tt)
	return out, nil
}

// DeleteLock removes a lock by ID; not-found is not an error (idempotent
// — matches the grant revoke pattern).
func (s *PostgresStore) DeleteLock(ctx context.Context, lockID string) error {
	if lockID == "" {
		return errors.New("jit: DeleteLock: id required")
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM jit_locks WHERE id = $1`, lockID)
	if err != nil {
		return fmt.Errorf("jit: DeleteLock: %w", err)
	}
	return nil
}

// ListLocks returns all currently-active locks, newest first.
func (s *PostgresStore) ListLocks(ctx context.Context) ([]Lock, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_type, target_value, reason, locked_by, locked_at, expires_at
		   FROM jit_locks
		  WHERE expires_at IS NULL OR expires_at > now()
		  ORDER BY locked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("jit: ListLocks: %w", err)
	}
	defer rows.Close()
	var out []Lock
	for rows.Next() {
		var l Lock
		var tt string
		if err := rows.Scan(&l.ID, &tt, &l.TargetVal, &l.Reason, &l.LockedBy, &l.LockedAt, &l.ExpiresAt); err != nil {
			return nil, fmt.Errorf("jit: ListLocks scan: %w", err)
		}
		l.TargetType = LockTargetType(tt)
		out = append(out, l)
	}
	return out, rows.Err()
}

// ExpireOldLocks deletes past-expiry rows. Idempotent, cheap (indexed
// on expires_at). The controller's background expirer goroutine calls
// this on the same 5-min cadence as the requests expirer.
func (s *PostgresStore) ExpireOldLocks(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM jit_locks WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("jit: ExpireOldLocks: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// AssertActiveID enforces the gate by grant ID: the grant must exist, be for the
// requested target, and be unexpired. Implements GrantStore.
func (s *PostgresStore) AssertActiveID(ctx context.Context, grantID, targetID string) (*Grant, error) {
	var g Grant
	err := s.pool.QueryRow(ctx,
		`SELECT id, subject, target_id, approved_by, issued_at, expires_at
		 FROM jit_grants WHERE id=$1`, grantID).
		Scan(&g.ID, &g.Subject, &g.TargetID, &g.ApprovedBy, &g.IssuedAt, &g.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoGrant
	}
	if err != nil {
		return nil, fmt.Errorf("jit: query grant: %w", err)
	}
	if g.TargetID != targetID {
		return nil, fmt.Errorf("jit: grant %q is not for target %q", grantID, targetID)
	}
	if !g.Active(time.Now()) {
		return nil, fmt.Errorf("jit: grant %q expired", grantID)
	}
	return &g, nil
}

// GetRecordingOverride implements RecordingOverrideStore — single-row read
// the controller does at session-open to resolve the effective recorded
// value. found=false means no override (caller falls back to the catalog
// default). Single PK lookup — cheap enough for the hot path.
func (s *PostgresStore) GetRecordingOverride(ctx context.Context, targetID string) (RecordingOverride, bool, error) {
	var ov RecordingOverride
	err := s.pool.QueryRow(ctx,
		`SELECT target_id, recorded, updated_by, updated_at
		   FROM target_recording_overrides WHERE target_id = $1`, targetID).
		Scan(&ov.TargetID, &ov.Recorded, &ov.UpdatedBy, &ov.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RecordingOverride{}, false, nil
	}
	if err != nil {
		return RecordingOverride{}, false, fmt.Errorf("jit: get recording override: %w", err)
	}
	return ov, true, nil
}

// SetRecordingOverride upserts the per-target override. updated_at is
// stamped to now() on every write so the audit/console shows the latest
// change time. Keyed by target_id (PK) so re-toggling is an UPDATE, not a
// duplicate row.
func (s *PostgresStore) SetRecordingOverride(ctx context.Context, targetID string, recorded bool, updatedBy string) (RecordingOverride, error) {
	if targetID == "" {
		return RecordingOverride{}, errors.New("jit: SetRecordingOverride: target_id required")
	}
	if updatedBy == "" {
		return RecordingOverride{}, errors.New("jit: SetRecordingOverride: updated_by required (verified subject)")
	}
	var ov RecordingOverride
	err := s.pool.QueryRow(ctx,
		`INSERT INTO target_recording_overrides (target_id, recorded, updated_by, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (target_id) DO UPDATE
		   SET recorded = EXCLUDED.recorded,
		       updated_by = EXCLUDED.updated_by,
		       updated_at = now()
		 RETURNING target_id, recorded, updated_by, updated_at`,
		targetID, recorded, updatedBy).
		Scan(&ov.TargetID, &ov.Recorded, &ov.UpdatedBy, &ov.UpdatedAt)
	if err != nil {
		return RecordingOverride{}, fmt.Errorf("jit: set recording override: %w", err)
	}
	return ov, nil
}

// ClearRecordingOverride removes the override, reverting to catalog default.
// Idempotent — not-found is nil error (matches grant Revoke / lock Delete).
func (s *PostgresStore) ClearRecordingOverride(ctx context.Context, targetID string) error {
	if targetID == "" {
		return errors.New("jit: ClearRecordingOverride: target_id required")
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM target_recording_overrides WHERE target_id = $1`, targetID)
	if err != nil {
		return fmt.Errorf("jit: clear recording override: %w", err)
	}
	return nil
}

// ListRecordingOverrides returns every override row, ordered by target_id.
func (s *PostgresStore) ListRecordingOverrides(ctx context.Context) ([]RecordingOverride, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT target_id, recorded, updated_by, updated_at
		   FROM target_recording_overrides ORDER BY target_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("jit: list recording overrides: %w", err)
	}
	defer rows.Close()
	out := make([]RecordingOverride, 0, 16)
	for rows.Next() {
		var ov RecordingOverride
		if err := rows.Scan(&ov.TargetID, &ov.Recorded, &ov.UpdatedBy, &ov.UpdatedAt); err != nil {
			return nil, fmt.Errorf("jit: scan recording override: %w", err)
		}
		out = append(out, ov)
	}
	return out, rows.Err()
}
