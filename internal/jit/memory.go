// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryBroker is an in-memory JIT grant store (ADR 0030 Phase 5a/5d). It is
// the enforcement substrate for "no session without an active grant". The 5d
// approval workflow (chat/Falcon-ID approver) layers on top; for 5a, Issue
// creates grants directly so the spine can enforce the gate end-to-end.
//
// Phase 5e-6: also implements SessionStore. The map is bounded by an
// LRU-ish eviction in OpenSession (max 1000 entries) so a long-lived
// dev controller doesn't grow unbounded. Production deploys use the
// PostgresStore which has no such cap.
type MemoryBroker struct {
	mu       sync.Mutex
	grants   map[string]Grant             // by grant ID
	requests map[string]pendingRequest    // by request ID
	sessions map[string]Session           // by session ID — Phase 5e-6
	locks    map[string]Lock              // by lock ID — Phase 5j-1 (LockStore)
	recOv    map[string]RecordingOverride // by target ID — per-target recording override
}

type pendingRequest struct {
	subject  string
	targetID string
	reason   string
}

// NewMemoryBroker returns an empty in-memory broker.
func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{
		grants:   map[string]Grant{},
		requests: map[string]pendingRequest{},
		sessions: map[string]Session{},
		locks:    map[string]Lock{},
		recOv:    map[string]RecordingOverride{},
	}
}

// --- RecordingOverrideStore (in-memory) -------------------------------------

// GetRecordingOverride implements RecordingOverrideStore.
func (m *MemoryBroker) GetRecordingOverride(_ context.Context, targetID string) (RecordingOverride, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ov, ok := m.recOv[targetID]
	return ov, ok, nil
}

// SetRecordingOverride implements RecordingOverrideStore (upsert).
func (m *MemoryBroker) SetRecordingOverride(_ context.Context, targetID string, recorded bool, updatedBy string) (RecordingOverride, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ov := RecordingOverride{
		TargetID:  targetID,
		Recorded:  recorded,
		UpdatedBy: updatedBy,
		UpdatedAt: time.Now(),
	}
	m.recOv[targetID] = ov
	return ov, nil
}

// ClearRecordingOverride implements RecordingOverrideStore (idempotent).
func (m *MemoryBroker) ClearRecordingOverride(_ context.Context, targetID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.recOv, targetID)
	return nil
}

// ListRecordingOverrides implements RecordingOverrideStore.
func (m *MemoryBroker) ListRecordingOverrides(_ context.Context) ([]RecordingOverride, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecordingOverride, 0, len(m.recOv))
	for _, ov := range m.recOv {
		out = append(out, ov)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out, nil
}

func id(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// IssueGrant satisfies GrantIssuer for admin-direct-connect. Wraps the
// non-ctx Issue() method — MemoryBroker is in-process so no IO blocks
// on ctx anyway. Returns (Grant, nil) — Issue cannot fail in-memory.
func (m *MemoryBroker) IssueGrant(_ context.Context, subject, targetID string, ttl time.Duration) (Grant, error) {
	return m.Issue(subject, targetID, ttl), nil
}

// Issue creates an already-approved grant (dev/admin convenience for 5a).
func (m *MemoryBroker) Issue(subject, targetID string, ttl time.Duration) Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := Grant{
		ID:         id("grant"),
		Subject:    subject,
		TargetID:   targetID,
		ApprovedBy: "system:dev-issue",
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
	m.grants[g.ID] = g
	return g
}

// Request records an access request (5d approval workflow front).
func (m *MemoryBroker) Request(ctx context.Context, subject, targetID, reason string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rid := id("req")
	m.requests[rid] = pendingRequest{subject: subject, targetID: targetID, reason: reason}
	return rid, nil
}

// Approve turns a pending request into a time-boxed grant.
func (m *MemoryBroker) Approve(ctx context.Context, requestID, approver string, ttl time.Duration) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[requestID]
	if !ok {
		return Grant{}, fmt.Errorf("jit: unknown request %q", requestID)
	}
	delete(m.requests, requestID)
	g := Grant{
		ID:         id("grant"),
		Subject:    r.subject,
		TargetID:   r.targetID,
		ApprovedBy: approver,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(ttl),
	}
	m.grants[g.ID] = g
	return g, nil
}

// ActiveGrant returns the active grant for (subject, target), if any.
func (m *MemoryBroker) ActiveGrant(ctx context.Context, subject, targetID string) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, g := range m.grants {
		if g.Subject == subject && g.TargetID == targetID && g.Active(now) {
			gg := g
			return &gg, nil
		}
	}
	return nil, ErrNoGrant
}

// AssertActiveID enforces the gate by grant ID (the worker checks the grant_id
// carried in the session header — defense in depth alongside the controller).
func (m *MemoryBroker) AssertActiveID(ctx context.Context, grantID, targetID string) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[grantID]
	if !ok {
		return nil, ErrNoGrant
	}
	if g.TargetID != targetID {
		return nil, fmt.Errorf("jit: grant %q is not for target %q", grantID, targetID)
	}
	if !g.Active(time.Now()) {
		return nil, fmt.Errorf("jit: grant %q expired", grantID)
	}
	gg := g
	return &gg, nil
}

// --- Phase 5e-6: SessionStore implementation -----------------------------

const memSessionCap = 1000 // bound the dev-mode map so a long-lived controller doesn't grow unbounded

// OpenSession persists a fresh active session row. Phase 5e-16 chains
// the row into the cross-session WORM audit chain (in-memory mirror of
// the Postgres path so tests can exercise VerifyChain locally).
func (m *MemoryBroker) OpenSession(_ context.Context, subject, targetID, grantID, protocol, controllerID string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.chainHeadLocked()
	sess := Session{
		ID:           id("sess"),
		Subject:      subject,
		TargetID:     targetID,
		GrantID:      grantID,
		Protocol:     protocol,
		StartedAt:    time.Now(),
		ControllerID: controllerID,
		PrevRowHash:  prev,
	}
	sess.RowHash = ComputeRowHash(sess.ID, sess.Subject, sess.TargetID, sess.StartedAt, sess.PrevRowHash)
	m.sessions[sess.ID] = sess
	if len(m.sessions) > memSessionCap {
		m.evictOldestSessionLocked()
	}
	return sess, nil
}

// chainHeadLocked returns the row_hash of the newest session in the
// in-memory store (by started_at, with id as the tiebreaker — matches
// the Postgres ORDER BY). Empty string when the store is empty.
// Caller must hold m.mu.
func (m *MemoryBroker) chainHeadLocked() string {
	var best Session
	var seen bool
	for _, s := range m.sessions {
		if !seen || s.StartedAt.After(best.StartedAt) || (s.StartedAt.Equal(best.StartedAt) && s.ID > best.ID) {
			best = s
			seen = true
		}
	}
	if !seen {
		return ""
	}
	return best.RowHash
}

// VerifyChain — Phase 5e-16. Walks the in-memory store in started_at
// order, recomputes each row's RowHash from current field values, and
// reports breaks. Mirrors PostgresStore.VerifyChain behaviour. Useful
// for unit tests + dev-mode admin curls.
func (m *MemoryBroker) VerifyChain(_ context.Context) (ChainReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		rows = append(rows, s)
	}
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].StartedAt.Before(rows[i].StartedAt) ||
				(rows[j].StartedAt.Equal(rows[i].StartedAt) && rows[j].ID < rows[i].ID) {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}
	rep := ChainReport{OK: true}
	const maxBreaks = 200
	var prev struct {
		hash string
		seen bool
	}
	pos := 0
	for _, r := range rows {
		rep.Total++
		if r.RowHash == "" {
			continue
		}
		if rep.GenesisHash == "" {
			rep.GenesisHash = r.RowHash
		}
		rep.HeadHash = r.RowHash
		expected := ComputeRowHash(r.ID, r.Subject, r.TargetID, r.StartedAt, r.PrevRowHash)
		if expected != r.RowHash {
			rep.OK = false
			if len(rep.Breaks) < maxBreaks {
				rep.Breaks = append(rep.Breaks, ChainBreak{
					SessionID: r.ID, Position: pos,
					Reason: "row_hash_mismatch", Expected: expected, Got: r.RowHash,
				})
			}
		}
		if prev.seen {
			if r.PrevRowHash != prev.hash {
				rep.OK = false
				if len(rep.Breaks) < maxBreaks {
					rep.Breaks = append(rep.Breaks, ChainBreak{
						SessionID: r.ID, Position: pos,
						Reason: "prev_row_hash_mismatch", Expected: prev.hash, Got: r.PrevRowHash,
					})
				}
			}
		} else if r.PrevRowHash != "" {
			rep.OK = false
			if len(rep.Breaks) < maxBreaks {
				rep.Breaks = append(rep.Breaks, ChainBreak{
					SessionID: r.ID, Position: pos,
					Reason: "prev_row_hash_orphan", Expected: "(no row before genesis)", Got: r.PrevRowHash,
				})
			}
		}
		prev.hash = r.RowHash
		prev.seen = true
		pos++
	}
	return rep, nil
}

// CloseSession sets ended_at + close_reason on the row. Idempotent: a
// second close OR a close on an unknown id is a no-op + nil error.
func (m *MemoryBroker) CloseSession(_ context.Context, sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	if sess.EndedAt != nil {
		return nil
	}
	now := time.Now()
	sess.EndedAt = &now
	sess.CloseReason = reason
	m.sessions[sessionID] = sess
	return nil
}

// ListSessions returns up to limit sessions, newest first. Empty subject
// = all sessions; subject filter applied in-memory (this is dev/test
// scale — Postgres handles production filtering at the index level).
func (m *MemoryBroker) ListSessions(_ context.Context, subject string, limit int) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	out := make([]Session, 0, len(m.sessions))
	for _, sess := range m.sessions {
		if subject != "" && sess.Subject != subject {
			continue
		}
		out = append(out, sess)
	}
	// Newest first.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartedAt.After(out[i].StartedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// SetRecordingPath stamps the recording_path field. Idempotent (same
// posture as CloseSession): unknown id = no-op + nil.
func (m *MemoryBroker) SetRecordingPath(_ context.Context, sessionID, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	sess.RecordingPath = path
	m.sessions[sessionID] = sess
	return nil
}

// RecordBytes stamps the final byte counts at bridge teardown.
// Idempotent (absolute totals, not deltas) — unknown id = no-op + nil.
func (m *MemoryBroker) RecordBytes(_ context.Context, sessionID string, in, out int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	sess.BytesIn = in
	sess.BytesOut = out
	m.sessions[sessionID] = sess
	return nil
}

// GetSession is the single-row read path.
func (m *MemoryBroker) GetSession(_ context.Context, sessionID string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return Session{}, ErrNoSession
	}
	return sess, nil
}

// evictOldestSessionLocked drops the oldest session row when the dev-mode
// cap is exceeded. Caller MUST hold m.mu.
func (m *MemoryBroker) evictOldestSessionLocked() {
	var oldestID string
	var oldestAt time.Time
	for id, sess := range m.sessions {
		if oldestID == "" || sess.StartedAt.Before(oldestAt) {
			oldestID = id
			oldestAt = sess.StartedAt
		}
	}
	if oldestID != "" {
		delete(m.sessions, oldestID)
	}
}

// --- LockStore (Phase 5j-1) -------------------------------------------------

// IsLockedAny implements LockStore. Iterates the in-memory map; fine
// for the dev path (lock count is tiny). Production uses PostgresStore.
func (m *MemoryBroker) IsLockedAny(_ context.Context, subject, targetID string) (bool, string, error) {
	if subject == "" && targetID == "" {
		return false, "", nil
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Subject takes precedence on multi-match (matches PostgresStore + lock.go header).
	var matched *Lock
	for i := range m.locks {
		l := m.locks[i]
		if !l.Active(now) {
			continue
		}
		if subject != "" && l.TargetType == LockTargetSubject && l.TargetVal == subject {
			matched = &l
			break
		}
	}
	if matched == nil {
		for i := range m.locks {
			l := m.locks[i]
			if !l.Active(now) {
				continue
			}
			if targetID != "" && l.TargetType == LockTargetTarget && l.TargetVal == targetID {
				matched = &l
				break
			}
		}
	}
	if matched == nil {
		return false, "", nil
	}
	return true, "locked_" + string(matched.TargetType) + ": " + matched.Reason, nil
}

// LookupLock returns the active lock on (type, value) or nil.
func (m *MemoryBroker) LookupLock(_ context.Context, t LockTargetType, value string) (*Lock, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("jit: LookupLock: invalid target_type %q", t)
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.locks {
		l := m.locks[id]
		if l.TargetType == t && l.TargetVal == value && l.Active(now) {
			return &l, nil
		}
	}
	return nil, nil
}

// InsertLock returns ErrLockExists when an active lock already covers
// the tuple. Mirrors PostgresStore semantics for the dev path.
func (m *MemoryBroker) InsertLock(_ context.Context, l Lock) (Lock, error) {
	if !l.TargetType.Valid() {
		return Lock{}, fmt.Errorf("jit: InsertLock: invalid target_type %q", l.TargetType)
	}
	if l.TargetVal == "" {
		return Lock{}, fmt.Errorf("jit: InsertLock: target_value required")
	}
	if l.LockedBy == "" {
		return Lock{}, fmt.Errorf("jit: InsertLock: locked_by required")
	}
	if l.ID == "" {
		l.ID = id("lock")
	}
	if l.LockedAt.IsZero() {
		l.LockedAt = time.Now().UTC()
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.locks {
		existing := m.locks[id]
		if existing.TargetType == l.TargetType && existing.TargetVal == l.TargetVal && existing.Active(now) {
			return Lock{}, ErrLockExists
		}
	}
	m.locks[l.ID] = l
	return l, nil
}

// ReplaceLock upserts on (target_type, target_value), preserving the
// existing lock's ID when one is found.
func (m *MemoryBroker) ReplaceLock(_ context.Context, l Lock) (Lock, error) {
	if !l.TargetType.Valid() {
		return Lock{}, fmt.Errorf("jit: ReplaceLock: invalid target_type %q", l.TargetType)
	}
	if l.TargetVal == "" {
		return Lock{}, fmt.Errorf("jit: ReplaceLock: target_value required")
	}
	if l.LockedBy == "" {
		return Lock{}, fmt.Errorf("jit: ReplaceLock: locked_by required")
	}
	if l.LockedAt.IsZero() {
		l.LockedAt = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.locks {
		existing := m.locks[id]
		if existing.TargetType == l.TargetType && existing.TargetVal == l.TargetVal {
			// Preserve the pre-existing ID; overwrite mutable fields.
			l.ID = existing.ID
			m.locks[id] = l
			return l, nil
		}
	}
	if l.ID == "" {
		l.ID = id("lock")
	}
	m.locks[l.ID] = l
	return l, nil
}

// DeleteLock removes by ID; idempotent (not-found is not an error).
func (m *MemoryBroker) DeleteLock(_ context.Context, lockID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.locks, lockID)
	return nil
}

// ListLocks returns active locks, newest first.
func (m *MemoryBroker) ListLocks(_ context.Context) ([]Lock, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Lock, 0, len(m.locks))
	for id := range m.locks {
		l := m.locks[id]
		if l.Active(now) {
			out = append(out, l)
		}
	}
	// Newest first — same ordering contract as PostgresStore.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].LockedAt.After(out[i].LockedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// ExpireOldLocks deletes past-expiry rows.
func (m *MemoryBroker) ExpireOldLocks(_ context.Context) (int, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id := range m.locks {
		if !m.locks[id].Active(now) {
			delete(m.locks, id)
			n++
		}
	}
	return n, nil
}

// TouchSessionActivity bumps last_activity_at to now() for the given
// session. Unknown id is a no-op — same teardown-race posture as
// CloseSession. Part of SessionActivityStore (gap audit #6 — AAL3
// inactivity timeout).
func (m *MemoryBroker) TouchSessionActivity(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	sess.LastActivityAt = time.Now()
	m.sessions[sessionID] = sess
	return nil
}

// SessionIdleFor returns time since the last TouchSessionActivity
// call. Unknown id or never-touched returns found=false; caller
// treats as "no idle check".
func (m *MemoryBroker) SessionIdleFor(_ context.Context, sessionID string) (time.Duration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return 0, false, nil
	}
	if sess.LastActivityAt.IsZero() {
		return 0, false, nil
	}
	return time.Since(sess.LastActivityAt), true, nil
}
