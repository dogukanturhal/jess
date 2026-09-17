// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"errors"
	"time"
)

// LockTargetType enumerates the orthogonal axes a lock can apply to.
// Subject + Target are the application-layer kill primitives; CertSerial
// belongs at the TLS-handshake layer (composes with admin.CRLCache from
// Phase 4 full) so it's tracked here for parity but checked separately by
// the VerifyPeerCertificate path. MFADevice is per-device kill (e.g., a
// stolen YubiKey) and requires Falcon-ID coordination to map the AMR
// claim back to a device-id — that's a follow-up; the type exists today
// so callers can begin emitting it.
type LockTargetType string

const (
	LockTargetSubject    LockTargetType = "subject"
	LockTargetTarget     LockTargetType = "target"
	LockTargetCertSerial LockTargetType = "cert_serial"
	LockTargetMFADevice  LockTargetType = "mfa_device"
)

// Valid reports whether t is one of the known lock-target types.
func (t LockTargetType) Valid() bool {
	switch t {
	case LockTargetSubject, LockTargetTarget, LockTargetCertSerial, LockTargetMFADevice:
		return true
	}
	return false
}

// Lock is an admin-issued kill primitive composing with the JIT grant
// substrate. A lock matched at session-open denies the open with reason
// "locked"; a lock matched by the continuous grant watcher kills the
// live session with reason "locked_<target_type>". Both surface in the
// audit log + Prometheus metrics.
//
// Lifetime model: locks are persistent until explicitly removed OR until
// ExpiresAt passes (nil = indefinite). Unique constraint on
// (target_type, target_value) means only one active lock per axis can
// exist — re-locking with a different reason is an UPDATE, not an INSERT.
type Lock struct {
	ID         string
	TargetType LockTargetType
	TargetVal  string
	Reason     string
	LockedBy   string     // verified Falcon-ID subject of the admin issuing the lock
	LockedAt   time.Time  // when the lock was issued
	ExpiresAt  *time.Time // nil = indefinite
}

// Active reports whether the lock is in effect at the given time.
// Indefinite locks (ExpiresAt == nil) are always active. Past-expiry
// locks are inactive and should be garbage-collected by ExpireOldLocks.
func (l Lock) Active(now time.Time) bool {
	if l.ExpiresAt == nil {
		return true
	}
	return now.Before(*l.ExpiresAt)
}

// LockStore is the durable lock state the controller queries on session-
// open + the watcher queries on each tick. Implementations: PostgresStore
// (production) + MemoryBroker (dev/tests). The interface is intentionally
// query-by-axis rather than fetch-all-then-filter so the hot path does a
// single indexed lookup, not a full-table scan.
//
// IsLockedAny returns true if EITHER the subject OR the target is locked.
// Callers wanting the actual reason can inspect the second return value.
// CertSerial / MFADevice axes are checked via LookupLock(type, value)
// from the TLS / authn paths respectively — keeping the hot session-open
// path tight to the two most common axes.
type LockStore interface {
	// IsLockedAny tests whether (subject) OR (targetID) has an active lock.
	// Empty subject or empty targetID means "skip this axis". Returns
	// (locked, reason, error). Reason is the first matching lock's Reason;
	// when both axes match, subject takes precedence (operator-side kill is
	// usually the more important signal for the audit log).
	IsLockedAny(ctx context.Context, subject, targetID string) (locked bool, reason string, err error)

	// LookupLock fetches the active lock on (target_type, target_value) or
	// returns (nil, nil) when no active lock exists. Returns an error only
	// for transport / storage failures, never for absence.
	LookupLock(ctx context.Context, t LockTargetType, value string) (*Lock, error)

	// InsertLock writes a new active lock. Returns ErrLockExists when an
	// active lock already covers (target_type, target_value) — callers
	// who want replace semantics should ReplaceLock instead. Generated
	// ID is set on the returned Lock.
	InsertLock(ctx context.Context, l Lock) (Lock, error)

	// ReplaceLock upserts — overwrites any existing active lock on the
	// same (target_type, target_value). Returns the resulting Lock with
	// its (possibly pre-existing) ID.
	ReplaceLock(ctx context.Context, l Lock) (Lock, error)

	// DeleteLock removes a lock by ID. Returns nil for both successful
	// delete and not-found (idempotent — matches the grant Revoke pattern).
	DeleteLock(ctx context.Context, id string) error

	// ListLocks returns all currently-active locks. Empty result is not an
	// error. Used by `jessctl admin list-locks` and the admin SPA tab.
	// Ordering is by LockedAt descending so the most recent locks appear
	// first (operator UX matches how revocation events are usually
	// inspected — newest first).
	ListLocks(ctx context.Context) ([]Lock, error)
}

// LockExpirer optionally garbage-collects past-expiry locks. The
// controller's background goroutine ticks ExpireOldLocks on the same
// 5-min cadence as the requests expirer. Stores that don't implement
// this just leave past-expiry rows in place (queries already filter by
// expires_at > NOW(), so it's a cosmetic-only no-op, not a correctness
// issue).
type LockExpirer interface {
	ExpireOldLocks(ctx context.Context) (int, error)
}

// ErrLockExists is returned by InsertLock when an active lock already
// covers the (target_type, target_value) tuple. Callers wanting replace
// semantics should use ReplaceLock; callers wanting strict insert (e.g.,
// a CI script that should not silently overwrite) get this error.
var ErrLockExists = errors.New("jess/jit: an active lock already exists for this target")

// ErrLockNotFound is returned by handlers when DeleteLock is called with
// an ID that doesn't exist. The store itself returns nil for not-found
// (idempotent), but admin handlers may want to distinguish.
var ErrLockNotFound = errors.New("jess/jit: lock not found")
