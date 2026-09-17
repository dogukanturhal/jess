// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestMemoryLockStoreInsertListDelete pins the round-trip on the
// in-memory store — same contract PostgresStore satisfies via SQL.
func TestMemoryLockStoreInsertListDelete(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()

	in := Lock{
		TargetType: LockTargetSubject,
		TargetVal:  "user-uuid-1",
		Reason:     "credentials suspected compromised",
		LockedBy:   "admin-uuid-x",
	}
	out, err := m.InsertLock(ctx, in)
	if err != nil {
		t.Fatalf("InsertLock: %v", err)
	}
	if out.ID == "" {
		t.Error("InsertLock should generate an ID when none supplied")
	}
	if out.LockedAt.IsZero() {
		t.Error("InsertLock should stamp LockedAt when zero")
	}

	// Duplicate insert on the same (target_type, target_value) is
	// rejected with ErrLockExists.
	if _, err := m.InsertLock(ctx, in); !errors.Is(err, ErrLockExists) {
		t.Errorf("duplicate InsertLock should return ErrLockExists, got %v", err)
	}

	// ReplaceLock upserts and PRESERVES the existing ID.
	in.Reason = "updated reason"
	replaced, err := m.ReplaceLock(ctx, in)
	if err != nil {
		t.Fatalf("ReplaceLock: %v", err)
	}
	if replaced.ID != out.ID {
		t.Errorf("ReplaceLock changed ID %q → %q (must preserve)", out.ID, replaced.ID)
	}
	if replaced.Reason != "updated reason" {
		t.Errorf("ReplaceLock didn't update Reason: %q", replaced.Reason)
	}

	// List returns the one lock.
	all, err := m.ListLocks(ctx)
	if err != nil {
		t.Fatalf("ListLocks: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("ListLocks count = %d, want 1", len(all))
	}

	// Delete is idempotent — second delete on the same ID is not an error.
	if err := m.DeleteLock(ctx, out.ID); err != nil {
		t.Fatalf("DeleteLock: %v", err)
	}
	if err := m.DeleteLock(ctx, out.ID); err != nil {
		t.Errorf("second DeleteLock on same id should be idempotent, got %v", err)
	}
	all, _ = m.ListLocks(ctx)
	if len(all) != 0 {
		t.Errorf("after delete, ListLocks count = %d, want 0", len(all))
	}
}

// TestMemoryLockStoreIsLockedAny pins the hot-path contract: subject
// match returns true; target match returns true; neither returns false.
// Subject takes precedence on multi-match (matches PostgresStore spec).
func TestMemoryLockStoreIsLockedAny(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()

	subjectLock := Lock{TargetType: LockTargetSubject, TargetVal: "sub-A", Reason: "subject-side", LockedBy: "x"}
	targetLock := Lock{TargetType: LockTargetTarget, TargetVal: "tgt-1", Reason: "target-side", LockedBy: "x"}
	if _, err := m.InsertLock(ctx, subjectLock); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InsertLock(ctx, targetLock); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name          string
		subject, tgt  string
		wantLocked    bool
		wantReasonHas string
	}{
		{"subject hit", "sub-A", "tgt-other", true, "subject-side"},
		{"target hit", "sub-other", "tgt-1", true, "target-side"},
		{"both hit — subject wins", "sub-A", "tgt-1", true, "subject-side"},
		{"no hit", "sub-other", "tgt-other", false, ""},
		{"empty subject + target hit", "", "tgt-1", true, "target-side"},
		{"empty target + subject hit", "sub-A", "", true, "subject-side"},
		{"both empty → no lock check", "", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			locked, reason, err := m.IsLockedAny(ctx, tc.subject, tc.tgt)
			if err != nil {
				t.Fatal(err)
			}
			if locked != tc.wantLocked {
				t.Errorf("locked = %v, want %v", locked, tc.wantLocked)
			}
			if tc.wantLocked && reason == "" {
				t.Error("locked but reason is empty — caller can't surface it in audit log")
			}
			if tc.wantReasonHas != "" && !contains(reason, tc.wantReasonHas) {
				t.Errorf("reason %q lacks substring %q", reason, tc.wantReasonHas)
			}
		})
	}
}

// TestMemoryLockStoreExpiry pins the time-bound semantics: an expired
// lock is invisible to IsLockedAny / ListLocks but ExpireOldLocks
// garbage-collects it.
func TestMemoryLockStoreExpiry(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour)
	if _, err := m.InsertLock(ctx, Lock{
		TargetType: LockTargetSubject, TargetVal: "expired-sub",
		Reason: "old", LockedBy: "x", ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	locked, _, _ := m.IsLockedAny(ctx, "expired-sub", "")
	if locked {
		t.Error("expired lock should NOT register on IsLockedAny")
	}
	all, _ := m.ListLocks(ctx)
	if len(all) != 0 {
		t.Errorf("ListLocks count after expired insert = %d, want 0", len(all))
	}
	n, err := m.ExpireOldLocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("ExpireOldLocks dropped %d, want 1", n)
	}
}

// TestLockTargetTypeValid pins the enum gate.
func TestLockTargetTypeValid(t *testing.T) {
	for _, tt := range []LockTargetType{LockTargetSubject, LockTargetTarget, LockTargetCertSerial, LockTargetMFADevice} {
		if !tt.Valid() {
			t.Errorf("%q.Valid() = false, want true", tt)
		}
	}
	if LockTargetType("garbage").Valid() {
		t.Error("garbage type should not validate")
	}
}

// TestMemoryLockStoreInvalidInputs pins handler-side validation done at
// the store layer — empty target_value, invalid type, missing locked_by.
func TestMemoryLockStoreInvalidInputs(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()
	cases := []struct {
		name string
		l    Lock
	}{
		{"invalid type", Lock{TargetType: "garbage", TargetVal: "x", LockedBy: "y"}},
		{"empty value", Lock{TargetType: LockTargetSubject, TargetVal: "", LockedBy: "y"}},
		{"empty locked_by", Lock{TargetType: LockTargetSubject, TargetVal: "x", LockedBy: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.InsertLock(ctx, tc.l); err == nil {
				t.Error("InsertLock should reject")
			}
			if _, err := m.ReplaceLock(ctx, tc.l); err == nil {
				t.Error("ReplaceLock should reject")
			}
		})
	}
}

// contains is a tiny helper to avoid importing strings in tests where
// only this single use is needed.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
