// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestVerifyChain_HappyPath confirms a clean MemoryBroker chain
// verifies OK after multiple OpenSession calls.
func TestVerifyChain_HappyPath(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := m.OpenSession(ctx, "user-"+itoa(i), "target-"+itoa(i), "", "ssh", "ctrl-1"); err != nil {
			t.Fatalf("OpenSession[%d]: %v", i, err)
		}
		// Tiny gap so the started_at ORDER BY tie-breaker isn't
		// exercised in the happy path (chain head selection stays
		// unambiguous).
		time.Sleep(time.Millisecond)
	}
	rep, err := m.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected OK=true, got breaks=%+v", rep.Breaks)
	}
	if rep.Total != 5 {
		t.Fatalf("expected total=5, got %d", rep.Total)
	}
	if rep.GenesisHash == "" || rep.HeadHash == "" {
		t.Fatalf("expected genesis + head hashes populated, got %+v", rep)
	}
}

// TestVerifyChain_RowMutation tampers a session's TargetID after
// insertion and confirms VerifyChain reports the mismatch.
func TestVerifyChain_RowMutation(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := m.OpenSession(ctx, "u", "t-"+itoa(i), "", "ssh", "c"); err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	// Pick any session and mutate target_id without rehashing.
	m.mu.Lock()
	var victimID string
	for id := range m.sessions {
		victimID = id
		break
	}
	v := m.sessions[victimID]
	v.TargetID = "tampered-" + v.TargetID
	m.sessions[victimID] = v
	m.mu.Unlock()
	rep, err := m.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.OK {
		t.Fatalf("expected OK=false after mutation")
	}
	if len(rep.Breaks) == 0 {
		t.Fatalf("expected at least one break")
	}
	// The tampered row should appear with row_hash_mismatch reason.
	found := false
	for _, b := range rep.Breaks {
		if b.SessionID == victimID && b.Reason == "row_hash_mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected row_hash_mismatch on %s, got %+v", victimID, rep.Breaks)
	}
}

// TestVerifyChain_DeletedRow drops a middle row and confirms the next
// row's prev_row_hash_mismatch is reported.
func TestVerifyChain_DeletedRow(t *testing.T) {
	m := NewMemoryBroker()
	ctx := context.Background()
	var middleID string
	for i := 0; i < 5; i++ {
		s, err := m.OpenSession(ctx, "u", "t-"+itoa(i), "", "ssh", "c")
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		if i == 2 {
			middleID = s.ID
		}
		time.Sleep(time.Millisecond)
	}
	m.mu.Lock()
	delete(m.sessions, middleID)
	m.mu.Unlock()
	rep, err := m.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.OK {
		t.Fatalf("expected OK=false after row deletion")
	}
	hasPrevMismatch := false
	for _, b := range rep.Breaks {
		if strings.Contains(b.Reason, "prev_row_hash") {
			hasPrevMismatch = true
			break
		}
	}
	if !hasPrevMismatch {
		t.Fatalf("expected prev_row_hash_mismatch break, got %+v", rep.Breaks)
	}
}

// TestComputeRowHash_Determinism: same inputs → same hash; any field
// change → different hash. Guards the canonicalisation against silent
// formula drift in future refactors.
func TestComputeRowHash_Determinism(t *testing.T) {
	t1 := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	a := ComputeRowHash("sess-1", "u", "t", t1, "")
	b := ComputeRowHash("sess-1", "u", "t", t1, "")
	if a != b {
		t.Fatalf("non-deterministic: %s vs %s", a, b)
	}
	// Changing any field changes the hash.
	cases := []struct {
		name string
		got  string
	}{
		{"id", ComputeRowHash("sess-2", "u", "t", t1, "")},
		{"subject", ComputeRowHash("sess-1", "u2", "t", t1, "")},
		{"target", ComputeRowHash("sess-1", "u", "t2", t1, "")},
		{"time", ComputeRowHash("sess-1", "u", "t", t1.Add(time.Second), "")},
		{"prev", ComputeRowHash("sess-1", "u", "t", t1, "deadbeef")},
	}
	for _, c := range cases {
		if c.got == a {
			t.Errorf("changing %s did NOT change hash", c.name)
		}
	}
}

// TestComputeRowHash_MicrosecondStable pins the fix for the Phase 5e-16
// chain-monitor false-positive. jit_sessions.started_at is Postgres
// `timestamptz` (microsecond resolution), but ComputeRowHash formats the
// time as RFC3339Nano. Hashing a full-nanosecond time.Now() at
// OpenSession and then recomputing from the µs-truncated value VerifyChain
// reads back yielded a row_hash_mismatch for any session whose clock
// carried sub-µs nanoseconds. OpenSession now truncates to µs before BOTH
// the hash and the INSERT, so the hashed value equals the DB read-back.
func TestComputeRowHash_MicrosecondStable(t *testing.T) {
	// A wall-clock instant carrying sub-microsecond nanoseconds, the way
	// time.Now() does in production.
	subMicro := time.Date(2026, 6, 22, 13, 14, 20, 391065678, time.UTC)
	// What Postgres stores for that instant and returns on read-back.
	dbReadBack := subMicro.Truncate(time.Microsecond)

	// Precondition (the bug): hashing the raw sub-µs time differs from the
	// recompute over the DB value — this is the mismatch VerifyChain saw.
	if ComputeRowHash("sess-1", "u", "t", subMicro, "") ==
		ComputeRowHash("sess-1", "u", "t", dbReadBack, "") {
		t.Fatal("precondition: sub-µs and µs-truncated times must hash differently")
	}
	// The fix: truncating to µs up front (as OpenSession now does) makes
	// the hashed value identical to what Postgres returns — stable across
	// the round trip.
	if ComputeRowHash("sess-1", "u", "t", subMicro.Truncate(time.Microsecond), "") !=
		ComputeRowHash("sess-1", "u", "t", dbReadBack, "") {
		t.Fatal("µs-truncated time must hash identically to the DB read-back value")
	}
}

func itoa(n int) string {
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
