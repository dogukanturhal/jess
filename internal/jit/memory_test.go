// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"testing"
)

// Phase 5e-6 session-store tests against the in-memory broker. The
// PostgresStore parallels these against a real database via the
// existing docker-gated postgres_test.go pattern.

func TestMemorySessionOpenInsertsRow(t *testing.T) {
	m := NewMemoryBroker()
	sess, err := m.OpenSession(context.Background(), "u-1", "node-app-01", "g-1", "ssh", "ctrl-pod-0")
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if sess.ID == "" || sess.Subject != "u-1" || sess.TargetID != "node-app-01" {
		t.Errorf("session fields wrong: %+v", sess)
	}
	if sess.EndedAt != nil {
		t.Errorf("freshly-opened session must NOT have ended_at set")
	}
	if sess.ControllerID != "ctrl-pod-0" {
		t.Errorf("controller id not propagated: %q", sess.ControllerID)
	}
}

func TestMemorySessionCloseIsIdempotent(t *testing.T) {
	m := NewMemoryBroker()
	sess, _ := m.OpenSession(context.Background(), "u-1", "t", "g", "ssh", "")
	// First close should set ended_at.
	if err := m.CloseSession(context.Background(), sess.ID, "ok"); err != nil {
		t.Fatalf("first close: %v", err)
	}
	// Second close must be a no-op (no error, no double-close).
	if err := m.CloseSession(context.Background(), sess.ID, "ok"); err != nil {
		t.Errorf("second close must be no-op no-err, got %v", err)
	}
	// Close on unknown id is also a no-op.
	if err := m.CloseSession(context.Background(), "sess-does-not-exist", "ok"); err != nil {
		t.Errorf("close-unknown must be no-op no-err, got %v", err)
	}
}

func TestMemorySessionListFiltersBySubject(t *testing.T) {
	m := NewMemoryBroker()
	m.OpenSession(context.Background(), "u-1", "t-a", "g-1", "ssh", "")
	m.OpenSession(context.Background(), "u-1", "t-b", "g-2", "ssh", "")
	m.OpenSession(context.Background(), "u-2", "t-c", "g-3", "ssh", "")

	out, err := m.ListSessions(context.Background(), "u-1", 10)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("u-1 should see 2 sessions, got %d", len(out))
	}
	for _, s := range out {
		if s.Subject != "u-1" {
			t.Errorf("filter leaked subject=%q", s.Subject)
		}
	}
}

func TestMemorySessionListEmptySubjectReturnsAll(t *testing.T) {
	m := NewMemoryBroker()
	m.OpenSession(context.Background(), "u-1", "t", "g", "ssh", "")
	m.OpenSession(context.Background(), "u-2", "t", "g", "ssh", "")
	out, _ := m.ListSessions(context.Background(), "", 10)
	if len(out) != 2 {
		t.Errorf("empty subject filter should return all rows, got %d", len(out))
	}
}

func TestMemorySessionGetReturnsErrNoSession(t *testing.T) {
	m := NewMemoryBroker()
	_, err := m.GetSession(context.Background(), "sess-nonexistent")
	if err != ErrNoSession {
		t.Errorf("missing id must return ErrNoSession, got %v", err)
	}
}

func TestMemorySessionSetRecordingPath(t *testing.T) {
	// Phase 5e-7: controller stamps the deterministic bundle key after
	// OpenSession. Must persist + survive a subsequent CloseSession.
	m := NewMemoryBroker()
	sess, _ := m.OpenSession(context.Background(), "u-1", "node-app-01", "g", "ssh", "")
	if err := m.SetRecordingPath(context.Background(), sess.ID, sess.ID+"/recording.cast"); err != nil {
		t.Fatalf("SetRecordingPath: %v", err)
	}
	got, _ := m.GetSession(context.Background(), sess.ID)
	if got.RecordingPath != sess.ID+"/recording.cast" {
		t.Errorf("recording_path not stamped: %q", got.RecordingPath)
	}
	// Close should keep the path intact (it's set BEFORE close).
	_ = m.CloseSession(context.Background(), sess.ID, "ok")
	got2, _ := m.GetSession(context.Background(), sess.ID)
	if got2.RecordingPath != sess.ID+"/recording.cast" {
		t.Errorf("close clobbered recording_path: %q", got2.RecordingPath)
	}
}

func TestMemorySessionRecordBytes(t *testing.T) {
	// Phase 5e-10: controller stamps final byte counts at teardown.
	// Idempotent (absolute totals not deltas) so a retry doesn't
	// double-count.
	m := NewMemoryBroker()
	sess, _ := m.OpenSession(context.Background(), "u-1", "t", "g", "ssh", "")
	if err := m.RecordBytes(context.Background(), sess.ID, 1024, 4096); err != nil {
		t.Fatalf("RecordBytes: %v", err)
	}
	got, _ := m.GetSession(context.Background(), sess.ID)
	if got.BytesIn != 1024 || got.BytesOut != 4096 {
		t.Errorf("bytes not stamped: in=%d out=%d", got.BytesIn, got.BytesOut)
	}
	// Idempotent — second call with same values stays at totals.
	_ = m.RecordBytes(context.Background(), sess.ID, 1024, 4096)
	got2, _ := m.GetSession(context.Background(), sess.ID)
	if got2.BytesIn != 1024 {
		t.Errorf("idempotent re-record corrupted bytes: %d", got2.BytesIn)
	}
}

func TestMemorySessionRecordBytesUnknownIsNoop(t *testing.T) {
	m := NewMemoryBroker()
	if err := m.RecordBytes(context.Background(), "sess-nonexistent", 100, 200); err != nil {
		t.Errorf("unknown id must be no-op no-err, got %v", err)
	}
}

func TestMemorySessionSetRecordingPathUnknownIsNoop(t *testing.T) {
	// Idempotency: unknown id must be a no-op + nil err, matching
	// CloseSession's posture so the controller's teardown path is
	// uniform.
	m := NewMemoryBroker()
	if err := m.SetRecordingPath(context.Background(), "sess-does-not-exist", "x"); err != nil {
		t.Errorf("unknown id must be no-op no-err, got %v", err)
	}
}

func TestMemorySessionListSortsByStartedDesc(t *testing.T) {
	// Ensure the SPA-facing order is newest-first regardless of insert
	// order — matches the PostgresStore's ORDER BY started_at DESC.
	m := NewMemoryBroker()
	first, _ := m.OpenSession(context.Background(), "u-1", "t-1", "g", "ssh", "")
	// Force a small timestamp gap so the sort has something to act on.
	first.StartedAt = first.StartedAt.Add(-2)
	m.sessions[first.ID] = first
	second, _ := m.OpenSession(context.Background(), "u-1", "t-2", "g", "ssh", "")

	out, _ := m.ListSessions(context.Background(), "u-1", 10)
	if len(out) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(out))
	}
	if out[0].ID != second.ID {
		t.Errorf("newest first ordering broken: got %s expected %s", out[0].ID, second.ID)
	}
}
