// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fetchOpenSessionForOperator semantics:
//
//   - mine=true filter on the controller is the auth gate; jess-web
//     filters in-memory to (target, grant, active=true) and picks newest.
//   - On 0 matches, returns nil (caller emits a degraded meta frame).
//   - On controller error / non-OK status, returns nil (fail-open).

func TestFetchOpenSessionPicksMatchingActiveRow(t *testing.T) {
	// Controller returns 3 rows: one closed for same target+grant, one
	// active for different target, one active matching. fetchOpenSession
	// must pick the matching active row.
	rows := []SessionView{
		{ID: "sess-old", TargetID: "node-app-01", GrantID: "g-1", Active: false, StartedAt: "2026-05-31T13:00:00Z"},
		{ID: "sess-other", TargetID: "k8s-other", GrantID: "g-1", Active: true, StartedAt: "2026-05-31T14:00:00Z"},
		{ID: "sess-match", TargetID: "node-app-01", GrantID: "g-1", Active: true, StartedAt: "2026-05-31T14:30:00Z",
			RecordingPath: "sess-match/recording.cast", Protocol: "ssh", ControllerID: "ctrl-pod-0"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	g := newGrantsClient(srv.URL, nil, newSessionStore())

	got := fetchOpenSessionForOperator(context.Background(), g, "tok", "node-app-01", "g-1")
	if got == nil {
		t.Fatal("expected match, got nil")
	}
	if got.ID != "sess-match" {
		t.Errorf("picked wrong row: %s", got.ID)
	}
	if got.RecordingPath == "" {
		t.Errorf("recording_path should pass through: %+v", got)
	}
}

func TestFetchOpenSessionNoMatchReturnsNil(t *testing.T) {
	rows := []SessionView{
		{ID: "sess-x", TargetID: "k8s-other", GrantID: "g-x", Active: true, StartedAt: "2026-05-31T14:00:00Z"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	g := newGrantsClient(srv.URL, nil, newSessionStore())
	if got := fetchOpenSessionForOperator(context.Background(), g, "tok", "node-app-01", "g-1"); got != nil {
		t.Errorf("expected nil for no match, got %+v", got)
	}
}

func TestFetchOpenSessionUpstreamErrorReturnsNil(t *testing.T) {
	// Closed listener — connection refused. fetchOpenSession must
	// fail-open with nil so emitSessionMeta still sends the degraded
	// frame instead of crashing or hanging the bridge.
	g := newGrantsClient("http://127.0.0.1:1", nil, newSessionStore())
	got := fetchOpenSessionForOperator(context.Background(), g, "tok", "t", "g")
	if got != nil {
		t.Errorf("upstream error must yield nil, got %+v", got)
	}
}

func TestFetchOpenSessionIgnoresClosedRowForSameTargetGrant(t *testing.T) {
	// Operator closed a session, reopened with same grant + same target.
	// Controller has both rows. fetchOpenSession must pick the active
	// one even though the closed one is "matching" by target+grant.
	rows := []SessionView{
		{ID: "sess-closed", TargetID: "t", GrantID: "g", Active: false, StartedAt: "2026-05-31T14:00:00Z"},
		{ID: "sess-active", TargetID: "t", GrantID: "g", Active: true, StartedAt: "2026-05-31T14:05:00Z"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	g := newGrantsClient(srv.URL, nil, newSessionStore())
	got := fetchOpenSessionForOperator(context.Background(), g, "tok", "t", "g")
	if got == nil || got.ID != "sess-active" {
		t.Errorf("must pick active over closed: got %+v", got)
	}
}

// captureWriteFrame intercepts the bridge's writeFrame to assert the
// metadata payload without standing up a real WebSocket.
type capturedFrame struct {
	typ  int
	body []byte
}

func TestEmitSessionMetaSendsTextFrameWithRowData(t *testing.T) {
	rows := []SessionView{
		{ID: "sess-abc123", TargetID: "node-app-01", GrantID: "g-1", Active: true,
			StartedAt: "2026-05-31T14:30:00Z", RecordingPath: "sess-abc123/recording.cast", Protocol: "ssh"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(srv.Close)
	g := newGrantsClient(srv.URL, nil, newSessionStore())

	var mu sync.Mutex
	var frames []capturedFrame
	writeFrame := func(typ int, b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		buf := make([]byte, len(b))
		copy(buf, b)
		frames = append(frames, capturedFrame{typ: typ, body: buf})
		return nil
	}
	op := &Operator{Subject: "u-1", Email: "u1@hexxlock.com", Token: "tok"}
	emitSessionMeta(context.Background(), writeFrame, g, op, "node-app-01", "g-1")

	mu.Lock()
	defer mu.Unlock()
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].typ != 1 { // websocket.TextMessage == 1
		t.Errorf("expected TextMessage(1), got %d", frames[0].typ)
	}
	var got SessionMeta
	if err := json.Unmarshal(frames[0].body, &got); err != nil {
		t.Fatalf("frame body is not JSON: %v body=%s", err, frames[0].body)
	}
	if got.Type != "session_meta" {
		t.Errorf("type=%q, want session_meta", got.Type)
	}
	if got.SessionID != "sess-abc123" {
		t.Errorf("session_id=%q, want sess-abc123", got.SessionID)
	}
	if got.RecordingPath != "sess-abc123/recording.cast" {
		t.Errorf("recording_path=%q", got.RecordingPath)
	}
	if got.OperatorEmail != "u1@hexxlock.com" {
		t.Errorf("operator_email=%q", got.OperatorEmail)
	}
}

func TestEmitSessionMetaSendsDegradedFrameOnFetchMiss(t *testing.T) {
	// Controller returns empty list — every fetch misses. emitSessionMeta
	// must STILL send a frame (degraded — empty session_id) so the SPA
	// flips from "pending…" to a stable "unavailable" state rather than
	// hanging on "pending…" forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	t.Cleanup(srv.Close)
	g := newGrantsClient(srv.URL, nil, newSessionStore())

	var mu sync.Mutex
	var frames []capturedFrame
	writeFrame := func(typ int, b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		frames = append(frames, capturedFrame{typ: typ, body: append([]byte(nil), b...)})
		return nil
	}
	op := &Operator{Subject: "u-1", Email: "u1@hexxlock.com", Token: "tok"}
	// Use a short ctx so the test doesn't wait the full 550ms.
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	emitSessionMeta(ctx, writeFrame, g, op, "t", "g")

	mu.Lock()
	defer mu.Unlock()
	if len(frames) != 1 {
		t.Fatalf("must still send degraded frame, got %d frames", len(frames))
	}
	var got SessionMeta
	_ = json.Unmarshal(frames[0].body, &got)
	if got.Type != "session_meta" {
		t.Errorf("degraded frame still must have type=session_meta")
	}
	if got.SessionID != "" {
		t.Errorf("degraded frame must have empty session_id, got %q", got.SessionID)
	}
	if got.TargetID != "t" || got.GrantID != "g" {
		t.Errorf("degraded frame must carry operator-side fields: %+v", got)
	}
}
