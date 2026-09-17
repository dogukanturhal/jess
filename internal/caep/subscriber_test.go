// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRevoker counts RevokeBySubject calls and lets each return a
// configurable count + err.
type fakeRevoker struct {
	mu     sync.Mutex
	calls  []string
	retCnt int
	retErr error
	signal chan string // signals AFTER revoker call so tests can wait
}

func (f *fakeRevoker) RevokeBySubject(_ context.Context, sub string) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, sub)
	cnt := f.retCnt
	err := f.retErr
	f.mu.Unlock()
	if f.signal != nil {
		f.signal <- sub
	}
	return cnt, err
}

func (f *fakeRevoker) callsCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type fakeTokenSource struct{ tok string }

func (f fakeTokenSource) Token(_ context.Context) (string, error) { return f.tok, nil }

type fakeMetrics struct {
	mu       sync.Mutex
	received map[string]int
	revoked  []struct {
		eventType string
		count     int
	}
	reconnects  int
	subFailures []string
}

func (m *fakeMetrics) CAEPEventReceived(t string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.received == nil {
		m.received = map[string]int{}
	}
	m.received[t]++
}
func (m *fakeMetrics) CAEPRevocation(t string, c int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked = append(m.revoked, struct {
		eventType string
		count     int
	}{t, c})
}
func (m *fakeMetrics) CAEPReconnect() { m.mu.Lock(); m.reconnects++; m.mu.Unlock() }
func (m *fakeMetrics) CAEPSubscribeFailure(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subFailures = append(m.subFailures, reason)
}

// sseServer builds an httptest server that streams the given frames
// in order, then closes when ctx cancels or all frames sent.
func sseServer(t *testing.T, frames []string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("test server doesn't support flusher")
			return
		}
		for _, f := range frames {
			_, _ = fmt.Fprintf(w, "%s\n\n", f)
			flusher.Flush()
		}
		// Block until ctx done so the subscriber doesn't immediately reconnect.
		<-r.Context().Done()
	}))
}

func TestSubscriber_ActionableEventTriggersRevoke(t *testing.T) {
	revoker := &fakeRevoker{retCnt: 2, signal: make(chan string, 4)}
	metrics := &fakeMetrics{}
	srv := sseServer(t, []string{
		`data: {"type":"session_revoked","user_id":"alice","tenant_id":"hexxlock","timestamp":"2026-06-01T10:00:00Z"}`,
		`data: {"type":"password_changed","user_id":"bob","tenant_id":"hexxlock","timestamp":"2026-06-01T10:00:01Z"}`,
		// Non-actionable type — should be received-metric'd but not revoked.
		`data: {"type":"ip_changed","user_id":"charlie","tenant_id":"hexxlock","timestamp":"2026-06-01T10:00:02Z"}`,
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sub := &Subscriber{
		EndpointURL: srv.URL,
		Token:       fakeTokenSource{tok: "test"},
		Revoker:     revoker,
		Metrics:     metrics,
	}
	go sub.Run(ctx)

	// Wait for two revoke calls.
	got := []string{}
	timeout := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case sub := <-revoker.signal:
			got = append(got, sub)
		case <-timeout:
			t.Fatalf("timed out waiting for revokes; got=%v", got)
		}
	}
	// Poll briefly for the ip_changed metric — the non-actionable
	// frame may still be in the SSE pump after the revoke signals
	// land; under `-race -p 1` CI the cancel can fire before the
	// 3rd frame is consumed. Bounded wait so the test fails loud if
	// the frame really never arrives.
	deadline := time.Now().Add(2 * time.Second)
	for {
		metrics.mu.Lock()
		ip := metrics.received["ip_changed"]
		metrics.mu.Unlock()
		if ip >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ip_changed never reached the metric after revokes settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	if calls := revoker.callsCopy(); len(calls) != 2 {
		t.Errorf("revoke calls = %v, want 2 (alice + bob)", calls)
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.received["session_revoked"] != 1 {
		t.Errorf("received[session_revoked] = %d, want 1", metrics.received["session_revoked"])
	}
	if metrics.received["ip_changed"] != 1 {
		t.Errorf("received[ip_changed] = %d (non-actionable still counted)", metrics.received["ip_changed"])
	}
	if len(metrics.revoked) != 2 {
		t.Errorf("revoked entries = %d, want 2", len(metrics.revoked))
	}
}

func TestSubscriber_HandlesBadJSON(t *testing.T) {
	revoker := &fakeRevoker{signal: make(chan string, 2)}
	srv := sseServer(t, []string{
		`data: this is not json`,
		`data: {"type":"session_revoked","user_id":"alice","tenant_id":"hexxlock","timestamp":"2026-06-01T10:00:00Z"}`,
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sub := &Subscriber{
		EndpointURL: srv.URL,
		Token:       fakeTokenSource{tok: "test"},
		Revoker:     revoker,
	}
	go sub.Run(ctx)
	select {
	case sub := <-revoker.signal:
		if sub != "alice" {
			t.Errorf("subject = %q, want alice", sub)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("bad JSON should be skipped, then alice should revoke")
	}
}

func TestSubscriber_EmptyUserIDSkipsRevoke(t *testing.T) {
	revoker := &fakeRevoker{signal: make(chan string, 1)}
	metrics := &fakeMetrics{}
	srv := sseServer(t, []string{
		`data: {"type":"session_revoked","user_id":"","tenant_id":"hexxlock","timestamp":"2026-06-01T10:00:00Z"}`,
	})
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	sub := &Subscriber{
		EndpointURL: srv.URL,
		Token:       fakeTokenSource{tok: "test"},
		Revoker:     revoker,
		Metrics:     metrics,
	}
	go sub.Run(ctx)
	<-ctx.Done()
	if calls := revoker.callsCopy(); len(calls) > 0 {
		t.Errorf("empty user_id revoke should skip; got calls=%v", calls)
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.received["session_revoked"] != 1 {
		t.Errorf("event still counted; received=%v", metrics.received)
	}
}

func TestSubscriber_AuthFailureRecorded(t *testing.T) {
	calls := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unauth", http.StatusUnauthorized)
	}))
	defer srv.Close()
	metrics := &fakeMetrics{}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	sub := &Subscriber{
		EndpointURL: srv.URL,
		Token:       fakeTokenSource{tok: "test"},
		Revoker:     &fakeRevoker{},
		Metrics:     metrics,
		Backoff:     100 * time.Millisecond,
	}
	go sub.Run(ctx)
	<-ctx.Done()

	if calls.Load() < 2 {
		t.Errorf("expected at least 2 reconnect attempts after 401, got %d", calls.Load())
	}
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if metrics.reconnects < 1 {
		t.Errorf("reconnects = %d, want >=1", metrics.reconnects)
	}
	found := false
	for _, r := range metrics.subFailures {
		if r == "http_401" {
			found = true
		}
	}
	if !found {
		t.Errorf("subFailures = %v, want http_401", metrics.subFailures)
	}
}
