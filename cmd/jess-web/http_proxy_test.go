// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 5h-3b — smoke tests for the jess-web HTTP proxy handler.
//
// Covers:
//   1. config parsing of JESS_HTTP_PROXY_TARGETS (good entries + malformed)
//   2. 401 when no operator session cookie
//   3. 404 when service not in the configured map
//   4. 503 when no recorder wired (recording is mandatory)
//   5. happy path: reverse-proxies to an upstream test server + records
//      one HTTPTransaction NDJSON line to the recorder.
//
// The recorder mock writes to an in-memory buffer; the test asserts the
// recorded line contains the expected method/url/status fields. This is
// purely a unit test — no MinIO, no real Vault, no real upstream.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/recording"
)

// memRecorder is an in-process recording.Recorder that appends every
// Write/Close into a single bytes.Buffer keyed by session.ID. Good
// enough to assert "the transaction was recorded with field X".
type memRecorder struct {
	mu       sync.Mutex
	sessions map[string]*memSession
}

type memSession struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool
}

func (m *memSession) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.buf.Write(p)
}

func (m *memSession) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func newMemRecorder() *memRecorder { return &memRecorder{sessions: map[string]*memSession{}} }

func (m *memRecorder) Open(_ context.Context, meta recording.Meta) (io.WriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &memSession{}
	m.sessions[meta.SessionID] = s
	return s, nil
}

func TestNewHTTPProxyConfig_ParsesTargets(t *testing.T) {
	t.Setenv("JESS_HTTP_PROXY_TARGETS", "grafana=grafana.monitoring.svc:80,alertmgr=https://alertmanager.monitoring.svc:9093,bad-no-equals,empty=")
	c := newHTTPProxyConfig(newMemRecorder())
	if got := len(c.targets); got != 2 {
		t.Fatalf("targets parsed = %d, want 2 (malformed entries should drop silently)", got)
	}
	if c.targets["grafana"].String() != "http://grafana.monitoring.svc:80" {
		t.Errorf("grafana = %q, want http-defaulted", c.targets["grafana"].String())
	}
	if c.targets["alertmgr"].Scheme != "https" {
		t.Errorf("alertmgr scheme = %q, want https", c.targets["alertmgr"].Scheme)
	}
}

func TestHTTPProxy_Returns401WhenNoSession(t *testing.T) {
	c := newHTTPProxyConfig(newMemRecorder())
	sessions := &sessionStore{by: map[string]*Operator{}}
	h := c.handleProxy(sessions)

	req := httptest.NewRequest("GET", "/proxy/grafana/api/health", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestHTTPProxy_Returns503WhenNoRecorder(t *testing.T) {
	c := newHTTPProxyConfig(nil) // explicit: no recorder
	sessions := &sessionStore{by: map[string]*Operator{"sess": {Subject: "alice", Expires: time.Now().Add(time.Hour)}}}
	h := c.handleProxy(sessions)

	req := httptest.NewRequest("GET", "/proxy/grafana/api/health", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sess"})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (recording mandatory)", rec.Code)
	}
}

func TestHTTPProxy_Returns404OnUnknownService(t *testing.T) {
	// No JESS_HTTP_PROXY_TARGETS set → empty service map, every
	// /proxy/<service>/... hit should 404.
	c := newHTTPProxyConfig(newMemRecorder())
	sessions := &sessionStore{by: map[string]*Operator{"sess": {Subject: "alice", Expires: time.Now().Add(time.Hour)}}}
	h := c.handleProxy(sessions)

	req := httptest.NewRequest("GET", "/proxy/nope/api/health", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sess"})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHTTPProxy_ReverseProxiesAndRecords(t *testing.T) {
	// Spin a tiny upstream that returns a known body so we can assert
	// the proxy passed it through AND recorded it.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-User") != "alice" {
			t.Errorf("upstream X-Forwarded-User = %q, want alice", r.Header.Get("X-Forwarded-User"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	t.Setenv("JESS_HTTP_PROXY_TARGETS", "grafana="+strings.TrimPrefix(upstream.URL, "http://"))
	rec := newMemRecorder()
	c := newHTTPProxyConfig(rec)
	if len(c.targets) != 1 {
		t.Fatalf("targets = %d, want 1 (upstream URL not parsed?)", len(c.targets))
	}
	sessions := &sessionStore{by: map[string]*Operator{"sess": {Subject: "alice", Expires: time.Now().Add(time.Hour)}}}
	h := c.handleProxy(sessions)

	req := httptest.NewRequest("GET", "/proxy/grafana/api/health", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "sess"})
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Errorf("body = %q, want upstream JSON passed through", rr.Body.String())
	}
	// Assert the recording captured one transaction with the right shape.
	if len(rec.sessions) != 1 {
		t.Fatalf("recorded sessions = %d, want 1", len(rec.sessions))
	}
	var line []byte
	for _, s := range rec.sessions {
		line = s.buf.Bytes()
	}
	var tx recording.HTTPTransaction
	if err := json.Unmarshal(bytes.TrimSpace(line), &tx); err != nil {
		t.Fatalf("recorded line not valid HTTPTransaction JSON: %v\n%s", err, line)
	}
	if tx.Method != "GET" || tx.URL != "/proxy/grafana/api/health" || tx.Status != 200 {
		t.Errorf("recorded tx = %+v, want GET /proxy/grafana/api/health 200", tx)
	}
	if tx.OperatorSub != "alice" {
		t.Errorf("recorded tx.OperatorSub = %q, want alice", tx.OperatorSub)
	}
}
