// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// fakeSessionStore is a tiny in-memory SessionStore for unit tests so we
// don't need a real MemoryBroker (which would couple this file to the
// jit package's GrantStore surface).
type fakeSessionStore struct {
	mu   sync.Mutex
	rows []jit.Session
	seq  int
}

func (f *fakeSessionStore) seed(sub, target string, ended bool) jit.Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	s := jit.Session{
		ID: "sess-" + itoa(f.seq), Subject: sub, TargetID: target,
		Protocol: "ssh", StartedAt: time.Now().Add(-time.Hour),
	}
	if ended {
		t := time.Now().Add(-time.Minute)
		s.EndedAt = &t
		s.CloseReason = "ok"
	}
	f.rows = append(f.rows, s)
	return s
}

func (f *fakeSessionStore) OpenSession(_ context.Context, _, _, _, _, _ string) (jit.Session, error) {
	// Not used by handler tests.
	return jit.Session{}, nil
}
func (f *fakeSessionStore) CloseSession(_ context.Context, _, _ string) error { return nil }
func (f *fakeSessionStore) RecordBytes(_ context.Context, sessionID string, in, out int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rows {
		if f.rows[i].ID == sessionID {
			f.rows[i].BytesIn = in
			f.rows[i].BytesOut = out
		}
	}
	return nil
}
func (f *fakeSessionStore) SetRecordingPath(_ context.Context, sessionID, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.rows {
		if f.rows[i].ID == sessionID {
			f.rows[i].RecordingPath = path
		}
	}
	return nil
}
func (f *fakeSessionStore) ListSessions(_ context.Context, subject string, limit int) ([]jit.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []jit.Session{}
	for _, s := range f.rows {
		if subject != "" && s.Subject != subject {
			continue
		}
		out = append(out, s)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (f *fakeSessionStore) GetSession(_ context.Context, id string) (jit.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.rows {
		if s.ID == id {
			return s, nil
		}
	}
	return jit.Session{}, jit.ErrNoSession
}

// mkSH composes the full handler chain so the embedded delegation
// works end-to-end. Uses dummy CertSigner=nil so /operator-cert
// surfaces 503 if accidentally hit — tests target /sessions only.
func mkSH(t *testing.T, sessions *fakeSessionStore, id pdp.Identity) *SessionsHandler {
	t.Helper()
	base := New(&fakeStore{}, &fakeVerifier{id: id}, "platform_admin")
	rh := NewRequests(base, &fakeReqStore{})
	ch := NewCert(rh, nil)
	return NewSessions(ch, sessions)
}

func TestListSessionsRequiresAdminWithoutMine(t *testing.T) {
	fs := &fakeSessionStore{}
	fs.seed("u-1", "node-app-01", true)
	h := mkSH(t, fs, pdp.Identity{Subject: "u-2", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin without ?mine must 403, got %d", w.Code)
	}
}

func TestListSessionsMineFiltersToOwn(t *testing.T) {
	fs := &fakeSessionStore{}
	fs.seed("u-1", "node-app-01", true)
	fs.seed("u-1", "k8s-app-02", false) // active
	fs.seed("u-2", "k8s-other", false)
	h := mkSH(t, fs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions?mine=true", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	var out []SessionView
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 2 {
		t.Fatalf("u-1 must see 2 own sessions, got %d", len(out))
	}
	for _, s := range out {
		if s.Subject != "u-1" {
			t.Errorf("?mine=true leaked subject=%q", s.Subject)
		}
	}
}

func TestListSessionsAdminSeesAll(t *testing.T) {
	fs := &fakeSessionStore{}
	fs.seed("u-1", "node-app-01", true)
	fs.seed("u-2", "k8s-app-02", false)
	h := mkSH(t, fs, pdp.Identity{Subject: "admin-1", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	var out []SessionView
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 2 {
		t.Errorf("admin must see all sessions, got %d", len(out))
	}
}

func TestListSessionsActiveFlagAndDuration(t *testing.T) {
	fs := &fakeSessionStore{}
	closed := fs.seed("u-1", "node-app-01", true)
	active := fs.seed("u-1", "k8s-app-02", false)
	h := mkSH(t, fs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions?mine=true", ""))
	var out []SessionView
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	var foundClosed, foundActive bool
	for _, s := range out {
		switch s.ID {
		case closed.ID:
			foundClosed = true
			if s.Active {
				t.Errorf("closed session must NOT have active=true")
			}
			if s.DurationSeconds <= 0 {
				t.Errorf("closed session duration must be positive: %d", s.DurationSeconds)
			}
		case active.ID:
			foundActive = true
			if !s.Active {
				t.Errorf("active session must have active=true")
			}
			if s.EndedAt != nil {
				t.Errorf("active session must NOT have ended_at")
			}
		}
	}
	if !foundClosed || !foundActive {
		t.Errorf("missing rows: closed=%v active=%v", foundClosed, foundActive)
	}
}

func TestGetSessionOwnerCanReadOwn(t *testing.T) {
	fs := &fakeSessionStore{}
	sess := fs.seed("u-1", "node-app-01", true)
	h := mkSH(t, fs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions/"+sess.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("owner must read own session: %d", w.Code)
	}
}

func TestGetSessionNonOwnerGets404(t *testing.T) {
	fs := &fakeSessionStore{}
	sess := fs.seed("u-1", "node-app-01", true)
	h := mkSH(t, fs, pdp.Identity{Subject: "u-2", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions/"+sess.ID, ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("non-owner non-admin MUST 404 (privacy), got %d", w.Code)
	}
}

func TestSessionsHandlerFallsThroughToCertAndRequests(t *testing.T) {
	// Regression: layering on /sessions must not break the existing
	// /requests + /grants + /operator-cert chain underneath.
	fs := &fakeSessionStore{}
	h := mkSH(t, fs, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants", `{"subject":"u-1","target_id":"t","ttl_seconds":60}`))
	if w.Code != http.StatusCreated {
		t.Errorf("expected /grants to still work under /sessions overlay, got %d", w.Code)
	}
}

func TestListSessionsUnavailableWithoutStore(t *testing.T) {
	// nil session store — handler returns 503 with a descriptive body
	// rather than silently returning [].
	base := New(&fakeStore{}, &fakeVerifier{id: pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}}}, "platform_admin")
	rh := NewRequests(base, &fakeReqStore{})
	ch := NewCert(rh, nil)
	h := NewSessions(ch, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/sessions?mine=true", ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("nil SessionStore must 503, got %d", w.Code)
	}
}
