// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// fakeStore is an in-memory jit Store with predictable IDs for tests.
type fakeStore struct {
	mu     sync.Mutex
	grants []jit.Grant
	seq    int
	revoke func(string) error // override for revoke-error scenarios
}

func (f *fakeStore) Issue(_ context.Context, sub, target string, ttl time.Duration) (jit.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	g := jit.Grant{
		ID: "g-" + itoa(f.seq), Subject: sub, TargetID: target,
		ApprovedBy: "system:issue",
		IssuedAt:   time.Now(), ExpiresAt: time.Now().Add(ttl),
	}
	f.grants = append(f.grants, g)
	return g, nil
}

func (f *fakeStore) List(_ context.Context, target string) ([]jit.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if target == "" {
		out := make([]jit.Grant, len(f.grants))
		copy(out, f.grants)
		return out, nil
	}
	var out []jit.Grant
	for _, g := range f.grants {
		if g.TargetID == target {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeStore) Revoke(_ context.Context, id string) error {
	if f.revoke != nil {
		return f.revoke(id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, g := range f.grants {
		if g.ID == id {
			f.grants = append(f.grants[:i], f.grants[i+1:]...)
			return nil
		}
	}
	return jit.ErrNoGrant
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	bp := len(b)
	for n > 0 {
		bp--
		b[bp] = byte('0' + n%10)
		n /= 10
	}
	return string(b[bp:])
}

// fakeVerifier returns whatever Identity the caller staged via With.
type fakeVerifier struct {
	id  pdp.Identity
	err error
}

func (f *fakeVerifier) Verify(_ context.Context, _ string) (pdp.Identity, error) {
	return f.id, f.err
}

func mkH(t *testing.T, store Store, id pdp.Identity) *Handler {
	t.Helper()
	return New(store, &fakeVerifier{id: id}, "platform_admin")
}

func bearerReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

func TestIssueAllowsAdmin(t *testing.T) {
	store := &fakeStore{}
	h := mkH(t, store, pdp.Identity{Subject: "admin-sub", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants",
		`{"subject":"u-1","target_id":"node-app-01","ttl_seconds":1800}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	var v GrantView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v.Subject != "u-1" || v.TargetID != "node-app-01" {
		t.Errorf("response payload mismatch: %+v", v)
	}
	if v.ApprovedBy != "sub:admin-sub" {
		t.Errorf("approved_by must be the verified caller's sub, got %q", v.ApprovedBy)
	}
}

func TestIssueRejectsNonAdmin(t *testing.T) {
	store := &fakeStore{}
	h := mkH(t, store, pdp.Identity{Subject: "ops-1", Roles: []string{"operator"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants",
		`{"subject":"u-1","target_id":"node-app-01","ttl_seconds":1800}`))
	if w.Code != http.StatusForbidden {
		t.Errorf("non-admin must get 403, got %d", w.Code)
	}
	if len(store.grants) != 0 {
		t.Error("non-admin must NOT create a grant")
	}
}

func TestIssueRejectsBadBody(t *testing.T) {
	h := mkH(t, &fakeStore{}, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	for _, tc := range []struct {
		name, body string
	}{
		{"missing sub", `{"target_id":"t","ttl_seconds":60}`},
		{"missing target", `{"subject":"s","ttl_seconds":60}`},
		{"zero ttl", `{"subject":"s","target_id":"t","ttl_seconds":0}`},
		{"negative ttl", `{"subject":"s","target_id":"t","ttl_seconds":-1}`},
		{"ttl > 24h", `{"subject":"s","target_id":"t","ttl_seconds":86401}`},
		{"bad json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, bearerReq("POST", "/grants", tc.body))
			if w.Code != http.StatusBadRequest {
				t.Errorf("got %d", w.Code)
			}
		})
	}
}

func TestListFiltersByTarget(t *testing.T) {
	store := &fakeStore{}
	_, _ = store.Issue(context.Background(), "u-1", "t-a", time.Hour)
	_, _ = store.Issue(context.Background(), "u-2", "t-b", time.Hour)
	_, _ = store.Issue(context.Background(), "u-3", "t-a", time.Hour)
	h := mkH(t, store, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/grants", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("list all: %d", w.Code)
	}
	var all []GrantView
	_ = json.Unmarshal(w.Body.Bytes(), &all)
	if len(all) != 3 {
		t.Errorf("list all: got %d want 3", len(all))
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/grants?target=t-a", ""))
	var aOnly []GrantView
	_ = json.Unmarshal(w.Body.Bytes(), &aOnly)
	if len(aOnly) != 2 {
		t.Errorf("list target=t-a: got %d want 2", len(aOnly))
	}
}

func TestRevokeRemovesGrant(t *testing.T) {
	store := &fakeStore{}
	g, _ := store.Issue(context.Background(), "u", "t", time.Hour)
	h := mkH(t, store, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("DELETE", "/grants/"+g.ID, ""))
	if w.Code != http.StatusNoContent {
		t.Errorf("got %d body=%s", w.Code, w.Body.String())
	}
	if len(store.grants) != 0 {
		t.Error("grant should be revoked")
	}
}

func TestRevokeMissingReturns404(t *testing.T) {
	store := &fakeStore{revoke: func(string) error { return jit.ErrNoGrant }}
	h := mkH(t, store, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("DELETE", "/grants/missing", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d", w.Code)
	}
}

func TestRevokeStoreErrorReturns500(t *testing.T) {
	store := &fakeStore{revoke: func(string) error { return errors.New("boom") }}
	h := mkH(t, store, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("DELETE", "/grants/x", ""))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("got %d", w.Code)
	}
}

func TestRejectsMissingBearer(t *testing.T) {
	h := mkH(t, &fakeStore{}, pdp.Identity{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/grants", bytes.NewReader(nil)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d", w.Code)
	}
}

func TestRejectsBadToken(t *testing.T) {
	store := &fakeStore{}
	h := New(store, &fakeVerifier{err: errors.New("bad sig")}, "platform_admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants",
		`{"subject":"u","target_id":"t","ttl_seconds":60}`))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d", w.Code)
	}
}

func TestDefaultsAdminRole(t *testing.T) {
	store := &fakeStore{}
	h := New(store, &fakeVerifier{id: pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}}}, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants",
		`{"subject":"u","target_id":"t","ttl_seconds":60}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("empty adminRole must default to platform_admin (got %d)", w.Code)
	}
}
