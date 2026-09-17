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

type fakeReqStore struct {
	mu      sync.Mutex
	rows    []jit.Request
	seq     int
	denyErr error
}

func (f *fakeReqStore) Submit(_ context.Context, sub, target, reason string, ttl time.Duration) (jit.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	r := jit.Request{
		ID: "r-" + itoa(f.seq), Subject: sub, TargetID: target, Reason: reason,
		RequestedAt: time.Now(), State: jit.RequestPending,
		ExpiresAt: time.Now().Add(ttl),
	}
	if ttl == 0 {
		r.ExpiresAt = time.Now().Add(4 * time.Hour)
	}
	f.rows = append(f.rows, r)
	return r, nil
}

func (f *fakeReqStore) GetRequest(_ context.Context, id string) (jit.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.rows {
		if r.ID == id {
			return r, nil
		}
	}
	return jit.Request{}, jit.ErrNoRequest
}

func (f *fakeReqStore) ListRequests(_ context.Context, state jit.RequestState) ([]jit.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if state == "" {
		out := make([]jit.Request, len(f.rows))
		copy(out, f.rows)
		return out, nil
	}
	var out []jit.Request
	for _, r := range f.rows {
		if r.State == state {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeReqStore) Approve(_ context.Context, id, approver string, ttl time.Duration) (jit.Request, jit.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.rows {
		if r.ID == id {
			if r.State != jit.RequestPending {
				return jit.Request{}, jit.Grant{}, jit.ErrRequestNotPending
			}
			g := jit.Grant{ID: "g-from-" + id, Subject: r.Subject, TargetID: r.TargetID,
				ApprovedBy: "sub:" + approver, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(ttl)}
			now := time.Now()
			f.rows[i].State = jit.RequestApproved
			f.rows[i].DecidedBy = approver
			f.rows[i].DecidedAt = now
			f.rows[i].GrantID = g.ID
			f.rows[i].ExpiresAt = g.ExpiresAt // Phase 5e-11: row carries grant's expiry post-approval
			return f.rows[i], g, nil
		}
	}
	return jit.Request{}, jit.Grant{}, jit.ErrNoRequest
}

func (f *fakeReqStore) Deny(_ context.Context, id, denier, reason string) (jit.Request, error) {
	if f.denyErr != nil {
		return jit.Request{}, f.denyErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.rows {
		if r.ID == id {
			if r.State != jit.RequestPending {
				return jit.Request{}, jit.ErrRequestNotPending
			}
			f.rows[i].State = jit.RequestDenied
			f.rows[i].DecidedBy = denier
			f.rows[i].DecidedAt = time.Now()
			f.rows[i].DecidedReason = reason
			return f.rows[i], nil
		}
	}
	return jit.Request{}, jit.ErrNoRequest
}

func mkRH(t *testing.T, gs Store, rs RequestStore, id pdp.Identity) *RequestsHandler {
	t.Helper()
	base := New(gs, &fakeVerifier{id: id}, "platform_admin")
	return NewRequests(base, rs)
}

func TestSubmitRequiresAuthOnly(t *testing.T) {
	gs := &fakeStore{}
	rs := &fakeReqStore{}
	// Even a NON-admin identity may submit a request.
	h := mkRH(t, gs, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests",
		`{"target_id":"node-app-01","reason":"deploy hotfix"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("non-admin should be allowed to submit: %d body=%s", w.Code, w.Body.String())
	}
	var rv RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &rv)
	if rv.Subject != "u-1" {
		t.Errorf("subject must be the verified caller, got %q", rv.Subject)
	}
	if rv.State != "pending" {
		t.Errorf("new request must start pending, got %q", rv.State)
	}
}

func TestSubmitRejectsMissingReason(t *testing.T) {
	h := mkRH(t, &fakeStore{}, &fakeReqStore{}, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests", `{"target_id":"t"}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing reason must 400, got %d", w.Code)
	}
}

func TestListRequiresAdmin(t *testing.T) {
	rs := &fakeReqStore{}
	rs.Submit(context.Background(), "u-1", "t", "test", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-2", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("list requires admin: got %d", w.Code)
	}
}

func TestApproveMintGrantAndLink(t *testing.T) {
	gs := &fakeStore{}
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "node-app-01", "fix", time.Hour)
	h := mkRH(t, gs, rs, pdp.Identity{Subject: "approver-1", Roles: []string{"platform_admin"}})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests/"+req.ID+"/approve", `{"ttl_seconds":1800}`))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Request RequestView `json:"request"`
		Grant   GrantView   `json:"grant"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Request.State != "approved" {
		t.Errorf("request state: %q", out.Request.State)
	}
	if out.Request.GrantID == "" || out.Request.GrantID != out.Grant.ID {
		t.Errorf("request.grant_id must link to grant.id: %s vs %s", out.Request.GrantID, out.Grant.ID)
	}
	if out.Grant.ApprovedBy != "sub:approver-1" {
		t.Errorf("grant.approved_by must be verified approver: %q", out.Grant.ApprovedBy)
	}
}

func TestApproveIdempotentReject(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	// First approve transitions to approved.
	_, _, _ = rs.Approve(context.Background(), req.ID, "a1", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "a2", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	// Second approve must NOT mint a duplicate grant.
	h.ServeHTTP(w, bearerReq("POST", "/requests/"+req.ID+"/approve", `{"ttl_seconds":60}`))
	if w.Code != http.StatusConflict {
		t.Errorf("re-approve must 409, got %d", w.Code)
	}
}

func TestDenyRequiresAdmin(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests/"+req.ID+"/deny", `{"reason":"nope"}`))
	if w.Code != http.StatusForbidden {
		t.Errorf("deny requires admin: got %d", w.Code)
	}
}

func TestDenyRequiresReason(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests/"+req.ID+"/deny", `{}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("deny without reason must 400 (auditability), got %d", w.Code)
	}
}

func TestDenyHappyPath(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/requests/"+req.ID+"/deny", `{"reason":"out of scope"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	var rv RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &rv)
	if rv.State != "denied" || rv.DecidedReason != "out of scope" {
		t.Errorf("decision state/reason mismatch: %+v", rv)
	}
}

// Phase 5e-4 GET /requests/{id} per-request projection. Three flavours:
// owner-can-read, admin-can-read-any, non-owner-gets-404-not-403 (privacy
// preservation), nonexistent-id-404.

func TestGetOneOwnerCanReadOwn(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	// Same subject as the request — viewer role suffices.
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests/"+req.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("owner must be able to read own request: %d body=%s", w.Code, w.Body.String())
	}
	var rv RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &rv)
	if rv.ID != req.ID || rv.Subject != "u-1" {
		t.Errorf("got %+v", rv)
	}
}

func TestGetOneAdminCanReadAny(t *testing.T) {
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	// Admin is a different subject; still allowed.
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "admin-1", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests/"+req.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("admin must read any request: %d", w.Code)
	}
}

func TestGetOneNonOwnerGets404NotForbidden(t *testing.T) {
	// Privacy posture: a non-admin non-owner must get 404 (not 403) so
	// they cannot distinguish "doesn't exist" from "exists but not yours".
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-2", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests/"+req.ID, ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("non-owner non-admin MUST 404, got %d (would leak request existence)", w.Code)
	}
}

func TestGetOneNonexistentReturns404(t *testing.T) {
	h := mkRH(t, &fakeStore{}, &fakeReqStore{}, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests/does-not-exist", ""))
	if w.Code != http.StatusNotFound {
		t.Errorf("nonexistent id must 404, got %d", w.Code)
	}
}

func TestGetOneSurvivesApproveTransition(t *testing.T) {
	// Polling-realism: SPA submits, then polls; between polls an admin
	// approves. The next GET MUST surface the new state + grant_id so
	// the SPA can stop polling and show the result.
	rs := &fakeReqStore{}
	req, _ := rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	_, _, _ = rs.Approve(context.Background(), req.ID, "admin-1", time.Hour)
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests/"+req.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	var rv RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &rv)
	if rv.State != "approved" || rv.GrantID == "" {
		t.Errorf("approved request must surface grant_id to owner: %+v", rv)
	}
}

// Phase 5e-5 GET /requests?mine=true — non-admin can list their own
// requests but only their own. Cross-tenant smear is impossible
// because the controller filters on the verified subject, not on
// any client-supplied filter.

func TestListMineNonAdminSeesOnlyOwn(t *testing.T) {
	rs := &fakeReqStore{}
	rs.Submit(context.Background(), "u-1", "node-app-01", "fix one", time.Hour)
	rs.Submit(context.Background(), "u-1", "k8s-app-02", "fix two", time.Hour)
	rs.Submit(context.Background(), "u-2", "k8s-other", "other fix", time.Hour)

	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests?mine=true", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("?mine=true must NOT require admin: %d body=%s", w.Code, w.Body.String())
	}
	var out []RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 2 {
		t.Fatalf("u-1 must see 2 own requests, got %d", len(out))
	}
	for _, r := range out {
		if r.Subject != "u-1" {
			t.Errorf("?mine=true leaked subject=%q to u-1", r.Subject)
		}
	}
}

func TestListWithoutMineStillRequiresAdmin(t *testing.T) {
	rs := &fakeReqStore{}
	rs.Submit(context.Background(), "u-1", "t", "x", time.Hour)
	// Non-admin, no ?mine — admin gate still applies (admin-list mode).
	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-2", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("admin gate must apply when ?mine is absent, got %d", w.Code)
	}
}

func TestListMineRespectsState(t *testing.T) {
	// ?mine=true + ?state=pending narrows further. Verifies the two
	// filters compose without one overriding the other.
	rs := &fakeReqStore{}
	req1, _ := rs.Submit(context.Background(), "u-1", "t1", "p1", time.Hour)
	_, _ = rs.Submit(context.Background(), "u-1", "t2", "p2", time.Hour)
	// Approve only one — the other stays pending.
	_, _, _ = rs.Approve(context.Background(), req1.ID, "admin-1", time.Hour)

	h := mkRH(t, &fakeStore{}, rs, pdp.Identity{Subject: "u-1", Roles: []string{"viewer"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("GET", "/requests?mine=true&state=pending", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	var out []RequestView
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out) != 1 || out[0].State != "pending" {
		t.Errorf("?mine + ?state=pending should return 1 pending row, got %d %+v", len(out), out)
	}
}

func TestFallthroughToGrants(t *testing.T) {
	// /grants routes still work after we add /requests on top.
	gs := &fakeStore{}
	h := mkRH(t, gs, &fakeReqStore{}, pdp.Identity{Subject: "a", Roles: []string{"platform_admin"}})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bearerReq("POST", "/grants",
		`{"subject":"u-1","target_id":"t","ttl_seconds":60}`))
	if w.Code != http.StatusCreated {
		t.Errorf("expected /grants to still work after /requests overlay, got %d", w.Code)
	}
}
