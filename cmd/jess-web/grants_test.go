// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeAdmin captures the upstream POST /requests call so we can assert
// the proxy sent the right Bearer + body, then returns a canned response.
type fakeAdmin struct {
	gotAuth     string
	gotBody     []byte
	gotPath     string // url.Path only
	gotRawQuery string // url.RawQuery (?key=val) — assert the SPA-supplied filter wasn't smuggled
	status      int
	resp        []byte
}

func newFakeAdmin(t *testing.T, status int, resp string) (*fakeAdmin, *httptest.Server) {
	t.Helper()
	f := &fakeAdmin{status: status, resp: []byte(resp)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotAuth = r.Header.Get("Authorization")
		f.gotPath = r.URL.Path
		f.gotRawQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		f.gotBody = b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write(f.resp)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// seedSession plants a session cookie + operator entry in the store and
// returns the cookie header value so test requests can present it.
func seedSession(t *testing.T, s *sessionStore, sub, email, token string) string {
	t.Helper()
	id, err := newSessionID()
	if err != nil {
		t.Fatal(err)
	}
	s.put(id, &Operator{
		Token: token, Subject: sub, Email: email,
		Roles: []string{"platform_admin"}, Expires: time.Now().Add(time.Hour),
	})
	return sessionCookie + "=" + id
}

// TestSubmitRequestForwardsBearerAndBody — the proxy must put the
// operator's session-held id_token in Authorization: Bearer …, never
// require the SPA to supply it.
func TestSubmitRequestForwardsBearerAndBody(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "id-token-XYZ")

	fa, srv := newFakeAdmin(t, http.StatusCreated, `{"id":"req-1","state":"pending"}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	body, _ := json.Marshal(SubmitRequestBody{
		TargetID: "node-app-01",
		Reason:   "INC-4421 — debug Linkerd OOM",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/requests", bytes.NewReader(body))
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleSubmitRequest(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "Bearer id-token-XYZ" {
		t.Errorf("upstream Authorization=%q, want Bearer id-token-XYZ", fa.gotAuth)
	}
	if fa.gotPath != "/requests" {
		t.Errorf("upstream path=%q, want /requests", fa.gotPath)
	}
	if !strings.Contains(string(fa.gotBody), "node-app-01") {
		t.Errorf("upstream body missing target: %s", fa.gotBody)
	}
	if !strings.Contains(rec.Body.String(), "req-1") {
		t.Errorf("relayed body missing upstream id: %s", rec.Body.String())
	}
}

// TestSubmitRequestUnauthWithoutSession — no cookie = 401, never
// reaches the upstream (so an unauthenticated caller can't abuse
// jess-web as a network bridge to the controller admin port).
func TestSubmitRequestUnauthWithoutSession(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusCreated, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodPost, "/api/requests",
		strings.NewReader(`{"target_id":"t","reason":"r"}`))
	rec := httptest.NewRecorder()
	g.handleSubmitRequest(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
	if fa.gotPath != "" {
		t.Errorf("unauthed call reached upstream (path=%q) — proxy MUST gate on session first", fa.gotPath)
	}
}

// TestSubmitRequestValidates — missing target_id / reason = 400 with
// no upstream call.
func TestSubmitRequestValidates(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	fa, srv := newFakeAdmin(t, http.StatusCreated, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	for _, body := range []string{
		`{"target_id":"","reason":"r"}`,
		`{"target_id":"t","reason":""}`,
		`{}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/requests", strings.NewReader(body))
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		g.handleSubmitRequest(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body=%s status=%d, want 400", body, rec.Code)
		}
	}
	if fa.gotPath != "" {
		t.Errorf("validation failure leaked through to upstream (path=%q)", fa.gotPath)
	}
}

// TestSubmitRequestUpstreamErrorReturns502 — when the controller
// admin port is unreachable (server down) the SPA gets 502, not a
// generic 500 — so the operator sees "controller down" vs "your
// request was malformed".
func TestSubmitRequestUpstreamErrorReturns502(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	// Point at a closed port — connection refused.
	g := newGrantsClient("http://127.0.0.1:1", nil, sessions)

	body, _ := json.Marshal(SubmitRequestBody{TargetID: "t", Reason: "r"})
	req := httptest.NewRequest(http.MethodPost, "/api/requests", bytes.NewReader(body))
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleSubmitRequest(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status=%d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unreachable") {
		t.Errorf("body should mention 'unreachable': %s", rec.Body.String())
	}
}

// TestGetRequestForwardsBearer — Phase 5e-4 controller addition went
// live; jess-web now proxies GET /api/requests/{id} to the controller's
// admin port with the cookie-session Bearer. Same bearer-handoff posture
// as POST.
func TestGetRequestForwardsBearer(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "id-token-XYZ")

	fa, srv := newFakeAdmin(t, http.StatusOK, `{"id":"req-1","state":"approved","grant_id":"grant-7f"}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/req-1", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleGetRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "Bearer id-token-XYZ" {
		t.Errorf("upstream Authorization=%q, want Bearer id-token-XYZ", fa.gotAuth)
	}
	if fa.gotPath != "/requests/req-1" {
		t.Errorf("upstream path=%q, want /requests/req-1", fa.gotPath)
	}
	if !strings.Contains(rec.Body.String(), "approved") {
		t.Errorf("relayed body missing approved state: %s", rec.Body.String())
	}
}

// TestGetRequestUnauthDoesntReachUpstream — same posture as POST: a
// missing session 401s at jess-web and never hits the controller.
func TestGetRequestUnauthDoesntReachUpstream(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusOK, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/req-1", nil)
	rec := httptest.NewRecorder()
	g.handleGetRequest(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
	if fa.gotPath != "" {
		t.Errorf("unauthed GET reached upstream (path=%q) — jess-web MUST gate on session first", fa.gotPath)
	}
}

// TestGetRequestRelays404 — the controller's privacy-preserving 404
// (not-yours OR not-found) must reach the SPA unchanged so the polling
// loop can stop without leaking owner-info via diverging error codes.
func TestGetRequestRelays404(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	_, srv := newFakeAdmin(t, http.StatusNotFound, `{"error":"request req-x not found"}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/req-x", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleGetRequest(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404 (controller's privacy posture must pass through)", rec.Code)
	}
}

// TestMyRequestsForwardsWithMineFilter — Phase 5e-5. jess-web must
// stamp ?mine=true on the upstream call so the controller filters to
// the caller's own requests. The SPA cannot smuggle ?mine=false to
// see other operators' requests because the proxy always re-stamps.
func TestMyRequestsForwardsWithMineFilter(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "id-token-XYZ")

	fa, srv := newFakeAdmin(t, http.StatusOK, `[{"id":"r-1","state":"approved"}]`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/requests", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleMyRequests(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "Bearer id-token-XYZ" {
		t.Errorf("upstream Authorization=%q, want Bearer id-token-XYZ", fa.gotAuth)
	}
	if fa.gotPath != "/requests" {
		t.Errorf("upstream path=%q, want /requests", fa.gotPath)
	}
	if !strings.Contains(fa.gotRawQuery, "mine=true") {
		t.Errorf("upstream MUST carry mine=true (proxy re-stamps so SPA cannot smuggle mine=false): %q", fa.gotRawQuery)
	}
}

// TestMyRequestsIgnoresSmuggledMineFalse — even if the SPA tries
// `/api/my/requests?mine=false`, the proxy re-stamps mine=true on
// the upstream. This is defence-in-depth.
func TestMyRequestsIgnoresSmuggledMineFalse(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	fa, srv := newFakeAdmin(t, http.StatusOK, `[]`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/requests?mine=false&state=pending", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleMyRequests(rec, req)

	if !strings.Contains(fa.gotRawQuery, "mine=true") {
		t.Errorf("upstream MUST always carry mine=true, even if SPA sent mine=false: %q", fa.gotRawQuery)
	}
	if !strings.Contains(fa.gotRawQuery, "state=pending") {
		t.Errorf("state filter should pass through: %q", fa.gotRawQuery)
	}
}

// TestMyRequestsUnauthDoesntReachUpstream — same posture as the other
// proxy handlers: 401 short-circuits before any controller dial.
func TestMyRequestsUnauthDoesntReachUpstream(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusOK, `[]`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/requests", nil)
	rec := httptest.NewRecorder()
	g.handleMyRequests(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
	if fa.gotPath != "" {
		t.Errorf("unauthed GET reached upstream (path=%q)", fa.gotPath)
	}
}

// TestMySessionsForwardsMineFilter — Phase 5e-6. jess-web's
// /api/my/sessions proxy must always stamp ?mine=true on the upstream
// call. Pass-through filter: ?limit.
func TestMySessionsForwardsMineFilter(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "id-token-XYZ")

	fa, srv := newFakeAdmin(t, http.StatusOK, `[{"id":"sess-1","target_id":"t","active":true}]`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/sessions?limit=5", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleMySessions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "Bearer id-token-XYZ" {
		t.Errorf("upstream Authorization=%q, want Bearer id-token-XYZ", fa.gotAuth)
	}
	if fa.gotPath != "/sessions" {
		t.Errorf("upstream path=%q, want /sessions", fa.gotPath)
	}
	if !strings.Contains(fa.gotRawQuery, "mine=true") {
		t.Errorf("upstream MUST carry mine=true: %q", fa.gotRawQuery)
	}
	if !strings.Contains(fa.gotRawQuery, "limit=5") {
		t.Errorf("limit pass-through missing: %q", fa.gotRawQuery)
	}
}

// TestMySessionsUnauthDoesntReachUpstream — same posture as the rest
// of the proxy handlers: no session cookie = 401 before upstream call.
func TestMySessionsUnauthDoesntReachUpstream(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusOK, `[]`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/sessions", nil)
	rec := httptest.NewRecorder()
	g.handleMySessions(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", rec.Code)
	}
	if fa.gotPath != "" {
		t.Errorf("unauthed call reached upstream (path=%q)", fa.gotPath)
	}
}

// TestMySessionsRelays503 — when controller's session log is
// unavailable (no SessionStore wired) the 503 must propagate so the
// SPA can render "session log unavailable" rather than failing.
func TestMySessionsRelays503(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	_, srv := newFakeAdmin(t, http.StatusServiceUnavailable, `{"error":"session log unavailable"}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/my/sessions", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleMySessions(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", rec.Code)
	}
}

// TestGetRequestRejectsNestedPath — /api/requests/x/y is not a valid
// route. Must 404 inside jess-web, not silently forward x/y to the
// controller (which might happen to expose a different x/y route in
// the future).
func TestGetRequestRejectsNestedPath(t *testing.T) {
	sessions := newSessionStore()
	cookie := seedSession(t, sessions, "user:abc", "abc@hexxlock.com", "tok")
	fa, srv := newFakeAdmin(t, http.StatusOK, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/api/requests/req-1/approve", nil)
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	g.handleGetRequest(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404 for nested path", rec.Code)
	}
	if fa.gotPath != "" {
		t.Errorf("nested path leaked to upstream (path=%q)", fa.gotPath)
	}
}
