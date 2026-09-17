// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Unit tests for the browser SQL console backend (/api/db/query). These cover
// the request-validation + auth + fail-closed paths that don't need a live
// controller/worker/DB. The live query path (pgx/go-mysql over the relay) is a
// runtime/deploy concern — it requires a running worker + a real DB target — and
// is exercised by the broker/dbproxy/mysqlproxy integration tests plus a manual
// end-to-end check (see the package header in db-console.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestConsole returns a dbConsoleConfig pointed at a deliberately-dead
// controller address so the dial fails fast and predictably — the validation
// tests never reach the dial, and the dial-failure test asserts the fail-closed
// error shape.
func newTestConsole(t *testing.T) (*dbConsoleConfig, *sessionStore) {
	t.Helper()
	ss := newSessionStore()
	return &dbConsoleConfig{
		// 127.0.0.1:1 — nothing listens; connect refused immediately.
		controllerAddr: "127.0.0.1:1",
		tlsCfg:         nil,
		sessions:       ss,
	}, ss
}

// signedInRequest builds a POST with a valid session cookie for op.
func signedInRequest(t *testing.T, ss *sessionStore, body any) *http.Request {
	t.Helper()
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("session id: %v", err)
	}
	ss.put(id, &Operator{
		Token:   "tok-abc",
		Subject: "u-1",
		Email:   "u1@hexxlock.com",
		Expires: time.Now().Add(time.Hour),
	})
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/db/query", bytes.NewReader(b))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	return r
}

func decodeResp(t *testing.T, w *httptest.ResponseRecorder) dbQueryResponse {
	t.Helper()
	var resp dbQueryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v body=%s", err, w.Body.String())
	}
	return resp
}

func TestQueryRejectsAnonymous(t *testing.T) {
	c, _ := newTestConsole(t)
	b, _ := json.Marshal(dbQueryRequest{Target: "pg-1", Protocol: "postgres", SQL: "select 1"})
	r := httptest.NewRequest(http.MethodPost, "/api/db/query", bytes.NewReader(b))
	w := httptest.NewRecorder()
	c.handleQuery(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anon must 401, got %d", w.Code)
	}
	if got := decodeResp(t, w); got.Error == "" {
		t.Errorf("401 must carry an error message")
	}
}

func TestQueryRejectsNonPost(t *testing.T) {
	c, ss := newTestConsole(t)
	id, _ := newSessionID()
	ss.put(id, &Operator{Token: "t", Expires: time.Now().Add(time.Hour)})
	r := httptest.NewRequest(http.MethodGet, "/api/db/query", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	w := httptest.NewRecorder()
	c.handleQuery(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must 405, got %d", w.Code)
	}
}

func TestQueryValidatesParams(t *testing.T) {
	cases := []struct {
		name string
		req  dbQueryRequest
		want int
	}{
		{"missing target", dbQueryRequest{Protocol: "postgres", SQL: "select 1"}, http.StatusBadRequest},
		{"missing sql", dbQueryRequest{Target: "pg-1", Protocol: "postgres", SQL: "   "}, http.StatusBadRequest},
		{"unsupported protocol", dbQueryRequest{Target: "t-1", Protocol: "ssh", SQL: "select 1"}, http.StatusBadRequest},
		{"empty protocol", dbQueryRequest{Target: "t-1", Protocol: "", SQL: "select 1"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ss := newTestConsole(t)
			r := signedInRequest(t, ss, tc.req)
			w := httptest.NewRecorder()
			c.handleQuery(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d (body=%s)", w.Code, tc.want, w.Body.String())
			}
			if got := decodeResp(t, w); got.Error == "" {
				t.Errorf("rejection must carry an error message")
			}
		})
	}
}

func TestQueryRejectsOversizeSQL(t *testing.T) {
	c, ss := newTestConsole(t)
	big := strings.Repeat("a", maxSQLBytes+1)
	r := signedInRequest(t, ss, dbQueryRequest{Target: "pg-1", Protocol: "postgres", SQL: big})
	w := httptest.NewRecorder()
	c.handleQuery(w, r)
	// Either the explicit length guard (413) or the MaxBytesReader on the body
	// (400) — both are fail-closed rejections; assert it's one of them and
	// carries an error.
	if w.Code != http.StatusRequestEntityTooLarge && w.Code != http.StatusBadRequest {
		t.Fatalf("oversize sql must be rejected (413/400), got %d", w.Code)
	}
	if got := decodeResp(t, w); got.Error == "" {
		t.Errorf("oversize rejection must carry an error message")
	}
}

// TestQueryFailsClosedOnDialFailure: a valid, authenticated request whose
// controller dial fails (nothing listening) must return a clean JSON error and
// a 502 — never a hang, never an open unmediated connection.
func TestQueryFailsClosedOnDialFailure(t *testing.T) {
	c, ss := newTestConsole(t)
	r := signedInRequest(t, ss, dbQueryRequest{Target: "pg-1", Protocol: "postgres", SQL: "select 1"})
	w := httptest.NewRecorder()
	c.handleQuery(w, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("dial failure must 502, got %d (body=%s)", w.Code, w.Body.String())
	}
	got := decodeResp(t, w)
	if got.Error == "" || !strings.Contains(got.Error, "controller dial failed") {
		t.Errorf("dial failure must surface a clear error, got %q", got.Error)
	}
}

// TestRelayNoCloseDoesNotCloseUnderlying verifies the lifecycle guard: the DB
// client's Close() must NOT tear down the relay socket (the handler owns it via
// defer). A double-close would otherwise corrupt the connection accounting.
func TestRelayNoCloseDoesNotCloseUnderlying(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wrapped := relayNoClose{client}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("relayNoClose.Close must be a no-op, got %v", err)
	}
	// The underlying conn must still be usable after the wrapper's Close.
	done := make(chan struct{})
	go func() {
		_, _ = server.Write([]byte("ping"))
		close(done)
	}()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("underlying conn must remain open after relayNoClose.Close, got read err %v", err)
	}
	<-done
	if string(buf) != "ping" {
		t.Errorf("read %q want ping", buf)
	}
}

// Compile-time sanity that pgErrorString / mysqlErrorString accept plain errors.
func TestErrorStringFallbacks(t *testing.T) {
	if got := pgErrorString(context.DeadlineExceeded); got == "" {
		t.Error("pgErrorString must render a non-PgError")
	}
	if got := mysqlErrorString(context.DeadlineExceeded); got == "" {
		t.Error("mysqlErrorString must render a plain error")
	}
}
