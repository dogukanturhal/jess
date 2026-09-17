// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDeviceCertAttestForwardsBearerAndBody_NoSession — the device-enrollment
// bootstrap proxy must forward the device's Falcon-ID access token + body to
// the controller's /device-cert/attest WITHOUT requiring a jess-web session
// cookie (the device is not yet enrolled). This is the property that makes
// enrollment possible at all.
func TestDeviceCertAttestForwardsBearerAndBody_NoSession(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusOK, `{"device_cert_pem":"-----BEGIN CERTIFICATE-----","tier":"TIER_BYOD"}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	body := `{"platform":"software-bootstrap","device_uuid":"68fff250","witness":{"signed_jws":"eyJ..."}}`
	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer falcon-access-token-123")
	// Deliberately NO session cookie.
	rec := httptest.NewRecorder()
	g.handleDeviceCertAttest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "Bearer falcon-access-token-123" {
		t.Errorf("upstream Authorization=%q, want Bearer falcon-access-token-123", fa.gotAuth)
	}
	if fa.gotPath != "/device-cert/attest" {
		t.Errorf("upstream path=%q, want /device-cert/attest", fa.gotPath)
	}
	if !strings.Contains(string(fa.gotBody), "68fff250") {
		t.Errorf("upstream body missing device payload: %s", fa.gotBody)
	}
	if !strings.Contains(rec.Body.String(), "TIER_BYOD") {
		t.Errorf("relayed body missing upstream cert response: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("relayed Content-Type=%q, want application/json", ct)
	}
}

// TestDeviceCertAttestMissingBearer401 — no Authorization header = 401, and
// the request must never reach the controller (so an anonymous caller can't
// use jess-web as an open bridge to the admin port).
func TestDeviceCertAttestMissingBearer401(t *testing.T) {
	sessions := newSessionStore()
	fa, srv := newFakeAdmin(t, http.StatusOK, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	g.handleDeviceCertAttest(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if fa.gotAuth != "" {
		t.Errorf("upstream was contacted (gotAuth=%q) but should not have been", fa.gotAuth)
	}
}

// TestDeviceCertAttestMethodNotAllowed — only POST is valid; the SPA catch-all
// would otherwise serve index.html for a GET, defeating the JSON contract.
func TestDeviceCertAttestMethodNotAllowed(t *testing.T) {
	sessions := newSessionStore()
	_, srv := newFakeAdmin(t, http.StatusOK, `{}`)
	g := newGrantsClient(srv.URL, nil, sessions)

	req := httptest.NewRequest(http.MethodGet, "/device-cert/attest", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	g.handleDeviceCertAttest(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}

// TestDeviceCertAttestUpstreamErrorReturns502 — a dead controller admin port
// surfaces as 502 JSON, not a panic or a hung browser connection.
func TestDeviceCertAttestUpstreamErrorReturns502(t *testing.T) {
	sessions := newSessionStore()
	g := newGrantsClient("http://127.0.0.1:1", nil, sessions)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer falcon-access-token-123")
	rec := httptest.NewRecorder()
	g.handleDeviceCertAttest(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502; body=%s", rec.Code, rec.Body.String())
	}
}

// TestBearerFromAuthHeader — scheme parsing is case-insensitive and rejects
// malformed headers.
func TestBearerFromAuthHeader(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER   abc  ", "abc"},
		{"Basic abc", ""},
		{"abc", ""},
		{"", ""},
		{"Bearer", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/device-cert/attest", nil)
		if c.in != "" {
			r.Header.Set("Authorization", c.in)
		}
		if got := bearerFromAuthHeader(r); got != c.want {
			t.Errorf("bearerFromAuthHeader(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}
