// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// In-browser grant-request flow — Phase 5e-3.
//
// Operators today open jessctl to submit a grant request (POST /requests
// on the controller's admin port). For browser-only operators (audit,
// SRE incident response from a fresh laptop) we proxy that surface
// behind the same Falcon-ID session jess-web already manages:
//
//	POST /api/requests       → controller {admin}/requests
//	GET  /api/requests/{id}  → controller {admin}/requests/{id}
//
// Auth: the cookie session must be valid. The session-held Falcon-ID
// id_token is forwarded as Bearer to the controller; the controller's
// existing admin auth path verifies it as it would for jessctl.
//
// Why a proxy (not direct call from the SPA)
//
//   - The operator's id_token never reaches the browser; it lives in
//     server-side session state. The SPA only has the session cookie.
//   - The controller's admin port is internal-only (network-policy
//     scoped to the jess namespace); the browser can't reach it
//     directly even if it had the token.
//   - jess-web is already in the trust boundary (mTLS + bearer to the
//     operator port) so it's the natural cross-boundary point.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// grantsClient holds the controller admin-port configuration used by
// the proxy handlers. Built once in main(); the sessions pointer lets
// each request resolve the operator from the cookie.
type grantsClient struct {
	adminBaseURL string // e.g. https://jess-controller.jess.svc.cluster.local:7103
	tlsCfg       *tls.Config
	sessions     *sessionStore
	hc           *http.Client
}

// newGrantsClient configures the http.Client once so request handlers
// don't pay per-request setup. Timeout is short enough that a hung
// controller surfaces quickly without holding browser connections open
// for minutes.
func newGrantsClient(adminBaseURL string, tlsCfg *tls.Config, sessions *sessionStore) *grantsClient {
	tr := &http.Transport{
		TLSClientConfig:   tlsCfg, // nil → http only; ok for dev / in-cluster
		ForceAttemptHTTP2: true,
	}
	return &grantsClient{
		adminBaseURL: strings.TrimRight(adminBaseURL, "/"),
		tlsCfg:       tlsCfg,
		sessions:     sessions,
		hc:           &http.Client{Transport: tr, Timeout: 15 * time.Second},
	}
}

// handleMyRequests — GET /api/my/requests[?state=pending]. Phase 5e-5
// operator self-service activity view: forwards to the controller's
// /requests endpoint with ?mine=true so the caller sees only their own
// requests (no admin role required). Same bearer-handoff posture as
// every other proxy in this file.
func (g *grantsClient) handleMyRequests(w http.ResponseWriter, r *http.Request) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	// Re-stamp the query so the SPA can't smuggle ?mine=false to escalate.
	// Allowed pass-throughs: state, limit (the controller doesn't honour
	// limit today but it's harmless and lets the SPA hint pagination).
	q := url.Values{}
	q.Set("mine", "true")
	if s := r.URL.Query().Get("state"); s != "" {
		q.Set("state", s)
	}
	upstream, status, derr := g.forward(r, op.Token, http.MethodGet, "/requests?"+q.Encode(), nil)
	if derr != nil {
		log.Printf("jess-web grants: forward GET /requests?mine=true op=%s err=%v", op.Subject, derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	relayJSON(w, status, upstream)
}

// handleMyRecording — GET /api/my/sessions/{id}/recording. Forwards
// to controller admin /sessions/{id}/recording. Owner-gate enforced
// upstream; streams asciicast bytes back with the right MIME so the
// SPA's asciinema-player picks it up directly.
//
// 503 from upstream (MinIO read creds not configured on the controller)
// propagates as-is so the SPA can fall back to the MinIO Console deep
// link (Phase 5e-9).
func (g *grantsClient) handleMyRecording(w http.ResponseWriter, r *http.Request) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	// Path shapes supported:
	//   /api/my/sessions/{id}/recording           → asciicast stream
	//   /api/my/sessions/{id}/recording/verify    → tamper-evidence JSON (5e-14)
	rest := strings.TrimPrefix(r.URL.Path, "/api/my/sessions/")
	if strings.HasSuffix(rest, "/recording/verify") {
		id := strings.TrimSuffix(rest, "/recording/verify")
		if id == "" || strings.Contains(id, "/") {
			writeJSONErr(w, http.StatusNotFound, "bad session id")
			return
		}
		body, status, derr := g.forward(r, op.Token, http.MethodGet, "/sessions/"+id+"/recording/verify", nil)
		if derr != nil {
			log.Printf("jess-web grants: forward GET /sessions/%s/recording/verify op=%s err=%v", id, op.Subject, derr)
			writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
			return
		}
		relayJSON(w, status, body)
		return
	}
	if !strings.HasSuffix(rest, "/recording") {
		writeJSONErr(w, http.StatusNotFound, "expected /api/my/sessions/{id}/recording[/verify]")
		return
	}
	id := strings.TrimSuffix(rest, "/recording")
	if id == "" || strings.Contains(id, "/") {
		writeJSONErr(w, http.StatusNotFound, "bad session id")
		return
	}
	body, status, derr := g.forward(r, op.Token, http.MethodGet, "/sessions/"+id+"/recording", nil)
	if derr != nil {
		log.Printf("jess-web grants: forward GET /sessions/%s/recording op=%s err=%v", id, op.Subject, derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	if status == http.StatusOK {
		w.Header().Set("Content-Type", "application/x-asciicast")
		w.Header().Set("Cache-Control", "private, max-age=3600, immutable")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	relayJSON(w, status, body)
}

// handleMySessions — GET /api/my/sessions[?limit=N]. Phase 5e-6
// operator self-service "recent sessions" view: forwards to the
// controller's /sessions endpoint with ?mine=true so the caller
// sees only their own brokered sessions (no admin role required).
//
// 503 from the controller propagates back to the SPA (session log
// unavailable — controller running with a grant store that doesn't
// implement SessionStore, e.g. a custom test broker). The SPA
// gracefully degrades to "session log unavailable" rather than
// hiding the card entirely.
func (g *grantsClient) handleMySessions(w http.ResponseWriter, r *http.Request) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	q := url.Values{}
	q.Set("mine", "true")
	if s := r.URL.Query().Get("limit"); s != "" {
		q.Set("limit", s)
	}
	upstream, status, derr := g.forward(r, op.Token, http.MethodGet, "/sessions?"+q.Encode(), nil)
	if derr != nil {
		log.Printf("jess-web grants: forward GET /sessions?mine=true op=%s err=%v", op.Subject, derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	relayJSON(w, status, upstream)
}

// SubmitRequestBody is the SPA-facing shape — same fields the
// controller's admin.SubmitRequest expects. Kept as an explicit local
// type so the SPA contract doesn't accidentally drift on an admin
// refactor.
type SubmitRequestBody struct {
	TargetID         string `json:"target_id"`
	Reason           string `json:"reason"`
	RequestTTLMinute int    `json:"request_ttl_minutes,omitempty"`
}

// handleSubmitRequest — POST /api/requests. Forwards the body to the
// controller admin port with the session-held Bearer.
func (g *grantsClient) handleSubmitRequest(w http.ResponseWriter, r *http.Request) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body SubmitRequestBody
	if derr := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body); derr != nil {
		writeJSONErr(w, http.StatusBadRequest, "bad json: "+derr.Error())
		return
	}
	if body.TargetID == "" || body.Reason == "" {
		writeJSONErr(w, http.StatusBadRequest, "target_id and reason required")
		return
	}
	// Cap relayed TTL at 24h so a buggy client can't ask for a year.
	// The controller also validates; this is defence-in-depth on the
	// edge of the trust boundary.
	if body.RequestTTLMinute > 24*60 {
		body.RequestTTLMinute = 24 * 60
	}
	payload, _ := json.Marshal(body)

	upstream, status, derr := g.forward(r, op.Token, http.MethodPost, "/requests", payload)
	if derr != nil {
		log.Printf("jess-web grants: forward POST /requests op=%s err=%v", op.Subject, derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	relayJSON(w, status, upstream)
}

// handleGetRequest — GET /api/requests/{id}. Forwards to the controller
// admin port's per-request GET (Phase 5e-4 controller addition). The
// SPA polls this after submit to surface state transitions
// (pending → approved/denied) so the operator sees their approver's
// decision in near-real time, without refreshing or waiting on a
// separate Slack notification.
//
// Auth posture matches the controller's own:
//   - 401 if no jess-web session cookie (we never reach the controller)
//   - 404 if controller doesn't recognise the request OR the request
//     exists but doesn't belong to the caller (the controller hides
//     existence to non-owner non-admins — see internal/admin/requests.go
//     handleGetOne; we relay that posture rather than overriding)
//   - 200 + RequestView on success — same JSON shape as submit returns
func (g *grantsClient) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/requests/")
	if id == "" || strings.Contains(id, "/") {
		writeJSONErr(w, http.StatusNotFound, "no route")
		return
	}
	upstream, status, derr := g.forward(r, op.Token, http.MethodGet, "/requests/"+id, nil)
	if derr != nil {
		log.Printf("jess-web grants: forward GET /requests/%s op=%s err=%v", id, op.Subject, derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	relayJSON(w, status, upstream)
}

// adminGet is the lightweight unauthenticated-via-cookie variant of
// forward — for jess-web INTERNAL callers (not browser-proxy) that
// need to query the controller admin port with the operator's bearer.
// Phase 5e-8 uses this to fetch the just-created jit_sessions row
// for the session_meta WS frame.
//
// Same TLS / dial config as forward(); the only differences are no
// r.Context() (caller supplies its own ctx) and no relayJSON wiring.
func (g *grantsClient) adminGet(ctx context.Context, bearer, path string) ([]byte, int, error) {
	if g.adminBaseURL == "" {
		return nil, 0, errors.New("controller admin URL not configured")
	}
	target, err := url.Parse(g.adminBaseURL + path)
	if err != nil {
		return nil, 0, fmt.Errorf("bad admin URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return raw, resp.StatusCode, nil
}

// forward is the actual HTTP roundtrip. Returns the upstream body
// (limited) + status code; never panics on bad responses.
func (g *grantsClient) forward(r *http.Request, bearer, method, path string, body []byte) ([]byte, int, error) {
	if g.adminBaseURL == "" {
		return nil, 0, errors.New("controller admin URL not configured (set JESS_CONTROLLER_ADMIN_ADDR)")
	}
	target, err := url.Parse(g.adminBaseURL + path)
	if err != nil {
		return nil, 0, fmt.Errorf("bad admin URL: %w", err)
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(r.Context(), method, target.String(), reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return raw, resp.StatusCode, nil
}

// relayJSON copies upstream body + status to the browser. We pass JSON
// through unchanged so the SPA can react to controller error shapes
// without jess-web reshaping them.
func relayJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Escape the message via json.Marshal so quotes / unicode / etc.
	// in error bodies can't break the response framing.
	enc, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(enc)
}

// maxAttestBody bounds the device-cert attestation request body. The payload
// (EK cert PEM, platform quote blob, WebAuthn witness JWS) is a few KB in
// practice; 1 MiB is generous headroom while capping a hostile upload.
const maxAttestBody = 1 << 20

// handleDeviceCertAttest — POST /device-cert/attest. The ZTNA device-
// enrollment bootstrap endpoint, proxied to the controller admin port.
//
// UNLIKE every other proxy in this file it does NOT require a jess-web
// session cookie: the calling device is by definition not yet enrolled, so it
// holds no operator session. Authentication is performed authoritatively by
// the controller's attest handler (the outermost layer of the admin chain on
// :7103) from the Falcon-ID access token (Authorization: Bearer) plus the
// WebAuthn witness JWS carried in the request body. jess-web is a transparent
// mTLS reverse-proxy here, nothing more — it relays the Bearer token verbatim
// and never inspects the witness.
//
// Talon fronts this exact method+path as a publicPath carve-out (the jess-ops
// TalonRoute); this handler is jess-web's matching no-cookie passthrough, so
// the two tiers agree that /device-cert/attest is reachable pre-enrollment
// while every other jess.ops path keeps its session + admin gating.
func (g *grantsClient) handleDeviceCertAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	// Reject an empty Authorization early so the device gets a crisp 401 JSON
	// rather than a controller round-trip. We do NOT verify the token here —
	// the controller does — we only relay it.
	bearer := bearerFromAuthHeader(r)
	if bearer == "" {
		writeJSONErr(w, http.StatusUnauthorized, "missing Authorization Bearer token")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttestBody))
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "read request body: "+err.Error())
		return
	}
	upstream, status, derr := g.forward(r, bearer, http.MethodPost, "/device-cert/attest", body)
	if derr != nil {
		log.Printf("jess-web grants: forward POST /device-cert/attest err=%v", derr)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+derr.Error())
		return
	}
	relayJSON(w, status, upstream)
}

// bearerFromAuthHeader extracts the token from an "Authorization: Bearer <t>"
// header, returning "" when absent or malformed. The scheme match is
// case-insensitive per RFC 7235 §2.1.
func bearerFromAuthHeader(r *http.Request) string {
	const scheme = "bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(h[len(scheme):])
}
