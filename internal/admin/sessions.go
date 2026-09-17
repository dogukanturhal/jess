// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Session admin API — ADR 0030 Phase 5e-6.
//
// Routes:
//
//	GET /sessions[?mine=true][&limit=N]   list (admin OR self)
//	GET /sessions/{id}                     per-id read
//
// Auth model mirrors /requests (Phase 5e-5):
//
//   - `?mine=true` mode: any verified caller gets back ONLY their own
//     sessions. No admin role required — operators can audit their
//     own activity (foundation for SOC 2 self-service reporting).
//   - Admin mode: caller must hold the admin role. Without `?mine` a
//     non-admin gets 403.
//   - Per-id GET: owner reads own; admin reads any; non-owner non-
//     admin gets 404 (privacy posture — does NOT distinguish
//     "doesn't exist" from "exists but not yours").

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/rdpprobe"
	"github.com/dogukanturhal/jess/internal/recording"
)

func newNDJSONEncoder(w io.Writer) ndjsonEncoder { return json.NewEncoder(w) }

// SessionsHandler wraps CertHandler with the /sessions routes. Falls
// through to the embedded chain for everything else (operator-cert,
// grants, requests).
type SessionsHandler struct {
	*CertHandler
	sessions jit.SessionStore
	rec      RecordingReader   // optional; nil = recording playback disabled (503)
	verifier RecordingVerifier // optional; nil = verify endpoint returns 503
	cat      CatalogLister     // optional; nil = sweep endpoint returns 503
}

// CatalogLister is the read surface of catalog.Catalog the sweep
// endpoint uses. Narrow interface so tests can wire a fake list
// without dragging in the full catalog package. The empty region
// arg means "all regions" — sweep walks every target so an admin
// monitors the whole inventory, not just the local one.
type CatalogLister interface {
	List(ctx context.Context, region string) ([]*CatalogTarget, error)
}

// CatalogTarget mirrors catalog.Target — internal/admin must not
// import internal/catalog (would create a dep cycle later if catalog
// grows admin endpoints). Exported so the controller's adapter
// (cmd/jess-controller/catalog_lister.go) can construct it.
type CatalogTarget struct {
	ID       string
	Name     string
	Protocol string
	Address  string
	Region   string
}

// RecordingReader is the read surface of recording.ObjectStore used by
// the recording-playback endpoint. Tiny interface so tests can wire a
// fake without dragging in the MinIO SDK.
type RecordingReader interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// RecordingVerifier re-checks a sealed bundle's tamper-evidence:
// Vault Transit-issued ed25519 signature over the manifest + SHA-256
// of the recording content vs the hash committed in the manifest.
// Implementations bind a pre-fetched Vault Transit public key so
// each verify is a few MinIO reads + local ed25519 verify (no Vault
// round-trip).
//
// Phase 5e-14 — separate from RecordingReader because verification
// needs both the read surface AND a verifier key, and we want admins
// to be able to flip read on/off independently of verify.
type RecordingVerifier interface {
	VerifyBundle(ctx context.Context, sessionID string) (recording.VerifyResult, error)
}

// NewSessions composes the sessions handler on top of CertHandler.
// Pass nil sessions to surface 503 on /sessions routes (dev mode w/o
// postgres) while leaving every other admin route working.
//
// Pass nil rec to disable in-browser recording playback (controller
// running without MinIO read creds — SPA falls back to the MinIO
// Console deep link from 5e-9).
func NewSessions(base *CertHandler, sessions jit.SessionStore) *SessionsHandler {
	return &SessionsHandler{CertHandler: base, sessions: sessions}
}

// WithRecordings attaches a recording reader (MinIO Object-Lock store)
// so GET /sessions/{id}/recording can stream the asciicast bundle.
// Builder pattern lets cmd/jess-controller wire optionally without a
// constructor-arg explosion.
func (h *SessionsHandler) WithRecordings(rec RecordingReader) *SessionsHandler {
	h.rec = rec
	return h
}

// WithVerifier attaches the tamper-evidence verifier (Phase 5e-14).
// nil-safe in the same way WithRecordings is — the verify endpoint
// surfaces 503 + a hint envelope so the SPA shows "verification not
// configured" instead of a generic error.
func (h *SessionsHandler) WithVerifier(v RecordingVerifier) *SessionsHandler {
	h.verifier = v
	return h
}

// WithCatalog attaches the target catalog used by the probe-sweep
// endpoint (Phase 5f-2d). nil-safe — sweep returns 503 without it.
func (h *SessionsHandler) WithCatalog(c CatalogLister) *SessionsHandler {
	h.cat = c
	return h
}

// ServeHTTP intercepts /sessions paths; everything else falls through.
func (h *SessionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/sessions" && r.Method == http.MethodGet:
		h.handleList(w, r)
		return
	case r.URL.Path == "/audit/export" && r.Method == http.MethodGet:
		h.handleAuditExport(w, r)
		return
	case r.URL.Path == "/audit/chain/verify" && r.Method == http.MethodGet:
		h.handleAuditChainVerify(w, r)
		return
	case r.URL.Path == "/rdp-probe" && r.Method == http.MethodGet:
		h.handleRDPProbe(w, r)
		return
	case r.URL.Path == "/rdp-probe/sweep" && r.Method == http.MethodGet:
		h.handleRDPProbeSweep(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/sessions/") && r.Method == http.MethodGet:
		rest := strings.TrimPrefix(r.URL.Path, "/sessions/")
		// Two-segment forms supported under /sessions/:
		//   /sessions/{id}            → handleGetOne (metadata JSON)
		//   /sessions/{id}/recording  → handleRecording (asciicast stream)
		if idx := strings.IndexByte(rest, '/'); idx > 0 {
			id := rest[:idx]
			sub := rest[idx+1:]
			if sub == "recording" {
				h.handleRecording(w, r, id)
				return
			}
			if sub == "recording/verify" {
				h.handleRecordingVerify(w, r, id)
				return
			}
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
			return
		}
		if rest == "" {
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
			return
		}
		h.handleGetOne(w, r, rest)
		return
	}
	h.CertHandler.ServeHTTP(w, r)
}

// SessionView is the JSON projection of jit.Session.
type SessionView struct {
	ID            string     `json:"id"`
	Subject       string     `json:"subject"`
	TargetID      string     `json:"target_id"`
	GrantID       string     `json:"grant_id,omitempty"`
	Protocol      string     `json:"protocol,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	CloseReason   string     `json:"close_reason,omitempty"`
	RecordingPath string     `json:"recording_path,omitempty"`
	ControllerID  string     `json:"controller_id,omitempty"`
	// DurationSeconds is a convenience for the SPA: integer
	// (now-started_at) for active sessions, (ended_at-started_at)
	// for closed ones. SPAs don't have to redo the math.
	DurationSeconds int64 `json:"duration_seconds"`
	Active          bool  `json:"active"`
	// Phase 5e-10 bytes counters. Pass-through from jit.Session.
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

func toSessView(s jit.Session) SessionView {
	out := SessionView{
		ID:            s.ID,
		Subject:       s.Subject,
		TargetID:      s.TargetID,
		GrantID:       s.GrantID,
		Protocol:      s.Protocol,
		StartedAt:     s.StartedAt,
		CloseReason:   s.CloseReason,
		RecordingPath: s.RecordingPath,
		ControllerID:  s.ControllerID,
		BytesIn:       s.BytesIn,
		BytesOut:      s.BytesOut,
	}
	if s.EndedAt != nil {
		t := *s.EndedAt
		out.EndedAt = &t
		out.DurationSeconds = int64(t.Sub(s.StartedAt).Seconds())
		out.Active = false
	} else {
		out.DurationSeconds = int64(time.Since(s.StartedAt).Seconds())
		out.Active = true
	}
	return out
}

// handleList — GET /sessions[?mine=true][&limit=N]. Same dual-mode
// auth as /requests handleList: ?mine bypasses the admin gate.
func (h *SessionsHandler) handleList(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable — controller running with in-memory or no SessionStore wired")
		return
	}
	mine := r.URL.Query().Get("mine") == "true"
	if !mine && !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required (or pass ?mine=true to list your own)")
		return
	}
	limit := 0
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			limit = n
		}
	}
	if limit <= 0 {
		limit = 50
	}
	// Server-side subject filter when caller is in self-mode. Admin
	// callers can pass an arbitrary ?subject=… to inspect a specific
	// operator; non-admins are pinned to their own.
	subjectFilter := ""
	if mine {
		subjectFilter = id.Subject
	} else if s := r.URL.Query().Get("subject"); s != "" {
		subjectFilter = s
	}
	rs, err := h.sessions.ListSessions(r.Context(), subjectFilter, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]SessionView, 0, len(rs))
	for _, x := range rs {
		out = append(out, toSessView(x))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRecording — GET /sessions/{id}/recording. Streams the asciicast
// bundle from MinIO so the SPA's in-browser player can render it.
//
// Auth: owner OR admin (same posture as handleGetOne; privacy-preserving
// 404 for non-owners).
//
// Storage: requires NewSessions().WithRecordings(rec) on the controller
// at startup. Without it, returns 503 with a hint — the SPA degrades
// to the MinIO Console deep link (Phase 5e-9) which uses the operator's
// SSO instead.
//
// Content-Type: application/x-asciicast (the asciinema-player understands
// this MIME directly; falls back to its own sniff if the server sends
// generic). The bundle key is the recording_path persisted on the
// jit_sessions row (Phase 5e-7), so the lookup is one cheap row read
// followed by one MinIO Get.
func (h *SessionsHandler) handleRecording(w http.ResponseWriter, r *http.Request, sessID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable")
		return
	}
	if h.rec == nil {
		writeErr(w, http.StatusServiceUnavailable, "recording playback not configured on this controller (set JESS_REC_S3_* envs + restart)")
		return
	}
	sess, err := h.sessions.GetSession(r.Context(), sessID)
	if err != nil {
		if errors.Is(err, jit.ErrNoSession) {
			writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !id.HasRole(h.adminRole) && sess.Subject != id.Subject {
		writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
		return
	}
	if sess.RecordingPath == "" {
		writeErr(w, http.StatusNotFound, "session "+sessID+" has no recording (target was not Recorded)")
		return
	}
	body, gerr := h.rec.Get(r.Context(), sess.RecordingPath)
	if gerr != nil {
		writeErr(w, http.StatusBadGateway, "fetch from object store: "+gerr.Error())
		return
	}
	// asciicast v2 MIME isn't IANA-registered; asciinema-player matches
	// on "x-asciicast" or sniffs the first byte. Set the well-known
	// header so server-side filters that key on Content-Type don't
	// surprise the player.
	w.Header().Set("Content-Type", "application/x-asciicast")
	// Long Cache-Control — WORM bundles are immutable for their
	// retention window (7y default), so the browser can hold the bytes
	// for the duration of the operator's session without re-fetching.
	w.Header().Set("Cache-Control", "private, max-age=3600, immutable")
	w.Header().Set("Content-Length", strconvItoa(len(body)))
	_, _ = w.Write(body)
}

// strconvItoa avoids dragging strconv into a file that doesn't otherwise
// need it; the existing iitoa helper lives in jit/postgres.go and the
// admin package shouldn't depend on jit/postgres internals.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// VerifyResponse is the JSON envelope the verify endpoint returns —
// composes the recording.VerifyResult with a top-level boolean so the
// SPA badge can be driven from a single field. We also surface
// session_id + the manifest's key id at the top so admin UIs can audit
// without parsing the nested object.
//
// Phase 5e-20 adds ChainLinkOK + the row hashes for the cross-link
// check: manifest.session_row_hash vs current jit_sessions.row_hash.
// ChainLinkOK is true iff:
//   - the bundle predates 5e-20 (manifest.session_row_hash == "" — no
//     check applicable), OR
//   - manifest.session_row_hash equals the row's current row_hash
//
// False means either the chain row was tampered AFTER seal, OR the
// bundle was swapped onto a different session id. Either way the
// bundle is no longer trustworthy in its claimed context.
type VerifyResponse struct {
	SessionID         string              `json:"session_id"`
	OK                bool                `json:"ok"`
	SignatureValid    bool                `json:"signature_valid"`
	HashMatch         bool                `json:"hash_match"`
	ChainLinkOK       bool                `json:"chain_link_ok"`
	ChainLinkExpected string              `json:"chain_link_expected,omitempty"`
	ChainLinkGot      string              `json:"chain_link_got,omitempty"`
	KeyID             string              `json:"key_id,omitempty"`
	SealedAt          *time.Time          `json:"sealed_at,omitempty"`
	ContentBytes      int64               `json:"content_bytes"`
	ContentSHA256     string              `json:"content_sha256,omitempty"`
	Error             string              `json:"error,omitempty"`
	Manifest          *recording.Manifest `json:"manifest,omitempty"`
}

// handleRecordingVerify — GET /sessions/{id}/recording/verify.
//
// Re-checks the sealed bundle against its detached Vault Transit
// signature AND the manifest-committed content SHA. Same owner-or-admin
// gate as handleRecording; same 404-on-not-yours privacy posture.
//
// 503 = verifier not configured (controller missing JESS_REC_VERIFY_*
// envs). The SPA will hide the badge in that case; this is acceptable
// in dev where MinIO might not even be wired.
//
// 200 + ok=false is intentional — we want admins to SEE the failure
// (tamper alert) instead of having it look like a transport error.
// 5xx is reserved for "we genuinely couldn't read the bundle".
func (h *SessionsHandler) handleRecordingVerify(w http.ResponseWriter, r *http.Request, sessID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable")
		return
	}
	if h.verifier == nil {
		writeErr(w, http.StatusServiceUnavailable, "recording verification not configured on this controller (set JESS_REC_VERIFY_VAULT_TRANSIT_* envs + restart)")
		return
	}
	sess, err := h.sessions.GetSession(r.Context(), sessID)
	if err != nil {
		if errors.Is(err, jit.ErrNoSession) {
			writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !id.HasRole(h.adminRole) && sess.Subject != id.Subject {
		writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
		return
	}
	if sess.RecordingPath == "" {
		writeErr(w, http.StatusNotFound, "session "+sessID+" has no recording")
		return
	}
	res, verr := h.verifier.VerifyBundle(r.Context(), sessID)
	out := VerifyResponse{
		SessionID:      sessID,
		SignatureValid: res.SignatureValid,
		HashMatch:      res.HashMatch,
		KeyID:          res.Manifest.KeyID,
		ContentBytes:   res.Manifest.Bytes,
		ContentSHA256:  res.Manifest.ContentSHA256,
		Manifest:       nonZeroManifest(res.Manifest),
	}
	if !res.Manifest.SealedAt.IsZero() {
		t := res.Manifest.SealedAt
		out.SealedAt = &t
	}
	if verr != nil {
		out.Error = verr.Error()
	}
	// Phase 5e-20: cross-check the manifest's session_row_hash claim
	// against the row's current row_hash. A bundle that predates
	// 5e-20 has an empty claim — chain_link_ok stays true in that
	// case (no check applicable, can't fail what wasn't pinned).
	out.ChainLinkOK = true
	if res.Manifest.SessionRowHash != "" {
		out.ChainLinkExpected = res.Manifest.SessionRowHash
		out.ChainLinkGot = sess.RowHash
		out.ChainLinkOK = res.Manifest.SessionRowHash == sess.RowHash
	}
	out.OK = res.SignatureValid && res.HashMatch && out.ChainLinkOK && verr == nil
	writeJSON(w, http.StatusOK, out)
}

// nonZeroManifest returns &m only when there is at least one
// meaningful field populated — avoids serialising an all-zero manifest
// when the verifier failed to read the file.
func nonZeroManifest(m recording.Manifest) *recording.Manifest {
	if m.SessionID == "" && m.ContentSHA256 == "" {
		return nil
	}
	return &m
}

// handleAuditExport — GET /audit/export?subject=&from=&to=&limit=
//
// Streams the session log as newline-delimited JSON (application/x-ndjson)
// for SOC 2 / ISO 27001 evidence collection.
//
// Auth: admin only. Subject is optional (per-operator export) but the
// endpoint itself requires the admin role even with a subject filter —
// operators wanting their own export can already use /sessions?mine=true
// and pipe to file client-side.
//
// Default window: 90 days back from now. Hard cap: 365 days. The cap
// is a guard against an accidental "give me everything" pull on a
// busy cluster — if longer windows are needed (e.g. retention review),
// the export can be batched by calling the endpoint repeatedly with
// adjusted windows.
//
// Server-side filtering uses ListSessions's existing subject+limit
// surface plus an in-handler started_at window filter. This avoids
// a new store method while keeping the export cheap for typical
// 90-day windows (hundreds-thousands of rows; well under streaming
// limits).
//
// Content-Disposition: attachment with a filename like
// "jess-audit-2026-03-01-2026-05-31.jsonl" so browsers download
// rather than render in-tab.
func (h *SessionsHandler) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable")
		return
	}
	q := r.URL.Query()
	from, to, perr := parseAuditWindow(q.Get("from"), q.Get("to"))
	if perr != nil {
		writeErr(w, http.StatusBadRequest, perr.Error())
		return
	}
	subject := q.Get("subject")
	limit := 5000
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 50000 {
			limit = n
		}
	}
	rows, err := h.sessions.ListSessions(r.Context(), subject, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	fname := "jess-audit-" + from.Format("2006-01-02") + "-" + to.Format("2006-01-02") + ".jsonl"
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.Header().Set("X-Audit-Window-From", from.Format(time.RFC3339))
	w.Header().Set("X-Audit-Window-To", to.Format(time.RFC3339))
	w.WriteHeader(http.StatusOK)
	enc := newNDJSONEncoder(w)
	emitted := 0
	dropped := 0
	for _, s := range rows {
		if s.StartedAt.Before(from) || s.StartedAt.After(to) {
			dropped++
			continue
		}
		if err := enc.Encode(toSessView(s)); err != nil {
			// Connection closed mid-stream — log? No, would leak.
			// Best-effort: stop quietly.
			return
		}
		emitted++
	}
	// Footer line carries the run metadata — a trailing JSON object
	// distinguishable by its `_meta:true` field. Consumers (jq, awk)
	// can filter it out cheaply; auditors get provenance for free.
	_ = enc.Encode(map[string]any{
		"_meta":          true,
		"emitted_count":  emitted,
		"dropped_count":  dropped,
		"window_from":    from,
		"window_to":      to,
		"subject_filter": subject,
		"limit":          limit,
		"caller":         id.Subject,
		"generated_at":   time.Now().UTC(),
	})
}

// parseAuditWindow resolves the [from, to] window. Defaults: now-90d → now.
// Hard cap: 365d span. Both ends RFC3339. Empty inputs use defaults; bad
// inputs return an error.
func parseAuditWindow(fromStr, toStr string) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	to := now
	from := now.Add(-90 * 24 * time.Hour)
	if toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid `to` (expected RFC3339): " + err.Error())
		}
		to = t
	}
	if fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid `from` (expected RFC3339): " + err.Error())
		}
		from = t
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("`from` must be earlier than `to`")
	}
	if to.Sub(from) > 365*24*time.Hour {
		return time.Time{}, time.Time{}, errors.New("window > 365 days; batch your export into smaller spans")
	}
	return from, to, nil
}

// ndjsonEncoder writes JSON values one per line. Tiny wrapper because
// encoding/json's Encoder defaults to JSON streams (object-per-line
// when called repeatedly), which is exactly what we want.
type ndjsonEncoder interface {
	Encode(any) error
}

// handleAuditChainVerify — GET /audit/chain/verify.
//
// Returns the cross-session WORM chain report (Phase 5e-16). Admin-only.
// 501 when the SessionStore doesn't implement jit.ChainVerifier (dev
// mode without postgres — MemoryBroker DOES implement it so tests
// exercise the same surface, but custom test brokers might not).
//
// 200 + ok=false intentionally: tampering is visible at the data
// layer, not via HTTP status. Same posture as recording verify
// (Phase 5e-14). Hard errors (DB unreachable, scan failure) still
// 5xx for monitoring + paging.
func (h *SessionsHandler) handleAuditChainVerify(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable")
		return
	}
	verifier, ok := h.sessions.(jit.ChainVerifier)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "session store does not support chain verify (5e-16)")
		return
	}
	rep, err := verifier.VerifyChain(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleRDPProbe — GET /rdp-probe?target=HOST:PORT[&protocols=tls,credssp][&cookie=mstshash=user]
//
// Admin-only RDP reachability + capability probe. Backs the SPA
// "Test target reachability" button on the Admin sessions tab and
// the jessctl admin rdp-probe-target subcommand. Phase 5f-2b.
//
// Security gates (in order):
//  1. admin role (avoid scope creep — operators can probe from
//     jessctl on their workstation)
//  2. SSRF guard (rdpprobe.IsAllowedTarget): port in {3389, 13389},
//     host MUST resolve to RFC1918/loopback ONLY
//  3. hard 5s timeout on the probe itself
//
// On allowed-target reject, returns 400 with the reason (so admins
// see the why instead of a generic forbidden). Probe failures
// (unreachable, neg-failure) come back as 200 + Report.Error /
// FailureCode populated — same shape as the CLI.
func (h *SessionsHandler) handleRDPProbe(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	q := r.URL.Query()
	target := q.Get("target")
	if target == "" {
		writeErr(w, http.StatusBadRequest, "target=HOST:PORT required")
		return
	}
	if err := rdpprobe.IsAllowedTarget(target); err != nil {
		writeErr(w, http.StatusBadRequest, "target rejected by SSRF guard: "+err.Error())
		return
	}
	requestedStr := q.Get("protocols")
	if requestedStr == "" {
		requestedStr = "tls,credssp"
	}
	requested, perr := rdpprobe.ParseRequestedProtocols(requestedStr)
	if perr != nil {
		writeErr(w, http.StatusBadRequest, perr.Error())
		return
	}
	// Hard timeout — independent of caller's request context so a
	// slow target can't tie up the admin port behind a hung probe.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rep := rdpprobe.Probe(ctx, target, q.Get("cookie"), requested, 5*time.Second)
	writeJSON(w, http.StatusOK, rep)
}

// SweepResult is one row of the probe-sweep response — a target +
// its probe verdict.
type SweepResult struct {
	TargetID   string          `json:"target_id"`
	TargetName string          `json:"target_name,omitempty"`
	Address    string          `json:"address"`
	Region     string          `json:"region,omitempty"`
	Probe      rdpprobe.Report `json:"probe"`
}

// SweepResponse is the full probe-sweep response envelope.
type SweepResponse struct {
	Total     int           `json:"total"`
	Reachable int           `json:"reachable"`
	Failed    int           `json:"failed"`
	Results   []SweepResult `json:"results"`
	ElapsedMs int64         `json:"elapsed_ms"`
}

// handleRDPProbeSweep — GET /rdp-probe/sweep
//
// Thin HTTP wrapper around RunRDPSweep. Admin-role gated; returns
// SweepResponse JSON. The Phase 5f-9 background monitor calls
// RunRDPSweep directly without going through HTTP.
func (h *SessionsHandler) handleRDPProbeSweep(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	if h.cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "catalog not configured on this controller")
		return
	}
	resp, err := h.RunRDPSweep(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// RunRDPSweep walks the catalog, filters to protocol=rdp, probes each
// target in bounded-parallel, returns the aggregated SweepResponse.
//
// Exposed for the Phase 5f-9 background monitor goroutine. NO auth
// check here — callers (HTTP handler, background tick) gate as
// appropriate. nil catalog → returns an error caller can map to 503.
//
// Per-target SSRF guard still applies — catalog entries with public
// IPs surface as Report.Error="ssrf guard: ..." instead of being
// probed.
//
// Concurrency: capped at 8 simultaneous probes to keep controller
// resource use bounded even with a large catalog. Each probe has its
// own 5s timeout; total wall-time bounded at ceil(targets/8) * 5s.
func (h *SessionsHandler) RunRDPSweep(ctx context.Context) (SweepResponse, error) {
	if h.cat == nil {
		return SweepResponse{}, errors.New("catalog not configured on this controller")
	}
	t0 := time.Now()
	targets, err := h.cat.List(ctx, "")
	if err != nil {
		return SweepResponse{}, fmt.Errorf("catalog list: %w", err)
	}
	rdpTargets := make([]*CatalogTarget, 0, len(targets))
	for _, t := range targets {
		if strings.EqualFold(t.Protocol, "rdp") {
			rdpTargets = append(rdpTargets, t)
		}
	}
	resp := SweepResponse{
		Total:   len(rdpTargets),
		Results: make([]SweepResult, len(rdpTargets)),
	}
	if len(rdpTargets) == 0 {
		resp.ElapsedMs = time.Since(t0).Milliseconds()
		return resp, nil
	}
	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, t := range rdpTargets {
		i, t := i, t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			resp.Results[i] = probeOneFromSweep(ctx, t)
		}()
	}
	wg.Wait()
	for _, r := range resp.Results {
		if r.Probe.Reachable && r.Probe.FailureCode == 0 {
			resp.Reachable++
		} else {
			resp.Failed++
		}
	}
	resp.ElapsedMs = time.Since(t0).Milliseconds()
	return resp, nil
}

func probeOneFromSweep(ctx context.Context, t *CatalogTarget) SweepResult {
	res := SweepResult{
		TargetID:   t.ID,
		TargetName: t.Name,
		Address:    t.Address,
		Region:     t.Region,
	}
	if err := rdpprobe.IsAllowedTarget(t.Address); err != nil {
		// Synthesise a Report with the SSRF-guard error so the
		// caller sees the catalog problem inline.
		res.Probe = rdpprobe.Report{
			Target: t.Address,
			Error:  "ssrf guard: " + err.Error(),
		}
		return res
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res.Probe = rdpprobe.Probe(probeCtx, t.Address, "", rdpprobe.ProtoTLS|rdpprobe.ProtoCredSSP, 5*time.Second)
	return res
}

// handleGetOne — GET /sessions/{id}. Same privacy posture as /requests.
func (h *SessionsHandler) handleGetOne(w http.ResponseWriter, r *http.Request, sessID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if h.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "session log unavailable")
		return
	}
	sess, err := h.sessions.GetSession(r.Context(), sessID)
	if err != nil {
		if errors.Is(err, jit.ErrNoSession) {
			writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !id.HasRole(h.adminRole) && sess.Subject != id.Subject {
		// Privacy: pretend not-found.
		writeErr(w, http.StatusNotFound, "session "+sessID+" not found")
		return
	}
	writeJSON(w, http.StatusOK, toSessView(sess))
}
