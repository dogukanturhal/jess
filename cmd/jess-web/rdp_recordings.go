// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// ADR 0051 P4 — RDP recording list / verify / download (replay backend).
//
// The live RDP bridge (ws_rdp_live.go) seals each session into a signed WORM
// jess-rdp-recording-v2 bundle in the SAME audit-archive bucket the SSH/DB
// recordings use. Unlike those, a live RDP session is NOT a controller
// jit_sessions row (its id is self-generated: rdp-<sub>-<target>-<ts>), so it
// isn't reachable via the controller /sessions/{id}/recording proxy. This handler
// serves those v2 bundles directly from the recorder's store, OWNER-SCOPED: a
// signed-in operator sees only recordings whose manifest Subject == their sub.
//
// Endpoints (all require a signed-in operator):
//
//	GET /api/rdp/recordings                      → list this operator's v2 bundles
//	GET /api/rdp/recordings/{id}/verify          → tamper-evidence verdict (sig+hash)
//	GET /api/rdp/recordings/{id}                  → stream the NDJSON content (replay)
//
// Owner-scoping is enforced on EVERY path by re-reading the manifest and checking
// Subject — the bundle id alone never grants access.
//
// When the recorder isn't configured (no store), every endpoint returns 503 so
// the SPA degrades gracefully ("recordings unavailable").

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// rdpRecordingsConfig serves owner-scoped v2 RDP recordings from the recorder
// store. store/signer are nil when no recorder is configured (→ 503).
type rdpRecordingsConfig struct {
	sessions *sessionStore
	store    recording.ObjectStore
	signer   recording.Signer
}

// newRDPRecordingsConfig derives the recordings handler from the live-RDP
// recorder. It pulls the store + signer off a *recording.BundleRecorder; any
// other Recorder implementation (or nil) yields a 503-only handler.
func newRDPRecordingsConfig(sessions *sessionStore, rec recording.Recorder) *rdpRecordingsConfig {
	c := &rdpRecordingsConfig{sessions: sessions}
	if br, ok := rec.(*recording.BundleRecorder); ok {
		c.store = br.Store()
		c.signer = br.Signer()
	}
	return c
}

// rdpRecordingSummary is one row in the list response.
type rdpRecordingSummary struct {
	SessionID string    `json:"session_id"`
	TargetID  string    `json:"target_id"`
	GrantID   string    `json:"grant_id,omitempty"`
	StartedAt time.Time `json:"started_at"`
	SealedAt  time.Time `json:"sealed_at"`
	Bytes     int64     `json:"bytes"`
	Format    string    `json:"format"`
}

// handleRecordings dispatches the three GET shapes under /api/rdp/recordings.
func (c *rdpRecordingsConfig) handleRecordings(w http.ResponseWriter, r *http.Request) {
	op, err := c.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if c.store == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "RDP recording store not configured")
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/rdp/recordings")
	rest = strings.TrimPrefix(rest, "/")
	switch {
	case rest == "":
		c.list(w, r, op.Subject)
	case strings.HasSuffix(rest, "/verify"):
		id := strings.TrimSuffix(rest, "/verify")
		c.verify(w, r, op.Subject, id)
	default:
		c.download(w, r, op.Subject, rest)
	}
}

// list returns the operator's own v2 recordings, newest first.
func (c *rdpRecordingsConfig) list(w http.ResponseWriter, r *http.Request, subject string) {
	lister, ok := c.store.(recording.ObjectLister)
	if !ok {
		writeJSONErr(w, http.StatusServiceUnavailable, "recording store does not support listing")
		return
	}
	// Live RDP bundles are keyed rdp-<sub>-<target>-<ts>/... — list the whole
	// store and filter to v2 manifests this operator owns.
	keys, err := lister.List(r.Context(), "")
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, "list recordings: "+err.Error())
		return
	}
	var out []rdpRecordingSummary
	for _, sid := range recording.SessionsFrom(keys) {
		man, ok := c.loadManifest(r.Context(), sid)
		if !ok {
			continue
		}
		if man.Subject != subject || man.Format != recording.FormatRDPStreamV2 {
			continue // owner-scope + RDP-v2 only
		}
		out = append(out, rdpRecordingSummary{
			SessionID: man.SessionID,
			TargetID:  man.TargetID,
			GrantID:   man.GrantID,
			StartedAt: man.StartedAt,
			SealedAt:  man.SealedAt,
			Bytes:     man.Bytes,
			Format:    string(man.Format),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SealedAt.After(out[j].SealedAt) })
	body, _ := json.Marshal(map[string]any{"recordings": out})
	relayJSON(w, http.StatusOK, body)
}

// verify returns the tamper-evidence verdict for one bundle (owner-scoped).
func (c *rdpRecordingsConfig) verify(w http.ResponseWriter, r *http.Request, subject, id string) {
	if !validSessionID(id) {
		writeJSONErr(w, http.StatusNotFound, "bad recording id")
		return
	}
	man, ok := c.loadManifest(r.Context(), id)
	if !ok || man.Subject != subject {
		writeJSONErr(w, http.StatusNotFound, "recording not found")
		return
	}
	if c.signer == nil {
		writeJSONErr(w, http.StatusServiceUnavailable, "no verification key available")
		return
	}
	res, err := recording.VerifyDetail(r.Context(), c.store, id, c.signer.Public())
	if err != nil {
		// Still report the (possibly partial) verdict so the SPA can show WHY.
		body, _ := json.Marshal(map[string]any{
			"ok":              false,
			"signature_valid": res.SignatureValid,
			"hash_match":      res.HashMatch,
			"key_id":          man.KeyID,
			"error":           err.Error(),
		})
		relayJSON(w, http.StatusOK, body)
		return
	}
	body, _ := json.Marshal(map[string]any{
		"ok":              res.SignatureValid && res.HashMatch,
		"signature_valid": res.SignatureValid,
		"hash_match":      res.HashMatch,
		"key_id":          res.Manifest.KeyID,
		"session_id":      res.Manifest.SessionID,
		"sealed_at":       res.Manifest.SealedAt,
		"content_bytes":   res.Manifest.Bytes,
	})
	relayJSON(w, http.StatusOK, body)
}

// download streams the v2 NDJSON content for replay (owner-scoped).
func (c *rdpRecordingsConfig) download(w http.ResponseWriter, r *http.Request, subject, id string) {
	if !validSessionID(id) {
		writeJSONErr(w, http.StatusNotFound, "bad recording id")
		return
	}
	man, ok := c.loadManifest(r.Context(), id)
	if !ok || man.Subject != subject {
		writeJSONErr(w, http.StatusNotFound, "recording not found")
		return
	}
	if man.Format != recording.FormatRDPStreamV2 {
		writeJSONErr(w, http.StatusNotFound, "not an RDP v2 recording")
		return
	}
	content, err := c.store.Get(r.Context(), man.ContentKey)
	if err != nil {
		writeJSONErr(w, http.StatusBadGateway, "read recording content: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "private, max-age=3600, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// loadManifest reads + parses a bundle manifest. Returns ok=false on any miss.
func (c *rdpRecordingsConfig) loadManifest(ctx context.Context, id string) (recording.Manifest, bool) {
	if !validSessionID(id) {
		return recording.Manifest{}, false
	}
	raw, err := c.store.Get(ctx, id+"/manifest.json")
	if err != nil {
		return recording.Manifest{}, false
	}
	var man recording.Manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		return recording.Manifest{}, false
	}
	return man, true
}

// validSessionID rejects ids that could traverse the store key namespace.
func validSessionID(id string) bool {
	if id == "" || strings.Contains(id, "/") || strings.Contains(id, "..") {
		return false
	}
	return true
}

// compile-time guard: the protocol const is used so this file owns the RDP
// recordings surface (and to fail loud if catalog drops ProtoRDP).
var _ = catalog.ProtoRDP
