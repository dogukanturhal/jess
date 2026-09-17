// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Per-target recording enable/disable — admin-controlled runtime override
// on top of the catalog's GitOps `recorded` default.
//
// Design (deliberate runtime-override-on-GitOps-default):
//
//	catalog target.recorded   = the DEFAULT, GitOps-managed (ConfigMap / CRD
//	                            / discovery annotation). Source of truth for
//	                            what recording SHOULD be unless an operator
//	                            decides otherwise at runtime.
//	override (controller DB)   = an admin's RUNTIME decision to flip a target
//	                            on/off without a Git round-trip. Persisted,
//	                            audited (updated_by = verified caller).
//
//	EFFECTIVE recorded = override if present, else catalog default.
//
// The controller's session-open path resolves the SAME effective value
// (spine.Controller.resolveEffectiveRecorded) and propagates it to the
// worker via SessionHeader.Recorded, so what this endpoint reports/sets is
// exactly what RDP/SSH/DB sessions honour.
//
// Routes (admin-only, platform_admin gated like every other admin handler):
//
//	GET    /recording-settings              list {target_id, recorded (effective),
//	                                              source: "override"|"catalog",
//	                                              catalog_default, updated_by, updated_at}
//	PUT    /recording-settings/{target_id}  {"recorded": bool} → upsert override
//	DELETE /recording-settings/{target_id}  clear override → revert to catalog default
//
// A toggle is a security-relevant change: updated_by is bound to the
// verified Falcon-ID subject (request-body updated_by, if any, is ignored)
// and every PUT/DELETE is emitted to the audit sink (Action recording.*).

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/jit"
)

// RecordingHandler adds the /recording-settings routes on top of the
// existing admin handler chain. Construct via NewRecording; it wraps the
// next handler so other traffic falls through unchanged.
type RecordingHandler struct {
	next  http.Handler
	base  *Handler                   // shared authn + role gate
	store jit.RecordingOverrideStore // nil = routes 503
	cat   catalog.Catalog            // nil = routes 503 (need defaults to compute effective)
	audit audit.Sink                 // nil-safe — audit emission optional
}

// NewRecording wires the recording-settings handler. `store` and `cat` may
// be nil (the routes then 503); `sink` may be nil (audit emission skipped).
func NewRecording(next http.Handler, base *Handler, store jit.RecordingOverrideStore, cat catalog.Catalog, sink audit.Sink) *RecordingHandler {
	return &RecordingHandler{next: next, base: base, store: store, cat: cat, audit: sink}
}

// RecordingSetting is the GET-shaped projection for one target. `recorded`
// is the EFFECTIVE value (what sessions actually honour); `source` tells the
// operator whether that came from an admin override or the catalog default;
// `catalog_default` surfaces the GitOps baseline so the UI can show what a
// DELETE would revert to.
type RecordingSetting struct {
	TargetID       string     `json:"target_id"`
	TargetName     string     `json:"target_name,omitempty"`
	Protocol       string     `json:"protocol,omitempty"`
	Recorded       bool       `json:"recorded"`        // EFFECTIVE
	Source         string     `json:"source"`          // "override" | "catalog"
	CatalogDefault bool       `json:"catalog_default"` // the GitOps baseline
	UpdatedBy      string     `json:"updated_by,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

// recordingSetReq is the PUT body.
type recordingSetReq struct {
	Recorded bool `json:"recorded"`
}

// ServeHTTP dispatches /recording-settings[...]; everything else falls
// through to next.
func (h *RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/recording-settings" && r.Method == http.MethodGet:
		h.handleList(w, r)
		return
	case strings.HasPrefix(p, "/recording-settings/") && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		id := strings.TrimPrefix(p, "/recording-settings/")
		if id == "" || strings.Contains(id, "/") {
			writeErr(w, http.StatusNotFound, "target_id required")
			return
		}
		if r.Method == http.MethodPut {
			h.handleSet(w, r, id)
		} else {
			h.handleClear(w, r, id)
		}
		return
	case p == "/recording-settings" || strings.HasPrefix(p, "/recording-settings/"):
		writeErr(w, http.StatusMethodNotAllowed, "GET /recording-settings, PUT/DELETE /recording-settings/{target_id}")
		return
	}
	if h.next != nil {
		h.next.ServeHTTP(w, r)
		return
	}
	writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
}

// adminGate runs authn + the platform_admin role check; returns the
// verified identity's subject + ok.
func (h *RecordingHandler) adminGate(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "recording handler: missing auth base")
		return "", false
	}
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return "", false
	}
	if !id.HasRole(h.base.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.base.adminRole+" required")
		return "", false
	}
	return id.Subject, true
}

// handleList — GET /recording-settings. Walks the catalog and joins each
// target against the override map to compute the effective recorded value +
// source. Stable order by target_id.
func (h *RecordingHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.adminGate(w, r); !ok {
		return
	}
	if h.store == nil || h.cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "recording-settings endpoint not configured (needs override store + catalog)")
		return
	}
	targets, err := h.cat.List(r.Context(), "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "catalog list: "+err.Error())
		return
	}
	overrides, err := h.store.ListRecordingOverrides(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list overrides: "+err.Error())
		return
	}
	byID := make(map[string]jit.RecordingOverride, len(overrides))
	for _, ov := range overrides {
		byID[ov.TargetID] = ov
	}
	out := make([]RecordingSetting, 0, len(targets))
	for _, t := range targets {
		s := RecordingSetting{
			TargetID:       t.ID,
			TargetName:     t.Name,
			Protocol:       string(t.Protocol),
			CatalogDefault: t.Recorded,
			Recorded:       t.Recorded,
			Source:         "catalog",
		}
		if ov, found := byID[t.ID]; found {
			s.Recorded = ov.Recorded
			s.Source = "override"
			s.UpdatedBy = ov.UpdatedBy
			ua := ov.UpdatedAt
			s.UpdatedAt = &ua
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	writeJSON(w, http.StatusOK, out)
}

// handleSet — PUT /recording-settings/{target_id}. Upserts the override and
// stamps updated_by from the verified caller. The target must exist in the
// catalog (so the operator can't pin recording for a phantom id). Emits a
// recording.override audit row.
func (h *RecordingHandler) handleSet(w http.ResponseWriter, r *http.Request, targetID string) {
	sub, ok := h.adminGate(w, r)
	if !ok {
		return
	}
	if h.store == nil || h.cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "recording-settings endpoint not configured")
		return
	}
	var req recordingSetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	// Validate the target exists (a runtime override on a non-existent
	// target would be silently ineffective — surface it as a 404).
	t, err := h.cat.Lookup(r.Context(), targetID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "target not in catalog: "+targetID)
		return
	}
	ov, err := h.store.SetRecordingOverride(r.Context(), targetID, req.Recorded, sub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "set override: "+err.Error())
		return
	}
	h.emitAudit(r, "recording.override", sub, targetID, req.Recorded, t.Recorded)
	ua := ov.UpdatedAt
	writeJSON(w, http.StatusOK, RecordingSetting{
		TargetID:       ov.TargetID,
		TargetName:     t.Name,
		Protocol:       string(t.Protocol),
		Recorded:       ov.Recorded,
		Source:         "override",
		CatalogDefault: t.Recorded,
		UpdatedBy:      ov.UpdatedBy,
		UpdatedAt:      &ua,
	})
}

// handleClear — DELETE /recording-settings/{target_id}. Removes the
// override, reverting the target to its catalog default. Idempotent. Emits
// a recording.override.clear audit row.
func (h *RecordingHandler) handleClear(w http.ResponseWriter, r *http.Request, targetID string) {
	sub, ok := h.adminGate(w, r)
	if !ok {
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "recording-settings endpoint not configured")
		return
	}
	if err := h.store.ClearRecordingOverride(r.Context(), targetID); err != nil {
		writeErr(w, http.StatusInternalServerError, "clear override: "+err.Error())
		return
	}
	// Report the reverted-to catalog default when the target still exists.
	var def bool
	var name, proto string
	if h.cat != nil {
		if t, err := h.cat.Lookup(r.Context(), targetID); err == nil {
			def = t.Recorded
			name = t.Name
			proto = string(t.Protocol)
		}
	}
	h.emitAudit(r, "recording.override.clear", sub, targetID, def, def)
	writeJSON(w, http.StatusOK, RecordingSetting{
		TargetID:       targetID,
		TargetName:     name,
		Protocol:       proto,
		Recorded:       def,
		Source:         "catalog",
		CatalogDefault: def,
	})
}

// emitAudit records a recording toggle. updated_by lineage is captured in
// the Subject field (sub:<verified>); the effective + catalog-default values
// land in Err (the audit Event's free-text diagnostic field, same as the
// other admin handlers use it) so a SOC2 trail can answer "who changed
// recording for target X, to what, and what was the GitOps default at the
// time?". Best-effort — audit failure never blocks the mutation (the write
// already committed).
func (h *RecordingHandler) emitAudit(r *http.Request, action, sub, targetID string, effective, catalogDefault bool) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Emit(r.Context(), audit.Event{
		Time:     time.Now(),
		Action:   action,
		Subject:  "sub:" + sub,
		TargetID: targetID,
		Err:      "recorded=" + b2s(effective) + " catalog_default=" + b2s(catalogDefault),
	})
}

func b2s(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
