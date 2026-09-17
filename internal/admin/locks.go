// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/metrics"
)

// LocksHandler wraps a base handler (RequestsHandler or CertHandler in
// prod) and adds the Phase 5j-1 lock-primitive routes:
//
//	POST   /locks         insert (or replace via ?replace=1)
//	GET    /locks         list active locks
//	DELETE /locks/{id}    delete (idempotent — 404 also returns 204)
//
// Locks compose with the grant substrate so admins can kill all sessions
// for a subject or to a target in one call (broader than per-grant
// revoke). The continuous grant watcher in spine.Controller also
// re-evaluates locks per tick — a lock dropped at T kills any matching
// live session within the watch interval (default 10s, env-tunable).
type LocksHandler struct {
	next    http.Handler // typically *RequestsHandler so /locks composes after grants + requests
	base    *Handler     // for auth + admin-role gate + now()
	store   jit.LockStore
	metrics *metrics.Metrics // nil-safe — observability optional
}

// NewLocks wires the locks handler on top of an existing chain.
func NewLocks(next http.Handler, base *Handler, store jit.LockStore) *LocksHandler {
	return &LocksHandler{next: next, base: base, store: store}
}

// WithMetrics attaches a metrics sink so insert/replace/delete events
// emit Prometheus counters. Nil disables instrumentation (default).
func (h *LocksHandler) WithMetrics(m *metrics.Metrics) *LocksHandler {
	h.metrics = m
	return h
}

// ServeHTTP dispatches /locks routes; everything else falls through.
func (h *LocksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/locks" && r.Method == http.MethodPost:
		h.handleInsert(w, r)
		return
	case r.URL.Path == "/locks" && r.Method == http.MethodGet:
		h.handleList(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/locks/") && r.Method == http.MethodDelete:
		rest := strings.TrimPrefix(r.URL.Path, "/locks/")
		if strings.Contains(rest, "/") || rest == "" {
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
			return
		}
		h.handleDelete(w, r, rest)
		return
	}
	h.next.ServeHTTP(w, r)
}

// LockRequest is the POST /locks body. Optional expires_at; nil/empty
// = indefinite. Replace=true upserts; default insert returns 409 on
// existing lock.
type LockRequest struct {
	TargetType  string     `json:"target_type"`          // subject | target | cert_serial | mfa_device
	TargetValue string     `json:"target_value"`         // the Falcon-ID sub / target_id / serial / device-id
	Reason      string     `json:"reason"`               // operator-facing message — appears in kill audit + denial reply
	ExpiresAt   *time.Time `json:"expires_at,omitempty"` // omit = indefinite
	Replace     bool       `json:"replace,omitempty"`    // upsert instead of error-on-exists
}

// LockView is the GET-shaped projection. Mirrors jit.Lock with JSON
// tags + string typing so cmd/jessctl can decode without importing the
// internal jit package.
type LockView struct {
	ID         string     `json:"id"`
	TargetType string     `json:"target_type"`
	TargetVal  string     `json:"target_value"`
	Reason     string     `json:"reason"`
	LockedBy   string     `json:"locked_by"`
	LockedAt   time.Time  `json:"locked_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func toLockView(l jit.Lock) LockView {
	return LockView{
		ID:         l.ID,
		TargetType: string(l.TargetType),
		TargetVal:  l.TargetVal,
		Reason:     l.Reason,
		LockedBy:   l.LockedBy,
		LockedAt:   l.LockedAt,
		ExpiresAt:  l.ExpiresAt,
	}
}

// handleInsert implements POST /locks. Verified Falcon-ID subject is
// stamped as LockedBy (admin who issued); request body's locked_by, if
// present, is ignored (RFC 8705-style binding to the verified identity).
func (h *LocksHandler) handleInsert(w http.ResponseWriter, r *http.Request) {
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.base.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.base.adminRole+" required")
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "locks endpoint not configured")
		return
	}
	var req LockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	tt := jit.LockTargetType(req.TargetType)
	if !tt.Valid() {
		writeErr(w, http.StatusBadRequest, "invalid target_type — must be subject|target|cert_serial|mfa_device")
		return
	}
	if req.TargetValue == "" {
		writeErr(w, http.StatusBadRequest, "target_value required")
		return
	}
	if req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "reason required (lock event needs a human-readable cause)")
		return
	}
	lock := jit.Lock{
		TargetType: tt,
		TargetVal:  req.TargetValue,
		Reason:     req.Reason,
		LockedBy:   id.Subject, // RFC 8705-style binding to verified identity
		ExpiresAt:  req.ExpiresAt,
	}
	var out jit.Lock
	var err error
	if req.Replace {
		out, err = h.store.ReplaceLock(r.Context(), lock)
	} else {
		out, err = h.store.InsertLock(r.Context(), lock)
		if errors.Is(err, jit.ErrLockExists) {
			writeErr(w, http.StatusConflict, "an active lock already exists for this (target_type, target_value) — pass replace=true to upsert")
			return
		}
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lock: "+err.Error())
		return
	}
	// Audit on the controller side (Vault writes its own audit entry
	// when the lock causes a kill; this captures the LockedBy lineage
	// at lock-insert time).
	log.Printf("admin lock %s: type=%s value=%s reason=%q by=%s expires=%v",
		mode(req.Replace), out.TargetType, out.TargetVal, out.Reason, out.LockedBy, out.ExpiresAt)
	h.metrics.JITLockInserted(string(out.TargetType), mode(req.Replace))
	status := http.StatusCreated
	if req.Replace {
		status = http.StatusOK
	}
	writeJSON(w, status, toLockView(out))
}

func mode(replace bool) string {
	if replace {
		return "replaced"
	}
	return "inserted"
}

// handleList implements GET /locks — admins only.
func (h *LocksHandler) handleList(w http.ResponseWriter, r *http.Request) {
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.base.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.base.adminRole+" required")
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "locks endpoint not configured")
		return
	}
	locks, err := h.store.ListLocks(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	out := make([]LockView, 0, len(locks))
	for _, l := range locks {
		out = append(out, toLockView(l))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDelete implements DELETE /locks/{id} — idempotent.
func (h *LocksHandler) handleDelete(w http.ResponseWriter, r *http.Request, lockID string) {
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.base.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.base.adminRole+" required")
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "locks endpoint not configured")
		return
	}
	if err := h.store.DeleteLock(r.Context(), lockID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete: "+err.Error())
		return
	}
	log.Printf("admin lock removed: id=%s by=%s", lockID, id.Subject)
	h.metrics.JITLockRemoved()
	w.WriteHeader(http.StatusNoContent)
}
