// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// ADR 0052 Phase F — discovery review queue admin API. The audit-only model
// holds discovered candidates in JessPendingTarget (phase=Pending); an operator
// approves (→ JessTarget, brokerable) or rejects them here. platform_admin-gated;
// every decision audited. Routes:
//
//	GET  /pending                 — list candidates (the review queue)
//	POST /pending/{name}/approve  — promote to JessTarget (operator decision)
//	POST /pending/{name}/reject   — terminally reject
//
// approve still refuses a Tier-0 RDP candidate (pending.ApprovePending enforces
// the ADR 0052 hard-guard — no operator override can broker DC RDP).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/lifecycle/pending"
)

// PendingHandler adds the /pending routes onto the admin chain.
type PendingHandler struct {
	next   http.Handler
	base   *Handler          // shared authn + role gate
	client dynamic.Interface // nil = routes 503 (discovery not enabled)
	audit  audit.Sink        // nil-safe
}

// NewPending wires the review-queue handler. `client` may be nil (routes 503).
func NewPending(next http.Handler, base *Handler, client dynamic.Interface, sink audit.Sink) *PendingHandler {
	return &PendingHandler{next: next, base: base, client: client, audit: sink}
}

func (h *PendingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/pending" && r.Method == http.MethodGet:
		h.handleList(w, r)
		return
	case strings.HasPrefix(p, "/pending/") && r.Method == http.MethodPost:
		rest := strings.TrimPrefix(p, "/pending/")
		slash := strings.LastIndex(rest, "/")
		if slash <= 0 {
			writeErr(w, http.StatusNotFound, "POST /pending/{name}/approve|reject")
			return
		}
		name, action := rest[:slash], rest[slash+1:]
		if name == "" || strings.Contains(name, "/") {
			writeErr(w, http.StatusNotFound, "invalid candidate name")
			return
		}
		switch action {
		case "approve":
			h.handleApprove(w, r, name)
		case "reject":
			h.handleReject(w, r, name)
		default:
			writeErr(w, http.StatusNotFound, "action must be approve|reject")
		}
		return
	case p == "/pending" || strings.HasPrefix(p, "/pending/"):
		writeErr(w, http.StatusMethodNotAllowed, "GET /pending, POST /pending/{name}/approve|reject")
		return
	}
	if h.next != nil {
		h.next.ServeHTTP(w, r)
		return
	}
	writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
}

func (h *PendingHandler) adminGate(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "pending handler: missing auth base")
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

func (h *PendingHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.adminGate(w, r); !ok {
		return
	}
	if h.client == nil {
		writeErr(w, http.StatusServiceUnavailable, "discovery not enabled (no k8s client)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := pending.ListPending(ctx, h.client)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "list pending: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

func (h *PendingHandler) handleApprove(w http.ResponseWriter, r *http.Request, name string) {
	sub, ok := h.adminGate(w, r)
	if !ok {
		return
	}
	if h.client == nil {
		writeErr(w, http.StatusServiceUnavailable, "discovery not enabled")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := pending.ApprovePending(ctx, h.client, name, sub); err != nil {
		writeErr(w, http.StatusBadGateway, "approve: "+err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Emit(ctx, audit.Event{Time: time.Now(), Action: "discovery.approved", Subject: sub, TargetID: name, Err: "operator-approved"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "approved": true, "by": sub})
}

func (h *PendingHandler) handleReject(w http.ResponseWriter, r *http.Request, name string) {
	sub, ok := h.adminGate(w, r)
	if !ok {
		return
	}
	if h.client == nil {
		writeErr(w, http.StatusServiceUnavailable, "discovery not enabled")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := pending.RejectPending(ctx, h.client, name, sub); err != nil {
		writeErr(w, http.StatusBadGateway, "reject: "+err.Error())
		return
	}
	if h.audit != nil {
		_ = h.audit.Emit(ctx, audit.Event{Time: time.Now(), Action: "discovery.rejected", Subject: sub, TargetID: name, Err: "operator-rejected"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "rejected": true, "by": sub})
}
