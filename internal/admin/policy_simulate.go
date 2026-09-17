// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Gap audit #12 — dry-run policy evaluation. POST /admin/policy/
// simulate accepts a synthetic OperatorRequest shape (subject +
// target + roles + amr) and runs it through the SAME pdp.Authorizer
// path as the live session-open without actually opening anything.
// Useful for incident response ("what would happen if user X
// requested target Y right now?") + for policy authoring tests.
//
// Routes:
//   POST /admin/policy/simulate
//   body: {"subject":"u-1","target_id":"node-app-01","subject_roles":
//          ["operator"],"amr":["webauthn"]}
//   body: {"verdict":"allow","decision_id":"...","reason":"..."}
//
// Security: admin-role gated like every other /admin/* route. The
// PDP evaluation is pure (no state mutation, no session row, no
// grant mint) — safe to expose to platform_admin without rate limits.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/hexx-pep-core/pkg/identity"
)

// PolicySimulateHandler wraps a base handler chain with the
// /admin/policy/simulate route. Constructed with the same shared
// admin.Handler base (for auth + role gate) and the live PDP +
// catalog so simulations reflect production behaviour exactly.
type PolicySimulateHandler struct {
	next http.Handler
	base *Handler
	pdp  pdp.Authorizer
	cat  catalog.Catalog
}

// NewPolicySimulate wires the handler on top of an existing chain.
// Either pdp or cat may be nil — when nil the handler 503s with a
// clear "not configured" message rather than panicking.
func NewPolicySimulate(next http.Handler, base *Handler, p pdp.Authorizer, c catalog.Catalog) *PolicySimulateHandler {
	return &PolicySimulateHandler{next: next, base: base, pdp: p, cat: c}
}

// SimulateRequest is the POST body.
type SimulateRequest struct {
	Subject      string   `json:"subject"`
	SubjectEmail string   `json:"subject_email"`
	TargetID     string   `json:"target_id"`
	SubjectRoles []string `json:"subject_roles"`
	AMR          []string `json:"amr"`
	Region       string   `json:"region"`
}

// SimulateResponse is the JSON projection of the PDP decision.
type SimulateResponse struct {
	Verdict    string `json:"verdict"` // "allow" | "deny"
	DecisionID string `json:"decision_id"`
	Reason     string `json:"reason"`
	TargetID   string `json:"target_id"`
	Protocol   string `json:"protocol"`
	Region     string `json:"region"`
}

// ServeHTTP dispatches /admin/policy/simulate locally; everything
// else falls through.
func (h *PolicySimulateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/policy/simulate" {
		h.next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.base.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.base.adminRole+" required")
		return
	}
	if h.pdp == nil || h.cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "policy simulate not configured")
		return
	}
	var req SimulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.TargetID) == "" {
		writeErr(w, http.StatusBadRequest, "subject and target_id are required")
		return
	}

	target, lerr := h.cat.Lookup(r.Context(), req.TargetID)
	if lerr != nil {
		// Treat unknown target as a denied decision rather than
		// 404 — that's the actual session-open shape too (a
		// session for an unknown target opens with openResult=
		// "authz"). Operator sees the same answer either way.
		writeJSON(w, http.StatusOK, SimulateResponse{
			Verdict:  "deny",
			Reason:   "catalog: target not found",
			TargetID: req.TargetID,
		})
		return
	}

	synth := identity.Identity{
		Subject: req.Subject,
		Email:   req.SubjectEmail,
		Roles:   req.SubjectRoles,
		AMR:     req.AMR,
	}
	pdpReq := pdp.Request{
		Identity:      synth,
		TargetID:      target.ID,
		Protocol:      string(target.Protocol),
		Region:        firstNonEmpty(req.Region, target.Region),
		RequiredRoles: target.RequiredRoles,
	}
	d, derr := h.pdp.Authorize(context.WithoutCancel(r.Context()), pdpReq)
	if derr != nil {
		writeErr(w, http.StatusBadGateway, "pdp error: "+derr.Error())
		return
	}
	verdict := "deny"
	if d.Allow {
		verdict = "allow"
	}
	writeJSON(w, http.StatusOK, SimulateResponse{
		Verdict:    verdict,
		DecisionID: d.DecisionID,
		Reason:     d.Reason,
		TargetID:   target.ID,
		Protocol:   string(target.Protocol),
		Region:     target.Region,
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
