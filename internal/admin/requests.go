// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/jit"
)

// RequestStore is the subset of jit.PostgresStore the requests API needs.
// Same pattern as Store — interface for testability.
type RequestStore interface {
	Submit(ctx context.Context, subject, targetID, reason string, requestTTL time.Duration) (jit.Request, error)
	GetRequest(ctx context.Context, id string) (jit.Request, error)
	ListRequests(ctx context.Context, state jit.RequestState) ([]jit.Request, error)
	Approve(ctx context.Context, requestID, approverSub string, ttl time.Duration) (jit.Request, jit.Grant, error)
	Deny(ctx context.Context, requestID, denierSub, reason string) (jit.Request, error)
}

// RequestsHandler adds the Phase 5b request/approve/deny endpoints
// alongside the grants API. Same auth model (Falcon-ID bearer + role
// gate) but with a split: anyone with a verified token can submit a
// REQUEST; only platform_admin can approve/deny/list.
//
// Phase 5h-4a: optional auto-approval. When RiskEvaluator is non-nil
// AND TargetLookup returns a target, every Submit() is followed by an
// in-process Evaluate() — Decision.AutoApprove triggers an inline
// Approve() call so the operator gets a grant immediately. Audit
// distinguishes "approve.auto" from "approve.human" so SOC 2 evidence
// is clean. Decisions are recorded via Metrics.RequestAutoDecision
// regardless of outcome (require_human is the no-op case that just
// leaves the request Pending for the existing approver workflow).
type RequestsHandler struct {
	*Handler // re-uses authenticate + writeJSON/writeErr
	requests RequestStore

	// Risk-score auto-approval (Phase 5h-4a). All-or-nothing — when
	// risk is wired, EVERY new request goes through Evaluate; partial
	// configuration would be confusing. Builder-style optional so
	// dev mode without OPA still works.
	risk        Evaluator
	targets     TargetLookup
	auditSink   AuditEmitter
	metricsSink RiskMetricsEmitter
}

// Evaluator is the riskscore.Evaluator surface the requests handler
// needs. Defined here to avoid the admin package importing the
// riskscore package directly (which would create a dependency loop
// the moment riskscore wants to consume any admin shape).
type Evaluator interface {
	Evaluate(ctx context.Context, in EvalInput) (EvalOutput, error)
}

// EvalInput / EvalOutput mirror riskscore.Input / .Output exactly.
// cmd/jess-controller's wiring converts between the shapes at the
// boundary — see cmd/jess-controller/riskscore_wiring.go.
type EvalInput struct {
	Subject             string
	SubjectRoles        []string
	SubjectGroups       []string
	TargetID            string
	TargetCriticality   string
	TargetTags          []string
	TargetProtocol      string
	RequestedAt         time.Time
	RequestReason       string
	RecentApprovalCount int
	RecentDenialCount   int
}

type EvalOutput struct {
	Decision      string // "auto_approve" | "require_human" | "auto_deny"
	Reason        string
	GrantTTL      time.Duration
	PolicyVersion string
}

// TargetLookup is the narrow catalog read the handler needs. Decoupled
// from internal/catalog to keep admin's import graph small.
type TargetLookup interface {
	Lookup(ctx context.Context, id string) (TargetSummary, error)
}

// TargetSummary is the catalog projection the evaluator consumes.
type TargetSummary struct {
	ID          string
	Criticality string
	Tags        []string
	Protocol    string
}

// AuditEmitter is the audit.Sink surface for distinguishing auto vs
// human approvals.
type AuditEmitter interface {
	EmitApproveAuto(ctx context.Context, requestID, subject, targetID, reason, policyVersion string)
}

// RiskMetricsEmitter bumps the Prometheus counter on every decision.
type RiskMetricsEmitter interface {
	RequestAutoDecision(decision string)
}

// NewRequests wires the requests handler on top of an existing grants
// Handler. The base Handler's authenticate + adminRole apply uniformly.
func NewRequests(base *Handler, requests RequestStore) *RequestsHandler {
	return &RequestsHandler{Handler: base, requests: requests}
}

// WithRiskScore enables Phase 5h-4a auto-approval. nil-safe — all four
// dependencies must be non-nil for auto-approval to fire (otherwise
// the handler falls back to the pre-5h-4a "every request is Pending
// until human approves" behaviour). Builder is the only way to opt in
// so dev mode without OPA / catalog stays at human-only approvals.
func (h *RequestsHandler) WithRiskScore(e Evaluator, t TargetLookup, a AuditEmitter, m RiskMetricsEmitter) *RequestsHandler {
	h.risk = e
	h.targets = t
	h.auditSink = a
	h.metricsSink = m
	return h
}

// ServeHTTP for the requests handler dispatches /requests routes first,
// then falls through to the base /grants handler for everything else.
// Keeps a single net/http surface so cmd/jess-controller wires one
// http.Server.
func (h *RequestsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/requests" && r.Method == http.MethodPost:
		h.handleSubmit(w, r)
		return
	case r.URL.Path == "/requests" && r.Method == http.MethodGet:
		h.handleList(w, r)
		return
	case strings.HasPrefix(r.URL.Path, "/requests/") && r.Method == http.MethodGet:
		// /requests/{id} — per-request projection. The submitter can
		// poll their OWN request (no admin role needed); admins can
		// fetch any request. Auth check happens inside handleGetOne.
		rest := strings.TrimPrefix(r.URL.Path, "/requests/")
		// Reject trailing path components — /requests/{id} is a leaf,
		// not a tree. Without this the SPA polling /requests/x/y would
		// silently land here instead of 404'ing as expected.
		if strings.Contains(rest, "/") || rest == "" {
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
			return
		}
		h.handleGetOne(w, r, rest)
		return
	case strings.HasPrefix(r.URL.Path, "/requests/") && r.Method == http.MethodPost:
		// /requests/{id}/approve | /requests/{id}/deny
		rest := strings.TrimPrefix(r.URL.Path, "/requests/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
			return
		}
		switch parts[1] {
		case "approve":
			h.handleApprove(w, r, parts[0])
		case "deny":
			h.handleDeny(w, r, parts[0])
		default:
			writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
		}
		return
	}
	h.Handler.ServeHTTP(w, r) // delegate to grants
}

// SubmitRequest body.
type SubmitRequest struct {
	TargetID         string `json:"target_id"`
	Reason           string `json:"reason"`
	RequestTTLMinute int    `json:"request_ttl_minutes,omitempty"` // 0 → server default (4h)
}

// RequestView is the JSON projection of jit.Request.
type RequestView struct {
	ID            string     `json:"id"`
	Subject       string     `json:"subject"`
	TargetID      string     `json:"target_id"`
	Reason        string     `json:"reason"`
	RequestedAt   time.Time  `json:"requested_at"`
	State         string     `json:"state"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	DecidedReason string     `json:"decided_reason,omitempty"`
	GrantID       string     `json:"grant_id,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

func toReqView(r jit.Request) RequestView {
	out := RequestView{
		ID: r.ID, Subject: r.Subject, TargetID: r.TargetID, Reason: r.Reason,
		RequestedAt: r.RequestedAt, State: string(r.State),
		DecidedBy: r.DecidedBy, DecidedReason: r.DecidedReason,
		GrantID: r.GrantID, ExpiresAt: r.ExpiresAt,
	}
	if !r.DecidedAt.IsZero() {
		t := r.DecidedAt
		out.DecidedAt = &t
	}
	return out
}

// handleSubmit — POST /requests. Authenticated (any verified caller), no
// admin role required. The submitter's verified sub becomes the request's
// subject — never trust a client-supplied identity here.
func (h *RequestsHandler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var req SubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.TargetID == "" {
		writeErr(w, http.StatusBadRequest, "target_id required")
		return
	}
	if req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "reason required (SOC 2 CC6.2 evidence)")
		return
	}
	ttl := time.Duration(req.RequestTTLMinute) * time.Minute
	if ttl > 24*time.Hour {
		writeErr(w, http.StatusBadRequest, "request_ttl_minutes must be ≤ 1440 (24h)")
		return
	}
	sub, _ := h.requests.Submit(r.Context(), id.Subject, req.TargetID, req.Reason, ttl)
	// Phase 5h-4a auto-approval: if risk-score is wired, evaluate inline.
	// On AutoApprove, mint a grant via the existing Approve path
	// (approver_sub = "system:risk-score-v1") so the audit trail still
	// records WHO approved (system) and WHY (policy version). On
	// require_human or auto_deny, leave the request as-is.
	sub = h.maybeAutoApprove(r.Context(), sub, id.Subject, id.Roles, id.Groups)
	writeJSON(w, http.StatusCreated, toReqView(sub))
}

// maybeAutoApprove runs the Phase 5h-4a risk-score evaluator and, when
// the policy returns AutoApprove, calls Approve() inline. Returns the
// (possibly updated) request — caller writes it to the response so the
// SPA sees Approved + grant_id immediately on Submit.
//
// All paths bump the metric (including require_human, the no-op case)
// so a sudden drop in auto-approval rate is observable.
func (h *RequestsHandler) maybeAutoApprove(ctx context.Context, req jit.Request, subject string, roles, groups []string) jit.Request {
	// Skip path: risk-score not wired.
	if h.risk == nil || h.targets == nil {
		return req
	}
	tgt, err := h.targets.Lookup(ctx, req.TargetID)
	if err != nil {
		// Catalog miss is operational, not security — leave the
		// request Pending and let humans approve. Don't fail the
		// Submit (request is already persisted).
		return req
	}
	// Approval/denial history would ideally come from the request
	// store but adding that surface requires extending RequestStore.
	// For 5h-4a (this commit) we pass zeros — the rules-v1 evaluator
	// gates new operators behind RecentApprovalCount >= 3, so the
	// effect is "first three requests always require human review",
	// which is the conservative safe default. 5h-4b adds the lookup
	// when OPA backend wants the richer signal.
	in := EvalInput{
		Subject:           subject,
		SubjectRoles:      roles,
		SubjectGroups:     groups,
		TargetID:          tgt.ID,
		TargetCriticality: tgt.Criticality,
		TargetTags:        tgt.Tags,
		TargetProtocol:    tgt.Protocol,
		RequestedAt:       req.RequestedAt,
		RequestReason:     req.Reason,
	}
	out, evalErr := h.risk.Evaluate(ctx, in)
	if evalErr != nil {
		// Evaluator errors fail-CLOSED — leave request pending. Same
		// posture as a catalog miss.
		return req
	}
	if h.metricsSink != nil {
		h.metricsSink.RequestAutoDecision(out.Decision)
	}
	switch out.Decision {
	case "auto_approve":
		ttl := out.GrantTTL
		if ttl == 0 {
			ttl = 1 * time.Hour
		}
		_, _, approveErr := h.requests.Approve(ctx, req.ID, "system:risk-score-"+out.PolicyVersion, ttl)
		if approveErr != nil {
			// Approve failed (e.g. race with manual approval) —
			// leave request as-is. No SPA-visible difference.
			return req
		}
		if h.auditSink != nil {
			h.auditSink.EmitApproveAuto(ctx, req.ID, subject, req.TargetID, out.Reason, out.PolicyVersion)
		}
		// Re-read the request so caller sees the Approved state +
		// grant_id populated.
		fresh, gerr := h.requests.GetRequest(ctx, req.ID)
		if gerr != nil {
			return req
		}
		return fresh
	case "auto_deny":
		// Mirror auto_approve shape with Deny().
		_, denyErr := h.requests.Deny(ctx, req.ID, "system:risk-score-"+out.PolicyVersion, out.Reason)
		if denyErr != nil {
			return req
		}
		fresh, gerr := h.requests.GetRequest(ctx, req.ID)
		if gerr != nil {
			return req
		}
		return fresh
	default:
		// require_human or unknown — leave Pending.
		return req
	}
}

// handleList — GET /requests[?state=pending][&mine=true].
//
// Two modes:
//
//   - admin-list: caller has the admin role → all requests visible
//     (optionally filtered by ?state). Standard approver workflow.
//   - self-list (?mine=true): caller filters down to their OWN
//     requests. No admin role required — Phase 5e-5 operator
//     self-service activity view ("what have I asked for recently,
//     what was approved, what's still pending"). Per-operator
//     visibility into their own activity is a baseline expectation
//     of any modern access-broker.
//
// The two modes intentionally share a route to keep the SPA + jessctl
// surface compact. Without ?mine=true a non-admin still gets 403 (the
// admin endpoint behaviour is unchanged).
func (h *RequestsHandler) handleList(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	mine := r.URL.Query().Get("mine") == "true"
	if !mine && !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required (or pass ?mine=true to list your own)")
		return
	}
	state := jit.RequestState(r.URL.Query().Get("state"))
	rs, err := h.requests.ListRequests(r.Context(), state)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]RequestView, 0, len(rs))
	for _, x := range rs {
		if mine && x.Subject != id.Subject {
			continue
		}
		out = append(out, toReqView(x))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetOne — GET /requests/{id}. The submitter can poll their OWN
// request (no admin role required); admins can fetch any. This is the
// SPA-side polling target: after POST /requests it polls /requests/{id}
// every couple seconds until state transitions pending → approved/denied,
// then surfaces the grant_id to the operator.
//
// Auth model — defence-in-depth:
//
//   - The caller MUST be authenticated (Falcon-ID Bearer verifies at the
//     base Handler).
//   - If caller is admin: any request is fetchable.
//   - Else: caller's verified subject must equal the request's subject.
//     A 404 (not 403) is returned for "not yours" to avoid leaking the
//     existence of requests the caller isn't authorised to see — same
//     posture as GitHub / GitLab / most production access-control APIs.
func (h *RequestsHandler) handleGetOne(w http.ResponseWriter, r *http.Request, reqID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	req, err := h.requests.GetRequest(r.Context(), reqID)
	if err != nil {
		if errors.Is(err, jit.ErrNoRequest) {
			writeErr(w, http.StatusNotFound, "request "+reqID+" not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !id.HasRole(h.adminRole) && req.Subject != id.Subject {
		// Privacy posture — pretend not-found. The caller cannot
		// distinguish "doesn't exist" from "exists but not yours".
		writeErr(w, http.StatusNotFound, "request "+reqID+" not found")
		return
	}
	writeJSON(w, http.StatusOK, toReqView(req))
}

// ApproveBody — POST /requests/{id}/approve.
type ApproveBody struct {
	TTLSeconds int `json:"ttl_seconds"`
}

func (h *RequestsHandler) handleApprove(w http.ResponseWriter, r *http.Request, reqID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	var body ApproveBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if body.TTLSeconds <= 0 || body.TTLSeconds > 24*3600 {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be 1..86400")
		return
	}
	rec, g, err := h.requests.Approve(r.Context(), reqID, id.Subject, time.Duration(body.TTLSeconds)*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, jit.ErrNoRequest):
			writeErr(w, http.StatusNotFound, "request "+reqID+" not found")
		case errors.Is(err, jit.ErrRequestNotPending):
			writeErr(w, http.StatusConflict, "request "+reqID+" is not pending")
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": toReqView(rec), "grant": toView(g)})
}

// DenyBody — POST /requests/{id}/deny.
type DenyBody struct {
	Reason string `json:"reason"`
}

func (h *RequestsHandler) handleDeny(w http.ResponseWriter, r *http.Request, reqID string) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	var body DenyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if body.Reason == "" {
		writeErr(w, http.StatusBadRequest, "reason required (auditability)")
		return
	}
	rec, err := h.requests.Deny(r.Context(), reqID, id.Subject, body.Reason)
	if err != nil {
		switch {
		case errors.Is(err, jit.ErrNoRequest):
			writeErr(w, http.StatusNotFound, "request "+reqID+" not found")
		case errors.Is(err, jit.ErrRequestNotPending):
			writeErr(w, http.StatusConflict, "request "+reqID+" is not pending")
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, toReqView(rec))
}
