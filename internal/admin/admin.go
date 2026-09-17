// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admin exposes a tiny HTTP API for managing JIT grants without
// shelling into the controller pod for psql INSERTs. Authenticated by the
// same Falcon-ID OIDC token the operator path uses and gated on a
// configured admin role (default `platform_admin`). Intentionally NOT
// served on the public/operator port; runs on a separate listener (default
// `:7103`) so an operator-port DoS or auth-token leak can't reach grant
// mutation.
//
// Routes:
//
//	POST   /grants            issue   — body {"subject","target_id","ttl_seconds"}
//	GET    /grants[?target=X] list    — active grants, optional target filter
//	DELETE /grants/{id}        revoke — soft-end via expires_at = now()
//
// Wire shape (one example each):
//
//	POST /grants
//	{ "subject":"04ad…", "target_id":"node-app-01", "ttl_seconds":1800 }
//	→ 201 { "id":"grant-…", "subject":"04ad…", "target_id":"node-app-01",
//	        "approved_by":"sub:04ad…", "issued_at":"…", "expires_at":"…" }
//
// The `approved_by` field captures the caller's subject (from the
// verified token) — SOC tooling joins this with audit_events for
// per-decision lineage.
package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/jit"
	"github.com/dogukanturhal/jess/internal/pdp"
)

// Store is the subset of jit.PostgresStore the admin API needs. Defined
// as an interface so tests can wire an in-memory fake without standing up
// a real Postgres.
type Store interface {
	Issue(ctx context.Context, subject, targetID string, ttl time.Duration) (jit.Grant, error)
	List(ctx context.Context, targetID string) ([]jit.Grant, error)
	Revoke(ctx context.Context, grantID string) error
}

// Handler wires the admin HTTP routes. Construct via New and mount on a
// dedicated http.Server.
type Handler struct {
	store         Store
	devices       DeviceStore            // task #136 — nil disables /devices routes
	preReg        PreRegStore            // nil disables /devices/pre-registrations routes
	pendingDev    PendingDeviceStore     // TOFU auto-enroll — nil disables /devices/pending routes
	sshCert       *SSHCertConfig         // task #130 — nil disables /ssh-cert route
	crlResponder  http.Handler           // task #131 — nil disables /crl.pem + /ocsp
	talonIdentity *TalonIdentityVerifier // task #140 — nil = trust X-Talon-Device-UUID bare header
	verifier      pdp.TokenVerifier
	adminRole     string
	audit         audit.Sink       // nil-safe — WORM sink for admin mutations (e.g. corp-asset approvals)
	now           func() time.Time // overridable for tests
}

// New returns a Handler that verifies bearer tokens via v and gates every
// route on the token carrying adminRole in its roles claim.
//
// Failing to set adminRole is a configuration error — every request would
// be allowed; New default-denies by setting "platform_admin" when empty.
func New(store Store, v pdp.TokenVerifier, adminRole string) *Handler {
	if adminRole == "" {
		adminRole = "platform_admin"
	}
	return &Handler{store: store, verifier: v, adminRole: adminRole, now: time.Now}
}

// WithDeviceStore wires the device-enrollment store so the Handler can
// serve GET /devices + POST /devices/{uuid}/disable. Optional — calls
// to those routes return 503 when unset (per devices.go), which matches
// the deployment phase where the FalconIDEnrollmentStore hasn't yet
// been wired by controller bootstrap.
func (h *Handler) WithDeviceStore(d DeviceStore) *Handler {
	h.devices = d
	return h
}

// WithPreRegStore wires the corporate device pre-registration store so the
// Handler can serve the /devices/pre-registrations CRUD subtree. Optional —
// calls to those routes return 503 when unset (mirrors WithDeviceStore), which
// matches the deployment phase before the FalconIDEnrollmentStore is wired by
// controller bootstrap.
func (h *Handler) WithPreRegStore(p PreRegStore) *Handler {
	h.preReg = p
	return h
}

// WithPendingDevices wires the TOFU auto-enroll review queue so the Handler can
// serve the /devices/pending subtree (list / approve / reject). Approve promotes
// a pending device through the pre-registration store, so it is only useful
// alongside WithPreRegStore. Optional — the routes return 503 when unset.
func (h *Handler) WithPendingDevices(p PendingDeviceStore) *Handler {
	h.pendingDev = p
	return h
}

// WithAuditSink wires the WORM audit sink the base Handler emits to for
// admin mutations that need a tamper-evident lineage row (e.g. the
// corp-asset approval on /devices/onboarding/{uuid}/approve). Optional —
// when unset, emitAudit is a no-op, so existing routes and tests that
// construct a bare Handler are unaffected. Mirrors the nil-safe pattern
// the PendingHandler / AttestHandler use for their own sinks.
func (h *Handler) WithAuditSink(s audit.Sink) *Handler {
	h.audit = s
	return h
}

// emitAudit writes one event to the WORM sink, stamping Time from the
// Handler clock when the caller left it zero. Nil-safe: a Handler built
// without WithAuditSink silently drops the event.
func (h *Handler) emitAudit(ctx context.Context, ev audit.Event) {
	if h.audit == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = h.now()
	}
	_ = h.audit.Emit(ctx, ev)
}

// WithCRLResponder mounts the devicecrl responder under the admin
// Handler. The responder serves GET /crl.pem, GET /crl.der, POST /ocsp,
// and GET /ocsp/{b64}. Unset = those paths 404.
//
// The responder is its own http.Handler (not a method on this struct)
// because it has its own dependencies (Vault PKI client + cache). Pass
// `devicecrl.New(cfg)` as the argument.
//
// CRL/OCSP routes are reached BEFORE the role-gate authentication —
// device-cert validation is by definition needed by clients that don't
// yet have a session bearer token. The admin port is firewalled at the
// network level so the lack of bearer auth here is intentional and
// matches Vault's PKI defaults.
func (h *Handler) WithCRLResponder(r http.Handler) *Handler {
	h.crlResponder = r
	return h
}

// ServeHTTP dispatches to the per-method handlers. Every route runs
// through authn (verify token) + authz (role gate) before any DB call.
//
// EXCEPTION: the /crl.* and /ocsp* paths handled by WithCRLResponder
// run BEFORE authentication — RFC 6960 OCSP responders are public by
// design (the OCSP request itself is signed; the response is signed).
// Admin port network ACL is the second barrier.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.crlResponder != nil {
		p := r.URL.Path
		if p == "/crl.pem" || p == "/crl.der" || p == "/ocsp" || strings.HasPrefix(p, "/ocsp/") {
			h.crlResponder.ServeHTTP(w, r)
			return
		}
	}
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	// /devices routes first — they're an entirely new subtree and the
	// dispatcher returns true on match so the /grants legacy path is
	// untouched. Pattern matches how the existing routes dispatch by
	// path prefix without bringing in a router crate.
	if h.handleDevices(w, r, id.Subject) {
		return
	}
	// /ssh-cert — same true-on-match dispatch pattern (task #130).
	if h.handleSSHCert(w, r, id.Subject) {
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/grants":
		h.issue(w, r, id.Subject)
	case r.Method == http.MethodGet && r.URL.Path == "/grants":
		h.list(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/grants/"):
		h.revoke(w, r, strings.TrimPrefix(r.URL.Path, "/grants/"))
	default:
		writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
	}
}

// IssueRequest is the body of POST /grants.
type IssueRequest struct {
	Subject    string `json:"subject"`
	TargetID   string `json:"target_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// GrantView is the JSON projection of jit.Grant returned to the caller.
// Mirrors the audit.Event subject/target shape so downstream consumers
// (CLI, dashboard, SOC tools) can use one parser across both surfaces.
type GrantView struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	TargetID   string    `json:"target_id"`
	ApprovedBy string    `json:"approved_by"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func toView(g jit.Grant) GrantView {
	return GrantView{ID: g.ID, Subject: g.Subject, TargetID: g.TargetID,
		ApprovedBy: g.ApprovedBy, IssuedAt: g.IssuedAt, ExpiresAt: g.ExpiresAt}
}

func (h *Handler) issue(w http.ResponseWriter, r *http.Request, callerSub string) {
	var req IssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Subject == "" || req.TargetID == "" || req.TTLSeconds <= 0 {
		writeErr(w, http.StatusBadRequest, "subject, target_id, ttl_seconds required")
		return
	}
	if req.TTLSeconds > 24*3600 {
		writeErr(w, http.StatusBadRequest, "ttl_seconds must be ≤ 86400 (24h)")
		return
	}
	g, err := h.store.Issue(r.Context(), req.Subject, req.TargetID, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Stamp who approved it — the verified caller, not whatever the request
	// body claimed. The Issue() helper sets ApprovedBy="system:issue"; we
	// overwrite with the human-meaningful sub:<caller> so lineage holds.
	g.ApprovedBy = "sub:" + callerSub
	writeJSON(w, http.StatusCreated, toView(g))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	gs, err := h.store.List(r.Context(), r.URL.Query().Get("target"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]GrantView, len(gs))
	for i, g := range gs {
		out[i] = toView(g)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeErr(w, http.StatusBadRequest, "grant id required")
		return
	}
	if err := h.store.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, jit.ErrNoGrant) {
			writeErr(w, http.StatusNotFound, "no active grant "+id)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// authenticate extracts and verifies the bearer token. Returns the
// verified identity (never trust the token sub directly without going
// through the verifier). Writes the HTTP error itself and reports ok=false
// when authn fails.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (pdp.Identity, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeErr(w, http.StatusUnauthorized, "Authorization: Bearer required")
		return pdp.Identity{}, false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "empty bearer")
		return pdp.Identity{}, false
	}
	id, err := h.verifier.Verify(r.Context(), tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return pdp.Identity{}, false
	}
	return id, true
}

// tenantIDFromRequest extracts the operator's tenant_id from the bearer
// token's claims. The shared identity.Identity (Subject/Email/Roles/…) is
// deliberately tenant-agnostic, so the tenant scope is read directly from the
// already-verified JWT payload here — ServeHTTP has already run authenticate
// (signature + issuer + audience) before any route handler is reached, so this
// only re-reads the trusted payload for the one claim the Identity doesn't
// carry. Returns "" when the header is missing or the claim is absent; callers
// reject an empty tenant with HTTP 400.
func tenantIDFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return ""
	}
	return c.TenantID
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
