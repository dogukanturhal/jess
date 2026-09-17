// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Phase 7g — Host attestation endpoint.
//
// POST /admin/attest verifies a cloud-signed identity document
// (presented by jess-attest or any compatible client) and audits
// every attempt — successful and rejected alike.
//
// Wire shape:
//
//	POST /admin/attest
//	Content-Type: application/json
//	{
//	   "provenance": "aws" | "azure",
//	   "presentation": "<base64-encoded provenance-specific envelope>"
//	}
//
// On success (200):
//
//	{
//	  "provenance": "aws",
//	  "account_id": "012345678901",
//	  "instance_id": "i-0abcdef1234567890",
//	  "region": "us-east-1",
//	  "issued_at": "2026-06-01T19:00:00Z",
//	  "expires_at": "2026-06-01T19:10:00Z"
//	}
//
// On failure (401):
//
//	{"error": "<verifier error>"}
//
// What this endpoint does NOT yet do (future MRs):
//   - Mint an SSH-CA cert bound to the attested identity (7g-2)
//   - Auto-create a JessTarget CR from the verified document (7g-3)
//
// For now the endpoint is a verification + audit surface. Operators
// of jess-attest see "your document checks out" or "no — here's why."

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/dogukanturhal/jess/internal/attestation"
	"github.com/dogukanturhal/jess/internal/audit"
)

// AttestHandler adds POST /admin/attest on top of the existing admin
// chain. Construct via NewAttest; wraps the next handler so non-
// attest traffic falls through.
type AttestHandler struct {
	next     http.Handler
	base     *Handler // shared authn + role gate
	registry *attestation.Registry
	audit    audit.Sink
}

// NewAttest wires the attestation handler. `reg` is the verifier
// registry built at controller startup (one Register call per cloud
// the operator enables). `sink` is the audit sink the controller is
// already writing other admin actions to — every attest attempt
// emits one audit row regardless of outcome.
func NewAttest(next http.Handler, base *Handler, reg *attestation.Registry, sink audit.Sink) *AttestHandler {
	return &AttestHandler{next: next, base: base, registry: reg, audit: sink}
}

// AttestRequest is the body of POST /admin/attest.
type AttestRequest struct {
	// Provenance names the cloud signing this document — "aws",
	// "azure", "gcp" (future).
	Provenance string `json:"provenance"`
	// Presentation is the base64-encoded provenance-specific envelope
	// (see internal/attestation/aws/Presentation +
	// internal/attestation/azure/Presentation). We use base64 over
	// raw bytes so the JSON wrapper stays well-formed even when the
	// envelope contains binary signature bytes.
	Presentation string `json:"presentation"`
}

// AttestResponse is the JSON projection of a successful attestation.
// Mirrors attestation.Document — the controller doesn't re-shape it.
type AttestResponse struct {
	Provenance string            `json:"provenance"`
	AccountID  string            `json:"account_id"`
	InstanceID string            `json:"instance_id"`
	Region     string            `json:"region"`
	IssuedAt   time.Time         `json:"issued_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Extras     map[string]string `json:"extras,omitempty"`
}

// ServeHTTP routes /admin/attest locally; everything else goes to next.
func (h *AttestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/attest" {
		if h.next != nil {
			h.next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
		return
	}
	if h.registry == nil {
		writeErr(w, http.StatusServiceUnavailable, "attestation endpoint not configured (no verifiers registered)")
		return
	}
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "attest handler: missing auth base")
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

	var req AttestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.auditFail(r, id.Subject, req.Provenance, "bad envelope JSON: "+err.Error())
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.Provenance == "" || req.Presentation == "" {
		h.auditFail(r, id.Subject, req.Provenance, "provenance and presentation are required")
		writeErr(w, http.StatusBadRequest, "provenance and presentation are required")
		return
	}
	verifier := h.registry.VerifierFor(attestation.Provenance(req.Provenance))
	if verifier == nil {
		h.auditFail(r, id.Subject, req.Provenance, "no verifier registered")
		writeErr(w, http.StatusBadRequest, "no verifier for provenance "+req.Provenance)
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Presentation)
	if err != nil {
		h.auditFail(r, id.Subject, req.Provenance, "base64 decode: "+err.Error())
		writeErr(w, http.StatusBadRequest, "bad base64 presentation: "+err.Error())
		return
	}
	doc, err := verifier.Verify(r.Context(), blob)
	if err != nil {
		h.auditFail(r, id.Subject, req.Provenance, err.Error())
		// Verification failures always 401 — caller MUST treat them
		// as "your document was rejected", not "try again with
		// different data."
		if errors.Is(err, attestation.ErrVerification) {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.auditOK(r, id.Subject, doc)
	writeJSON(w, http.StatusOK, AttestResponse{
		Provenance: string(doc.Provenance),
		AccountID:  doc.AccountID,
		InstanceID: doc.InstanceID,
		Region:     doc.Region,
		IssuedAt:   doc.IssuedAt,
		ExpiresAt:  doc.ExpiresAt,
		Extras:     doc.Extras,
	})
}

func (h *AttestHandler) auditOK(r *http.Request, callerSub string, doc attestation.Document) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Emit(r.Context(), audit.Event{
		Time:    time.Now(),
		Action:  "attest.ok",
		Subject: "sub:" + callerSub,
		Err:     "provenance=" + string(doc.Provenance) + " account=" + doc.AccountID + " instance=" + doc.InstanceID + " region=" + doc.Region,
	})
}

func (h *AttestHandler) auditFail(r *http.Request, callerSub, provenance, reason string) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Emit(r.Context(), audit.Event{
		Time:    time.Now(),
		Action:  "attest.deny",
		Subject: "sub:" + callerSub,
		Err:     "provenance=" + provenance + " reason=" + reason,
	})
}
