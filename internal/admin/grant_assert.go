// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Active-grant re-check endpoint — GET /grants/assert?grant=<id>&target=<id>.
//
// WHY THIS EXISTS (ASVS 5.0 L2, V8 — RDP-live grant parity):
//
// The data-plane worker (internal/spine/worker.go) gets an independent,
// authoritative grant re-check for free — it holds the shared jit.GrantStore
// and calls GrantStore.AssertActiveID(grantID, targetID) before brokering an
// SSH/DB session (defense in depth alongside the controller's own check). The
// in-browser RDP-live path (cmd/jess-web/ws_rdp_live.go + wt_rdp_live.go) runs
// IN jess-web, on the far side of the controller admin-port trust boundary, so
// it cannot touch the grant store directly. Before this endpoint its
// assertGrant() was a LOG-ONLY soft check ("a present grant is accepted"),
// leaving RDP without the hard, store-backed authorization the SSH/DB path has.
//
// This endpoint exposes the EXACT worker check over the admin port so jess-web
// can hard-gate the RDP-live session open (and re-check it continuously) with
// real store authority — reaching parity with SSH/DB.
//
// AUTH MODEL — self-service, subject-scoped (NOT platform_admin gated):
//
//   - The caller's Falcon-ID bearer is verified (base.authenticate) — same
//     token jess-web already forwards for /admin/catalog resolution.
//   - The grant is asserted ACTIVE for (grant, target) via the store — byte
//     identical to the worker's AssertActiveID call.
//   - The grant is then BOUND to the caller: grant.Subject MUST equal the
//     verified token subject. This is the one rung the worker does not need
//     (the worker trusts the controller-signed session header for the subject);
//     jess-web sources the grant id from an UNTRUSTED query param, so without
//     this bind an operator could replay another operator's still-active grant
//     id for the same target. A mismatch is 403.
//
// Deliberately NOT admin-role gated: an operator re-checking THEIR OWN grant is
// legitimate self-service and must work for non-admin operators. Every other
// admin route on this port keeps its platform_admin gate; this decorator runs
// its own authn ahead of the base role gate (mirrors CatalogHandler's
// self-contained auth) and never leaks another subject's grant metadata.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/dogukanturhal/jess/internal/jit"
)

// GrantAsserter is the subset of jit.GrantStore this endpoint needs — the same
// independent re-check the data-plane worker performs. Narrow interface so a
// test can inject an in-memory fake; satisfied by *jit.PostgresStore and
// *jit.MemoryBroker (both implement jit.GrantStore).
type GrantAsserter interface {
	AssertActiveID(ctx context.Context, grantID, targetID string) (*jit.Grant, error)
}

// GrantAssertHandler adds GET /grants/assert on top of the admin handler chain.
// Construct via NewGrantAssert; it wraps the next handler so all other traffic
// falls through unchanged.
type GrantAssertHandler struct {
	next  http.Handler
	base  *Handler // shared authn (deliberately NOT the role gate — see file header)
	store GrantAsserter
}

// NewGrantAssert wires the active-grant re-check handler. store may be any
// jit.GrantStore (PostgresStore in prod, MemoryBroker in dev/tests). nil store
// makes the route 503 (mirrors CatalogHandler's nil-cat posture).
func NewGrantAssert(next http.Handler, base *Handler, store GrantAsserter) *GrantAssertHandler {
	return &GrantAssertHandler{next: next, base: base, store: store}
}

// grantAssertPath is the exact route this decorator owns. Kept distinct from the
// base handler's POST/GET /grants + DELETE /grants/{id} routes; the decorator
// intercepts only this path and method, so /grants/{id} DELETE still reaches
// the base.
const grantAssertPath = "/grants/assert"

// ServeHTTP routes GET /grants/assert locally; everything else goes to next.
func (h *GrantAssertHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != grantAssertPath {
		if h.next != nil {
			h.next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "grant assert endpoint not configured")
		return
	}
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "grant assert handler: missing auth base")
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	// Authn ONLY — no admin-role gate (self-service, subject-scoped; see header).
	id, ok := h.base.authenticate(w, r)
	if !ok {
		return
	}
	grantID := r.URL.Query().Get("grant")
	targetID := r.URL.Query().Get("target")
	if grantID == "" || targetID == "" {
		writeErr(w, http.StatusBadRequest, "grant and target query params required")
		return
	}
	g, err := h.store.AssertActiveID(r.Context(), grantID, targetID)
	if err != nil {
		// Distinguish a definitively NOT-ACTIVE grant (revoked / expired /
		// wrong-target — the caller must fail closed and stop retrying) from a
		// transient store error (DB blip — the caller may tolerate it up to its
		// failure budget rather than tear down a live session). The jess-web
		// grant-watch keys its permanent-vs-transient logic off this status,
		// mirroring spine.classifyGrantError.
		if permanentGrantError(err) {
			// 404, deliberately terse: do NOT echo the raw store error — it can
			// name internal grant/target ids the caller shouldn't enumerate.
			writeErr(w, http.StatusNotFound, "no active grant for target")
			return
		}
		// Transient store failure — 503 so the caller tolerates it.
		writeErr(w, http.StatusServiceUnavailable, "grant store unavailable")
		return
	}
	// Subject binding — the grant MUST belong to the authenticated caller. The
	// store check above does not verify this (parity with the worker, which
	// gets the subject from the controller-signed header); we add it because
	// jess-web sources the grant id from an untrusted query param.
	if g.Subject != id.Subject {
		// 403, terse: don't confirm the grant exists for another subject.
		writeErr(w, http.StatusForbidden, "grant not authorized for caller")
		return
	}
	writeJSON(w, http.StatusOK, toView(*g))
}

// permanentGrantError reports whether an AssertActiveID error is a definitive
// "grant is not active" signal (revoked / expired / wrong-target) rather than a
// transient store/query error. Mirrors spine.classifyGrantError so the
// controller-side assert and the data-plane grant-watch agree on what counts as
// revocation. Kept as a local sentinel/string match — the bridge until
// AssertActiveID grows typed errors (the sibling in spine carries the same
// note); when it does, both switch to errors.Is together.
func permanentGrantError(err error) bool {
	if errors.Is(err, jit.ErrNoGrant) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "is not for target") || strings.Contains(msg, "expired")
}
