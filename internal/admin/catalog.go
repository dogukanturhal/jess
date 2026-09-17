// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Phase 7h — Admin catalog list endpoint.
//
// Surfaces the UNIFIED catalog (across every DiscoveryProvider) to
// the SPA admin panel. Distinct from TargetsHandler:
//
//   /admin/targets       (Phase 7f) — CRUD on the admin-api provider only
//   /admin/catalog       (this file) — read-only list of ALL providers
//                                       merged through the Aggregator's
//                                       precedence ladder
//
// The SPA's "Targets" tab uses this to render the full fleet with
// per-target source badges (static / k8s-nodes / proxmox / admin-api)
// so operators can see WHERE a given target came from.
//
// Future surfaces (Phase 7h-2):
//   /admin/catalog/status — per-provider last-refresh/error/target-count
//                            (uses Aggregator.Status())

import (
	"net/http"
	"sort"

	"github.com/dogukanturhal/jess/internal/catalog"
)

// CatalogHandler adds /admin/catalog on top of the existing admin
// handler chain. Construct via NewCatalog; it wraps the next handler
// so non-/admin/catalog traffic falls through unchanged.
type CatalogHandler struct {
	next http.Handler
	base *Handler // shared authn + role gate
	cat  catalog.Catalog
}

// NewCatalog wires the catalog handler. `cat` may be the Aggregator
// OR a plain MemoryCatalog — both implement catalog.Catalog. nil is
// acceptable (the route 503s).
func NewCatalog(next http.Handler, base *Handler, cat catalog.Catalog) *CatalogHandler {
	return &CatalogHandler{next: next, base: base, cat: cat}
}

// ServeHTTP routes /admin/catalog locally; everything else goes to next.
func (h *CatalogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/catalog" {
		if h.next != nil {
			h.next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+r.URL.Path)
		return
	}
	if h.cat == nil {
		writeErr(w, http.StatusServiceUnavailable, "catalog list endpoint not configured")
		return
	}
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "catalog handler: missing auth base")
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET required")
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

	// Region filter via ?region=eu-tr. Empty = all regions.
	region := r.URL.Query().Get("region")
	targets, err := h.cat.List(r.Context(), region)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "catalog list: "+err.Error())
		return
	}
	// Stable order by id so the SPA + jessctl can rely on it.
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	writeJSON(w, http.StatusOK, targets)
}
