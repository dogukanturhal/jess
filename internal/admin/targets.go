// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

// Phase 7f — Admin REST for the ad-hoc target catalog.
//
// Routes (all platform_admin-gated; same authn chain as /grants):
//
//   POST   /admin/targets         create one
//   GET    /admin/targets         list all admin-managed entries
//   GET    /admin/targets/{id}    fetch one
//   PATCH  /admin/targets/{id}    update fields (id pinned, can't rename)
//   DELETE /admin/targets/{id}    delete (idempotent)
//
// Delegates persistence to the in-memory adminapi.Provider. Storage
// swap (Phase 7f-2 Postgres) is a one-line wiring change in
// cmd/jess-controller/catalog_wiring.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/catalog/providers/adminapi"
)

// TargetsHandler adds /admin/targets[/...] on top of the existing
// admin handler chain. Construct via NewTargets; it wraps the next
// handler (typically *CertHandler) so non-/admin/targets traffic
// falls through unchanged.
type TargetsHandler struct {
	next  http.Handler // fall-through for everything not /admin/targets[/*]
	base  *Handler     // for authenticate() — shared role gate + token verify
	store *adminapi.Provider
}

// NewTargets returns a TargetsHandler. `base` provides the shared
// authn (token verify + role gate); `next` is what to call when the
// path doesn't match. Either may be nil during construction — the
// handler 503s its own routes and falls through for the rest.
func NewTargets(next http.Handler, base *Handler, store *adminapi.Provider) *TargetsHandler {
	return &TargetsHandler{next: next, base: base, store: store}
}

// ServeHTTP routes /admin/targets[/...] locally; everything else
// goes to next.
func (h *TargetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/admin/targets" && !strings.HasPrefix(path, "/admin/targets/") {
		if h.next != nil {
			h.next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusNotFound, "no route for "+r.Method+" "+path)
		return
	}
	if h.store == nil {
		writeErr(w, http.StatusServiceUnavailable, "admin targets API not configured")
		return
	}
	if h.base == nil {
		writeErr(w, http.StatusInternalServerError, "admin targets: missing auth base")
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

	rest := strings.TrimPrefix(path, "/admin/targets")
	rest = strings.TrimPrefix(rest, "/")

	switch r.Method {
	case http.MethodGet:
		if rest == "" {
			h.list(w, r)
		} else {
			h.get(w, r, rest)
		}
	case http.MethodPost:
		if rest != "" {
			writeErr(w, http.StatusMethodNotAllowed, "POST not allowed on /admin/targets/{id}")
			return
		}
		h.create(w, r, id.Subject)
	case http.MethodPatch:
		if rest == "" {
			writeErr(w, http.StatusMethodNotAllowed, "PATCH requires /admin/targets/{id}")
			return
		}
		h.update(w, r, rest, id.Subject)
	case http.MethodDelete:
		if rest == "" {
			writeErr(w, http.StatusMethodNotAllowed, "DELETE requires /admin/targets/{id}")
			return
		}
		h.delete(w, r, rest)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method "+r.Method+" not allowed on "+path)
	}
}

// TargetView is the JSON projection of an admin-managed entry,
// including audit metadata so SOC tooling + the SPA (Phase 7h) get
// full provenance with one fetch.
type TargetView struct {
	Target    catalog.Target `json:"target"`
	AddedBy   string         `json:"added_by"`
	AddedAt   time.Time      `json:"added_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func toTargetView(e adminapi.Entry) TargetView {
	return TargetView{
		Target:    e.Target,
		AddedBy:   string(e.AddedBy),
		AddedAt:   e.AddedAt,
		UpdatedAt: e.UpdatedAt,
	}
}

func (h *TargetsHandler) list(w http.ResponseWriter, _ *http.Request) {
	rows := h.store.ListWithMeta()
	out := make([]TargetView, 0, len(rows))
	for _, e := range rows {
		out = append(out, toTargetView(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target.ID < out[j].Target.ID })
	writeJSON(w, http.StatusOK, out)
}

func (h *TargetsHandler) get(w http.ResponseWriter, _ *http.Request, id string) {
	t, by, updated, ok := h.store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "target "+id+" not found")
		return
	}
	writeJSON(w, http.StatusOK, TargetView{
		Target: t, AddedBy: string(by), AddedAt: updated, UpdatedAt: updated,
	})
}

func (h *TargetsHandler) create(w http.ResponseWriter, r *http.Request, sub string) {
	var t catalog.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if t.ID == "" || t.Address == "" {
		writeErr(w, http.StatusBadRequest, "id and address are required")
		return
	}
	if t.Protocol == "" {
		t.Protocol = catalog.ProtoSSH
	}
	// Gap audit #9: SSRF guard on admin-API target registration. Without
	// this, an admin (or compromised admin token) can register
	// 169.254.169.254 (cloud metadata) or other privileged addresses
	// and use jess as a confused-deputy to reach them. Block well-known
	// metadata + loopback + link-local before the row lands in storage.
	// Allowed: RFC1918 + DNS hostnames + service-DNS suffixes.
	if err := validateAddressNotSSRF(t.Address); err != nil {
		writeErr(w, http.StatusBadRequest, "address rejected: "+err.Error())
		return
	}
	err := h.store.Create(r.Context(), t, adminapi.AddedBy("sub:"+sub))
	if errors.Is(err, adminapi.ErrAlreadyExists) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, by, updated, _ := h.store.Get(t.ID)
	writeJSON(w, http.StatusCreated, TargetView{
		Target: got, AddedBy: string(by), AddedAt: updated, UpdatedAt: updated,
	})
}

func (h *TargetsHandler) update(w http.ResponseWriter, r *http.Request, id, sub string) {
	var t catalog.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if t.Address == "" {
		writeErr(w, http.StatusBadRequest, "address is required on PATCH")
		return
	}
	if t.Protocol == "" {
		t.Protocol = catalog.ProtoSSH
	}
	if err := validateAddressNotSSRF(t.Address); err != nil {
		writeErr(w, http.StatusBadRequest, "address rejected: "+err.Error())
		return
	}
	err := h.store.Update(r.Context(), id, t, adminapi.AddedBy("sub:"+sub))
	if errors.Is(err, adminapi.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	got, by, updated, _ := h.store.Get(id)
	writeJSON(w, http.StatusOK, TargetView{
		Target: got, AddedBy: string(by), AddedAt: updated, UpdatedAt: updated,
	})
}

func (h *TargetsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	err := h.store.Delete(r.Context(), id)
	if errors.Is(err, adminapi.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateAddressNotSSRF rejects target addresses that would let an
// admin-API registration become an SSRF vector through jess-worker.
// Gap audit #9 — Boundary host-catalogs + StrongDM gateways apply
// equivalent guards on admin-side target registration. Rejected:
//   - cloud metadata IPs (169.254.169.254, fd00:ec2::254 v6)
//   - loopback (127.0.0.0/8, ::1)
//   - link-local (169.254.0.0/16, fe80::/10)
//
// Accepted: RFC1918 private + non-metadata hostnames + cluster-DNS
// suffixes. The validator parses host:port and checks the host only —
// port range is enforced by the catalog protocol-specific consumers.
func validateAddressNotSSRF(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	// Exact-string metadata + dangerous endpoints. Hostname literals
	// like `metadata.google.internal` are also blocked since they
	// resolve to 169.254.169.254 inside GCE.
	switch strings.ToLower(host) {
	case "metadata.google.internal",
		"169.254.169.254",
		"fd00:ec2::254",
		"localhost":
		return fmt.Errorf("address %q is on the SSRF deny list (cloud metadata / loopback)", host)
	}
	// Literal IP parse — block loopback + link-local (RFC 3927 / RFC
	// 4291). Note: RFC1918 + ULA + IPv6-private are ALLOWED — those
	// are the legitimate internal-target ranges jess fronts.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("address %q is loopback / link-local / unspecified — not a brokerable target", host)
		}
	}
	return nil
}
