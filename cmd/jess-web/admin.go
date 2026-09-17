// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Admin-panel proxy handlers — backs the SPA's /admin surface.
//
// Auth model: server-side role gate (operator must hold the configured
// admin role, default "platform_admin"). The SPA also gates client-side
// for UX (hides the admin nav link from non-admins), but the SPA gate
// is decorative — these handlers are the authoritative check.
//
// All endpoints forward to the controller admin port with the cookie-
// session's Falcon-ID Bearer. The controller does its own admin-role
// check too (handleList / handleApprove / etc. require platform_admin),
// so even if these jess-web handlers were bypassed somehow, the
// controller would still 403. Defence-in-depth.
//
// Endpoints (mounted at /api/admin/...):
//
//	GET    /api/admin/requests[?state=pending]         list all requests
//	POST   /api/admin/requests/{id}/approve            {ttl_seconds}
//	POST   /api/admin/requests/{id}/deny               {reason}
//	GET    /api/admin/sessions[?subject=X]             list all sessions
//	GET    /api/admin/grants[?target=X]                list active grants
//	POST   /api/admin/grants                           {subject,target_id,ttl_seconds} issue
//	DELETE /api/admin/grants/{id}                      revoke grant

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// adminRole returns the role string an operator must hold to use the
// admin-panel endpoints. Defaults to "platform_admin" — overridable via
// env so tests / non-prod can swap. Matches the controller's admin gate
// default.
func (g *grantsClient) adminRole() string {
	if v := env("JESS_WEB_ADMIN_ROLE", ""); v != "" {
		return v
	}
	return "platform_admin"
}

// requireAdmin extracts the operator from the cookie session AND checks
// the role gate. On miss, writes the appropriate error and returns
// ok=false. Always-check pattern — every admin handler starts with this.
func (g *grantsClient) requireAdmin(w http.ResponseWriter, r *http.Request) (*Operator, bool) {
	op, err := g.sessions.operatorFromRequest(r)
	if err != nil {
		writeJSONErr(w, http.StatusUnauthorized, "not signed in")
		return nil, false
	}
	role := g.adminRole()
	for _, x := range op.Roles {
		if x == role {
			return op, true
		}
	}
	// Mirror the controller's posture — 403 with the role name so the
	// SPA can show a useful "you need <role>" hint instead of a
	// generic forbidden.
	writeJSONErr(w, http.StatusForbidden, "role "+role+" required")
	return nil, false
}

// handleAdminListRequests — GET /api/admin/requests[?state=pending].
// Admin-only list of ALL requests (no mine=true). Pass-through filter
// on ?state for the approver queue view.
func (g *grantsClient) handleAdminListRequests(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/requests"
	if s := r.URL.Query().Get("state"); s != "" {
		path += "?state=" + s
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
}

// handleAdminRequestAction — POST /api/admin/requests/{id}/approve|deny.
// Dispatched on the URL suffix. Body pass-through (controller validates
// shape: approve needs ttl_seconds, deny needs reason).
func (g *grantsClient) handleAdminRequestAction(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/admin/requests/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" {
		writeJSONErr(w, http.StatusNotFound, "no route")
		return
	}
	action := parts[1]
	if action != "approve" && action != "deny" {
		writeJSONErr(w, http.StatusNotFound, "action must be approve or deny")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	relayAdmin(w, g, r, op.Token, http.MethodPost, "/requests/"+parts[0]+"/"+action, body)
}

// handleAdminListSessions — GET /api/admin/sessions[?subject=X].
// Admin-only list of ALL sessions (no mine=true). subject query
// passes through for per-operator drilldown.
func (g *grantsClient) handleAdminListSessions(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/sessions"
	q := r.URL.RawQuery
	if q != "" {
		path += "?" + q
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
}

// handleAdminAuditExport — GET /api/admin/audit/export?subject=&from=&to=&limit=
//
// Proxies the controller's /audit/export (NDJSON stream). We forward the
// raw response body verbatim (no JSON re-parse) so attachment download
// works without buffering the entire stream in memory.
func (g *grantsClient) handleAdminAuditExport(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/audit/export"
	if q := r.URL.RawQuery; q != "" {
		path += "?" + q
	}
	body, status, err := g.forward(r, op.Token, http.MethodGet, path, nil)
	if err != nil {
		log.Printf("jess-web admin proxy: GET %s err=%v", path, err)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+err.Error())
		return
	}
	if status != http.StatusOK {
		relayJSON(w, status, body)
		return
	}
	// Preserve the streamed shape — let the browser download the
	// .jsonl file directly. We don't get the upstream's Content-
	// Disposition through forward() so we synthesise one with a
	// today-stamp; the controller's window header is informative
	// but not load-bearing for the filename.
	fname := "jess-audit-" + time.Now().UTC().Format("2006-01-02") + ".jsonl"
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleAdminCatalog — GET /api/admin/catalog[?region=X]
// Phase 7h: surfaces the unified catalog (all DiscoveryProviders
// merged through the Aggregator's precedence ladder). Each target
// carries its provenance via source + last_seen fields. The SPA's
// Targets panel renders source badges off these.
func (g *grantsClient) handleAdminCatalog(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/admin/catalog"
	if q := r.URL.RawQuery; q != "" {
		path += "?" + q
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
}

// handleAdminRDPProbe — GET /api/admin/rdp-probe?target=&protocols=&cookie=
// Forwards to controller's /rdp-probe (Phase 5f-2b). Pass-through.
func (g *grantsClient) handleAdminRDPProbe(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/rdp-probe"
	if q := r.URL.RawQuery; q != "" {
		path += "?" + q
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
}

// handleAdminRDPProbeSweep — GET /api/admin/rdp-probe/sweep
// Walks the catalog and probes every RDP target. Pass-through.
// Phase 5f-2d.
func (g *grantsClient) handleAdminRDPProbeSweep(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, "/rdp-probe/sweep", nil)
}

// handleAdminAuditChainVerify — GET /api/admin/audit/chain/verify.
// Forwards to controller; pure JSON pass-through.
func (g *grantsClient) handleAdminAuditChainVerify(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, "/audit/chain/verify", nil)
}

// handleAdminGrants — GET (list) / POST (direct issue) / DELETE (revoke) on
// /api/admin/grants[/{id}].
func (g *grantsClient) handleAdminGrants(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		path := "/grants"
		if q := r.URL.RawQuery; q != "" {
			path += "?" + q
		}
		relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
	case http.MethodPost:
		// Direct admin self-issue: forward {subject,target_id,ttl_seconds} to the
		// controller's POST /grants. Lets a platform_admin mint a JIT grant in ONE
		// call and connect immediately — no request→approve detour through the
		// admin console (an admin shouldn't have to approve their own request to
		// reach a session). Still ZSP: the controller time-boxes it (ttl_seconds ≤
		// 24h), stamps ApprovedBy=sub:<caller> from the verified token (not the
		// body), and records the mint in the WORM audit chain.
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		relayAdmin(w, g, r, op.Token, http.MethodPost, "/grants", body)
	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/admin/grants/")
		if id == "" || strings.Contains(id, "/") {
			writeJSONErr(w, http.StatusNotFound, "grant id required")
			return
		}
		relayAdmin(w, g, r, op.Token, http.MethodDelete, "/grants/"+id, nil)
	default:
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET, POST or DELETE")
	}
}

// handleAdminRecordingSettings — proxy for the per-target recording
// override. GET on /api/admin/recording-settings lists effective settings;
// PUT/DELETE on /api/admin/recording-settings/{target_id} sets/clears the
// override. platform_admin gated (requireAdmin) + forwarded to the
// controller, which does its own admin gate + stamps updated_by from the
// verified token (defence-in-depth, same as every other admin proxy).
func (g *grantsClient) handleAdminRecordingSettings(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		// List path: only the collection route serves GET.
		if r.URL.Path != "/api/admin/recording-settings" {
			writeJSONErr(w, http.StatusNotFound, "GET only on /api/admin/recording-settings")
			return
		}
		relayAdmin(w, g, r, op.Token, http.MethodGet, "/recording-settings", nil)
	case http.MethodPut, http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/api/admin/recording-settings/")
		if id == "" || strings.Contains(id, "/") {
			writeJSONErr(w, http.StatusNotFound, "target_id required")
			return
		}
		var body []byte
		if r.Method == http.MethodPut {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 64*1024))
		}
		relayAdmin(w, g, r, op.Token, r.Method, "/recording-settings/"+id, body)
	default:
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET, PUT or DELETE")
	}
}

// handleAdminPending — proxy for the ADR 0052 discovery review queue.
// GET  /api/admin/pending                 → list candidates
// POST /api/admin/pending/{name}/approve  → promote to JessTarget
// POST /api/admin/pending/{name}/reject   → terminally reject
// platform_admin gated; the controller does its own admin gate + stamps the
// verified subject as approved-by/rejected-by + audits the decision.
func (g *grantsClient) handleAdminPending(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/api/admin/pending" {
			writeJSONErr(w, http.StatusNotFound, "GET only on /api/admin/pending")
			return
		}
		relayAdmin(w, g, r, op.Token, http.MethodGet, "/pending", nil)
	case http.MethodPost:
		rest := strings.TrimPrefix(r.URL.Path, "/api/admin/pending/")
		if rest == "" || !strings.Contains(rest, "/") {
			writeJSONErr(w, http.StatusNotFound, "POST /api/admin/pending/{name}/approve|reject")
			return
		}
		relayAdmin(w, g, r, op.Token, http.MethodPost, "/pending/"+rest, nil)
	default:
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET or POST")
	}
}

// handleAdminPreRegistrations — GET (list) on /api/admin/devices/pre-registrations.
// Lists the operator-tenant's corporate device pre-registrations (the
// allowlist the corp-asset check reads). The controller derives the tenant
// from the forwarded operator bearer.
func (g *grantsClient) handleAdminPreRegistrations(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, "/devices/pre-registrations", nil)
}

// handleAdminPreRegistrationsImport — POST /api/admin/devices/pre-registrations/import.
// Body pass-through ({"devices":[…]}); the controller validates shape +
// attributes the rows to the verified operator sub.
func (g *grantsClient) handleAdminPreRegistrationsImport(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	relayAdmin(w, g, r, op.Token, http.MethodPost, "/devices/pre-registrations/import", body)
}

// handleAdminPreRegistrationDelete — DELETE /api/admin/devices/pre-registrations/{id}.
func (g *grantsClient) handleAdminPreRegistrationDelete(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		writeJSONErr(w, http.StatusMethodNotAllowed, "DELETE required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/devices/pre-registrations/")
	if id == "" || strings.Contains(id, "/") {
		writeJSONErr(w, http.StatusNotFound, "pre-registration id required")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodDelete, "/devices/pre-registrations/"+id, nil)
}

// handleAdminPendingDevices — GET /api/admin/devices/pending. Lists the TOFU
// auto-enroll review queue (genuine-TPM would-be-CORP devices not yet
// pre-registered) for the operator's tenant.
func (g *grantsClient) handleAdminPendingDevices(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, "/devices/pending", nil)
}

// handleAdminPendingDeviceAction — POST /api/admin/devices/pending/{ekHash}/approve|reject.
// Approve promotes the device to the corporate-asset allowlist; reject drops it.
func (g *grantsClient) handleAdminPendingDeviceAction(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/admin/devices/pending/")
	hash, action, found := strings.Cut(rest, "/")
	if !found || hash == "" || (action != "approve" && action != "reject") {
		writeJSONErr(w, http.StatusNotFound, "expected /api/admin/devices/pending/{ekHash}/approve|reject")
		return
	}
	relayAdmin(w, g, r, op.Token, http.MethodPost, "/devices/pending/"+hash+"/"+action, nil)
}

// handleAdminOnboardingDevices — GET /api/admin/devices/onboarding. Lists
// enrolled devices that are NOT yet corporate assets (still BYOD/posture-only)
// for the operator's tenant — the registry-backed enroll-first/approve-later
// queue. Any narrowing query params (user_sub/platform/limit) pass through.
func (g *grantsClient) handleAdminOnboardingDevices(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	path := "/devices/onboarding"
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	relayAdmin(w, g, r, op.Token, http.MethodGet, path, nil)
}

// handleAdminOnboardingApprove — POST /api/admin/devices/onboarding/{uuid}/approve.
// Body pass-through ({"ek_pubkey_hash","serial_number","model"}); the controller
// validates the hash, writes the corp-asset allowlist entry attributed to the
// verified operator sub, and WORM-audits the approval.
func (g *grantsClient) handleAdminOnboardingApprove(w http.ResponseWriter, r *http.Request) {
	op, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/admin/devices/onboarding/")
	uuid, action, found := strings.Cut(rest, "/")
	if !found || uuid == "" || action != "approve" {
		writeJSONErr(w, http.StatusNotFound, "expected /api/admin/devices/onboarding/{uuid}/approve")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	relayAdmin(w, g, r, op.Token, http.MethodPost, "/devices/onboarding/"+uuid+"/approve", body)
}

// relayAdmin is the shared forward path for admin proxies. Wraps
// grantsClient.forward + relayJSON so the per-handler code is
// uniformly tiny.
func relayAdmin(w http.ResponseWriter, g *grantsClient, r *http.Request, bearer, method, path string, body []byte) {
	upstream, status, err := g.forward(r, bearer, method, path, body)
	if err != nil {
		log.Printf("jess-web admin proxy: %s %s err=%v", method, path, err)
		writeJSONErr(w, http.StatusBadGateway, "controller admin port unreachable: "+err.Error())
		return
	}
	relayJSON(w, status, upstream)
}
