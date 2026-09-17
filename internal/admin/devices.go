// SPDX-License-Identifier: AGPL-3.0-or-later

// devices.go — admin endpoints for device enrollment management.
//
// Task #136 — surfaces the EnrollmentStore methods added in #128
// (List/UpdateLastSeen/Disable) over the same authenticated admin HTTP
// API the JIT-grant routes use.
//
// Routes:
//
//	GET    /devices                  list — supports filter query params:
//	                                    user_sub, tier, platform,
//	                                    include_disabled (bool), limit, offset
//	POST   /devices/{uuid}/disable    disable — body {"reason":"…"}; the
//	                                    audit chain captures who via the
//	                                    verified caller subject
//
// Operators query the list view from the admin UI (jess-web) +
// targeted disable on a per-device basis. The status view at
// `internal.example.com/admin/devices` is the SOC's primary
// surface for "is the fleet posture-emitting and trustworthy?".
package admin

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicepolicy"
)

// DeviceStore is the subset of deviceattest.EnrollmentStore the admin
// devices routes need. Defined as an interface for test injection.
type DeviceStore interface {
	List(ctx context.Context, filter deviceattest.EnrollmentFilter) ([]deviceattest.EnrolledDevice, error)
	Disable(ctx context.Context, deviceUUID string, reason string) error
}

// PreRegStore is the subset of devicepolicy.FalconIDEnrollmentStore the admin
// pre-registration routes need. Defined as an interface for test injection.
type PreRegStore interface {
	BulkPreRegister(ctx context.Context, tenantID, createdBy string, devices []devicepolicy.PreRegDevice) (devicepolicy.PreRegBulkResult, error)
	ListPreRegistrations(ctx context.Context, tenantID string) ([]devicepolicy.PreRegistration, error)
	DeletePreRegistration(ctx context.Context, tenantID, id string) error
}

// DeviceView is the JSON projection returned by GET /devices. Mirrors
// deviceattest.EnrolledDevice but with explicit time-string formatting
// so callers don't have to parse Go's marshal default (`time.Time` is
// RFC 3339 already; we lock the format on the wire so a downstream
// rewrite of the marshal default doesn't drift the contract).
type DeviceView struct {
	DeviceUUID      string `json:"device_uuid"`
	UserSub         string `json:"user_sub"`
	Platform        string `json:"platform"`
	AttestationPath string `json:"attestation_path"`
	Tier            string `json:"tier"`
	EKPubkeyHash    string `json:"ek_pubkey_hash"`
	TPMManufacturer string `json:"tpm_manufacturer,omitempty"`
	TPMKind         string `json:"tpm_kind,omitempty"`
	WitnessAdminSub string `json:"witness_admin_sub,omitempty"`
	EnrolledAt      string `json:"enrolled_at"`
	LastSeenAt      string `json:"last_seen_at,omitempty"`
	DisabledAt      string `json:"disabled_at,omitempty"`
}

func toDeviceView(d deviceattest.EnrolledDevice) DeviceView {
	v := DeviceView{
		DeviceUUID:      d.DeviceUUID,
		UserSub:         d.UserSub,
		Platform:        d.Platform,
		AttestationPath: d.AttestationPath,
		Tier:            d.Tier,
		EKPubkeyHash:    d.EKPubkeyHash,
		TPMManufacturer: d.TPMManufacturer,
		TPMKind:         d.TPMKind,
		WitnessAdminSub: d.WitnessAdminSub,
	}
	if !d.EnrolledAt.IsZero() {
		v.EnrolledAt = d.EnrolledAt.UTC().Format(time.RFC3339)
	}
	if !d.LastSeenAt.IsZero() {
		v.LastSeenAt = d.LastSeenAt.UTC().Format(time.RFC3339)
	}
	if !d.DisabledAt.IsZero() {
		v.DisabledAt = d.DisabledAt.UTC().Format(time.RFC3339)
	}
	return v
}

// DisableRequest is the body of POST /devices/{uuid}/disable.
type DisableRequest struct {
	Reason string `json:"reason"`
}

// ListDevicesResponse wraps the list payload so the response is a JSON
// object rather than a bare array (forward-compatible with paging
// metadata like next_offset/total without breaking existing clients).
type ListDevicesResponse struct {
	Devices []DeviceView `json:"devices"`
}

// handleDevices routes the /devices sub-tree under the admin Handler.
// Returns true if the request matched a /devices route (so the parent
// dispatcher can stop trying). Pre-auth + role-check are done by the
// parent Handler.ServeHTTP.
func (h *Handler) handleDevices(w http.ResponseWriter, r *http.Request, callerSub string) bool {
	// Pre-registration CRUD subtree first — these paths are prefixes/suffixes
	// of the /devices/ space so they must win before the generic exact-match
	// "/devices" and "/devices/{uuid}/disable" checks below.
	if r.Method == http.MethodGet && r.URL.Path == "/devices/pre-registrations" {
		h.listPreRegistrations(w, r)
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/devices/pre-registrations/import" {
		h.importPreRegistrations(w, r, callerSub)
		return true
	}
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/devices/pre-registrations/") {
		id := strings.TrimPrefix(r.URL.Path, "/devices/pre-registrations/")
		h.deletePreRegistration(w, r, id)
		return true
	}
	// TOFU auto-enroll review queue (/devices/pending).
	if r.Method == http.MethodGet && r.URL.Path == "/devices/pending" {
		h.listPendingDevices(w, r)
		return true
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/devices/pending/") {
		rest := strings.TrimPrefix(r.URL.Path, "/devices/pending/")
		if hash, ok := strings.CutSuffix(rest, "/approve"); ok {
			h.approvePendingDevice(w, r, hash, callerSub)
			return true
		}
		if hash, ok := strings.CutSuffix(rest, "/reject"); ok {
			h.rejectPendingDevice(w, r, hash)
			return true
		}
	}
	// Enroll-first, approve-later onboarding — registry-backed (not the in-memory
	// TOFU queue above). Lists enrolled devices that are NOT yet corporate assets
	// and one-click-approves a chosen one into the allowlist.
	if r.Method == http.MethodGet && r.URL.Path == "/devices/onboarding" {
		h.listOnboardingDevices(w, r)
		return true
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/devices/onboarding/") {
		rest := strings.TrimPrefix(r.URL.Path, "/devices/onboarding/")
		if uuid, ok := strings.CutSuffix(rest, "/approve"); ok {
			h.approveOnboardingDevice(w, r, uuid, callerSub)
			return true
		}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/devices" {
		h.listDevices(w, r)
		return true
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/devices/") &&
		strings.HasSuffix(r.URL.Path, "/disable") {
		uuid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/devices/"), "/disable")
		h.disableDevice(w, r, uuid, callerSub)
		return true
	}
	return false
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		writeErr(w, http.StatusServiceUnavailable, "device store not configured")
		return
	}
	q := r.URL.Query()
	filter := deviceattest.EnrollmentFilter{
		// Tenant scope from the operator's token claim. The real Falcon-ID store
		// requires it (rejects a tenant-less list with 400); when the claim is
		// absent the empty value is sent through and the store decides (the unit
		// tests' fake store ignores it).
		TenantID: tenantIDFromRequest(r),
		UserSub:  q.Get("user_sub"),
		Tier:     q.Get("tier"),
		Platform: q.Get("platform"),
	}
	if v := q.Get("include_disabled"); v == "true" || v == "1" {
		filter.IncludeDisabled = true
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		filter.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return
		}
		filter.Offset = n
	}

	devices, err := h.devices.List(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]DeviceView, len(devices))
	for i, d := range devices {
		out[i] = toDeviceView(d)
	}
	writeJSON(w, http.StatusOK, ListDevicesResponse{Devices: out})
}

func (h *Handler) disableDevice(w http.ResponseWriter, r *http.Request, deviceUUID, callerSub string) {
	if h.devices == nil {
		writeErr(w, http.StatusServiceUnavailable, "device store not configured")
		return
	}
	if deviceUUID == "" {
		writeErr(w, http.StatusBadRequest, "device uuid required")
		return
	}
	var req DisableRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
	}
	if req.Reason == "" {
		writeErr(w, http.StatusBadRequest, "reason required (audit-chain row attribution)")
		return
	}
	// Audit lineage: prefix the reason with the verified caller's sub so
	// downstream WORM consumers can attribute the deny without joining
	// against the request log.
	auditedReason := "sub:" + callerSub + " — " + req.Reason
	if err := h.devices.Disable(r.Context(), deviceUUID, auditedReason); err != nil {
		// Match upstream-error shapes back to HTTP semantics.
		if errors.Is(err, errDeviceNotFound) || strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, "no device "+deviceUUID)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// Corporate device pre-registration (allowlist) CRUD — relays the React
// admin UI's manage-pre-registrations surface through to Falcon-ID. The
// allowlist is what the corp-asset check reads, so editing it here directly
// controls which devices earn TIER_CORP.
//
// All three routes scope to the operator's own tenant_id (read from the
// verified bearer). The bulk import attributes rows to the operator's sub.
//
// Multi-tenant TODO: a platform_admin managing another tenant's fleet needs a
// tenant override param; v1 scopes to the operator's own tenant_id.
// ---------------------------------------------------------------------

// ImportPreRegRequest is the body of POST /devices/pre-registrations/import.
type ImportPreRegRequest struct {
	Devices []devicepolicy.PreRegDevice `json:"devices"`
}

// PendingDeviceStore is the subset of *deviceattest.PendingDeviceStore the admin
// pending-device routes need (TOFU auto-enroll review queue).
type PendingDeviceStore interface {
	List() []deviceattest.PendingDevice
	Take(ekHash string) (deviceattest.PendingDevice, bool)
	Delete(ekHash string) bool
	Observe(d deviceattest.PendingDevice) // re-queue on a failed promotion
}

// listPendingDevices serves GET /devices/pending — the TOFU auto-enroll review
// queue (genuine-TPM would-be-CORP devices not yet pre-registered).
func (h *Handler) listPendingDevices(w http.ResponseWriter, r *http.Request) {
	if h.pendingDev == nil {
		writeErr(w, http.StatusServiceUnavailable, "pending-device queue not configured")
		return
	}
	rows := h.pendingDev.List()
	if rows == nil {
		rows = []deviceattest.PendingDevice{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// approvePendingDevice promotes a pending device to the corporate-asset
// allowlist (BulkPreRegister by its EK hash) and removes it from the queue. The
// device earns TIER_CORP on its next attestation. createdBy = the verified
// caller's sub (audit attribution), never anything the request claimed.
func (h *Handler) approvePendingDevice(w http.ResponseWriter, r *http.Request, ekHash, callerSub string) {
	if h.pendingDev == nil || h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "pending-device queue or pre-registration store not configured")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	pd, ok := h.pendingDev.Take(ekHash)
	if !ok {
		writeErr(w, http.StatusNotFound, "no pending device with that EK hash")
		return
	}
	res, err := h.preReg.BulkPreRegister(r.Context(), tenantID, callerSub, []devicepolicy.PreRegDevice{{
		EKPubkeyHash: pd.EKHash,
		Note:         "approved from TOFU auto-enroll review queue",
	}})
	if err != nil {
		// Promotion failed — put it back so the admin can retry rather than
		// silently losing the candidate.
		h.pendingDev.Observe(pd)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// rejectPendingDevice drops a pending device from the queue without promoting
// it. The device stays BYOD/posture-only; it'll reappear if it keeps attesting.
func (h *Handler) rejectPendingDevice(w http.ResponseWriter, r *http.Request, ekHash string) {
	if h.pendingDev == nil {
		writeErr(w, http.StatusServiceUnavailable, "pending-device queue not configured")
		return
	}
	if !h.pendingDev.Delete(ekHash) {
		writeErr(w, http.StatusNotFound, "no pending device with that EK hash")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected", "ek_hash": ekHash})
}

// ---------------------------------------------------------------------
// Enroll-first, approve-later onboarding — the registry-backed companion to
// the (in-memory) TOFU review queue above. A device that has already enrolled
// (and is currently BYOD/posture-only because its EK hash isn't in the
// corp-asset allowlist) is listed here and can be one-click-approved into a
// corporate asset — no pre-harvested CSV needed. Approve writes through the
// SAME allowlist path the CSV import uses, attributed to the operator's sub,
// scoped to the operator's tenant, and is WORM-audited.
// ---------------------------------------------------------------------

// OnboardingDeviceView is one row of GET /devices/onboarding: an enrolled
// device that is NOT yet a corporate asset. SerialNumber/Model/Manufacturer are
// the hardware-identity columns falcon-id now carries on the iam_devices row
// (populated from the agent's device inventory report); they may be empty until
// the device has reported inventory, in which case the console renders "—".
// Hostname is not yet a registry column, so it stays empty on the wire (present
// so a later column doesn't break the contract).
type OnboardingDeviceView struct {
	DeviceUUID   string `json:"device_uuid"`
	UserSub      string `json:"user_sub"`
	Platform     string `json:"platform"`
	Tier         string `json:"tier"`
	EKPubkeyHash string `json:"ek_pubkey_hash"`
	Hostname     string `json:"hostname"`
	SerialNumber string `json:"serial_number"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	EnrolledAt   string `json:"enrolled_at,omitempty"`
	LastSeenAt   string `json:"last_seen_at,omitempty"`
}

func toOnboardingView(d deviceattest.EnrolledDevice) OnboardingDeviceView {
	v := OnboardingDeviceView{
		DeviceUUID:   d.DeviceUUID,
		UserSub:      d.UserSub,
		Platform:     d.Platform,
		Tier:         d.Tier,
		EKPubkeyHash: d.EKPubkeyHash,
		SerialNumber: d.SerialNumber,
		Model:        d.Model,
		Manufacturer: d.Manufacturer,
		// Hostname intentionally empty — not yet a registry column (see type doc).
	}
	if !d.EnrolledAt.IsZero() {
		v.EnrolledAt = d.EnrolledAt.UTC().Format(time.RFC3339)
	}
	if !d.LastSeenAt.IsZero() {
		v.LastSeenAt = d.LastSeenAt.UTC().Format(time.RFC3339)
	}
	return v
}

// ListOnboardingResponse wraps the onboarding payload as a JSON object (not a
// bare array) so paging metadata can be added without breaking clients.
type ListOnboardingResponse struct {
	Devices []OnboardingDeviceView `json:"devices"`
}

// listOnboardingDevices serves GET /devices/onboarding — enrolled (active)
// devices whose EK-pubkey hash is NOT in the operator-tenant's corp-asset
// allowlist (i.e. still BYOD/posture-only and thus approval candidates). The
// set-difference is the precise definition of "not yet a corporate asset": the
// allowlist EK hashes are exactly what falcon-id's corp-asset check matches.
//
// Optional narrowing via the same query params as GET /devices (user_sub,
// platform, limit). Disabled devices are never onboarding candidates (the
// active-only default filter excludes them).
func (h *Handler) listOnboardingDevices(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil || h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "device store or pre-registration store not configured")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	q := r.URL.Query()
	filter := deviceattest.EnrollmentFilter{
		TenantID: tenantID,
		UserSub:  q.Get("user_sub"),
		Platform: q.Get("platform"),
		// IncludeDisabled stays false: a retired device is not a candidate.
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		filter.Limit = n
	}

	enrolled, err := h.devices.List(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The corp-asset allowlist for this tenant — its EK hashes mark the devices
	// that are ALREADY corporate assets, so we subtract them from the enrolled
	// set to leave the still-pending ones.
	allow, err := h.preReg.ListPreRegistrations(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	approved := make(map[string]struct{}, len(allow))
	for _, p := range allow {
		if p.EKPubkeyHash != "" {
			approved[strings.ToLower(p.EKPubkeyHash)] = struct{}{}
		}
	}

	out := make([]OnboardingDeviceView, 0, len(enrolled))
	for _, d := range enrolled {
		// A device with no EK hash can never be approved — the approve body
		// requires the 64-char hex hash — so it would sit in the queue
		// forever as an un-actionable row. Exclude it.
		if d.EKPubkeyHash == "" {
			continue
		}
		if _, ok := approved[strings.ToLower(d.EKPubkeyHash)]; ok {
			continue // already a corporate asset
		}
		out = append(out, toOnboardingView(d))
	}
	writeJSON(w, http.StatusOK, ListOnboardingResponse{Devices: out})
}

// ApproveCorpAssetRequest is the body of POST /devices/onboarding/{uuid}/approve.
// EKPubkeyHash is the device's 64-char lowercase-hex SHA-256 anchor (the SPA
// reads it from the onboarding list row it's approving). Serial/Model are
// optional best-effort metadata for the allowlist entry.
type ApproveCorpAssetRequest struct {
	EKPubkeyHash string `json:"ek_pubkey_hash"`
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
}

// approveOnboardingDevice serves POST /devices/onboarding/{uuid}/approve —
// promotes an already-enrolled device into a corporate asset by adding its EK
// hash to the allowlist via the SAME write path the CSV import uses (no
// duplicate allowlist logic). The device earns TIER_CORP on its next
// attestation. createdBy = the verified caller's sub (audit attribution), scoped
// to the operator's tenant; the approval is WORM-audited (who / device_uuid /
// ek_hash / when).
func (h *Handler) approveOnboardingDevice(w http.ResponseWriter, r *http.Request, deviceUUID, callerSub string) {
	if h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "pre-registration store not configured")
		return
	}
	if deviceUUID == "" {
		writeErr(w, http.StatusBadRequest, "device uuid required")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	var req ApproveCorpAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	hash := strings.ToLower(strings.TrimSpace(req.EKPubkeyHash))
	if len(hash) != 64 {
		writeErr(w, http.StatusBadRequest, "ek_pubkey_hash must be the 64-char hex SHA-256 of the device EK pubkey")
		return
	}
	if _, err := hex.DecodeString(hash); err != nil {
		writeErr(w, http.StatusBadRequest, "ek_pubkey_hash is not valid hex")
		return
	}

	// Re-derive the authoritative EK hash from the device identified by the
	// {uuid} path param, so the allowlist write and the audit row (TargetID =
	// deviceUUID) describe the SAME device — a buggy/tampered client body can't
	// allowlist a hash unrelated to the uuid it claims to approve. The body
	// hash (sent by the SPA from the row it's approving) is only the fallback
	// when the store can't resolve the uuid. Optional capability via type
	// assertion so the DeviceStore interface (and its test fakes) stay unchanged.
	if g, ok := h.devices.(interface {
		GetByUUID(context.Context, string) (deviceattest.EnrolledDevice, error)
	}); ok {
		if dev, err := g.GetByUUID(r.Context(), deviceUUID); err == nil && dev.EKPubkeyHash != "" {
			hash = strings.ToLower(strings.TrimSpace(dev.EKPubkeyHash))
		}
	}

	res, err := h.preReg.BulkPreRegister(r.Context(), tenantID, callerSub, []devicepolicy.PreRegDevice{{
		EKPubkeyHash: hash,
		SerialNumber: strings.TrimSpace(req.SerialNumber),
		Model:        strings.TrimSpace(req.Model),
		Note:         "approved from console (device " + deviceUUID + ")",
	}})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// WORM audit — tamper-evident lineage of the privilege grant. TargetID is
	// the device; the EK hash + tenant ride in the note field (the same
	// repurposing the discovery review queue uses for its operator-decision row).
	h.emitAudit(r.Context(), audit.Event{
		Action:   "device.approve.corp-asset",
		Subject:  callerSub,
		TargetID: deviceUUID,
		Err:      "approved corp-asset; ek_hash=" + hash + "; tenant=" + tenantID,
	})
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) listPreRegistrations(w http.ResponseWriter, r *http.Request) {
	if h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "pre-registration store not configured")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	rows, err := h.preReg.ListPreRegistrations(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Return a JSON array shaped like the Falcon-ID list rows (the SPA reads
	// a bare array). Never null — emit [] when the allowlist is empty.
	if rows == nil {
		rows = []devicepolicy.PreRegistration{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) importPreRegistrations(w http.ResponseWriter, r *http.Request, callerSub string) {
	if h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "pre-registration store not configured")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	var req ImportPreRegRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if len(req.Devices) == 0 {
		writeErr(w, http.StatusBadRequest, "devices required")
		return
	}
	// createdBy = the verified caller's sub, not anything the body claimed —
	// matches the audit-attribution posture of the other admin mutations.
	res, err := h.preReg.BulkPreRegister(r.Context(), tenantID, callerSub, req.Devices)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) deletePreRegistration(w http.ResponseWriter, r *http.Request, id string) {
	if h.preReg == nil {
		writeErr(w, http.StatusServiceUnavailable, "pre-registration store not configured")
		return
	}
	if id == "" || strings.Contains(id, "/") {
		writeErr(w, http.StatusBadRequest, "pre-registration id required")
		return
	}
	tenantID := tenantIDFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "operator token has no tenant_id claim")
		return
	}
	if err := h.preReg.DeletePreRegistration(r.Context(), tenantID, id); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeErr(w, http.StatusNotFound, "no pre-registration "+id)
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// errDeviceNotFound is the canonical sentinel for "device row missing"
// from the EnrollmentStore.Disable contract. Concrete implementations
// wrap this via fmt.Errorf("%w: …") so callers can errors.Is-match.
var errDeviceNotFound = errors.New("device not found")
