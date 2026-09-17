// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devicepolicy contains concrete implementations of the
// deviceattest package interfaces for the jess-controller production wiring.
//
// FalconIDEnrollmentStore is the concrete EnrollmentStore implementation;
// it delegates to Falcon-ID's internal s2s API for device-enrollment
// persistence. Jess never writes directly to Falcon-ID's Postgres — the
// IAM system-of-record owns the iam_devices table and exposes it via a
// gated internal HTTP endpoint (ServiceAuth middleware, same envelope as
// /internal/v1/tenant-discovery and /internal/v1/tenant-hosts).
//
// HTTP-only (no gRPC) for now. Rationale: Falcon-ID exposes no gRPC
// contract today; its service surface is gin+JSON. The internal/v1
// ServiceAuth pattern (OAuth2 client_credentials Bearer) is the canonical
// s2s auth for this fleet (see internal engineering notes in memory). A
// gRPC migration path is straightforward — the interface is isolated here,
// so swapping transport requires only this file.
//
// TODO(ztna-phase3-grpc): Once falcon-id ships a gRPC service definition
// for IAMDevices, replace the HTTP calls below with a generated stub client
// and remove the JSON structs.
package devicepolicy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
)

// enrollDevicePath is the Falcon-ID internal endpoint for device enrollment.
// Auth: OAuth2 client_credentials Bearer (ServiceAuth middleware).
const enrollDevicePath = "/internal/v1/iam-devices/enroll"

// getByEKHashPathPrefix is the prefix for the EK hash lookup endpoint.
// Full URL: <prefix>/<hex-hash>
const getByEKHashPathPrefix = "/internal/v1/iam-devices/by-ek-hash"

// getByUUIDPathPrefix is the prefix for the device-UUID lookup endpoint.
// Full URL: <prefix>/<device-uuid>. Used by the device-cert renewal gate
// (ADR 0048) to read a device's revocation state by its SPIFFE-SAN UUID.
const getByUUIDPathPrefix = "/internal/v1/iam-devices/by-uuid"

// corpAssetByEKHashPathPrefix is the prefix for the corporate-asset allowlist
// check. Full URL: <prefix>/<hex-hash>. Returns 200 with
// {"is_corporate_asset": bool} — false (not 404) for a device that was never
// pre-registered. The attest handler downgrades CORP -> BYOD when false.
const corpAssetByEKHashPathPrefix = "/internal/v1/iam-devices/corp-asset/by-ek-hash"

// preRegPath is the Falcon-ID internal collection endpoint for corporate
// device pre-registrations (the migration-0007 allowlist the corp-asset
// check reads). The admin UI manages this allowlist end-to-end:
//
//	POST   <preRegPath>/bulk            -- BulkPreRegister
//	GET    <preRegPath>?tenant_id=<id>  -- ListPreRegistrations
//	DELETE <preRegPath>/<id>?tenant_id= -- DeletePreRegistration
const preRegPath = "/internal/v1/iam-devices/pre-registrations"

// preRegBulkPath is the bulk-import endpoint. Full URL: <preRegPath>/bulk.
const preRegBulkPath = preRegPath + "/bulk"

// falconIDEnrollRequest mirrors the JSON body expected by Falcon-ID's
// POST /internal/v1/iam-devices/enroll handler.
// All fields are snake_case matching the iam_devices table columns.
type falconIDEnrollRequest struct {
	DeviceUUID      string `json:"device_uuid"`
	UserSub         string `json:"user_sub"`
	Platform        string `json:"platform"`
	AttestationPath string `json:"attestation_path"`
	Tier            string `json:"tier"`
	// EKPubkeyHash is the 64-char lowercase hex encoding of SHA-256(EK pubkey PEM).
	// Falcon-ID decodes it to []byte before writing to the bytea column.
	EKPubkeyHash    string  `json:"ek_pubkey_hash"`
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	WitnessSignedAt *string `json:"witness_signed_at,omitempty"` // RFC3339
	// System/machine hardware identity (DMI/SMBIOS), distinct from
	// tpm_manufacturer. Omitted when empty; Falcon-ID stores '' for absent.
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	EnrolledAt   string `json:"enrolled_at"` // RFC3339 UTC
}

// falconIDEnrollResponse is the JSON body returned by Falcon-ID on a
// successful 201 enrollment. The response body is consumed but only
// validated for well-formedness — the caller does not need the database-
// assigned ID; the EK pubkey hash is the caller-side anchor.
type falconIDEnrollResponse struct {
	DeviceUUID string `json:"device_uuid"`
}

// falconIDGetByEKResponse is the JSON body returned by Falcon-ID's
// GET /internal/v1/iam-devices/by-ek-hash/:hash endpoint.
// A 404 response means the device has not been enrolled before (not an
// error — Path B first-enrollment path).
type falconIDGetByEKResponse struct {
	DeviceUUID      string  `json:"device_uuid"`
	UserSub         string  `json:"user_sub"`
	Platform        string  `json:"platform"`
	AttestationPath string  `json:"attestation_path"`
	Tier            string  `json:"tier"`
	EKPubkeyHash    string  `json:"ek_pubkey_hash"`
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	// Hardware identity columns (falcon-id-owned). Carried in the attest
	// request's hardware block and persisted on first-enrollment; see the
	// cross-repo iam_devices contract. Optional; empty when the agent could
	// not read DMI. Distinct from tpm_manufacturer above (the TPM chip
	// vendor) — manufacturer here is the machine vendor (DMI/SMBIOS).
	SerialNumber string `json:"serial_number,omitempty"`
	Model        string `json:"model,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	EnrolledAt   string `json:"enrolled_at"`            // RFC3339
	LastSeenAt   string `json:"last_seen_at,omitempty"` // RFC3339; empty = never seen
	DisabledAt   string `json:"disabled_at,omitempty"`  // RFC3339; empty = active
}

// falconIDErrorResponse is a best-effort parse of Falcon-ID's error body.
// Falcon-ID returns {"error": "<message>"} on 4xx/5xx responses.
type falconIDErrorResponse struct {
	Error string `json:"error"`
}

// FalconIDEnrollmentStore implements deviceattest.EnrollmentStore by
// delegating to Falcon-ID's internal s2s API for all persistence
// operations. It holds no Postgres connection — the iam_devices table
// is Falcon-ID-owned (ADR 0043 Q5).
//
// Thread-safe: the only mutable state is the http.Client which is safe
// for concurrent use per the Go net/http contract.
type FalconIDEnrollmentStore struct {
	baseURL  string // e.g. "http://falcon-id.falcon-id.svc.cluster.local:18080"
	tokenSrc TokenSource
	hc       *http.Client
}

// TokenSource yields the current OAuth2 client_credentials Bearer token for
// each request. It is consulted on every call so a sidecar-refreshed token
// (the svctoken-refresher native-sidecar writing a shared tmpfs file)
// propagates without a process restart — the same live-read contract
// caep.FileTokenSource provides for the CAEP subscriber, and the same
// pattern gitlab-bcl-receiver / argocd-repo-server use for their s2s tokens.
// caep.FileTokenSource and caep.StaticTokenSource both satisfy this
// interface structurally.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// staticTokenSource returns the same token on every call. Backs the legacy
// NewFalconIDEnrollmentStore(baseURL, accessToken) constructor and tests;
// production wiring prefers a file-backed source so token rotation never
// requires a pod restart.
type staticTokenSource string

func (t staticTokenSource) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("devicepolicy: static token is empty")
	}
	return string(t), nil
}

// bearer resolves the current token via the configured TokenSource and
// returns the full "Bearer <token>" Authorization header value. A token-
// source error (e.g. the shared token file is briefly empty mid-atomic-
// write) is surfaced to the caller rather than sending an unauthenticated
// request that would 401 — the caller retries on the next reconcile.
func (s *FalconIDEnrollmentStore) bearer(ctx context.Context) (string, error) {
	tok, err := s.tokenSrc.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("falconid_enrollment_store: resolve bearer token: %w", err)
	}
	return "Bearer " + tok, nil
}

// FalconIDEnrollmentStoreOption configures a FalconIDEnrollmentStore.
type FalconIDEnrollmentStoreOption func(*FalconIDEnrollmentStore)

// WithEnrollmentHTTPClient replaces the default http.Client. Used in
// tests to inject an httptest.Server transport without modifying the
// default global client.
func WithEnrollmentHTTPClient(hc *http.Client) FalconIDEnrollmentStoreOption {
	return func(s *FalconIDEnrollmentStore) { s.hc = hc }
}

// NewFalconIDEnrollmentStore constructs a production EnrollmentStore.
//
// baseURL is the Falcon-ID cluster-internal base URL without a trailing
// slash (e.g. "http://falcon-id.falcon-id.svc.cluster.local:18080").
// accessToken is the OAuth2 client_credentials Bearer token obtained via
// the jess service-account credentials — it authorises requests to the
// /internal/v1/* endpoints protected by ServiceAuth middleware in
// Falcon-ID.
//
// Neither baseURL nor accessToken may be empty; both panics surface at
// controller startup so misconfiguration never reaches a request.
//
// This static-token constructor is retained for tests and the legacy
// env-token wiring path. Production wiring should prefer
// NewFalconIDEnrollmentStoreWithSource with a caep.FileTokenSource so the
// ~hourly token rotation propagates without a pod restart.
func NewFalconIDEnrollmentStore(baseURL, accessToken string, opts ...FalconIDEnrollmentStoreOption) *FalconIDEnrollmentStore {
	if accessToken == "" {
		panic("devicepolicy: NewFalconIDEnrollmentStore: accessToken must not be empty")
	}
	return NewFalconIDEnrollmentStoreWithSource(baseURL, staticTokenSource(accessToken), opts...)
}

// NewFalconIDEnrollmentStoreWithSource constructs a production EnrollmentStore
// that resolves its Bearer token from src on every request. This is the
// canonical production wiring: pass a caep.FileTokenSource pointed at the
// svctoken-refresher's shared tmpfs file (/var/run/svctoken/jwt) so the
// client_credentials rotation propagates with no pod restart — the same
// pattern the CAEP subscriber and the platform's other s2s consumers use.
//
// baseURL must not be empty and src must be non-nil; both panics surface at
// controller startup so misconfiguration never reaches a request.
func NewFalconIDEnrollmentStoreWithSource(baseURL string, src TokenSource, opts ...FalconIDEnrollmentStoreOption) *FalconIDEnrollmentStore {
	if baseURL == "" {
		panic("devicepolicy: NewFalconIDEnrollmentStore: baseURL must not be empty")
	}
	if src == nil {
		panic("devicepolicy: NewFalconIDEnrollmentStore: token source must not be nil")
	}
	s := &FalconIDEnrollmentStore{
		baseURL:  strings.TrimRight(baseURL, "/"),
		tokenSrc: src,
		hc: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Register persists a new enrollment row in Falcon-ID's iam_devices table.
// It is idempotent: a second call with the same EKPubkeyHash and DeviceUUID
// succeeds when the existing row is consistent (Falcon-ID returns 200 for
// re-enrollment of the same device). A conflicting DeviceUUID (same EK key,
// different device_uuid) returns an error wrapping deviceattest.ErrVerification.
//
// Implements deviceattest.EnrollmentStore.
func (s *FalconIDEnrollmentStore) Register(ctx context.Context, row deviceattest.EnrolledDevice) error {
	req := falconIDEnrollRequest{
		DeviceUUID:      row.DeviceUUID,
		UserSub:         row.UserSub,
		Platform:        row.Platform,
		AttestationPath: row.AttestationPath,
		Tier:            row.Tier,
		EKPubkeyHash:    row.EKPubkeyHash,
		SerialNumber:    row.SerialNumber,
		Model:           row.Model,
		Manufacturer:    row.Manufacturer,
		EnrolledAt:      row.EnrolledAt.UTC().Format(time.RFC3339),
	}
	if row.TPMManufacturer != "" {
		req.TPMManufacturer = &row.TPMManufacturer
	}
	if row.TPMKind != "" {
		req.TPMKind = &row.TPMKind
	}
	if row.WitnessAdminSub != "" {
		req.WitnessAdminSub = &row.WitnessAdminSub
		now := row.EnrolledAt.UTC().Format(time.RFC3339)
		req.WitnessSignedAt = &now
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: register: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.baseURL+enrollDevicePath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: register: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	authz, err := s.bearer(ctx)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: register: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: register: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // max 64KiB

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// Created or re-enrolled (idempotent success). No further action needed.
		return nil
	case http.StatusConflict:
		// Falcon-ID maps iam_devices_device_uuid_key (UNIQUE conflict on
		// device_uuid with a different EK pubkey hash) to 409 with a
		// body indicating which constraint fired. We treat any 409 here
		// as a potential impersonation attempt and surface it as
		// ErrVerification so the controller returns 403.
		return fmt.Errorf("falconid_enrollment_store: register: device_uuid conflict (possible impersonation): %w: %s",
			deviceattest.ErrVerification, extractErrorMessage(rawBody))
	case http.StatusBadRequest:
		return fmt.Errorf("falconid_enrollment_store: register: bad request to falcon-id: %s", extractErrorMessage(rawBody))
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("falconid_enrollment_store: register: access denied (check jess service-account token): HTTP %d", resp.StatusCode)
	default:
		return fmt.Errorf("falconid_enrollment_store: register: unexpected status from falcon-id: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// GetByEKPubkeyHash looks up the enrollment by the SHA-256 digest of the
// EK public key PEM. Returns a zero EnrolledDevice with nil error when no
// prior enrollment exists (caller interprets empty DeviceUUID as "not found").
//
// Implements deviceattest.EnrollmentStore.
func (s *FalconIDEnrollmentStore) GetByEKPubkeyHash(ctx context.Context, hash string) (deviceattest.EnrolledDevice, error) {
	// Validate: must be 64 lowercase hex chars (SHA-256 hex encoding).
	if len(hash) != 64 {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: hash must be 64 hex chars, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: hash is not valid hex: %w", err)
	}

	url := s.baseURL + getByEKHashPathPrefix + "/" + hash
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusOK:
		var out falconIDGetByEKResponse
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf(
				"falconid_enrollment_store: get_by_ek_pubkey_hash: decode response: %w", err)
		}
		enrolled, err := falconIDGetRespToEnrolledDevice(out)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf(
				"falconid_enrollment_store: get_by_ek_pubkey_hash: parse response: %w", err)
		}
		return enrolled, nil

	case http.StatusNotFound:
		// No prior enrollment — return zero value with nil error so the
		// caller (tofuVerifier) takes the first-enrollment path.
		return deviceattest.EnrolledDevice{}, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: access denied: HTTP %d", resp.StatusCode)

	default:
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_ek_pubkey_hash: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// corpAssetResponse mirrors Falcon-ID's GET
// /internal/v1/iam-devices/corp-asset/by-ek-hash/:hash body.
type corpAssetResponse struct {
	IsCorporateAsset bool `json:"is_corporate_asset"`
}

// IsCorporateAsset reports whether the device with the given EK pubkey hash has
// been pre-registered as a corporate asset (migration 0007 allowlist). The jess
// attest handler calls this AFTER a verifier returns TIER_CORP and downgrades
// to TIER_BYOD when the answer is false — closing the gap where a genuine TPM
// (chains to a trusted vendor root) buys CORP without being one of OUR devices.
//
// hash is the 64-char lowercase hex SHA-256 of the EK pubkey PEM. A device that
// was never pre-registered yields (false, nil) — that is a normal answer, not
// an error. Transport/auth failures return a non-nil error; the caller is
// expected to fail closed (treat the device as non-corporate).
func (s *FalconIDEnrollmentStore) IsCorporateAsset(ctx context.Context, hash string) (bool, error) {
	if len(hash) != 64 {
		return false, fmt.Errorf(
			"falconid_enrollment_store: is_corporate_asset: hash must be 64 hex chars, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return false, fmt.Errorf(
			"falconid_enrollment_store: is_corporate_asset: hash is not valid hex: %w", err)
	}

	url := s.baseURL + corpAssetByEKHashPathPrefix + "/" + hash
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("falconid_enrollment_store: is_corporate_asset: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return false, fmt.Errorf("falconid_enrollment_store: is_corporate_asset: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("falconid_enrollment_store: is_corporate_asset: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusOK:
		var out corpAssetResponse
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return false, fmt.Errorf("falconid_enrollment_store: is_corporate_asset: decode response: %w", err)
		}
		return out.IsCorporateAsset, nil

	case http.StatusNotFound:
		// Defensive: a 200 {is_corporate_asset:false} is the documented
		// not-found answer, but tolerate a 404 as "not a corporate asset".
		return false, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return false, fmt.Errorf(
			"falconid_enrollment_store: is_corporate_asset: access denied: HTTP %d", resp.StatusCode)

	default:
		return false, fmt.Errorf(
			"falconid_enrollment_store: is_corporate_asset: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// falconIDGetByUUIDResponse mirrors Falcon-ID's GET
// /internal/v1/iam-devices/by-uuid/:uuid body. Superset of the by-ek-hash
// shape, adding the revocation signal (revoked_at / revoked_reason). We map
// revoked_at onto EnrolledDevice.DisabledAt so the renewal gate's
// "DisabledAt != zero ⇒ revoked" check is uniform across lookup paths.
type falconIDGetByUUIDResponse struct {
	DeviceUUID      string  `json:"device_uuid"`
	UserSub         string  `json:"user_sub"`
	Platform        string  `json:"platform"`
	AttestationPath string  `json:"attestation_path"`
	Tier            string  `json:"tier"`
	EKPubkeyHash    string  `json:"ek_pubkey_hash"`
	TPMManufacturer *string `json:"tpm_manufacturer,omitempty"`
	TPMKind         *string `json:"tpm_kind,omitempty"`
	WitnessAdminSub *string `json:"witness_admin_sub,omitempty"`
	// Hardware identity columns — see falconIDGetByEKResponse for provenance.
	SerialNumber  string  `json:"serial_number,omitempty"`
	Model         string  `json:"model,omitempty"`
	Manufacturer  string  `json:"manufacturer,omitempty"`
	EnrolledAt    string  `json:"enrolled_at"`
	RevokedAt     string  `json:"revoked_at,omitempty"`
	RevokedReason *string `json:"revoked_reason,omitempty"`
}

// GetByUUID fetches a device by its SPIFFE-SAN UUID. The returned
// EnrolledDevice carries DisabledAt populated from the server's revoked_at
// (empty ⇒ active). A 404 returns a zero-value device with nil error —
// callers detect "not found" via an empty DeviceUUID, matching
// GetByEKPubkeyHash semantics. Used by the device-cert renewal handler
// (ADR 0048) to fail-closed on a revoked-but-not-yet-expired device.
func (s *FalconIDEnrollmentStore) GetByUUID(ctx context.Context, deviceUUID string) (deviceattest.EnrolledDevice, error) {
	if deviceUUID == "" {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: device_uuid must not be empty")
	}

	url := s.baseURL + getByUUIDPathPrefix + "/" + deviceUUID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))

	switch resp.StatusCode {
	case http.StatusOK:
		var out falconIDGetByUUIDResponse
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf(
				"falconid_enrollment_store: get_by_uuid: decode response: %w", err)
		}
		return falconIDByUUIDRespToEnrolledDevice(out)

	case http.StatusNotFound:
		// Unknown device — zero value + nil error (caller treats empty
		// DeviceUUID as "not found").
		return deviceattest.EnrolledDevice{}, nil

	case http.StatusUnauthorized, http.StatusForbidden:
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: access denied: HTTP %d", resp.StatusCode)

	default:
		return deviceattest.EnrolledDevice{}, fmt.Errorf(
			"falconid_enrollment_store: get_by_uuid: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// falconIDByUUIDRespToEnrolledDevice maps the by-uuid response to the
// domain type, mapping revoked_at → DisabledAt.
func falconIDByUUIDRespToEnrolledDevice(r falconIDGetByUUIDResponse) (deviceattest.EnrolledDevice, error) {
	if r.DeviceUUID == "" {
		return deviceattest.EnrolledDevice{}, errors.New("response missing device_uuid")
	}
	d := deviceattest.EnrolledDevice{
		DeviceUUID:      r.DeviceUUID,
		UserSub:         r.UserSub,
		Platform:        r.Platform,
		AttestationPath: r.AttestationPath,
		Tier:            r.Tier,
		EKPubkeyHash:    r.EKPubkeyHash,
		SerialNumber:    r.SerialNumber,
		Model:           r.Model,
		Manufacturer:    r.Manufacturer,
	}
	if r.TPMManufacturer != nil {
		d.TPMManufacturer = *r.TPMManufacturer
	}
	if r.TPMKind != nil {
		d.TPMKind = *r.TPMKind
	}
	if r.WitnessAdminSub != nil {
		d.WitnessAdminSub = *r.WitnessAdminSub
	}
	if r.EnrolledAt != "" {
		t, err := time.Parse(time.RFC3339, r.EnrolledAt)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf("parse enrolled_at %q: %w", r.EnrolledAt, err)
		}
		d.EnrolledAt = t
	}
	if r.RevokedAt != "" {
		t, err := time.Parse(time.RFC3339, r.RevokedAt)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf("parse revoked_at %q: %w", r.RevokedAt, err)
		}
		d.DisabledAt = t
	}
	return d, nil
}

// falconIDGetRespToEnrolledDevice maps the Falcon-ID HTTP response body to
// the deviceattest.EnrolledDevice domain type used by the verifier chain.
func falconIDGetRespToEnrolledDevice(r falconIDGetByEKResponse) (deviceattest.EnrolledDevice, error) {
	if r.DeviceUUID == "" {
		return deviceattest.EnrolledDevice{}, errors.New("response missing device_uuid")
	}
	d := deviceattest.EnrolledDevice{
		DeviceUUID:      r.DeviceUUID,
		UserSub:         r.UserSub,
		Platform:        r.Platform,
		AttestationPath: r.AttestationPath,
		Tier:            r.Tier,
		EKPubkeyHash:    r.EKPubkeyHash,
		SerialNumber:    r.SerialNumber,
		Model:           r.Model,
		Manufacturer:    r.Manufacturer,
	}
	if r.TPMManufacturer != nil {
		d.TPMManufacturer = *r.TPMManufacturer
	}
	if r.TPMKind != nil {
		d.TPMKind = *r.TPMKind
	}
	if r.WitnessAdminSub != nil {
		d.WitnessAdminSub = *r.WitnessAdminSub
	}
	if r.EnrolledAt != "" {
		t, err := time.Parse(time.RFC3339, r.EnrolledAt)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf("parse enrolled_at %q: %w", r.EnrolledAt, err)
		}
		d.EnrolledAt = t
	}
	if r.LastSeenAt != "" {
		t, err := time.Parse(time.RFC3339, r.LastSeenAt)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf("parse last_seen_at %q: %w", r.LastSeenAt, err)
		}
		d.LastSeenAt = t
	}
	if r.DisabledAt != "" {
		t, err := time.Parse(time.RFC3339, r.DisabledAt)
		if err != nil {
			return deviceattest.EnrolledDevice{}, fmt.Errorf("parse disabled_at %q: %w", r.DisabledAt, err)
		}
		d.DisabledAt = t
	}
	return d, nil
}

// extractErrorMessage parses a best-effort {"error": "..."} body from
// Falcon-ID and returns the message string. On parse failure it returns
// the raw body truncated to 256 bytes.
func extractErrorMessage(body []byte) string {
	var e falconIDErrorResponse
	if err := json.Unmarshal(body, &e); err == nil && e.Error != "" {
		return e.Error
	}
	// Fallback: return truncated raw body.
	if len(body) > 256 {
		return string(body[:256]) + "…"
	}
	return string(body)
}

// ---------------------------------------------------------------------
// Admin / device-management endpoints — task #128 (EnrollmentStore
// contract extension) wired into the Falcon-ID side via three new
// internal HTTP routes:
//
//   GET  /internal/v1/iam-devices                 -- List
//   POST /internal/v1/iam-devices/<uuid>/seen     -- UpdateLastSeen
//   POST /internal/v1/iam-devices/<uuid>/disable  -- Disable
//
// All three reuse the same ServiceAuth Bearer wrapper as the existing
// /enroll + /by-ek-hash endpoints. Falcon-ID side ships in falcon-id!
// (next MR) — these client methods are forward-defined so the jess
// build doesn't lag the spec.
// ---------------------------------------------------------------------

const (
	listPath        = "/internal/v1/iam-devices"
	updateSeenPath  = "/internal/v1/iam-devices/%s/seen" // %s = device_uuid
	disableDevPath  = "/internal/v1/iam-devices/%s/disable"
	listMaxPageSize = 200
)

// falconIDListResponse mirrors the JSON body returned by the GET list
// endpoint. `devices` is an array of the same shape as the by-ek-hash
// response (one row per match).
type falconIDListResponse struct {
	Devices []falconIDGetByEKResponse `json:"devices"`
}

// falconIDDisableRequest is the JSON body for POST /disable.
type falconIDDisableRequest struct {
	Reason string `json:"reason"`
}

// falconIDUpdateSeenRequest is the JSON body for POST /seen.
type falconIDUpdateSeenRequest struct {
	// RFC 3339 timestamp. Server clamps to its clock if the value drifts
	// >5 min from server-now (replay defense — a malicious agent cannot
	// stamp a future LastSeen to dodge stale-device detection).
	LastSeen string `json:"last_seen"`
}

// List implements deviceattest.EnrollmentStore.
func (s *FalconIDEnrollmentStore) List(ctx context.Context, filter deviceattest.EnrollmentFilter) ([]deviceattest.EnrolledDevice, error) {
	if filter.Limit < 0 {
		return nil, fmt.Errorf("falconid_enrollment_store: list: limit must be >= 0, got %d", filter.Limit)
	}
	if filter.Offset < 0 {
		return nil, fmt.Errorf("falconid_enrollment_store: list: offset must be >= 0, got %d", filter.Offset)
	}
	limit := filter.Limit
	if limit == 0 {
		limit = listMaxPageSize
	}

	// Build query string. omit-if-empty so the server receives only the
	// fields the operator narrowed by.
	q := make([]string, 0, 7)
	// Falcon-ID scopes the iam-devices fleet per tenant and rejects a
	// tenant-less list with 400 "Tenant context required" — mirror the
	// pre-registration endpoints, which already pass ?tenant_id=.
	if filter.TenantID != "" {
		q = append(q, "tenant_id="+filter.TenantID)
	}
	if filter.UserSub != "" {
		q = append(q, "user_sub="+filter.UserSub)
	}
	if filter.Tier != "" {
		q = append(q, "tier="+filter.Tier)
	}
	if filter.Platform != "" {
		q = append(q, "platform="+filter.Platform)
	}
	if filter.IncludeDisabled {
		q = append(q, "include_disabled=true")
	}
	q = append(q, fmt.Sprintf("limit=%d", limit))
	if filter.Offset > 0 {
		q = append(q, fmt.Sprintf("offset=%d", filter.Offset))
	}
	url := s.baseURL + listPath + "?" + strings.Join(q, "&")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap

	switch resp.StatusCode {
	case http.StatusOK:
		var out falconIDListResponse
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return nil, fmt.Errorf("falconid_enrollment_store: list: decode response: %w", err)
		}
		devices := make([]deviceattest.EnrolledDevice, 0, len(out.Devices))
		for _, r := range out.Devices {
			d, err := falconIDGetRespToEnrolledDevice(r)
			if err != nil {
				return nil, fmt.Errorf("falconid_enrollment_store: list: parse row: %w", err)
			}
			devices = append(devices, d)
		}
		return devices, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("falconid_enrollment_store: list: access denied: HTTP %d", resp.StatusCode)
	default:
		return nil, fmt.Errorf("falconid_enrollment_store: list: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// UpdateLastSeen implements deviceattest.EnrollmentStore.
func (s *FalconIDEnrollmentStore) UpdateLastSeen(ctx context.Context, deviceUUID string, t time.Time) error {
	if deviceUUID == "" {
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: device_uuid must not be empty")
	}
	body, err := json.Marshal(falconIDUpdateSeenRequest{LastSeen: t.UTC().Format(time.RFC3339)})
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: marshal: %w", err)
	}
	url := s.baseURL + fmt.Sprintf(updateSeenPath, deviceUUID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: transport error: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<14))

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		// Heartbeat-without-enrollment race: per the interface contract,
		// not an error. Caller surfaces via a dedicated metric.
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: access denied: HTTP %d", resp.StatusCode)
	default:
		return fmt.Errorf("falconid_enrollment_store: update_last_seen: unexpected status: HTTP %d", resp.StatusCode)
	}
}

// Disable implements deviceattest.EnrollmentStore.
func (s *FalconIDEnrollmentStore) Disable(ctx context.Context, deviceUUID, reason string) error {
	if deviceUUID == "" {
		return fmt.Errorf("falconid_enrollment_store: disable: device_uuid must not be empty")
	}
	body, err := json.Marshal(falconIDDisableRequest{Reason: reason})
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: disable: marshal: %w", err)
	}
	url := s.baseURL + fmt.Sprintf(disableDevPath, deviceUUID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: disable: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: disable: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: disable: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("falconid_enrollment_store: disable: device %q not found", deviceUUID)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("falconid_enrollment_store: disable: access denied: HTTP %d", resp.StatusCode)
	default:
		return fmt.Errorf("falconid_enrollment_store: disable: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// ---------------------------------------------------------------------
// Corporate device pre-registration (allowlist) management — the admin UI
// CRUD surface for the migration-0007 allowlist that IsCorporateAsset reads.
// Three internal Falcon-ID routes, all behind the same ServiceAuth Bearer
// wrapper as the /enroll + /corp-asset endpoints:
//
//	POST   /internal/v1/iam-devices/pre-registrations/bulk       -- BulkPreRegister
//	GET    /internal/v1/iam-devices/pre-registrations?tenant_id= -- ListPreRegistrations
//	DELETE /internal/v1/iam-devices/pre-registrations/:id        -- DeletePreRegistration
//
// All three are scoped to a tenant_id: the jess-controller admin handler
// derives it from the operator's verified Falcon-ID token so an operator can
// only manage their own tenant's fleet (Falcon-ID enforces the same scoping
// server-side as defence-in-depth).
// ---------------------------------------------------------------------

// PreRegDevice is one row of a bulk pre-registration request. All fields are
// optional except that Falcon-ID requires at least an identifying field
// (ek_pubkey_hash or serial_number); the server validates per-row and reports
// rejects via PreRegBulkResult.Errors rather than failing the whole batch.
type PreRegDevice struct {
	// EKPubkeyHash is the 64-char lowercase hex SHA-256 of the EK pubkey PEM
	// (the same anchor IsCorporateAsset looks up). Optional — a device may be
	// pre-registered by serial/asset-tag before its EK is known.
	EKPubkeyHash string `json:"ek_pubkey_hash,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Model        string `json:"model,omitempty"`
	Note         string `json:"note,omitempty"`
}

// preRegBulkRequest mirrors the JSON body of POST .../pre-registrations/bulk.
type preRegBulkRequest struct {
	TenantID  string         `json:"tenant_id"`
	CreatedBy string         `json:"created_by"`
	Devices   []PreRegDevice `json:"devices"`
}

// PreRegRowError reports a single row that Falcon-ID rejected during a bulk
// import. Row is the zero-based index into the submitted devices slice.
type PreRegRowError struct {
	Row   int    `json:"row"`
	Error string `json:"error"`
}

// PreRegBulkResult is the JSON body returned by POST .../pre-registrations/bulk.
// Imported counts the rows persisted; Errors carries the per-row rejects.
type PreRegBulkResult struct {
	Imported int              `json:"imported"`
	Errors   []PreRegRowError `json:"errors"`
}

// PreRegistration is one row returned by GET .../pre-registrations. Mirrors
// the Falcon-ID list shape (omitempty fields are dropped server-side when
// unset); CreatedAt is RFC3339.
type PreRegistration struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	EKPubkeyHash string `json:"ek_pubkey_hash,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	Model        string `json:"model,omitempty"`
	Note         string `json:"note,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// BulkPreRegister imports a batch of corporate device pre-registrations for
// tenantID, attributing them to createdBy (the operator's verified subject).
// Falcon-ID validates each row independently: the returned PreRegBulkResult
// carries the count persisted plus a per-row Errors list for any rejects, so
// a partially-valid batch still imports the good rows.
func (s *FalconIDEnrollmentStore) BulkPreRegister(ctx context.Context, tenantID, createdBy string, devices []PreRegDevice) (PreRegBulkResult, error) {
	if tenantID == "" {
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: tenant_id must not be empty")
	}
	body, err := json.Marshal(preRegBulkRequest{TenantID: tenantID, CreatedBy: createdBy, Devices: devices})
	if err != nil {
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+preRegBulkPath, bytes.NewReader(body))
	if err != nil {
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	authz, err := s.bearer(ctx)
	if err != nil {
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap

	switch resp.StatusCode {
	case http.StatusOK:
		var out PreRegBulkResult
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: decode response: %w", err)
		}
		return out, nil
	case http.StatusBadRequest:
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: bad request to falcon-id: %s", extractErrorMessage(rawBody))
	case http.StatusUnauthorized, http.StatusForbidden:
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: access denied: HTTP %d", resp.StatusCode)
	default:
		return PreRegBulkResult{}, fmt.Errorf("falconid_enrollment_store: bulk_pre_register: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// ListPreRegistrations returns the corporate device pre-registrations for
// tenantID. An empty allowlist yields an empty slice with nil error.
func (s *FalconIDEnrollmentStore) ListPreRegistrations(ctx context.Context, tenantID string) ([]PreRegistration, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: tenant_id must not be empty")
	}
	url := s.baseURL + preRegPath + "?tenant_id=" + tenantID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap

	switch resp.StatusCode {
	case http.StatusOK:
		var out []PreRegistration
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: decode response: %w", err)
		}
		return out, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: access denied: HTTP %d", resp.StatusCode)
	default:
		return nil, fmt.Errorf("falconid_enrollment_store: list_pre_registrations: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}

// DeletePreRegistration removes the pre-registration row id from tenantID's
// allowlist. A 404 (already gone) is surfaced as an error so the admin handler
// can map it to HTTP 404 for the caller.
func (s *FalconIDEnrollmentStore) DeletePreRegistration(ctx context.Context, tenantID, id string) error {
	if tenantID == "" {
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: tenant_id must not be empty")
	}
	if id == "" {
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: id must not be empty")
	}
	url := s.baseURL + preRegPath + "/" + id + "?tenant_id=" + tenantID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: build request: %w", err)
	}
	authz, err := s.bearer(ctx)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: %w", err)
	}
	httpReq.Header.Set("Authorization", authz)

	resp, err := s.hc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: transport error: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: pre-registration %q not found", id)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: access denied: HTTP %d", resp.StatusCode)
	default:
		return fmt.Errorf("falconid_enrollment_store: delete_pre_registration: unexpected status: HTTP %d: %s",
			resp.StatusCode, extractErrorMessage(rawBody))
	}
}
