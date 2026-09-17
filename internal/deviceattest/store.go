// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"time"
)

// EnrollmentStore is the persistence boundary for Path B TOFU records.
// The concrete implementation wraps the Falcon-ID iam_devices repository
// (falcon-id!284 migration 0004_iam_devices.sql). Tests inject a fake.
//
// All methods must be safe for concurrent use. The concrete implementation
// backs onto a pgx connection pool with UNIQUE(sha256(ek_pubkey)) to make
// first-enrollment idempotent at the database layer.
type EnrollmentStore interface {
	// Register persists a new Path B TOFU enrollment. Must be idempotent:
	// if a row for row.EKPubkeyHash already exists with the same
	// DeviceUUID and UserSub, the implementation MUST succeed without
	// creating a duplicate. If the existing row has a different DeviceUUID
	// (a replay with a forged UUID), the implementation MUST return an
	// error wrapping ErrVerification.
	Register(ctx context.Context, row EnrolledDevice) error

	// GetByEKPubkeyHash looks up the enrollment by the SHA-256 digest of
	// the EK public key PEM. Returns (EnrolledDevice{}, nil) if no prior
	// enrollment exists — callers distinguish "not found" from error by
	// checking the returned struct's DeviceUUID (empty = not found).
	// Returning a zero EnrolledDevice with nil error signals a first-time
	// enrollment.
	GetByEKPubkeyHash(ctx context.Context, hash string) (EnrolledDevice, error)

	// List returns all enrolled devices matching the filter. Used by the
	// admin status/device-management endpoints (task #136). The filter is
	// ALL-AND: every non-zero field narrows the result set. A zero
	// EnrollmentFilter returns every enrolled device. Implementations MUST
	// return a stable order (most recently enrolled first) so paginated
	// callers can rely on offset/limit semantics.
	List(ctx context.Context, filter EnrollmentFilter) ([]EnrolledDevice, error)

	// UpdateLastSeen records that the device has emitted a posture
	// heartbeat at time `t`. Idempotent — calling twice with the same
	// (deviceUUID, t) is a no-op. Returns nil if the device row does not
	// exist (heartbeat-without-enrollment is a known race during initial
	// enrollment; surfaced via a dedicated metric, not an error).
	UpdateLastSeen(ctx context.Context, deviceUUID string, t time.Time) error

	// Disable marks the device row as administratively disabled. After
	// this returns, every subsequent Verify call for the same EK pubkey
	// hash MUST be rejected with ErrVerification (the verifier consults
	// the EnrollmentStore.GetByEKPubkeyHash and inspects DisabledAt).
	// The `reason` is persisted to the audit chain (not stored on the row
	// itself — the row only records DisabledAt; the reason is in the
	// associated audit event).
	//
	// Disabling is a soft delete: GetByEKPubkeyHash continues to return
	// the row (with DisabledAt set) so operators can audit who/when. A
	// future re-enrollment with the same EK pubkey is a separate decision
	// — Register must reject when a disabled row exists, unless an
	// operator explicitly clears it via a sibling admin path (not in this
	// interface; the cluster operator path uses the audit-and-confirm
	// flow at internal.example.com).
	Disable(ctx context.Context, deviceUUID string, reason string) error
}

// EnrollmentFilter narrows the List result set. Zero values are
// "no constraint on this field"; every set field is AND-combined.
type EnrollmentFilter struct {
	// TenantID scopes results to a single tenant. The Falcon-ID
	// iam-devices list endpoint REQUIRES it — a tenant-less query is
	// rejected with 400 "Tenant context required". The admin handlers
	// set it from the operator's tenant_id token claim. Empty = the
	// implementation sends no tenant scope (only valid for stores that
	// don't enforce one, e.g. tests / in-memory).
	TenantID string

	// UserSub limits results to devices enrolled under the given
	// Falcon-ID subject. Empty = all users.
	UserSub string

	// Tier limits results to a specific access tier (TIER_CORP,
	// TIER_BYOD, TIER_BREAKGLASS). Empty = all tiers.
	Tier string

	// Platform limits results to a specific platform name
	// (tpm2-linux, tpm2-windows, android-strongbox, apple-app-attest,
	// macos-mdm). Empty = all platforms.
	Platform string

	// IncludeDisabled controls whether soft-deleted rows are returned.
	// Default (false) = active only. The admin UI's "Show retired
	// devices" toggle flips this on.
	IncludeDisabled bool

	// Limit caps the result-set size. 0 means the implementation chooses
	// a sensible default (FalconIDEnrollmentStore: 200). Negative values
	// MUST return an error.
	Limit int

	// Offset is the starting offset for pagination. 0 = start at the
	// most-recently-enrolled device. Implementations MUST be stable
	// under offset (every call with the same filter returns the same
	// ordering).
	Offset int
}

// EnrolledDevice is the persisted Path B TOFU record. The shape mirrors
// the Falcon-ID iam_devices table columns (falcon-id!284) for SQL
// friendliness — flat struct, no nested types.
type EnrolledDevice struct {
	// DeviceUUID is the UUIDv4 bound to this device's EK public key.
	// Used as the SPIFFE SAN: spiffe://hexxlock.com/device/<uuid>.
	DeviceUUID string

	// UserSub is the Falcon-ID subject claim of the user who enrolled
	// this device. Stamped into the audit row.
	UserSub string

	// Platform is one of: tpm2-linux, tpm2-windows, android-strongbox,
	// apple-app-attest, macos-mdm.
	Platform string

	// AttestationPath is "A_chain" or "B_tofu".
	AttestationPath string

	// Tier is the access tier this device qualifies for: TIER_CORP,
	// TIER_BYOD, or TIER_BREAKGLASS.
	Tier string

	// EKPubkeyHash is hex(sha256(ek_pubkey_pem)) — the TOFU anchor.
	// Indexed with a UNIQUE constraint in the database.
	EKPubkeyHash string

	// TPMManufacturer is the ASCII manufacturer string (e.g. "AMD",
	// "INTC"). Empty for non-TPM platforms.
	TPMManufacturer string

	// TPMKind is the TPM module classification: discrete, firmware, pluton.
	// Empty for non-TPM platforms.
	TPMKind string

	// SerialNumber is the system/chassis serial number (DMI/SMBIOS, e.g.
	// the laptop's service tag). Distinct from TPMManufacturer/TPMKind,
	// which describe the TPM chip — this describes the MACHINE. Carried in
	// the attest request's `hardware` block (alongside, but distinct from,
	// the TPM attestation evidence) and persisted to the Falcon-ID-owned
	// column on first-enrollment (Path B TOFU). May be empty when the agent
	// could not read DMI (e.g. an unprivileged probe). Surfaced read-only by
	// the admin onboarding view.
	SerialNumber string

	// Model is the system/product model string (DMI/SMBIOS product name,
	// e.g. "Latitude 7440"). Same provenance + emptiness semantics as
	// SerialNumber.
	Model string

	// Manufacturer is the system/hardware manufacturer (DMI/SMBIOS system
	// vendor, e.g. "Dell Inc.", "LENOVO"). NOT the TPM manufacturer
	// (TPMManufacturer) — this is the machine vendor. Same provenance +
	// emptiness semantics as SerialNumber.
	Manufacturer string

	// WitnessAdminSub is the Falcon-ID sub of the operator who signed the
	// enrollment witness (WebAuthn-signed JWS). Empty if no witness was
	// required (returning-device path after initial enrollment).
	WitnessAdminSub string

	// EnrolledAt is the wall-clock time of first enrollment, as recorded
	// by the database. Zero value indicates a lookup miss (not found).
	EnrolledAt time.Time

	// LastSeenAt is the wall-clock time of the most recent posture
	// heartbeat from this device. Zero value indicates no heartbeat
	// ever — useful for the admin UI's "stale device" filter (any
	// device with LastSeenAt older than ~3x its tier cadence is
	// considered offline).
	LastSeenAt time.Time

	// DisabledAt is the wall-clock time when the device was
	// administratively disabled via the Disable() method. Zero value
	// means active. Soft-delete: GetByEKPubkeyHash continues to return
	// the row with DisabledAt set so operators can audit; Verify MUST
	// reject any device with non-zero DisabledAt.
	DisabledAt time.Time
}
