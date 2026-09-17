// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"context"
	"time"
)

// RecordingOverride is an admin-set, persisted, per-target override of
// whether a session to that target is recorded. It layers ON TOP OF the
// catalog target's static `recorded` default (a GitOps-managed ConfigMap /
// CRD / discovery annotation): the override is operational RUNTIME state in
// the controller DB, the catalog stays the GitOps source of the DEFAULT.
//
// The EFFECTIVE recorded value for a target is:
//
//	override.Recorded   if an override row exists
//	catalog.Recorded    otherwise (no override → fall back to the GitOps default)
//
// This is a deliberate runtime-override-on-GitOps-default design: an
// on-call platform_admin can flip recording on/off for a target from the
// console without a Git round-trip, and the change is durable + audited
// (UpdatedBy stamped from the verified caller). Clearing the override
// (DELETE) reverts the target to its catalog default.
type RecordingOverride struct {
	TargetID  string    // catalog target id this override applies to
	Recorded  bool      // the admin-chosen effective value
	UpdatedBy string    // verified Falcon-ID subject of the admin who set it
	UpdatedAt time.Time // when the override was last upserted
}

// RecordingOverrideStore is the durable per-target recording-override state.
// Implementations: PostgresStore (production) + MemoryBroker (dev/tests).
//
// The controller consults Get at session-open to resolve the effective
// recorded value (override beats catalog default); the admin handler uses
// List/Set/Clear to drive the console toggle. All methods are nil-safe at
// the call sites — a controller without a store falls back to the catalog
// default unconditionally.
type RecordingOverrideStore interface {
	// GetRecordingOverride returns the override for targetID. found=false
	// (with a zero RecordingOverride + nil error) means no override exists
	// and the caller should fall back to the catalog default. Returns an
	// error only for transport / storage failures.
	GetRecordingOverride(ctx context.Context, targetID string) (ov RecordingOverride, found bool, err error)

	// SetRecordingOverride upserts the override for targetID. UpdatedBy must
	// be the verified caller's subject (RFC 8705-style binding to identity).
	// UpdatedAt is stamped to now() by the store. Returns the resulting row.
	SetRecordingOverride(ctx context.Context, targetID string, recorded bool, updatedBy string) (RecordingOverride, error)

	// ClearRecordingOverride removes the override for targetID, reverting the
	// target to its catalog default. Idempotent — not-found is nil error
	// (matches the grant Revoke / lock Delete pattern).
	ClearRecordingOverride(ctx context.Context, targetID string) error

	// ListRecordingOverrides returns every override row. Empty result is not
	// an error. Ordered by target_id for stable rendering. The admin handler
	// joins these against the catalog to compute the per-target effective
	// value + source.
	ListRecordingOverrides(ctx context.Context) ([]RecordingOverride, error)
}

// EffectiveRecorded resolves the effective recorded value for a target,
// given the catalog default and the (possibly absent) override. This is the
// single resolution rule shared by the controller (session-open) and the
// admin handler (console listing) so the two never disagree:
//
//	override present → override wins (the admin's runtime decision)
//	override absent  → catalog default (the GitOps source of truth)
func EffectiveRecorded(catalogDefault bool, ov RecordingOverride, haveOverride bool) bool {
	if haveOverride {
		return ov.Recorded
	}
	return catalogDefault
}
