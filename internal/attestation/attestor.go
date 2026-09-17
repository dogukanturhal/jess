// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attestation verifies cloud-signed host identity documents
// as the basis for jess host attestation (Phase 7g — Teleport
// IAM-join pattern).
//
// Why attestation
// ===============
// Phase 7 (catalog discovery) says WHAT exists. Attestation says
// "the host claiming to be ID X is provably that host." Without it,
// any actor who can reach the controller admin port + present a
// fabricated identity could enroll a fake host.
//
// Industry convention (per docs/adr/0030-phase-7-dynamic-catalog.md
// §Industry survey):
//   - AWS: Instance Identity Document signed by AWS-region RSA key
//   - Azure: VM attested data — JWT signed by Azure's well-known JWKS
//   - GCP: signed identity document JWT from metadata server
//   - Teleport: identical pattern, packaged as "IAM-join"
//
// What 7g v1 ships (this MR)
// ==========================
// Verifier framework + AWS + Azure verifiers + POST /admin/attest
// endpoint that audits every attempt.
//
// What 7g v1 does NOT yet do (follow-up MRs)
// ==========================================
//   - Mint an SSH-CA cert bound to the attested identity (7g-2)
//   - Auto-create a JessTarget CR from a successful attestation (7g-3)
//   - GCP attestor (7g-4 — symmetric work; Azure pattern transfers)
//
// Fail-closed posture
// ===================
// Any verification error (signature mismatch, expired document,
// unknown issuer, claim missing) returns ErrVerification — controller
// MUST 401 the request. There is no "soft" attestation. The audit
// trail records the attempt regardless so SOC tools see both
// successful and rejected attestations.
package attestation

import (
	"context"
	"errors"
	"time"
)

// Provenance names the cloud that signed the document — recorded in
// the audit row so SOC tools can filter by attestation source.
type Provenance string

const (
	ProvenanceAWS   Provenance = "aws"
	ProvenanceAzure Provenance = "azure"
	ProvenanceGCP   Provenance = "gcp" // reserved; Phase 7g-4
)

// Document is the verified identity claims that survive attestation.
// Verifiers produce one of these on success; the controller stamps
// the attested fields into the audit row + (Phase 7g-2) the issued
// cert's Subject.
//
// Provider-specific fields (instance ID, region) live in Extras so
// the type stays narrow. Production code reading those fields should
// switch on Provenance and use the named keys documented in each
// verifier's package.
type Document struct {
	Provenance Provenance
	// AccountID is the cloud account / subscription / project that
	// owns the attested host. Surfaces in the audit row.
	AccountID string
	// InstanceID is the cloud-native unique id for the host
	// (EC2 instance id, Azure VM ID, GCP instance id).
	InstanceID string
	// Region narrows the scope — the controller can refuse
	// attestations from unexpected regions if configured.
	Region string
	// IssuedAt + ExpiresAt are the signing-time + validity bounds.
	// Verifiers reject any document with ExpiresAt < now.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Extras carry provider-specific claims (architecture, image
	// id, pending-time, …). Callers needing them must know the
	// provider's claim namespace.
	Extras map[string]string
}

// Verifier verifies a presented attestation document. Receivers MUST
// NOT trust ANY field of the input outside the verifier's own
// signature check — the document is operator-supplied and could be
// fabricated.
//
// Implementations:
//   - aws.New() — AWS Instance Identity Document
//   - azure.New() — Azure VM attested-data JWT
type Verifier interface {
	// Provenance returns the cloud this verifier handles. Used by
	// the controller's dispatch + the audit row.
	Provenance() Provenance

	// Verify validates the presented blob (raw bytes — could be
	// JSON, JWT, etc., the verifier knows). Returns Document on
	// success or ErrVerification on any failure.
	Verify(ctx context.Context, blob []byte) (Document, error)
}

// ErrVerification is the canonical sentinel — every verifier failure
// path returns this (possibly wrapping a more specific error via
// fmt.Errorf("%w: …", ErrVerification, …)). Callers should match on
// errors.Is(err, ErrVerification) rather than the concrete error so
// the controller's HTTP response stays the same regardless of which
// internal validation rule fired.
var ErrVerification = errors.New("attestation: verification failed")

// Registry is the controller-side dispatch from Provenance → Verifier.
// Built at controller startup; immutable thereafter.
type Registry struct {
	verifiers map[Provenance]Verifier
}

// NewRegistry constructs an empty Registry. Call Register for each
// verifier the operator wants enabled (AWS, Azure, …).
func NewRegistry() *Registry { return &Registry{verifiers: map[Provenance]Verifier{}} }

// Register adds a Verifier. Calling twice with the same Provenance
// overwrites the previous — caller's responsibility to be intentional
// (the controller's catalog_wiring is single-threaded at startup).
func (r *Registry) Register(v Verifier) {
	r.verifiers[v.Provenance()] = v
}

// VerifierFor returns the verifier for a given Provenance, or nil if
// the operator didn't enable that cloud. Callers MUST treat nil as
// "attestation source disabled" — DO NOT fall back to "trust
// unsigned" or any other looser posture.
func (r *Registry) VerifierFor(p Provenance) Verifier {
	return r.verifiers[p]
}

// Enabled lists every Provenance the registry serves. Used by the
// admin status endpoint + the audit row when an attestation is
// rejected for "unknown provenance".
func (r *Registry) Enabled() []Provenance {
	out := make([]Provenance, 0, len(r.verifiers))
	for p := range r.verifiers {
		out = append(out, p)
	}
	return out
}
