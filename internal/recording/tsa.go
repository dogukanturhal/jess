// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// Gap audit #8 — RFC 3161 trusted timestamping scaffold for the
// cross-session WORM chain. The chain currently signs each session
// row's row_hash via Ed25519/Vault Transit; that's tier-1 OSS but
// lacks an external trusted-time anchor. FedRAMP 3PAOs vary in
// whether they require RFC 3161 TSA stamping on chain heads, but
// the safer posture is to ship the capability so it can be turned
// on per-deployment.
//
// This file holds the TSAClient interface + a no-op stub + the shared
// type definitions. The real RFC 3161 HTTP client (DigiCert, Sectigo,
// FreeTSA, or self-hosted) lives in tsa_http.go (HTTPTSAClient, built on
// github.com/digitorus/timestamp): construct one via NewTSAClient /
// TSAClientFromEnv (env JESS_TSA_URL etc.), which returns the NoopTSAClient
// when no URL is configured.
//
// Status: client implemented + unit-tested (tsa_http_test.go). Remaining
// integration = calling Stamp on chain-head seal and persisting the returned
// token alongside the row for later verification (a follow-on that adds the
// token-storage column). Selecting/configuring a per-deployment TSA (URL +
// trust chain) stays a deploy-time concern.

import (
	"context"
	"errors"
	"time"
)

// TSARequest is the input to an RFC 3161 TimeStampRequest. The hash
// algorithm + digest of the chain head are the only required fields
// per RFC 3161 §2.4.1; nonce + cert_req + tsa_policy are optional.
type TSARequest struct {
	HashAlgorithm string // OID — typically id-sha256 (1.3.14.3.2.26 in practice)
	Digest        []byte // hash of the chain head row_hash
	Nonce         []byte // RFC 3161 §2.4.1 — random nonce to detect replay
}

// TSAResponse is the TimeStampToken returned by the TSA, structured
// per RFC 3161 §2.4.2. The Token field is the raw ASN.1 DER bytes
// that need to be persisted alongside the chain-head row for later
// verification.
type TSAResponse struct {
	Status        TSAStatus
	Token         []byte    // raw ASN.1 DER — opaque to jess; verified by RFC 3161 toolchain
	GenTime       time.Time // genTime extracted from the token (decoded for audit/UI)
	SerialNumber  []byte    // TSA-assigned serial — uniquely identifies this token
	PolicyOID     string    // policy OID the TSA chose to apply
	TSACertSerial string    // signing cert serial of the TSA (for revocation check)
}

// TSAStatus mirrors RFC 3161 §2.4.2 PKIStatusInfo. Granted is the only
// good outcome; everything else is a permanent rejection (the request
// MUST be reformulated, not retried).
type TSAStatus int

const (
	TSAStatusGranted               TSAStatus = 0
	TSAStatusGrantedWithMods       TSAStatus = 1
	TSAStatusRejection             TSAStatus = 2
	TSAStatusWaiting               TSAStatus = 3 // RFC 3161 doesn't use; reserved
	TSAStatusRevocationWarning     TSAStatus = 4
	TSAStatusRevocationNotificaton TSAStatus = 5
)

// TSAClient is the abstraction for an RFC 3161 timestamping service.
// Implementations: DigiCertTSA, SectigoTSA, FreeTSA, SelfHostedTSA.
// All return a TSAResponse on the happy path; on transport / parse /
// rejection failures they return an error.
type TSAClient interface {
	Stamp(ctx context.Context, req TSARequest) (TSAResponse, error)
}

// NoopTSAClient is the default — never call the TSA, never error.
// Used in dev + integration tests where stamping the head every tick
// would burn external API budget for no gain. Production deploys
// should swap this for a real TSAClient via env JESS_TSA_URL.
type NoopTSAClient struct{}

// Stamp returns ErrTSANotConfigured so chain-monitor callers can
// distinguish "no TSA wired" from "TSA wired but failed". The chain
// monitor logs but does NOT fail the verify when this is the error
// — the Ed25519 + cross-session hash chain stays the load-bearing
// integrity layer regardless of TSA availability.
func (NoopTSAClient) Stamp(_ context.Context, _ TSARequest) (TSAResponse, error) {
	return TSAResponse{}, ErrTSANotConfigured
}

// ErrTSANotConfigured signals the no-op TSA path. Callers treat as
// info, not warn — TSA is optional reinforcement.
var ErrTSANotConfigured = errors.New("recording/tsa: no TSA client configured (gap audit #8 follow-up)")

// MerkleNode is the scaffold for the per-segment Merkle tree
// aggregation (Sigstore Rekor / CT log pattern). A real
// implementation builds a binary tree over per-chunk hashes so a
// challenger can prove inclusion of any single chunk by sending
// just log(N) sibling hashes, not the whole chain.
//
// Status: scaffold-only — see follow-up ADR addendum on Phase
// 5e-17 chain-aggregation-and-tsa for the full design.
type MerkleNode struct {
	Hash     []byte
	Left     *MerkleNode
	Right    *MerkleNode
	IsLeaf   bool
	LeafData []byte // chunk hash for leaves; nil for interior nodes
}
