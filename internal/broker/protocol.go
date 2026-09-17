// SPDX-License-Identifier: AGPL-3.0-or-later

// ADR 0049 (multi-protocol brokering) Phase 0: the protocol-pluggable Broker
// seam. Today jess brokers SSH end-to-end (short-lived cert mint → target dial →
// WORM session recording, ADR 0030); every other protocol (k8s exec, Postgres,
// RDP, …) applies the SAME spine — only the credential mint and the wire relay
// are protocol-specific. This file lands the seam: one Broker interface so each
// protocol is an implementation, not a fork. The reference SSH implementation is
// in ssh.go and preserves the existing behaviour exactly (no behaviour change).
package broker

import (
	"context"
	"fmt"
	"io"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

// Target is the catalog endpoint a session is brokered to. It is the existing
// catalog.Target unchanged — the broker reuses the protocol-agnostic catalog
// model rather than introducing a parallel one (ADR 0049: "the catalog target
// model … is reused unchanged").
type Target = catalog.Target

// AccessGrant is an authorized, recordable session request handed to a Broker.
// It is protocol-agnostic: it carries the identity + JIT-grant + recording-chain
// metadata that the reused spine (catalog/jit/recording, ADR 0030) already
// produces, plus the operator-side connection the relay proxies. A Broker mints
// the matching backend Credential and dials the Target — the grant itself never
// names a protocol-specific credential.
type AccessGrant struct {
	// Target is the resolved catalog target this session reaches.
	Target *Target
	// GrantID is the active jit grant authorizing the session (the worker has
	// already re-checked it via jit.GrantStore.AssertActiveID).
	GrantID string
	// Subject is the operator identity (Falcon-ID), for recording + audit.
	Subject string
	// SessionID is the controller-issued jit_sessions row id (ADR 0030 Phase
	// 5e-7) so the WORM bundle storage key matches the persisted session row.
	// Empty = the relay falls back to a locally generated id.
	SessionID string
	// SessionRowHash pins the cross-session WORM chain link (ADR 0030 Phase
	// 5e-20) into the bundle manifest. Empty when the store has no chain.
	SessionRowHash string
	// Client is the operator-side connection (the tunnel session stream). The
	// relay proxies bytes between this and the backend, teeing into the
	// recorder. Reads/writes follow the operator session lifecycle.
	Client io.ReadWriteCloser
}

// Credential is a short-lived, per-session backend credential minted for an
// AccessGrant — an SSH cert, an ephemeral DB role, a k8s impersonation token,
// etc. (ADR 0049: "No standing credentials"). It is opaque at this layer: the
// minting Broker is the only thing that interprets it, and Dial of the same
// Broker consumes it. Protocol names the issuing protocol so a registry/factory
// can sanity-check that a Credential is fed back to the matching Broker.
type Credential interface {
	// Protocol is the broker protocol that minted this credential ("ssh", …).
	Protocol() string
}

// RecordedConn is an open brokered session whose backend reads/writes are teed
// into the WORM recorder (ADR 0030). Wait blocks until the session ends and
// returns its terminal error (nil on a clean operator disconnect). Close tears
// the session down and seals the recording bundle — a Close error MUST fail the
// session closed (no un-recorded privileged session, ADR 0030 Phase 5).
type RecordedConn interface {
	// Wait runs the brokered+recorded session, returning when the operator
	// disconnects (or on a fatal relay error).
	Wait() error
	// Close tears the session down and seals the recording bundle.
	Close() error
}

// Broker brokers one wire protocol end-to-end behind the shared jess spine
// (identity/posture → policy/JIT → mint → relay → WORM recording → revocation).
// Only Mint (the per-protocol short-lived credential) and Dial (the per-protocol
// wire relay) are protocol-specific; everything else is reused (ADR 0049).
//
// The reference implementation is the SSH broker (ssh.go), refactored from the
// existing sshproxy path with no behaviour change.
type Broker interface {
	// Protocol is the catalog protocol this broker serves: "ssh" | "rdp" |
	// "postgres" | "k8s". It MUST equal the string form of the catalog.Protocol
	// constant the broker handles.
	Protocol() string
	// Mint issues the short-lived backend credential for an approved session
	// (SSH cert, ephemeral DB role, k8s impersonation token, …). It is scoped
	// to the grant's target + subject and is consumed by Dial.
	Mint(ctx context.Context, grant AccessGrant) (Credential, error)
	// Dial opens the backend connection for grant.Target using cred and returns
	// a RecordedConn whose reads/writes are teed into the WORM recorder (ADR
	// 0030). The returned conn's Wait runs the session; Close seals it.
	Dial(ctx context.Context, target *Target, cred Credential) (RecordedConn, error)
}

// Registry maps a catalog protocol to its Broker — the factory the worker uses
// to dispatch an authorized session to the matching protocol implementation,
// instead of the per-protocol switch. Brokers register themselves at wiring
// time; unregistered protocols are denied (no silent fall-through).
type Registry struct {
	brokers map[string]Broker
}

// NewRegistry returns an empty Broker registry.
func NewRegistry() *Registry { return &Registry{brokers: make(map[string]Broker)} }

// Register adds b under b.Protocol(). It returns an error on a duplicate
// protocol or a nil broker — a misconfigured registry must fail loud at wiring
// time, never silently shadow a protocol.
func (r *Registry) Register(b Broker) error {
	if b == nil {
		return fmt.Errorf("broker: register nil broker")
	}
	p := b.Protocol()
	if p == "" {
		return fmt.Errorf("broker: register broker with empty protocol")
	}
	if _, dup := r.brokers[p]; dup {
		return fmt.Errorf("broker: protocol %q already registered", p)
	}
	r.brokers[p] = b
	return nil
}

// For returns the Broker registered for protocol, or an error if none is — the
// caller denies the session (ADR 0049: direct paths are firewalled off, so an
// unbrokered protocol means no access, not a bypass).
func (r *Registry) For(protocol string) (Broker, error) {
	b, ok := r.brokers[protocol]
	if !ok {
		return nil, fmt.Errorf("broker: no broker registered for protocol %q", protocol)
	}
	return b, nil
}

// recordingMetaFor builds the ADR-0030 recording metadata for a grant + format,
// mirroring the worker's existing construction (Phase 5e-7 session id fallback +
// Phase 5e-20 chain link) so the WORM bundle is byte-for-byte equivalent to the
// pre-refactor path. Shared by every protocol broker that records a session.
func recordingMetaFor(grant AccessGrant, protocol string, format recording.Format) recording.Meta {
	sid := grant.SessionID
	if sid == "" {
		sid = newSessionID()
	}
	return recording.Meta{
		SessionID:      sid,
		Subject:        grant.Subject,
		GrantID:        grant.GrantID,
		TargetID:       grant.Target.ID,
		Protocol:       protocol,
		Format:         format,
		StartedAt:      nowFunc(),
		SessionRowHash: grant.SessionRowHash,
	}
}
