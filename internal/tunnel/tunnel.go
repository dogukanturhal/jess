// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tunnel is the reverse-tunnel fabric: workers dial the controller
// OUTBOUND-ONLY and the controller opens session streams back into them
// (HashiCorp Boundary egress-worker / Teleport reverse-tunnel model). No
// inbound ports on the target network. v1 = yamux over SPIFFE-mTLS (ADR 0030 5a).
package tunnel

import (
	"context"
	"net"
)

// SessionHeader is sent by the controller when it opens a stream into a worker.
type SessionHeader struct {
	TargetID string
	Protocol string // tcp | ssh | postgres | rdp | web-ssh
	GrantID  string // active JIT grant; worker refuses a session without one
	Subject  string // operator identity (for recording/audit metadata)

	// SessionID — Phase 5e-7. The controller-issued jit_sessions row
	// id propagated to the worker so the recording bundle's storage
	// key matches the persisted session row (recording.Meta.SessionID
	// → contentKey is "<SessionID>/recording.<ext>"). Without this
	// the worker generated a fresh id locally and the controller had
	// no way to point at the resulting recording bundle.
	//
	// Backwards-compatible: zero value means the worker falls back to
	// its own local sessionID() (5e-6 behaviour). Old controllers
	// talking to new workers send an empty field; old workers talking
	// to new controllers silently drop the field on JSON decode.
	SessionID string

	// SessionRowHash — Phase 5e-20 cross-session WORM chain link.
	// The controller stamps the session row's row_hash here (from
	// jit_sessions.row_hash) so the worker can write it into the
	// recording manifest. The signature covers the manifest, so the
	// chain-position claim becomes tamper-evident along with the
	// bundle content.
	//
	// Backwards-compatible: zero value means the controller's
	// SessionStore doesn't implement the chain (dev brokers) — the
	// worker still seals; verify-side admin endpoint reports
	// chain_link_ok=true (no claim to check) for those bundles.
	SessionRowHash string

	// Recorded is the controller-resolved EFFECTIVE recording decision
	// for this session (the per-target admin recording override resolved
	// against the catalog default). The worker honours THIS instead of
	// its own catalog's static `recorded` flag so an admin's runtime
	// toggle is authoritative end-to-end — the worker shares the same
	// Postgres, but resolving once in the controller (where the session
	// row + recording_path are already computed) keeps a single source
	// of truth and avoids a second per-session DB round-trip on the data
	// plane.
	//
	// Tri-state pointer for backwards-compatibility: nil means "no
	// effective decision was propagated" (an old controller, or a
	// controller without a RecordingOverrideStore) — the worker then
	// falls back to its own catalog's target.Recorded exactly as it did
	// before. Non-nil pins the effective value (override-or-default).
	Recorded *bool `json:",omitempty"`
}

// SessionStream is one multiplexed session (a yamux stream) plus its header.
type SessionStream interface {
	net.Conn
	Header() SessionHeader
}

// Worker (data plane) dials home and serves controller-initiated sessions.
type Worker interface {
	// Dial connects outbound to the controller over mTLS/SPIFFE, then blocks
	// accepting streams the controller opens, invoking handle per session.
	Dial(ctx context.Context, controllerAddr string, handle func(SessionStream)) error
}

// Pool (control plane) tracks connected workers and opens streams into them.
type Pool interface {
	Register(workerID string, conn net.Conn) error // worker dialed in (yamux.Server side)
	Open(ctx context.Context, workerID string, hdr SessionHeader) (SessionStream, error)
}
