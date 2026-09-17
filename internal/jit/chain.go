// SPDX-License-Identifier: AGPL-3.0-or-later

package jit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Phase 5e-16: cross-session WORM audit chain.
//
// ComputeRowHash returns the canonical hash for a session row. Inputs
// are joined with NUL bytes (which can't appear in any of the source
// values — they're either UUIDs, RFC3339 timestamps, or operator
// identifiers from Falcon-ID claims) so the concatenation can't be
// ambiguity-attacked by carefully-chosen field contents.
//
// Why these fields and not others:
//
//   - id, subject, target_id are the load-bearing audit-identity
//     fields. An attacker who can edit them can mis-attribute a
//     session — most worth pinning to the chain.
//   - started_at to UTC RFC3339 gives a deterministic format that's
//     stable across timezones + reboots.
//   - prev_row_hash links this row to its predecessor — that's what
//     makes this a chain, not a per-row checksum.
//
// Intentionally OMITTED:
//
//   - ended_at, close_reason, bytes_in, bytes_out, recording_path: all
//     mutated AFTER OpenSession. Including them would force a re-hash
//     on every CloseSession / SetRecordingPath, complicating the chain
//     invariant. Tamper detection for these mutable fields lives
//     elsewhere (recording_path is signed via the bundle manifest —
//     5e-14 verify).
//   - grant_id: may be empty on direct-connect admin sessions; leaving
//     it out keeps the canonicalisation consistent.
//
// The output is a hex-encoded sha256 — 64 chars, fits cleanly in
// existing varchar columns; small enough to log + read in admin tools.
func ComputeRowHash(id, subject, targetID string, startedAt time.Time, prevHash string) string {
	h := sha256.New()
	// Tag the canonical form so two different schemas can't collide.
	// "jess.session.v1" pins this to the 5e-16 layout — future schema
	// additions bump the tag.
	h.Write([]byte("jess.session.v1\x00"))
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(subject))
	h.Write([]byte{0})
	h.Write([]byte(targetID))
	h.Write([]byte{0})
	h.Write([]byte(startedAt.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(prevHash))) // tolerate case-drift on read-back
	return hex.EncodeToString(h.Sum(nil))
}
