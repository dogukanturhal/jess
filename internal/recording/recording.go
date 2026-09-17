// SPDX-License-Identifier: AGPL-3.0-or-later

// Package recording writes tamper-evident session recordings to WORM storage.
// Terminal -> asciicast v2; graphical (RDP/VNC) -> drawing-instruction dump.
// Bundles follow a Boundary-BSR-style layout: per-session SHA256SUMS + a
// detached ed25519 signature (via Vault Transit) + a hash-chain across chunks,
// committed to MinIO Object-Lock (compliance mode, 7-yr). Fail-closed: if the
// recorder can't persist, the session is refused/killed (ADR 0030 Phase 5).
package recording

import (
	"context"
	"io"
	"time"
)

// Format of a recording stream.
type Format string

const (
	FormatAsciicastV2 Format = "asciicast-v2" // terminal (SSH / web-SSH)
	FormatDrawing     Format = "drawing"      // graphical (RDP/VNC), Guacamole-style
	// FormatHTTPNDJSON — browser session recording (Phase 5h-3a).
	// Each line in the content stream is one HTTP transaction as JSON
	// (recording.HTTPTransaction shape). The same WORM signature +
	// manifest + cross-session chain (5e-14/5e-16) covers it identically
	// to terminal recordings — same VerifyDetail path, same SPA player
	// fallback to MinIO Console.
	//
	// Why NDJSON: per-line framing means partial-write tolerance + cheap
	// append (one io.Writer.Write per transaction, no buffering), matches
	// the existing per-line audit Sink shape so SRE can grep with jq.
	FormatHTTPNDJSON Format = "http-ndjson"
	// FormatQueryLog — database session recording (ADR 0049 Phase 2). Each line
	// in the content stream is one brokered SQL statement as JSON
	// (recording.QueryEvent shape): the per-statement "query log" the broker
	// tees into the WORM chain. Same Bundle signature + manifest + cross-session
	// chain covers it identically to terminal recordings — same VerifyDetail
	// path. Per-line NDJSON framing matches the per-line audit Sink shape so SRE
	// can grep brokered SQL with jq.
	FormatQueryLog Format = "query-log"
	// FormatRawStream — opaque byte-stream recording (ADR 0049 Phase 4,
	// Kubernetes port-forward). A port-forward tunnel is NOT a terminal
	// (asciicast) or a sequence of statements (query-log); it is raw
	// bidirectional bytes between the operator and a pod port. The content
	// stream is base64 NDJSON: a one-time metadata header line then one line per
	// captured chunk carrying direction + sequence + timestamp + base64 bytes
	// (recording.RawStreamWriter). Base64 keeps each binary chunk a single safe
	// line; per-line framing tees to WORM identically to the other formats so the
	// same Bundle signature + manifest + cross-session chain + VerifyDetail path
	// covers it. See internal/recording/rawstream.go for the full rationale.
	FormatRawStream Format = "raw-stream"
	// FormatRDPStreamV2 — full decoded RDP stream recording (ADR 0051 P4,
	// `jess-rdp-recording-v2`). SUPERSEDES the ADR 0033 §5f-8b-4 raw v1 container
	// AND the ADR 0049 Phase-3 periodic-screenshot track (FormatDrawing): the
	// content stream is NDJSON carrying a one-time meta header then every
	// DESKTOP_SIZE, every decoded dirty-region FRAME (PNG inline base64), and
	// every operator input event the session produced (recording.RDPStreamWriter).
	// The same Bundle signature + manifest + cross-session chain covers it
	// identically to the other formats — same VerifyDetail path — and replay
	// reuses the SPA canvas renderer (no separate raw replayer). See
	// internal/recording/rdpstream.go for the full rationale.
	FormatRDPStreamV2 Format = "rdp-stream-v2"
)

// Meta is the self-describing session metadata embedded in the bundle.
type Meta struct {
	SessionID string
	GrantID   string
	Subject   string
	TargetID  string
	Protocol  string
	Format    Format
	StartedAt time.Time

	// SessionRowHash — Phase 5e-20 bundle ↔ chain link. The
	// controller passes the session's row_hash (from the jit_sessions
	// chain, see jit.ComputeRowHash) here so the worker can write it
	// into the bundle's Manifest. The signature covers the manifest,
	// so the chain position becomes tamper-evident along with the
	// rest of the bundle.
	//
	// Empty when the SessionStore doesn't implement the chain
	// (dev brokers) — the bundle still seals; verify-side tools
	// just won't have a cross-reference to check.
	SessionRowHash string
}

// Recorder tees a live session to a tamper-evident WORM bundle.
type Recorder interface {
	// Open starts a recording; the caller tees session bytes to the WriteCloser.
	// Its Close() SEALS the bundle: hash the content, sign the manifest, and
	// commit to WORM storage. Close returning an error MUST fail the session
	// closed (no un-recorded privileged session).
	Open(ctx context.Context, meta Meta) (io.WriteCloser, error)
}
