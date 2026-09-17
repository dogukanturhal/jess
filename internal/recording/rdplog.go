// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// ADR 0049 Phase 3 — RDP session recording track. The RDP broker
// (internal/broker/rdp.go) tees a metadata + periodic-screenshot track into a
// Recorder using this writer. Each event lands as one JSON line in the bundle's
// content stream; the same Bundle infrastructure (signature, manifest,
// cross-session chain) covers it identically to terminal asciicast and
// query-log recordings.
//
// WHY metadata + periodic screenshots (not full graphics+input):
//   - Full RDP graphics+input recording (every bitmap update + every keystroke/
//     mouse event) is by far the heaviest recording track — a Guacamole-style
//     drawing-instruction dump (recording.FormatDrawing) can be tens of MB/min
//     per session and needs the IronRDP graphics pipeline to even produce.
//   - For audit ("who connected, when, for how long, what did the screen show
//     periodically, which channels were used / blocked") a metadata track plus
//     periodic full-frame screenshots is far lighter and is the fidelity ADR
//     0049 explicitly offers as the alternative: "a metadata + periodic-
//     screenshot track where full pixel recording is too heavy". The pixel
//     bytes live as separate bundle artifacts referenced by hash; this NDJSON
//     stream carries only the small per-event records.
//   - Upgrading to full graphics+input later is a track-format change behind the
//     same Recorder + Bundle seam — the WORM chain, signature, and verify path
//     do not change.
//
// FORMAT (one line per event):
//
//	{
//	  "kind": "rdp",
//	  "seq": 1,                               // monotonic, per-session, 1-based
//	  "at": "2026-06-20T15:30:00Z",           // RFC3339Nano
//	  "event": "session_start",               // see RDPEvent* constants
//	  "channel": "cliprdr",                   // for channel events
//	  "decision": "allowed",                  // "allowed" | "denied" (channel gating)
//	  "deny_reason": "clipboard redirection disabled by policy",
//	  "screenshot_sha256": "ab12…",           // for screenshot events: bundle artifact hash
//	  "width": 1920, "height": 1080,          // for screenshot events
//	  "detail": "NLA/CredSSP terminated at broker"
//	}

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// RDP event kinds recorded to the WORM track.
const (
	// RDPEventSessionStart marks the brokered RDP session opening (after the
	// broker has terminated NLA/CredSSP and connected to the target).
	RDPEventSessionStart = "session_start"
	// RDPEventSessionEnd marks the brokered RDP session closing.
	RDPEventSessionEnd = "session_end"
	// RDPEventScreenshot is one periodic full-frame screenshot reference (the
	// pixel bytes are a separate bundle artifact named by ScreenshotSHA256).
	RDPEventScreenshot = "screenshot"
	// RDPEventChannel is a virtual-channel open attempt (clipboard / drive /
	// printer …) with the relay's policy decision (allowed | denied).
	RDPEventChannel = "channel"
)

// RDP channel-decision labels (reuse the query-log vocabulary so verify clients
// share one decision enum across protocols).
const (
	RDPAllowed = QueryAllowed // "allowed"
	RDPDenied  = QueryDenied  // "denied"
)

// RDPEvent is one recorded RDP session event (start/end, a periodic screenshot
// reference, or a policy-gated virtual-channel attempt).
type RDPEvent struct {
	Kind     string    `json:"kind"` // always "rdp"
	Seq      int64     `json:"seq"`
	At       time.Time `json:"at"`
	Event    string    `json:"event"` // RDPEventSessionStart | …
	Channel  string    `json:"channel,omitempty"`
	Decision string    `json:"decision,omitempty"` // RDPAllowed | RDPDenied (channel events)

	DenyReason       string `json:"deny_reason,omitempty"`
	ScreenshotSHA256 string `json:"screenshot_sha256,omitempty"` // screenshot artifact hash
	Width            int    `json:"width,omitempty"`
	Height           int    `json:"height,omitempty"`
	Detail           string `json:"detail,omitempty"`
}

// RDPLogWriter is a recording writer that accepts RDPEvent structs and emits
// NDJSON to the underlying bundle io.WriteCloser. Safe for concurrent use by the
// relay goroutines on the same session (the screenshot pump and the channel-gate
// hook both Record into it).
type RDPLogWriter struct {
	w      io.WriteCloser
	enc    *json.Encoder
	mu     sync.Mutex
	seq    atomic.Int64
	closed atomic.Bool
}

// NewRDPLogWriter wraps a bundle io.WriteCloser with the NDJSON encoder. Close on
// the returned writer SEALS the bundle (delegates to the underlying bundle
// WriteCloser), mirroring NewQueryLogWriter.
func NewRDPLogWriter(w io.WriteCloser) *RDPLogWriter {
	return &RDPLogWriter{w: w, enc: json.NewEncoder(w)}
}

// Record stamps + writes one event. It fills Seq + At when zero and defaults
// Kind. Returns io.ErrClosedPipe after Close.
func (q *RDPLogWriter) Record(ev RDPEvent) error {
	if q.closed.Load() {
		return io.ErrClosedPipe
	}
	if ev.Kind == "" {
		ev.Kind = "rdp"
	}
	if ev.Seq == 0 {
		ev.Seq = q.seq.Add(1)
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.enc.Encode(&ev)
}

// Close seals the bundle (signs the manifest, commits to WORM). Safe to call
// more than once.
func (q *RDPLogWriter) Close() error {
	q.closed.Store(true)
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.w.Close()
}
