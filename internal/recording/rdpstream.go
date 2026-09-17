// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// ADR 0051 P4 — full decoded-stream RDP recording (`jess-rdp-recording-v2`).
//
// This SUPERSEDES the ADR 0033 §5f-8b-4 raw `jess-rdp-recording-v1` container
// AND the ADR 0049 Phase-3 "metadata + periodic-screenshot" track (rdplog.go):
// instead of one screenshot every N seconds, the recorder tees the ENTIRE
// DECODED frame stream the operator saw — every DESKTOP_SIZE, every dirty-region
// FRAME (the decoded PNG), and every input event — into the SAME ADR-0030
// tamper-evident WORM bundle (signature + manifest + cross-session Merkle chain)
// that the SSH asciicast / DB query-log / k8s raw-stream recordings use. The
// recording is therefore a faithful, inspectable record of what the operator saw
// and did, which is the whole point of the fork decision in ADR 0051 ("WORM
// recording requires decode").
//
// WHY a NEW format (not reuse rdplog.go / FormatDrawing):
//   - rdplog's RDPEvent is a periodic-screenshot summary; v2 is the full stream.
//     Reusing the same Format string would make verify/replay clients unable to
//     tell a sampled track from a full one. v2 is a distinct Format + version so
//     a consumer knows it has every frame.
//   - The decoded frame model (DESKTOP_SIZE + per-region PNG + input) is the
//     drawing-instruction stream ADR 0051 P2 emits over the WS; recording it is a
//     verbatim tee of that same protocol, so replay reuses the SPA canvas
//     renderer (no separate raw replayer — ADR 0051 drops services/jess-rdp-replay).
//
// FORMAT — NDJSON, one record per line, sealed into the bundle content stream:
//
// Line 1 is a one-time METADATA header:
//
//	{"kind":"meta","version":2,"protocol":"rdp","subject":"u-7","target":"win-dc-01",
//	 "session_id":"sess-…","at":"2026-06-21T…Z"}
//
// then one line per stream event (monotonic seq, RFC3339Nano `at`):
//
//	{"kind":"resize","seq":1,"at":"…","width":1280,"height":1024}
//	{"kind":"frame","seq":2,"at":"…","x":0,"y":0,"width":1280,"height":1024,
//	 "png_b64":"iVBORw0K…"}                                   // the decoded region PNG, inline
//	{"kind":"h264","seq":3,"at":"…","x":0,"y":0,"width":1280,"height":1024,
//	 "keyframe":true,"avc444":false,"nal_b64":"AAAAAWdC…"}    // an AVC420 access unit (Annex-B), inline
//	{"kind":"input","seq":4,"at":"…","input":"mouse","x":640,"y":512,"buttons":1,"wheel":0}
//	{"kind":"input","seq":5,"at":"…","input":"key","down":true,"scancode":30}
//	{"kind":"close","seq":6,"at":"…"}
//
// H.264 (ADR 0058): when the live session uses the MS-RDPEGFX/AVC420 H.264 path
// (JESS_RDP_H264 on), the engine records each access unit as a "h264" event —
// the AU's Annex-B NAL bytes (inline base64), the keyframe flag (a keyframe is an
// IDR carrying SPS+PPS so replay can (re)initialise its decoder from it), the
// AVC444 flag, and the surface rect. This LIFTS the previous "EGFX off when
// recording" gate: a recorded H.264 session is now fully replayable (the SPA
// replayer feeds these NALs to the SAME WebCodecs decoder the live console uses).
// "frame" (PNG) and "h264" never appear in the SAME recording — a session is
// either bitmap-driven (PNG) or EGFX-driven (H.264), never both.
//
// WHY the PNG bytes are INLINE (base64) rather than a per-frame bundle artifact:
//   - A bundle is one signed content stream + manifest; storing thousands of
//     separate PNG artifacts per session and referencing them by hash would make
//     the manifest the only signed thing and leave the PNGs as un-chained side
//     objects. Inlining keeps the ENTIRE recording inside the single signed,
//     hash-chained content stream — one VerifyDetail covers all pixels.
//   - Each FRAME is a dirty REGION, not a full desktop, so inline base64 is
//     bounded per line; oversized regions are truncated + flagged (rare — a
//     full-desktop initial frame is well under the cap).
//   - Per-line framing is partial-write tolerant + append-only, so it tees to
//     WORM exactly like the asciicast / query-log / raw-stream writers.
//
// CONCURRENCY: safe for the two relay legs on one session (server→client frame
// tee and client→server input tee both Record into it). Close SEALS the bundle.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// rdpStreamVersion is the on-disk version of the jess-rdp-recording-v2 format.
const rdpStreamVersion = 2

// rdpFrameTruncate bounds the inline (pre-base64) PNG bytes per frame line. A
// dirty-region PNG is comfortably under this; a pathological full-desktop frame
// is truncated + flagged so one line can't blow the bundle up.
const rdpFrameTruncate = 8 << 20 // 8 MiB

// RDP v2 record kinds.
const (
	rdpV2KindMeta   = "meta"
	rdpV2KindResize = "resize" // DESKTOP_SIZE
	rdpV2KindFrame  = "frame"  // decoded dirty-region PNG (bitmap path)
	rdpV2KindH264   = "h264"   // MS-RDPEGFX/AVC420 access unit (Annex-B NAL) — ADR 0058
	rdpV2KindInput  = "input"  // operator mouse/key event
	rdpV2KindClose  = "close"  // session end
)

// RDP v2 input-event labels.
const (
	RDPInputMouse = "mouse"
	RDPInputKey   = "key"
)

// rdpStreamMeta is the one-time header line — it binds the recording to the real
// operator identity (subject), the target, and the session, mirroring the bundle
// Manifest so the audit story holds even reading just the content stream.
type rdpStreamMeta struct {
	Kind      string    `json:"kind"` // always "meta"
	Version   int       `json:"version"`
	Protocol  string    `json:"protocol"` // "rdp"
	Subject   string    `json:"subject"`  // Falcon-ID sub of the OPERATOR (never the broker)
	Target    string    `json:"target"`
	SessionID string    `json:"session_id,omitempty"`
	At        time.Time `json:"at"`
}

// rdpStreamEvent is one decoded-stream event (resize / frame / input / close).
type rdpStreamEvent struct {
	Kind string    `json:"kind"`
	Seq  int64     `json:"seq"`
	At   time.Time `json:"at"`

	// resize + frame geometry.
	X      int `json:"x,omitempty"`
	Y      int `json:"y,omitempty"`
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`

	// frame pixels (decoded region PNG, base64), and a truncation flag.
	PNGB64    string `json:"png_b64,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`

	// h264 access unit (ADR 0058): the Annex-B NAL bytes (base64), the keyframe
	// flag (IDR carrying SPS+PPS — a replayer can (re)init its decoder from it),
	// and the AVC444 flag. The geometry (X/Y/Width/Height above) is the surface
	// rect the AU paints into. Truncated (shared above) flags an oversized AU.
	NALB64   string `json:"nal_b64,omitempty"`
	Keyframe bool   `json:"keyframe,omitempty"`
	AVC444   bool   `json:"avc444,omitempty"`

	// input events.
	Input    string `json:"input,omitempty"` // RDPInputMouse | RDPInputKey
	MouseX   int    `json:"mouse_x,omitempty"`
	MouseY   int    `json:"mouse_y,omitempty"`
	Buttons  int    `json:"buttons,omitempty"`
	Wheel    int    `json:"wheel,omitempty"`
	KeyDown  bool   `json:"key_down,omitempty"`
	Scancode uint32 `json:"scancode,omitempty"`
}

// RDPStreamMeta is the caller-supplied identity binding for a v2 recording. The
// live engine fills it from the operator's grant — Subject MUST be the real
// Falcon-ID operator sub, NEVER the broker/service identity.
type RDPStreamMeta struct {
	Subject   string
	Target    string
	SessionID string
}

// RDPStreamWriter records the full decoded RDP stream as jess-rdp-recording-v2
// NDJSON to the underlying bundle io.WriteCloser. It writes the metadata header
// on the first Record and then one line per event. Close SEALS the bundle.
type RDPStreamWriter struct {
	w      io.WriteCloser
	enc    *json.Encoder
	meta   RDPStreamMeta
	mu     sync.Mutex
	seq    atomic.Int64
	header bool // metadata header written (guarded by mu)
	closed atomic.Bool
}

// NewRDPStreamWriter wraps a bundle io.WriteCloser with the NDJSON encoder and
// the identity-binding metadata. Close on the returned writer SEALS the bundle.
func NewRDPStreamWriter(w io.WriteCloser, meta RDPStreamMeta) *RDPStreamWriter {
	return &RDPStreamWriter{w: w, enc: json.NewEncoder(w), meta: meta}
}

// ensureHeader lazily emits the one-time meta line. Caller holds mu.
func (s *RDPStreamWriter) ensureHeader() error {
	if s.header {
		return nil
	}
	hdr := rdpStreamMeta{
		Kind:      rdpV2KindMeta,
		Version:   rdpStreamVersion,
		Protocol:  "rdp",
		Subject:   s.meta.Subject,
		Target:    s.meta.Target,
		SessionID: s.meta.SessionID,
		At:        time.Now(),
	}
	if err := s.enc.Encode(&hdr); err != nil {
		return err
	}
	s.header = true
	return nil
}

// record stamps seq/at, lazily writes the header, and encodes one event.
func (s *RDPStreamWriter) record(ev rdpStreamEvent) error {
	if s.closed.Load() {
		return io.ErrClosedPipe
	}
	ev.Seq = s.seq.Add(1)
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureHeader(); err != nil {
		return err
	}
	return s.enc.Encode(&ev)
}

// Resize records a DESKTOP_SIZE event (the negotiated desktop dimensions).
func (s *RDPStreamWriter) Resize(width, height int) error {
	return s.record(rdpStreamEvent{Kind: rdpV2KindResize, Width: width, Height: height})
}

// Frame records one decoded dirty-region: the region rectangle + the region PNG
// bytes (inline base64). Oversized PNGs are truncated + flagged. The bytes are
// copied via base64 so the caller may reuse png after Frame returns.
func (s *RDPStreamWriter) Frame(x, y, width, height int, png []byte) error {
	trunc := false
	if len(png) > rdpFrameTruncate {
		png = png[:rdpFrameTruncate]
		trunc = true
	}
	return s.record(rdpStreamEvent{
		Kind:      rdpV2KindFrame,
		X:         x,
		Y:         y,
		Width:     width,
		Height:    height,
		PNGB64:    base64.StdEncoding.EncodeToString(png),
		Truncated: trunc,
	})
}

// H264Frame records one MS-RDPEGFX/AVC420 access unit (ADR 0058): the surface
// rectangle, the keyframe + AVC444 flags, and the AU's Annex-B NAL bytes (inline
// base64). A keyframe AU carries SPS+PPS+IDR so a replayer can (re)initialise its
// WebCodecs decoder from it. Oversized AUs are truncated + flagged (same bound as
// a PNG frame). The bytes are copied via base64 so the caller may reuse nal after
// H264Frame returns. This is the H.264 sibling of Frame — used INSTEAD of Frame
// for an EGFX-driven session (never both in one recording).
func (s *RDPStreamWriter) H264Frame(x, y, width, height int, keyframe, avc444 bool, nal []byte) error {
	trunc := false
	if len(nal) > rdpFrameTruncate {
		nal = nal[:rdpFrameTruncate]
		trunc = true
	}
	return s.record(rdpStreamEvent{
		Kind:      rdpV2KindH264,
		X:         x,
		Y:         y,
		Width:     width,
		Height:    height,
		Keyframe:  keyframe,
		AVC444:    avc444,
		NALB64:    base64.StdEncoding.EncodeToString(nal),
		Truncated: trunc,
	})
}

// Mouse records an operator mouse event (position, button mask, wheel step).
func (s *RDPStreamWriter) Mouse(x, y, buttons, wheel int) error {
	return s.record(rdpStreamEvent{
		Kind:    rdpV2KindInput,
		Input:   RDPInputMouse,
		MouseX:  x,
		MouseY:  y,
		Buttons: buttons,
		Wheel:   wheel,
	})
}

// Key records an operator key event (down/up + RDP scancode).
func (s *RDPStreamWriter) Key(down bool, scancode uint32) error {
	return s.record(rdpStreamEvent{
		Kind:     rdpV2KindInput,
		Input:    RDPInputKey,
		KeyDown:  down,
		Scancode: scancode,
	})
}

// CloseEvent records the session-end marker (distinct from Close, which seals
// the bundle). Best-effort: a CloseEvent failure does not block the seal.
func (s *RDPStreamWriter) CloseEvent() error {
	return s.record(rdpStreamEvent{Kind: rdpV2KindClose})
}

// Close seals the bundle (signs the manifest, commits to WORM). Safe to call
// more than once. A Close error MUST fail the session closed (ADR 0030 Phase 5):
// a recorded session whose bundle didn't seal is an audit gap.
func (s *RDPStreamWriter) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Close()
}
