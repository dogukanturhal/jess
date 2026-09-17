// SPDX-License-Identifier: AGPL-3.0-or-later

// Package render is the browser-facing layer of the jess-web worker
// ("build-our-own Guacamole"). It turns a backend graphical protocol (RDP/VNC)
// into a display-agnostic drawing-instruction stream for an HTML5 canvas, and a
// terminal protocol (SSH) into an xterm.js stream — so the browser NEVER speaks
// the backend protocol (Guacamole / Teleport-TDP model). RDP decoding is
// delegated to a sandboxed Rust IronRDP worker (see rust/rdp-render); SSH and
// VNC are handled in Go. (ADR 0030 Phase 5e.)
package render

import (
	"context"
	"io"
)

// InputEvent is keyboard/mouse/clipboard/resize coming from the browser.
type InputEvent struct {
	Kind string // key | mouse | clipboard | resize
	Data []byte
}

// DrawClient is the browser side over one WebSocket: drawing instructions out,
// input events in. Mirrors the Guacamole display-agnostic instruction model.
type DrawClient interface {
	SendInstruction(op string, args ...any) error // rect | img | copy | sync | ...
	Inputs() <-chan InputEvent
}

// RDPRenderer bridges a backend RDP target to a DrawClient via the sandboxed
// Rust IronRDP worker (decode server-side; ship PNG/draw ops; never raw RDP to
// the browser). rec receives the drawing dump for tamper-evident recording.
type RDPRenderer interface {
	Render(ctx context.Context, target string, client DrawClient, rec io.Writer) error
}
