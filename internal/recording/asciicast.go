// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AsciicastWriter writes an asciicast v2 stream (https://docs.asciinema.org).
// Line 1 is the header; each subsequent Write emits an `[elapsed,"o",data]`
// output event. Streamable + append-only, so it tees straight to WORM storage.
// (ADR 0030 Phase 5b — terminal session recording.)
type AsciicastWriter struct {
	mu     sync.Mutex
	w      io.Writer
	start  time.Time
	header bool
	width  int
	height int
}

// NewAsciicastWriter records output to w with the given terminal dimensions
// (defaults 80x24 if non-positive — refined from the pty-req in a later pass).
func NewAsciicastWriter(w io.Writer, width, height int) *AsciicastWriter {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	return &AsciicastWriter{w: w, width: width, height: height}
}

func (a *AsciicastWriter) writeHeader() error {
	h := map[string]any{
		"version":   2,
		"width":     a.width,
		"height":    a.height,
		"timestamp": time.Now().Unix(),
	}
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = a.w.Write(append(b, '\n'))
	return err
}

// Write records p as one output event (lazily writing the header first).
func (a *AsciicastWriter) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.header {
		a.start = time.Now()
		if err := a.writeHeader(); err != nil {
			return 0, err
		}
		a.header = true
	}
	ev := []any{time.Since(a.start).Seconds(), "o", string(p)}
	b, err := json.Marshal(ev)
	if err != nil {
		return 0, err
	}
	if _, err := a.w.Write(append(b, '\n')); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying writer if it is a Closer.
func (a *AsciicastWriter) Close() error {
	if c, ok := a.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
