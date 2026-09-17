// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// nopWriteCloser wraps a bytes.Buffer as an io.WriteCloser; Close marks sealed.
type nopRDPWriteCloser struct {
	buf    bytes.Buffer
	closed bool
}

func (c *nopRDPWriteCloser) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *nopRDPWriteCloser) Close() error                { c.closed = true; return nil }

// TestRDPLogWriterRecord proves each RDPEvent lands as one NDJSON line with a
// monotonic 1-based seq, a defaulted kind/timestamp, and that Close seals the
// underlying bundle and rejects further writes.
func TestRDPLogWriterRecord(t *testing.T) {
	w := &nopRDPWriteCloser{}
	q := NewRDPLogWriter(w)

	if err := q.Record(RDPEvent{Event: RDPEventSessionStart}); err != nil {
		t.Fatalf("record start: %v", err)
	}
	if err := q.Record(RDPEvent{Event: RDPEventScreenshot, ScreenshotSHA256: "abc", Width: 800, Height: 600}); err != nil {
		t.Fatalf("record screenshot: %v", err)
	}
	if err := q.Record(RDPEvent{Event: RDPEventChannel, Channel: "cliprdr", Decision: RDPDenied, DenyReason: "off"}); err != nil {
		t.Fatalf("record channel: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(w.buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 NDJSON lines, got %d", len(lines))
	}
	var evs []RDPEvent
	for _, ln := range lines {
		var ev RDPEvent
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("unmarshal %q: %v", ln, err)
		}
		evs = append(evs, ev)
	}
	for i, ev := range evs {
		if ev.Kind != "rdp" {
			t.Errorf("event[%d] kind = %q, want rdp", i, ev.Kind)
		}
		if ev.Seq != int64(i+1) {
			t.Errorf("event[%d] seq = %d, want %d (monotonic 1-based)", i, ev.Seq, i+1)
		}
		if ev.At.IsZero() {
			t.Errorf("event[%d] must carry a timestamp", i)
		}
	}
	if evs[1].ScreenshotSHA256 != "abc" || evs[1].Width != 800 {
		t.Errorf("screenshot event lost fields: %+v", evs[1])
	}
	if evs[2].Decision != RDPDenied || evs[2].DenyReason != "off" {
		t.Errorf("channel event lost decision: %+v", evs[2])
	}

	if err := q.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !w.closed {
		t.Error("Close must seal the underlying bundle")
	}
	if err := q.Record(RDPEvent{Event: RDPEventSessionEnd}); err != io.ErrClosedPipe {
		t.Errorf("Record after Close = %v, want io.ErrClosedPipe", err)
	}
}
