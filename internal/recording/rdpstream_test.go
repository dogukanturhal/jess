// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// nopRDPStreamWriteCloser wraps a bytes.Buffer as an io.WriteCloser; Close marks
// the bundle sealed.
type nopRDPStreamWriteCloser struct {
	buf    bytes.Buffer
	closed bool
}

func (c *nopRDPStreamWriteCloser) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *nopRDPStreamWriteCloser) Close() error                { c.closed = true; return nil }

// TestRDPStreamWriterFullStream feeds a synthetic decoded RDP stream
// (DESKTOP_SIZE → FRAME → mouse → key → CLOSE) and asserts the bundle is a
// jess-rdp-recording-v2 NDJSON stream: a meta header binding the REAL operator
// subject, then the right resize/frame/input/close events with monotonic seq +
// timestamps, the PNG bytes preserved (base64 round-trip), and that Close seals
// the underlying bundle + rejects further writes.
func TestRDPStreamWriterFullStream(t *testing.T) {
	w := &nopRDPStreamWriteCloser{}
	s := NewRDPStreamWriter(w, RDPStreamMeta{
		Subject:   "u-operator-7", // the OPERATOR Falcon-ID sub, not the broker
		Target:    "win-dc-01",
		SessionID: "sess-abc",
	})

	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xDE, 0xAD} // PNG-ish bytes
	if err := s.Resize(1280, 1024); err != nil {
		t.Fatalf("resize: %v", err)
	}
	if err := s.Frame(0, 0, 1280, 1024, png); err != nil {
		t.Fatalf("frame: %v", err)
	}
	if err := s.Mouse(640, 512, 1, 0); err != nil {
		t.Fatalf("mouse: %v", err)
	}
	if err := s.Key(true, 30); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := s.CloseEvent(); err != nil {
		t.Fatalf("close event: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(w.buf.String()), "\n")
	// meta header + 5 events = 6 lines.
	if len(lines) != 6 {
		t.Fatalf("want 6 NDJSON lines (meta + 5 events), got %d:\n%s", len(lines), w.buf.String())
	}

	// Line 1: meta header with the v2 version + real operator identity binding.
	var meta rdpStreamMeta
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta.Kind != rdpV2KindMeta {
		t.Errorf("meta kind = %q, want %q", meta.Kind, rdpV2KindMeta)
	}
	if meta.Version != rdpStreamVersion {
		t.Errorf("meta version = %d, want %d (jess-rdp-recording-v2)", meta.Version, rdpStreamVersion)
	}
	if meta.Protocol != "rdp" {
		t.Errorf("meta protocol = %q, want rdp", meta.Protocol)
	}
	if meta.Subject != "u-operator-7" {
		t.Errorf("meta subject = %q, want the real operator sub (NOT the broker)", meta.Subject)
	}
	if meta.Target != "win-dc-01" || meta.SessionID != "sess-abc" {
		t.Errorf("meta target/session lost: %+v", meta)
	}

	// Lines 2..6: the events, monotonic seq 1..5, all timestamped.
	var evs []rdpStreamEvent
	for _, ln := range lines[1:] {
		var ev rdpStreamEvent
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("unmarshal event %q: %v", ln, err)
		}
		evs = append(evs, ev)
	}
	for i, ev := range evs {
		if ev.Seq != int64(i+1) {
			t.Errorf("event[%d] seq = %d, want %d (monotonic 1-based)", i, ev.Seq, i+1)
		}
		if ev.At.IsZero() {
			t.Errorf("event[%d] must carry a timestamp", i)
		}
	}

	// resize.
	if evs[0].Kind != rdpV2KindResize || evs[0].Width != 1280 || evs[0].Height != 1024 {
		t.Errorf("resize event wrong: %+v", evs[0])
	}
	// frame — geometry + PNG bytes preserved.
	if evs[1].Kind != rdpV2KindFrame || evs[1].Width != 1280 || evs[1].Height != 1024 {
		t.Errorf("frame event geometry wrong: %+v", evs[1])
	}
	gotPNG, err := base64.StdEncoding.DecodeString(evs[1].PNGB64)
	if err != nil {
		t.Fatalf("decode frame png_b64: %v", err)
	}
	if !bytes.Equal(gotPNG, png) {
		t.Errorf("frame PNG bytes = %x, want %x", gotPNG, png)
	}
	// mouse input.
	if evs[2].Kind != rdpV2KindInput || evs[2].Input != RDPInputMouse || evs[2].MouseX != 640 || evs[2].MouseY != 512 || evs[2].Buttons != 1 {
		t.Errorf("mouse event wrong: %+v", evs[2])
	}
	// key input.
	if evs[3].Kind != rdpV2KindInput || evs[3].Input != RDPInputKey || !evs[3].KeyDown || evs[3].Scancode != 30 {
		t.Errorf("key event wrong: %+v", evs[3])
	}
	// close.
	if evs[4].Kind != rdpV2KindClose {
		t.Errorf("close event wrong: %+v", evs[4])
	}

	// Close seals the bundle and rejects further writes.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !w.closed {
		t.Error("Close must seal the underlying bundle")
	}
	if err := s.Frame(0, 0, 1, 1, png); err != io.ErrClosedPipe {
		t.Errorf("Frame after Close = %v, want io.ErrClosedPipe", err)
	}
}

// TestRDPStreamWriterTruncatesOversizedFrame proves a pathologically large
// region PNG is truncated + flagged so one line can't blow the bundle up.
func TestRDPStreamWriterTruncatesOversizedFrame(t *testing.T) {
	w := &nopRDPStreamWriteCloser{}
	s := NewRDPStreamWriter(w, RDPStreamMeta{Subject: "u", Target: "t"})
	big := make([]byte, rdpFrameTruncate+100)
	if err := s.Frame(0, 0, 100, 100, big); err != nil {
		t.Fatalf("frame: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(w.buf.String()), "\n")
	var ev rdpStreamEvent
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if !ev.Truncated {
		t.Error("oversized frame must be flagged Truncated")
	}
	gotPNG, _ := base64.StdEncoding.DecodeString(ev.PNGB64)
	if len(gotPNG) != rdpFrameTruncate {
		t.Errorf("truncated png len = %d, want %d", len(gotPNG), rdpFrameTruncate)
	}
}

// TestRDPStreamWriterBundleSeals proves the writer composes correctly over a
// real BundleRecorder: the sealed bundle is a valid v2 NDJSON content stream that
// VerifyDetail accepts (signature + hash), with the manifest carrying the real
// operator subject and the rdp-stream-v2 format.
func TestRDPStreamWriterBundleSeals(t *testing.T) {
	store := NewFSStore(t.TempDir())
	signer, err := NewEd25519Signer("test-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	rec := NewBundleRecorder(store, signer)

	meta := Meta{
		SessionID: "sess-seal",
		Subject:   "u-operator-9",
		TargetID:  "win-dc-01",
		Protocol:  "rdp",
		Format:    FormatRDPStreamV2,
	}
	bw, err := rec.Open(t.Context(), meta)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	sw := NewRDPStreamWriter(bw, RDPStreamMeta{Subject: meta.Subject, Target: meta.TargetID, SessionID: meta.SessionID})
	_ = sw.Resize(800, 600)
	_ = sw.Frame(0, 0, 800, 600, []byte{1, 2, 3})
	_ = sw.CloseEvent()
	if err := sw.Close(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	res, err := VerifyDetail(t.Context(), store, "sess-seal", signer.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.SignatureValid || !res.HashMatch {
		t.Fatalf("sealed v2 bundle should verify: %+v", res)
	}
	if res.Manifest.Format != FormatRDPStreamV2 {
		t.Errorf("manifest format = %q, want %q", res.Manifest.Format, FormatRDPStreamV2)
	}
	if res.Manifest.Subject != "u-operator-9" {
		t.Errorf("manifest subject = %q, want the operator sub", res.Manifest.Subject)
	}
}

// TestFSStoreListAndSessionsFrom proves the List capability enumerates a sealed
// bundle's keys and SessionsFrom recovers the session id from the manifest keys —
// the discovery primitive the recordings list endpoint relies on.
func TestFSStoreListAndSessionsFrom(t *testing.T) {
	store := NewFSStore(t.TempDir())
	signer, _ := NewEd25519Signer("k")
	rec := NewBundleRecorder(store, signer)

	for _, id := range []string{"rdp-a-win-1", "rdp-b-win-2"} {
		bw, err := rec.Open(t.Context(), Meta{SessionID: id, Subject: "u", TargetID: "win", Protocol: "rdp", Format: FormatRDPStreamV2})
		if err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		sw := NewRDPStreamWriter(bw, RDPStreamMeta{Subject: "u", Target: "win", SessionID: id})
		_ = sw.Resize(800, 600)
		if err := sw.Close(); err != nil {
			t.Fatalf("seal %s: %v", id, err)
		}
	}

	keys, err := store.List(t.Context(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Each sealed bundle = 3 objects (recording.ndjson + manifest.json + manifest.sig).
	if len(keys) != 6 {
		t.Errorf("listed %d keys, want 6 (2 bundles × 3 objects): %v", len(keys), keys)
	}
	sessions := SessionsFrom(keys)
	if len(sessions) != 2 {
		t.Fatalf("SessionsFrom = %v, want 2 session ids", sessions)
	}
	got := map[string]bool{sessions[0]: true, sessions[1]: true}
	if !got["rdp-a-win-1"] || !got["rdp-b-win-2"] {
		t.Errorf("SessionsFrom = %v, want rdp-a-win-1 + rdp-b-win-2", sessions)
	}
}

// TestFSStoreListMissingPrefix proves listing a not-yet-populated store yields no
// keys (and no error) — the recordings endpoint then returns an empty list.
func TestFSStoreListMissingPrefix(t *testing.T) {
	store := NewFSStore(t.TempDir())
	keys, err := store.List(t.Context(), "")
	if err != nil {
		t.Fatalf("list empty store: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("empty store listed %d keys, want 0", len(keys))
	}
}
