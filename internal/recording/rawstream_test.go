// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

// rawNopWC adapts a strings.Builder-like buffer to an io.WriteCloser so the
// RawStreamWriter (which seals via Close on the underlying bundle writer) can be
// driven without a real bundle.
type rawNopWC struct {
	mu     sync.Mutex
	b      strings.Builder
	closed bool
}

func (w *rawNopWC) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *rawNopWC) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}
func (w *rawNopWC) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// TestRawStreamWriterEmitsMetaThenChunks proves the writer emits a single meta
// header line first, then one base64 chunk line per Record with the direction +
// monotonic seq, and that Close seals the underlying bundle.
func TestRawStreamWriterEmitsMetaThenChunks(t *testing.T) {
	under := &rawNopWC{}
	w := NewRawStreamWriter(under, RawStreamMeta{
		Protocol: "k8s", Verb: "port-forward", Namespace: "default", Pod: "db", Port: 5432,
	})

	if err := w.Record(RawDirClientToTarget, []byte("hello")); err != nil {
		t.Fatalf("record c2t: %v", err)
	}
	if err := w.Record(RawDirTargetToClient, []byte("world")); err != nil {
		t.Fatalf("record t2c: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !under.closed {
		t.Error("Close did not seal the underlying bundle")
	}

	lines := strings.Split(strings.TrimSpace(under.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 1 meta + 2 chunk lines, got %d:\n%s", len(lines), under.String())
	}

	var meta struct {
		Kind, Protocol, Verb, Namespace, Pod string
		Port                                 int
	}
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if meta.Kind != "meta" || meta.Verb != "port-forward" || meta.Port != 5432 || meta.Pod != "db" {
		t.Errorf("meta header = %+v, want the tunnel coordinates", meta)
	}

	type chunk struct {
		Kind, Dir, Data string
		Seq             int64
	}
	var c1, c2 chunk
	if err := json.Unmarshal([]byte(lines[1]), &c1); err != nil {
		t.Fatalf("parse chunk1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &c2); err != nil {
		t.Fatalf("parse chunk2: %v", err)
	}
	if c1.Dir != RawDirClientToTarget || c1.Seq != 1 {
		t.Errorf("chunk1 = %+v, want c2t seq 1", c1)
	}
	if c2.Dir != RawDirTargetToClient || c2.Seq != 2 {
		t.Errorf("chunk2 = %+v, want t2c seq 2", c2)
	}
	if got, _ := base64.StdEncoding.DecodeString(c1.Data); string(got) != "hello" {
		t.Errorf("chunk1 data = %q, want base64(hello)", c1.Data)
	}
	if got, _ := base64.StdEncoding.DecodeString(c2.Data); string(got) != "world" {
		t.Errorf("chunk2 data = %q, want base64(world)", c2.Data)
	}
}

// TestRawStreamWriterTruncatesOversizedChunk proves a chunk larger than the
// bound is truncated + flagged so a single huge io.Copy buffer can't blow one
// line up.
func TestRawStreamWriterTruncatesOversizedChunk(t *testing.T) {
	under := &rawNopWC{}
	w := NewRawStreamWriter(under, RawStreamMeta{Protocol: "k8s", Verb: "port-forward"})
	big := make([]byte, rawChunkTruncate+100)
	if err := w.Record(RawDirClientToTarget, big); err != nil {
		t.Fatalf("record: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(under.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want meta + 1 chunk, got %d", len(lines))
	}
	var c struct {
		Data      string
		Truncated bool
	}
	if err := json.Unmarshal([]byte(lines[1]), &c); err != nil {
		t.Fatalf("parse chunk: %v", err)
	}
	if !c.Truncated {
		t.Error("oversized chunk must be flagged Truncated")
	}
	got, _ := base64.StdEncoding.DecodeString(c.Data)
	if len(got) != rawChunkTruncate {
		t.Errorf("truncated chunk len = %d, want %d", len(got), rawChunkTruncate)
	}
}

// TestRawStreamWriterClosedRejects proves Record after Close returns
// io.ErrClosedPipe (no writes to a sealed bundle).
func TestRawStreamWriterClosedRejects(t *testing.T) {
	w := NewRawStreamWriter(&rawNopWC{}, RawStreamMeta{})
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := w.Record(RawDirClientToTarget, []byte("x")); err != io.ErrClosedPipe {
		t.Errorf("Record after Close = %v, want io.ErrClosedPipe", err)
	}
}
