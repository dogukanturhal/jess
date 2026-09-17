// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// ADR 0049 Phase 4 — raw byte-stream recording for Kubernetes port-forward
// brokering. Unlike exec/attach (a TTY → asciicast) or the DB broker (one JSON
// line per SQL statement), `kubectl port-forward` is an OPAQUE tunnelled byte
// stream: there is no terminal geometry, no per-event semantics, just bytes in
// each direction between the operator and the pod port. There is therefore no
// honest way to render it as an asciicast (it isn't a terminal) — recording it
// as one would fabricate timing/output-event framing that doesn't exist.
//
// FORMAT CHOICE — base64 NDJSON over a metadata header line:
//
// Line 1 is a one-time METADATA header describing the tunnel (the pod
// coordinates + remote port + direction legend), then each subsequent line is
// one captured byte chunk:
//
//	{"kind":"meta","version":1,"protocol":"k8s","verb":"port-forward",
//	 "namespace":"default","pod":"db","port":5432,"at":"2026-06-20T15:30:00Z"}
//	{"kind":"chunk","seq":1,"at":"...","dir":"c2t","data":"<base64>"}   // operator → target
//	{"kind":"chunk","seq":2,"at":"...","dir":"t2c","data":"<base64>"}   // target  → operator
//
// WHY base64 NDJSON rather than a raw concatenated byte dump:
//   - The tunnel carries arbitrary binary (TLS records, Postgres wire frames),
//     so the bytes cannot be stored verbatim inside a JSON/NDJSON line; base64
//     keeps each chunk a single safe line and preserves byte-exactness.
//   - Per-line framing is partial-write tolerant and append-only, so it tees
//     straight to WORM exactly like the asciicast/query-log writers — the SAME
//     Bundle infrastructure (signature, manifest, cross-session chain) covers
//     it identically, same VerifyDetail path.
//   - Capturing DIRECTION + sequence + timestamp makes the WORM record a
//     faithful, replayable transcript of the tunnel (who sent what, when)
//     without pretending it is a terminal.
//
// The chunk payload is BOUNDED (rawChunkTruncate) so a single very large
// io.Copy buffer can't blow one line up; oversized chunks are truncated and
// flagged. The relay copies in modest buffers so truncation is rare in practice.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// rawChunkTruncate bounds the recorded (pre-base64) bytes per chunk line. 64KiB
// matches a typical io.Copy buffer; larger writes are truncated + flagged so the
// recording stays a stream of bounded lines.
const rawChunkTruncate = 64 << 10

// Raw-stream record kinds.
const (
	rawKindMeta  = "meta"
	rawKindChunk = "chunk"
)

// Raw-stream direction labels (from the broker's point of view).
const (
	// RawDirClientToTarget — bytes the operator sent toward the pod port.
	RawDirClientToTarget = "c2t"
	// RawDirTargetToClient — bytes the pod port sent back to the operator.
	RawDirTargetToClient = "t2c"
)

// rawStreamMeta is the one-time header line describing the tunnel.
type rawStreamMeta struct {
	Kind      string    `json:"kind"` // always "meta"
	Version   int       `json:"version"`
	Protocol  string    `json:"protocol"`
	Verb      string    `json:"verb"`
	Namespace string    `json:"namespace,omitempty"`
	Pod       string    `json:"pod,omitempty"`
	Container string    `json:"container,omitempty"`
	Port      int       `json:"port,omitempty"`
	At        time.Time `json:"at"`
}

// rawChunk is one captured byte chunk in one direction.
type rawChunk struct {
	Kind      string    `json:"kind"` // always "chunk"
	Seq       int64     `json:"seq"`
	At        time.Time `json:"at"`
	Dir       string    `json:"dir"`  // RawDirClientToTarget | RawDirTargetToClient
	Data      string    `json:"data"` // base64 of the (possibly truncated) bytes
	Truncated bool      `json:"truncated,omitempty"`
}

// RawStreamMeta describes the tunnel a RawStreamWriter records. The broker fills
// it from the resolved session coordinates so the WORM header is self-describing.
type RawStreamMeta struct {
	Protocol  string
	Verb      string
	Namespace string
	Pod       string
	Container string
	Port      int
}

// RawStreamWriter records an opaque bidirectional byte stream as base64 NDJSON
// to the underlying bundle io.WriteCloser (see the package doc above for the
// format + rationale). It writes a one-time metadata header on the first Record
// and then one line per captured chunk. Safe for concurrent use by the two
// relay-copy goroutines (operator→target and target→operator) on one session.
type RawStreamWriter struct {
	w      io.WriteCloser
	enc    *json.Encoder
	meta   RawStreamMeta
	mu     sync.Mutex
	seq    atomic.Int64
	header bool // metadata line written (guarded by mu)
	closed atomic.Bool
}

// NewRawStreamWriter wraps a bundle io.WriteCloser with the NDJSON encoder and
// the tunnel metadata. Close on the returned writer SEALS the bundle (delegates
// to the underlying bundle WriteCloser).
func NewRawStreamWriter(w io.WriteCloser, meta RawStreamMeta) *RawStreamWriter {
	return &RawStreamWriter{w: w, enc: json.NewEncoder(w), meta: meta}
}

// Record stamps + writes one captured chunk in direction dir (RawDir*). It
// lazily emits the metadata header on the first call. The bytes are copied via
// base64 encoding, so the caller may reuse p after Record returns. Returns
// io.ErrClosedPipe after Close.
func (r *RawStreamWriter) Record(dir string, p []byte) error {
	if r.closed.Load() {
		return io.ErrClosedPipe
	}
	trunc := false
	if len(p) > rawChunkTruncate {
		p = p[:rawChunkTruncate]
		trunc = true
	}
	ev := rawChunk{
		Kind:      rawKindChunk,
		Seq:       r.seq.Add(1),
		At:        time.Now(),
		Dir:       dir,
		Data:      base64.StdEncoding.EncodeToString(p),
		Truncated: trunc,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.header {
		hdr := rawStreamMeta{
			Kind:      rawKindMeta,
			Version:   1,
			Protocol:  r.meta.Protocol,
			Verb:      r.meta.Verb,
			Namespace: r.meta.Namespace,
			Pod:       r.meta.Pod,
			Container: r.meta.Container,
			Port:      r.meta.Port,
			At:        time.Now(),
		}
		if err := r.enc.Encode(&hdr); err != nil {
			return err
		}
		r.header = true
	}
	return r.enc.Encode(&ev)
}

// Close seals the bundle (signs the manifest, commits to WORM). Safe to call
// more than once.
func (r *RawStreamWriter) Close() error {
	r.closed.Store(true)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.w.Close()
}
