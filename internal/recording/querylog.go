// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// ADR 0049 Phase 2 — per-statement query-log recording for database session
// brokering. The Postgres broker (internal/broker/postgres.go) tees every
// brokered SQL statement into a Recorder using this writer. Each statement
// lands as one JSON line in the bundle's content stream; the same Bundle
// infrastructure (signature, manifest, cross-session chain) covers it
// identically to terminal asciicast recordings.
//
// WHY a dedicated writer + event shape (rather than just any io.Writer over
// JSON):
//   - QueryEvent enforces the schema across the recorder and any future
//     replay/verify client — adding a field touches one place.
//   - The SQL text is BOUNDED (queryTruncate, default 8KiB) so a bulk
//     `INSERT INTO huge VALUES (...)` can't blow the recording up; oversized
//     statements get Truncated=true.
//   - The decision (allowed | denied) is captured per statement so the WORM
//     query log is the tamper-evident record of BOTH what ran and what the
//     per-statement policy blocked at the relay.
//
// FORMAT (one line per statement):
//
//	{
//	  "kind": "query",
//	  "seq": 1,                              // monotonic, per-session, 1-based
//	  "at": "2026-06-20T15:30:00Z",          // RFC3339Nano
//	  "sql": "SELECT 1",
//	  "decision": "allowed",                 // "allowed" | "denied"
//	  "deny_reason": "read-only: writes are not permitted", // only when denied
//	  "truncated": false
//	}

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// queryTruncate bounds the recorded SQL text — 8KiB is enough for any
// reasonable statement while bounding the recording size for bulk-value
// payloads (a single multi-MB `INSERT ... VALUES` must not blow the bundle up).
const queryTruncate = 8 << 10

// Query decision labels.
const (
	QueryAllowed = "allowed"
	QueryDenied  = "denied"
)

// QueryEvent is one brokered SQL statement recorded to the WORM query log.
type QueryEvent struct {
	Kind       string    `json:"kind"` // always "query"
	Seq        int64     `json:"seq"`
	At         time.Time `json:"at"`
	SQL        string    `json:"sql"`
	Decision   string    `json:"decision"` // QueryAllowed | QueryDenied
	DenyReason string    `json:"deny_reason,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
}

// QueryLogWriter is a recording writer that accepts QueryEvent structs and emits
// NDJSON to the underlying bundle io.WriteCloser. Safe for concurrent use by the
// relay goroutines on the same session.
type QueryLogWriter struct {
	w      io.WriteCloser
	enc    *json.Encoder
	mu     sync.Mutex
	seq    atomic.Int64
	closed atomic.Bool
}

// NewQueryLogWriter wraps a bundle io.WriteCloser with the NDJSON encoder. Close
// on the returned writer SEALS the bundle (delegates to the underlying bundle
// WriteCloser).
func NewQueryLogWriter(w io.WriteCloser) *QueryLogWriter {
	return &QueryLogWriter{w: w, enc: json.NewEncoder(w)}
}

// Record stamps + writes one statement. It fills Seq + At when zero, defaults
// Kind/Decision, and truncates oversized SQL. Returns io.ErrClosedPipe after
// Close.
func (q *QueryLogWriter) Record(ev QueryEvent) error {
	if q.closed.Load() {
		return io.ErrClosedPipe
	}
	if ev.Kind == "" {
		ev.Kind = "query"
	}
	if ev.Seq == 0 {
		ev.Seq = q.seq.Add(1)
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Decision == "" {
		ev.Decision = QueryAllowed
	}
	if len(ev.SQL) > queryTruncate {
		ev.SQL = ev.SQL[:queryTruncate]
		ev.Truncated = true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.enc.Encode(&ev)
}

// Close seals the bundle (signs the manifest, commits to WORM). Safe to call
// more than once.
func (q *QueryLogWriter) Close() error {
	q.closed.Store(true)
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.w.Close()
}
