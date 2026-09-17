// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// Phase 5h-3a — HTTP transaction recording for browser session brokering.
//
// jess-web's /proxy/<service>/<path> handler tees every operator HTTP
// request + upstream response into a Recorder using this writer. Each
// transaction lands as one JSON line in the bundle's content stream;
// the same Bundle infrastructure (5e-14 signature, 5e-16 chain) covers
// it identically to terminal asciicast recordings.
//
// WHY a separate writer + transaction shape (rather than just any
// io.Writer over JSON):
//   - HTTPTransaction enforces the schema across both the recorder
//     and any future SPA/E2E replay client. Adding a field requires
//     touching one place.
//   - Body capture is BOUNDED — recordings can otherwise consume
//     gigabytes when an admin downloads a large file via the proxy.
//     Default cap = 64KiB per direction; bodies larger than that get
//     {truncated:true, original_bytes:N}.
//   - PII / secret redaction lives here: Authorization / Cookie /
//     Set-Cookie headers are stripped by default; opt-in via the
//     CaptureSensitiveHeaders flag for forensic investigations.
//
// FORMAT (one line per transaction):
//
//	{
//	  "seq": 0,                              // monotonic, per-session
//	  "started_at": "2026-06-01T15:30:00Z",  // RFC3339Nano
//	  "duration_ms": 42,                     // from request-received to response-sent
//	  "method": "POST",
//	  "url": "/api/v1/applications/foo/sync",
//	  "status": 200,
//	  "request": {
//	    "headers": { "user-agent": ["..."], ... },
//	    "body_b64": "...",                   // omitted if 0 bytes
//	    "body_bytes": 142,
//	    "truncated": false
//	  },
//	  "response": { ... },
//	  "remote_ip": "10.0.50.5"              // operator's WG IP
//	}
//
// Per-frame WebSocket capture (for upstreams with WS terminals like
// ArgoCD pod logs) ships as Phase 5h-3b — one frame per JSON line
// using a different "kind" discriminator.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPTransaction is one operator-request + upstream-response pair.
type HTTPTransaction struct {
	Kind       string      `json:"kind"` // always "http" — Phase 5h-3b WS frames use "ws"
	Seq        int64       `json:"seq"`
	StartedAt  time.Time   `json:"started_at"`
	DurationMs int64       `json:"duration_ms"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Status     int         `json:"status"`
	Request    HTTPMessage `json:"request"`
	Response   HTTPMessage `json:"response"`
	RemoteIP   string      `json:"remote_ip,omitempty"`
	// OperatorSub is the verified Falcon-ID subject of the operator
	// at the moment the request was proxied — duplicates the manifest
	// but is per-transaction so partial extracts still attribute.
	OperatorSub string `json:"operator_sub,omitempty"`
}

// HTTPMessage captures one direction of a transaction.
type HTTPMessage struct {
	Headers   http.Header `json:"headers,omitempty"`
	BodyB64   string      `json:"body_b64,omitempty"`
	BodyBytes int64       `json:"body_bytes"`
	Truncated bool        `json:"truncated,omitempty"`
}

// HTTPWriter is a recording.Writer that accepts HTTPTransaction structs
// and emits NDJSON to the underlying bundle io.WriteCloser. Safe for
// concurrent use by multiple proxy goroutines on the same session.
type HTTPWriter struct {
	w                io.WriteCloser
	enc              *json.Encoder
	mu               sync.Mutex
	seq              atomic.Int64
	maxBodyBytes     int64
	captureSensitive bool
	closed           atomic.Bool
}

// NewHTTPWriter wraps a bundle io.WriteCloser with the NDJSON encoder
// and the safety knobs. maxBodyBytes=0 → 64KiB default. Close on the
// returned writer SEALS the bundle (delegates to the underlying
// bundleWriter).
func NewHTTPWriter(w io.WriteCloser, maxBodyBytes int64, captureSensitive bool) *HTTPWriter {
	if maxBodyBytes <= 0 {
		maxBodyBytes = 64 * 1024
	}
	return &HTTPWriter{
		w:                w,
		enc:              json.NewEncoder(w),
		maxBodyBytes:     maxBodyBytes,
		captureSensitive: captureSensitive,
	}
}

// Record stamps + writes one transaction. Mutates t to fill Seq +
// StartedAt if zero; the proxy handler typically sets StartedAt
// explicitly so DurationMs is accurate.
func (h *HTTPWriter) Record(t HTTPTransaction) error {
	if h.closed.Load() {
		return io.ErrClosedPipe
	}
	if t.Seq == 0 {
		t.Seq = h.seq.Add(1)
	}
	if t.StartedAt.IsZero() {
		t.StartedAt = time.Now()
	}
	if t.Kind == "" {
		t.Kind = "http"
	}
	if !h.captureSensitive {
		t.Request.Headers = redactHeaders(t.Request.Headers)
		t.Response.Headers = redactHeaders(t.Response.Headers)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.enc.Encode(&t)
}

// MaxBodyBytes is the per-direction body capture cap. Callers (the
// proxy handler) use this to decide when to set Truncated=true.
func (h *HTTPWriter) MaxBodyBytes() int64 { return h.maxBodyBytes }

// Close seals the bundle (signs the manifest, commits to WORM).
func (h *HTTPWriter) Close() error {
	h.closed.Store(true)
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.w.Close()
}

// sensitiveHeaders are stripped unless captureSensitive is set.
// Lowercase comparison — Go's http.Header keys are canonicalised but
// we compare case-insensitively for safety.
var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"set-cookie":          {},
	"proxy-authorization": {},
	"x-csrf-token":        {},
	"x-api-key":           {},
}

func redactHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, v := range h {
		if _, sensitive := sensitiveHeaders[strings.ToLower(k)]; sensitive {
			out[k] = []string{"<redacted>"}
			continue
		}
		out[k] = v
	}
	return out
}
