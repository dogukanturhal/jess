// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// nopWC adapts a *bytes.Buffer to an io.WriteCloser (the HTTPWriter
// closes its underlying writer; the test wants to inspect bytes after).
type nopWC struct{ *bytes.Buffer }

func (nopWC) Close() error { return nil }

func TestHTTPWriter_RedactsSensitiveHeaders_ByDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTTPWriter(nopWC{buf}, 0, false)
	err := w.Record(HTTPTransaction{
		Method: "GET",
		URL:    "/api/v1/foo",
		Status: 200,
		Request: HTTPMessage{
			Headers: http.Header{
				"Authorization": []string{"Bearer secret-token"},
				"Cookie":        []string{"session=secret"},
				"User-Agent":    []string{"curl/8.0"},
			},
		},
		Response: HTTPMessage{
			Headers: http.Header{
				"Set-Cookie":   []string{"sid=abc"},
				"Content-Type": []string{"application/json"},
			},
		},
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	out := buf.String()
	if contains(out, "secret-token") || contains(out, "session=secret") || contains(out, "sid=abc") {
		t.Fatalf("sensitive header leaked into recording:\n%s", out)
	}
	// JSON encoder HTML-escapes < and > to < / > — check for
	// the inner "redacted" token rather than the bracketed literal.
	if !contains(out, "redacted") {
		t.Fatalf("expected redacted marker, got:\n%s", out)
	}
	if !contains(out, "curl/8.0") || !contains(out, "application/json") {
		t.Fatalf("non-sensitive header was incorrectly redacted:\n%s", out)
	}
}

func TestHTTPWriter_PreservesSensitiveHeaders_WhenOptIn(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTTPWriter(nopWC{buf}, 0, true) // captureSensitive=true
	_ = w.Record(HTTPTransaction{
		Method: "GET", URL: "/x", Status: 200,
		Request: HTTPMessage{
			Headers: http.Header{"Authorization": []string{"Bearer X"}},
		},
	})
	if !contains(buf.String(), "Bearer X") {
		t.Fatalf("opt-in capture missing the secret:\n%s", buf.String())
	}
}

func TestHTTPWriter_AssignsMonotonicSeq(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewHTTPWriter(nopWC{buf}, 0, false)
	for i := 0; i < 5; i++ {
		_ = w.Record(HTTPTransaction{Method: "GET", URL: "/", Status: 200})
	}
	// Decode each line and verify seq increments.
	dec := json.NewDecoder(buf)
	var prev int64
	for i := 0; i < 5; i++ {
		var tx HTTPTransaction
		if err := dec.Decode(&tx); err != nil {
			t.Fatalf("decode[%d]: %v", i, err)
		}
		if tx.Seq != prev+1 {
			t.Fatalf("seq[%d] = %d, want %d", i, tx.Seq, prev+1)
		}
		if tx.Kind != "http" {
			t.Fatalf("default kind = %q, want \"http\"", tx.Kind)
		}
		prev = tx.Seq
	}
}

func TestHTTPWriter_RejectsRecordAfterClose(t *testing.T) {
	w := NewHTTPWriter(nopWC{&bytes.Buffer{}}, 0, false)
	_ = w.Close()
	err := w.Record(HTTPTransaction{Method: "GET", URL: "/", Status: 200})
	if err != io.ErrClosedPipe {
		t.Fatalf("post-close Record err = %v, want ErrClosedPipe", err)
	}
}

func TestExt_HTTPNDJSON(t *testing.T) {
	if got := ext(FormatHTTPNDJSON); got != "ndjson" {
		t.Fatalf("ext(FormatHTTPNDJSON) = %q, want %q", got, "ndjson")
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}
