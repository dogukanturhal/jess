// SPDX-License-Identifier: AGPL-3.0-or-later

package tunnel

import (
	"bytes"
	"testing"
)

// FuzzReadHeader fuzzes the session-header parser, which reads untrusted bytes
// off the wire. It must never panic — only return a header or an error
// (ADR 0030 security hardening: fuzz every parser that touches untrusted input).
// Run active fuzzing with: go test -run=x -fuzz=FuzzReadHeader ./internal/tunnel/
func FuzzReadHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})            // valid empty-object header
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3}) // absurd length
	f.Add([]byte{0, 0, 0, 5, '{', 'x'})            // truncated body
	f.Add([]byte{})                                // empty
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readHeader(bytes.NewReader(data)) // must not panic
	})
}
