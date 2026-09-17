// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
)

func TestJSONSinkHashChain(t *testing.T) {
	var buf bytes.Buffer
	s := NewJSONSink(&buf)
	for i := 0; i < 3; i++ {
		if err := s.Emit(context.Background(), Event{Action: "open", TargetID: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}

	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(lines))
	}

	prev := ""
	for i, ln := range lines {
		var ev Event
		if err := json.Unmarshal(ln, &ev); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if ev.Seq != uint64(i) {
			t.Errorf("line %d: seq = %d, want %d", i, ev.Seq, i)
		}
		if ev.PrevHash != prev {
			t.Errorf("line %d: prev_hash = %q, want %q (chain broken)", i, ev.PrevHash, prev)
		}
		sum := sha256.Sum256(append(append([]byte{}, ln...), '\n'))
		prev = hex.EncodeToString(sum[:])
	}

	// Tamper with line 0 → line 1's prev_hash no longer matches its hash.
	tampered := bytes.Replace(lines[0], []byte(`"target_id":"0"`), []byte(`"target_id":"x"`), 1)
	if bytes.Equal(tampered, lines[0]) {
		t.Fatal("test setup: tamper had no effect")
	}
	sum := sha256.Sum256(append(append([]byte{}, tampered...), '\n'))
	var ev1 Event
	_ = json.Unmarshal(lines[1], &ev1)
	if ev1.PrevHash == hex.EncodeToString(sum[:]) {
		t.Fatal("tampering line 0 should have broken the chain to line 1")
	}
}
