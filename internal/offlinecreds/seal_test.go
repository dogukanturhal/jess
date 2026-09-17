// SPDX-License-Identifier: AGPL-3.0-or-later

package offlinecreds

import (
	"bytes"
	"testing"
)

// TestSealRoundTrip: seal→open returns the exact plaintext, and two seals of the
// same plaintext differ (fresh nonce per call).
func TestSealRoundTrip(t *testing.T) {
	s, err := NewEphemeralSealer()
	if err != nil {
		t.Fatalf("NewEphemeralSealer: %v", err)
	}
	pt := []byte(`{"Username":"v-ldap-eph","Password":"s3cret","Domain":"HEXXLOCK"}`)
	a, err := s.Seal(pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := s.Seal(pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (nonce reuse)")
	}
	if bytes.Contains(a, []byte("s3cret")) {
		t.Fatal("sealed blob must not contain the plaintext secret")
	}
	got, err := s.Open(a)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
	}
}

// TestSealTamperAndWrongKeyFailClosed: a mutated blob and a wrong-key open both
// fail (authenticated encryption), so a caller can never trust unverified bytes.
func TestSealTamperAndWrongKeyFailClosed(t *testing.T) {
	s, _ := NewEphemeralSealer()
	sealed, _ := s.Seal([]byte("credential"))

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := s.Open(tampered); err == nil {
		t.Fatal("Open of a tampered blob must fail")
	}

	other, _ := NewEphemeralSealer()
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("Open with the wrong key must fail")
	}

	if _, err := s.Open([]byte("short")); err == nil {
		t.Fatal("Open of a truncated blob must fail")
	}
}

// TestNewSealerRejectsBadKeyLength: only a 32-byte key is accepted.
func TestNewSealerRejectsBadKeyLength(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("NewSealer must reject a 16-byte key")
	}
	if _, err := NewSealer(make([]byte, KeySize)); err != nil {
		t.Fatalf("NewSealer(32 bytes): %v", err)
	}
}
