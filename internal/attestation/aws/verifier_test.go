// SPDX-License-Identifier: AGPL-3.0-or-later

package aws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/attestation"
)

// signFixture builds a valid {document, signature} envelope using a
// test key. Test-only — production never sees synthesized envelopes.
func signFixture(t *testing.T, key *rsa.PrivateKey, doc identityDocument) []byte {
	t.Helper()
	docJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	hash := sha256.Sum256(docJSON)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope, err := json.Marshal(Presentation{DocumentJSON: docJSON, Signature: sig})
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return envelope
}

func newTestVerifier(t *testing.T, key *rsa.PrivateKey, region string) *Verifier {
	t.Helper()
	return NewWithKeys(map[string]*rsa.PublicKey{region: &key.PublicKey}, DefaultMaxDocumentAge)
}

func TestVerifier_HappyPath(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "us-east-1")
	envelope := signFixture(t, key, identityDocument{
		AccountID:    "012345678901",
		InstanceID:   "i-0abcdef1234567890",
		Region:       "us-east-1",
		Architecture: "x86_64",
		ImageID:      "ami-12345",
		PendingTime:  time.Now().Add(-1 * time.Minute),
	})
	got, err := v.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.AccountID != "012345678901" || got.InstanceID != "i-0abcdef1234567890" {
		t.Errorf("claims mismatch: %+v", got)
	}
	if got.Provenance != attestation.ProvenanceAWS {
		t.Errorf("provenance = %q, want aws", got.Provenance)
	}
	if got.Extras["architecture"] != "x86_64" {
		t.Errorf("extras lost: %+v", got.Extras)
	}
}

func TestVerifier_RejectsTamperedDocument(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "us-east-1")
	envelope := signFixture(t, key, identityDocument{
		AccountID: "012345678901", InstanceID: "i-aaa", Region: "us-east-1",
		PendingTime: time.Now().Add(-1 * time.Minute),
	})
	// Bit-flip the envelope after signing.
	var pres Presentation
	_ = json.Unmarshal(envelope, &pres)
	tampered := append([]byte{}, pres.DocumentJSON...)
	tampered[10] ^= 0x01
	pres.DocumentJSON = tampered
	envelope, _ = json.Marshal(pres)

	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected ErrVerification on tamper; got %v", err)
	}
}

func TestVerifier_RejectsWrongRegionKey(t *testing.T) {
	usEast, _ := rsa.GenerateKey(rand.Reader, 2048)
	euWest, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Verifier trusts only us-east-1 — signed by us-east-1 but claims eu-west-1.
	v := newTestVerifier(t, usEast, "us-east-1")
	envelope := signFixture(t, usEast, identityDocument{
		AccountID: "x", InstanceID: "y", Region: "eu-west-1",
		PendingTime: time.Now().Add(-1 * time.Minute),
	})
	_ = euWest // unused — we want the cross-region rejection
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected reject on unknown region; got %v", err)
	}
	if !strings.Contains(err.Error(), "no public key for region") {
		t.Errorf("err = %v, expected 'no public key' text", err)
	}
}

func TestVerifier_RejectsExpiredDocument(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "us-east-1")
	v.MaxDocumentAge = 1 * time.Minute
	envelope := signFixture(t, key, identityDocument{
		AccountID: "x", InstanceID: "y", Region: "us-east-1",
		PendingTime: time.Now().Add(-10 * time.Minute), // 10min old > 1min limit
	})
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected reject on expired; got %v", err)
	}
	if !strings.Contains(err.Error(), "old") {
		t.Errorf("err = %v, expected 'old' text", err)
	}
}

func TestVerifier_RejectsEmptyEnvelope(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "us-east-1")
	cases := [][]byte{
		[]byte(`{}`),
		[]byte(`{"document": "", "signature": ""}`),
		[]byte(`not json`),
	}
	for _, c := range cases {
		_, err := v.Verify(context.Background(), c)
		if !errors.Is(err, attestation.ErrVerification) {
			t.Errorf("expected reject on %q; got %v", c, err)
		}
	}
}

func TestVerifier_RejectsMissingRegionInDocument(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := newTestVerifier(t, key, "us-east-1")
	envelope := signFixture(t, key, identityDocument{
		AccountID: "x", InstanceID: "y", Region: "",
		PendingTime: time.Now().Add(-1 * time.Minute),
	})
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected reject on empty region; got %v", err)
	}
}

func TestNew_FailsWithoutEmbeddedKeys(t *testing.T) {
	// The intentional shipping state — no embedded keys, so New()
	// succeeds (returns an empty map). The first verify attempt then
	// fails with "no public key for region X" — the fail-closed posture.
	v, err := New(0)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if len(v.PubKeys) != 0 {
		t.Errorf("PubKeys = %d, want 0 (intentional empty shipping state)", len(v.PubKeys))
	}
	// A presentation against any region must fail-closed.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	envelope := signFixture(t, key, identityDocument{
		AccountID: "x", InstanceID: "y", Region: "us-east-1",
		PendingTime: time.Now().Add(-1 * time.Minute),
	})
	_, err = v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected reject (empty keys); got %v", err)
	}
}

func TestVerifier_Provenance(t *testing.T) {
	v := &Verifier{}
	if v.Provenance() != attestation.ProvenanceAWS {
		t.Errorf("Provenance() = %q, want aws", v.Provenance())
	}
}
