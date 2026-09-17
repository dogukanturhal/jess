// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation

import (
	"context"
	"errors"
	"testing"
)

type fakeVerifier struct {
	prov Provenance
	doc  Document
	err  error
}

func (f fakeVerifier) Provenance() Provenance { return f.prov }
func (f fakeVerifier) Verify(_ context.Context, _ []byte) (Document, error) {
	return f.doc, f.err
}

func TestRegistry_Dispatch(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeVerifier{prov: ProvenanceAWS, doc: Document{AccountID: "aws"}})
	r.Register(fakeVerifier{prov: ProvenanceAzure, doc: Document{AccountID: "azure"}})

	if got := r.VerifierFor(ProvenanceAWS); got == nil {
		t.Fatal("AWS verifier missing after Register")
	}
	if got := r.VerifierFor(ProvenanceGCP); got != nil {
		t.Errorf("GCP should be nil (not registered); got %+v", got)
	}
}

func TestRegistry_OverwriteOnDoubleRegister(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeVerifier{prov: ProvenanceAWS, doc: Document{AccountID: "first"}})
	r.Register(fakeVerifier{prov: ProvenanceAWS, doc: Document{AccountID: "second"}})
	doc, err := r.VerifierFor(ProvenanceAWS).Verify(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if doc.AccountID != "second" {
		t.Errorf("second Register didn't overwrite first: got %q", doc.AccountID)
	}
}

func TestRegistry_Enabled(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeVerifier{prov: ProvenanceAWS})
	r.Register(fakeVerifier{prov: ProvenanceAzure})
	got := r.Enabled()
	if len(got) != 2 {
		t.Fatalf("Enabled() = %d entries, want 2", len(got))
	}
	have := map[Provenance]bool{}
	for _, p := range got {
		have[p] = true
	}
	if !have[ProvenanceAWS] || !have[ProvenanceAzure] {
		t.Errorf("missing entries: %v", got)
	}
}

func TestErrVerification_IsAssertion(t *testing.T) {
	// Wrappers should still match errors.Is(err, ErrVerification).
	wrapped := errors.New("not a wrap")
	if errors.Is(wrapped, ErrVerification) {
		t.Errorf("plain error should not be ErrVerification")
	}
	v := fakeVerifier{prov: ProvenanceAWS, err: ErrVerification}
	_, err := v.Verify(context.Background(), nil)
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected errors.Is(err, ErrVerification) true; got %v", err)
	}
}
