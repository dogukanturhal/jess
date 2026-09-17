// SPDX-License-Identifier: AGPL-3.0-or-later

package azure

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dogukanturhal/jess/internal/attestation"
)

const fakeRootPEM = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUFakeRootForTests000000000000000000=
-----END CERTIFICATE-----`

func TestNew_RequiresRoots(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Errorf("New(nil) should reject empty roots")
	}
	if _, err := New([]byte{}); err == nil {
		t.Errorf("New(empty) should reject empty roots")
	}
}

func TestVerifier_Provenance(t *testing.T) {
	v, _ := New([]byte(fakeRootPEM))
	if v.Provenance() != attestation.ProvenanceAzure {
		t.Errorf("Provenance() = %q, want azure", v.Provenance())
	}
}

func TestVerifier_RejectsBadEnvelope(t *testing.T) {
	v, _ := New([]byte(fakeRootPEM))
	_, err := v.Verify(context.Background(), []byte("not json"))
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected ErrVerification; got %v", err)
	}
}

func TestVerifier_RejectsWrongEncoding(t *testing.T) {
	v, _ := New([]byte(fakeRootPEM))
	envelope, _ := json.Marshal(Presentation{Encoding: "jwt", Signature: []byte("xx")})
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected ErrVerification on encoding=jwt; got %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported encoding") {
		t.Errorf("err = %v, expected 'unsupported encoding'", err)
	}
}

func TestVerifier_RejectsMissingSignature(t *testing.T) {
	v, _ := New([]byte(fakeRootPEM))
	envelope, _ := json.Marshal(Presentation{Encoding: "pkcs7", Signature: nil})
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected ErrVerification on empty signature; got %v", err)
	}
}

func TestVerifier_ScaffoldReturnsNotImplemented(t *testing.T) {
	// Phase 7g-1: even a well-formed envelope must fail-closed
	// because the PKCS#7 + chain validation isn't implemented yet.
	v, _ := New([]byte(fakeRootPEM))
	envelope, _ := json.Marshal(Presentation{
		Encoding:  "pkcs7",
		Signature: []byte("any-bytes-here"),
	})
	_, err := v.Verify(context.Background(), envelope)
	if !errors.Is(err, attestation.ErrVerification) {
		t.Errorf("expected ErrVerification (scaffold path); got %v", err)
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("err = %v, expected 'not yet implemented'", err)
	}
}
