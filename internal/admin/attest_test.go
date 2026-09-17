// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/attestation"
	awsverifier "github.com/dogukanturhal/jess/internal/attestation/aws"
	"github.com/dogukanturhal/jess/internal/audit"
	"github.com/dogukanturhal/jess/internal/pdp"
)

type collectingSink struct {
	events []audit.Event
}

func (c *collectingSink) Emit(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}
func (c *collectingSink) Close() error { return nil }

func TestAttestHandler_HappyPath(t *testing.T) {
	// Build a real AWS verifier wired with a test key, then a
	// matching signed envelope, and POST it through the handler.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := awsverifier.NewWithKeys(map[string]*rsa.PublicKey{"us-east-1": &key.PublicKey}, 10*time.Minute)
	reg := attestation.NewRegistry()
	reg.Register(v)

	// Build the signed envelope inline (same shape as
	// internal/attestation/aws/verifier_test.go).
	doc := map[string]any{
		"accountId":   "012345678901",
		"instanceId":  "i-0abc",
		"region":      "us-east-1",
		"pendingTime": time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339Nano),
	}
	docJSON, _ := json.Marshal(doc)
	hash := sha256.Sum256(docJSON)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	envelope, _ := json.Marshal(awsverifier.Presentation{DocumentJSON: docJSON, Signature: sig})

	sink := &collectingSink{}
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, sink)
	req := AttestRequest{
		Provenance:   "aws",
		Presentation: base64.StdEncoding.EncodeToString(envelope),
	}
	body, _ := json.Marshal(req)
	r := bearerReq(http.MethodPost, "/admin/attest", string(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp AttestResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.AccountID != "012345678901" || resp.InstanceID != "i-0abc" {
		t.Errorf("decoded resp wrong: %+v", resp)
	}
	if resp.Region != "us-east-1" {
		t.Errorf("region = %q", resp.Region)
	}
	// Audit row stamped attest.ok
	if len(sink.events) != 1 || sink.events[0].Action != "attest.ok" {
		t.Errorf("audit events = %+v", sink.events)
	}
}

func TestAttestHandler_RejectsNonAdmin(t *testing.T) {
	reg := attestation.NewRegistry()
	h := mkAttestHandler(t, pdp.Identity{Subject: "bob", Roles: []string{"viewer"}}, reg, &collectingSink{})
	body, _ := json.Marshal(AttestRequest{Provenance: "aws", Presentation: "Zm9v"})
	r := bearerReq(http.MethodPost, "/admin/attest", string(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAttestHandler_RejectsUnknownProvenance(t *testing.T) {
	reg := attestation.NewRegistry() // empty — no verifiers
	sink := &collectingSink{}
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, sink)
	body, _ := json.Marshal(AttestRequest{Provenance: "aws", Presentation: "Zm9v"})
	r := bearerReq(http.MethodPost, "/admin/attest", string(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	// Audit row stamps the rejection.
	if len(sink.events) != 1 || sink.events[0].Action != "attest.deny" {
		t.Errorf("audit events = %+v", sink.events)
	}
}

func TestAttestHandler_RejectsBadBase64(t *testing.T) {
	reg := attestation.NewRegistry()
	reg.Register(&fakeOKVerifier{prov: attestation.ProvenanceAWS})
	sink := &collectingSink{}
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, sink)
	body, _ := json.Marshal(AttestRequest{Provenance: "aws", Presentation: "not-base64-!!"})
	r := bearerReq(http.MethodPost, "/admin/attest", string(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAttestHandler_VerificationFailure401(t *testing.T) {
	reg := attestation.NewRegistry()
	reg.Register(&fakeFailVerifier{prov: attestation.ProvenanceAWS})
	sink := &collectingSink{}
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, sink)
	body, _ := json.Marshal(AttestRequest{
		Provenance:   "aws",
		Presentation: base64.StdEncoding.EncodeToString([]byte(`{"document": "x", "signature": "y"}`)),
	})
	r := bearerReq(http.MethodPost, "/admin/attest", string(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (ErrVerification)", w.Code)
	}
	if len(sink.events) != 1 || sink.events[0].Action != "attest.deny" {
		t.Errorf("audit events = %+v", sink.events)
	}
	if !strings.Contains(sink.events[0].Err, "synthetic verify fail") {
		t.Errorf("audit reason missing: %+v", sink.events[0])
	}
}

func TestAttestHandler_FallsThroughForNonAttestPath(t *testing.T) {
	reg := attestation.NewRegistry()
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, &collectingSink{})
	r := bearerReq(http.MethodGet, "/grants", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("fall-through 404 expected; got %d", w.Code)
	}
}

func TestAttestHandler_RejectsMissingFields(t *testing.T) {
	reg := attestation.NewRegistry()
	reg.Register(&fakeOKVerifier{prov: attestation.ProvenanceAWS})
	h := mkAttestHandler(t, pdp.Identity{Subject: "alice", Roles: []string{"platform_admin"}}, reg, &collectingSink{})
	cases := []AttestRequest{
		{}, // both empty
		{Provenance: "aws"},
		{Presentation: "Zm9v"},
	}
	for _, c := range cases {
		body, _ := json.Marshal(c)
		r := bearerReq(http.MethodPost, "/admin/attest", string(body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("case %+v: status = %d, want 400", c, w.Code)
		}
	}
}

// ---- helpers --------------------------------------------------------

func mkAttestHandler(t *testing.T, id pdp.Identity, reg *attestation.Registry, sink audit.Sink) *AttestHandler {
	t.Helper()
	base := New(&fakeStore{}, &fakeVerifier{id: id}, "platform_admin")
	notFound := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return NewAttest(notFound, base, reg, sink)
}

type fakeOKVerifier struct{ prov attestation.Provenance }

func (f *fakeOKVerifier) Provenance() attestation.Provenance { return f.prov }
func (f *fakeOKVerifier) Verify(_ context.Context, _ []byte) (attestation.Document, error) {
	return attestation.Document{Provenance: f.prov, AccountID: "test", InstanceID: "i-test"}, nil
}

type fakeFailVerifier struct{ prov attestation.Provenance }

func (f *fakeFailVerifier) Provenance() attestation.Provenance { return f.prov }
func (f *fakeFailVerifier) Verify(_ context.Context, _ []byte) (attestation.Document, error) {
	return attestation.Document{}, errSyntheticVerify
}

var errSyntheticVerify = errVerifyWrap("synthetic verify fail")

func errVerifyWrap(msg string) error {
	return &wrappedVerifyErr{msg: msg}
}

type wrappedVerifyErr struct{ msg string }

func (e *wrappedVerifyErr) Error() string { return "attestation: verification failed: " + e.msg }
func (e *wrappedVerifyErr) Is(target error) bool {
	return target == attestation.ErrVerification
}
