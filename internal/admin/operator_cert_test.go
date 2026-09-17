// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/pdp"
)

// mintTestCA creates a self-signed CA usable by NewCertSignerFromPEM.
func mintTestCA(t *testing.T) (caCertPEM, caKeyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jess-ca-test", Organization: []string{"HexxLock-Test"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// mintCSR generates an EC P-256 key + CSR with the supplied CN.
func mintCSR(t *testing.T, cn string) (csrPEM []byte, _ *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// TestCertSignerSignsValidCSR pins the signer's core contract:
//   - CSR signature is verified before signing
//   - Issued cert chains to the CA (verifies under x509.Verify)
//   - CN is OVERRIDDEN to the caller's verified subject (not what CSR claimed)
//   - ExtKeyUsage = clientAuth, KeyUsage = digSig+keyEnc
//   - NotAfter respects TTL ceiling.
func TestCertSignerSignsValidCSR(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, err := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := mintCSR(t, "what-the-operator-claimed")

	certPEM, err := signer.SignCSR(context.Background(), csrPEM, "verified-subject-uuid", "ops@example.com", 4*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("issued cert PEM is empty")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// CN binding — CSR's CN is dropped, caller subject is stamped in.
	if cert.Subject.CommonName != "verified-subject-uuid" {
		t.Errorf("CN=%q, want verified-subject-uuid (CSR's claimed CN MUST be ignored)", cert.Subject.CommonName)
	}
	if cert.Subject.CommonName == "what-the-operator-claimed" {
		t.Error("CSR's CN leaked into the issued cert — CRITICAL identity-binding failure")
	}
	if len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "ops@example.com" {
		t.Errorf("email=%v, want [ops@example.com]", cert.EmailAddresses)
	}

	// clientAuth EKU is the WHOLE POINT of an operator cert (RFC 8705 §2.1).
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage=%v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage missing DigitalSignature")
	}

	// Cert chains under the CA.
	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued cert fails to verify against CA: %v", err)
	}

	// TTL ceiling — 4h request stays at 4h (under the 8h ceiling).
	wantNotAfter := time.Now().Add(4 * time.Hour)
	if cert.NotAfter.Before(wantNotAfter.Add(-5*time.Minute)) || cert.NotAfter.After(wantNotAfter.Add(5*time.Minute)) {
		t.Errorf("NotAfter=%v, want ~%v", cert.NotAfter, wantNotAfter)
	}
}

// TestCertSignerEnforcesTTLCeiling — request 99h, get 8h.
func TestCertSignerEnforcesTTLCeiling(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, err := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := mintCSR(t, "x")
	certPEM, err := signer.SignCSR(context.Background(), csrPEM, "sub", "", 99*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	max := time.Now().Add(MaxOperatorCertTTL).Add(5 * time.Minute)
	if cert.NotAfter.After(max) {
		t.Errorf("TTL not capped: NotAfter=%v, ceiling=%v", cert.NotAfter, max)
	}
}

// TestCertSignerRejectsMalformedCSR catches the common "wrong PEM block" case.
func TestCertSignerRejectsMalformedCSR(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, _ := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	if _, err := signer.SignCSR(context.Background(), []byte("not a csr"), "sub", "", 0); err == nil {
		t.Error("malformed CSR should error")
	}
	// Wrong PEM type — passes pem.Decode but ParseCertificateRequest fails.
	garbage := pem.EncodeToMemory(&pem.Block{Type: "GARBAGE", Bytes: []byte{0xde, 0xad}})
	if _, err := signer.SignCSR(context.Background(), garbage, "sub", "", 0); err == nil {
		t.Error("garbage DER should error")
	}
}

// stubVerifier returns a pre-canned identity. Mirrors the pattern used by
// admin_test.go for the existing routes.
type stubVerifier struct{ id pdp.Identity }

func (s stubVerifier) Verify(_ context.Context, _ string) (pdp.Identity, error) {
	return s.id, nil
}

// TestCertHandlerSignsViaHTTP exercises the full POST /operator-cert flow:
// authn → role gate → sign → response shape.
func TestCertHandlerSignsViaHTTP(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, err := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, _ := mintCSR(t, "ignored-cn")

	verifier := stubVerifier{id: pdp.Identity{
		Subject: "04ad2960-3202-4718-833e-2d58c948b09d",
		Email:   "dogukanturhal@example.com",
		Roles:   []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, signer)

	body, _ := json.Marshal(OperatorCertRequest{CSR: string(csrPEM), TTLSeconds: 600})
	req := httptest.NewRequest(http.MethodPost, "/operator-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp OperatorCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.CertPEM, "BEGIN CERTIFICATE") {
		t.Errorf("cert_pem doesn't look like PEM: %q", resp.CertPEM[:80])
	}
	if !strings.Contains(resp.CAPEM, "BEGIN CERTIFICATE") {
		t.Error("ca_pem missing — CLI needs this for first-time setup")
	}
}

func TestCertHandlerRejectsMissingRole(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, _ := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	csrPEM, _ := mintCSR(t, "x")

	verifier := stubVerifier{id: pdp.Identity{
		Subject: "u",
		Roles:   []string{"some_other_role"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, signer)

	body, _ := json.Marshal(OperatorCertRequest{CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/operator-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin should get 403, got %d", rec.Code)
	}
}

func TestCertHandlerUnconfiguredReturns503(t *testing.T) {
	verifier := stubVerifier{id: pdp.Identity{
		Subject: "u",
		Roles:   []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, nil) // signer omitted

	csrPEM, _ := mintCSR(t, "x")
	body, _ := json.Marshal(OperatorCertRequest{CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/operator-cert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured endpoint should 503, got %d", rec.Code)
	}
}

// fakeRevoker captures revoke calls for handler-level tests. Pretends the
// active Signer also implements Revoker (the VaultSigner does in prod;
// LocalSigner doesn't, which the 501-fallback path tests separately).
type fakeRevoker struct {
	Signer
	gotSerial string
	err       error
}

func (f *fakeRevoker) RevokeSerial(_ context.Context, serial string) error {
	f.gotSerial = serial
	return f.err
}

// TestCertHandlerRevokeNormalisesAndCalls verifies:
//   - the colons-and-mixed-case serial form the operator pastes from
//     `openssl x509 -serial` is normalised to lower-colon form
//   - the verified Falcon-ID subject + admin role gate is enforced
//   - the response echoes the normalised serial + a server timestamp.
func TestCertHandlerRevokeNormalisesAndCalls(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	localSigner, _ := NewCertSignerFromPEM(caCertPEM, caKeyPEM)
	rev := &fakeRevoker{Signer: localSigner}

	verifier := stubVerifier{id: pdp.Identity{
		Subject: "verified-sub-uuid", Email: "ops@example.com",
		Roles: []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, rev)

	// openssl pastes serial as upper-case hex with colons; verify normalise.
	in := OperatorCertRevokeRequest{Serial: "4B:95:F9:03:71:32:dc:80"}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/operator-cert/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	wantSerial := "4b:95:f9:03:71:32:dc:80"
	if rev.gotSerial != wantSerial {
		t.Errorf("backend got serial=%q, want %q (normalised lower-hex colon form)", rev.gotSerial, wantSerial)
	}
	var resp OperatorCertRevokeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Serial != wantSerial {
		t.Errorf("response.Serial = %q, want %q", resp.Serial, wantSerial)
	}
	if resp.RevokedAt.IsZero() {
		t.Error("response.RevokedAt is zero — server-side timestamp missing")
	}
}

// TestCertHandlerRevokeRejectsNonAdmin pins the role-gate. Non-admins
// presenting a valid token must NOT be able to revoke (only the
// platform_admin role can).
func TestCertHandlerRevokeRejectsNonAdmin(t *testing.T) {
	rev := &fakeRevoker{}
	verifier := stubVerifier{id: pdp.Identity{
		Subject: "u", Roles: []string{"some_other_role"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, rev)

	body, _ := json.Marshal(OperatorCertRevokeRequest{Serial: "ab:cd"})
	req := httptest.NewRequest(http.MethodPost, "/operator-cert/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin should get 403, got %d", rec.Code)
	}
	if rev.gotSerial != "" {
		t.Errorf("backend should NOT have been called; got serial=%q", rev.gotSerial)
	}
}

// TestCertHandlerRevokeReturns501OnLocalSigner pins the contract: when
// the active signer is the file-mount LocalSigner (no Revoker interface),
// /operator-cert/revoke MUST return 501 Not Implemented — not crash, not
// silently succeed.
func TestCertHandlerRevokeReturns501OnLocalSigner(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, _ := NewCertSignerFromPEM(caCertPEM, caKeyPEM) // LocalSigner: no Revoker
	verifier := stubVerifier{id: pdp.Identity{
		Subject: "admin", Roles: []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, signer)

	body, _ := json.Marshal(OperatorCertRevokeRequest{Serial: "ab:cd"})
	req := httptest.NewRequest(http.MethodPost, "/operator-cert/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("LocalSigner (no Revoker) should give 501, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestCertHandlerRevokeBadSerial pins input validation: non-hex chars or
// odd-length hex must 400 before reaching the backend.
func TestCertHandlerRevokeBadSerial(t *testing.T) {
	rev := &fakeRevoker{}
	verifier := stubVerifier{id: pdp.Identity{
		Subject: "admin", Roles: []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, rev)

	cases := []struct {
		name, serial string
	}{
		{"empty", ""},
		{"non-hex", "zzz:nope"},
		{"odd-length-hex", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(OperatorCertRevokeRequest{Serial: tc.serial})
			req := httptest.NewRequest(http.MethodPost, "/operator-cert/revoke", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer t")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for serial=%q, got %d", tc.serial, rec.Code)
			}
		})
	}
	if rev.gotSerial != "" {
		t.Errorf("backend should not have been called for bad inputs; got %q", rev.gotSerial)
	}
}

// TestNormaliseSerialRoundtrip pins the helper's contract for the formats
// operators paste from openssl x509 -serial / Vault audit logs / hex.
func TestNormaliseSerialRoundtrip(t *testing.T) {
	cases := []struct{ in, want string }{
		{"4b:95:f9:03", "4b:95:f9:03"},
		{"4B:95:F9:03", "4b:95:f9:03"},
		{"4b95f903", "4b:95:f9:03"},
		{"4B 95 F9 03", "4b:95:f9:03"},
		{"", ""},
		{"zz", ""},  // non-hex
		{"abc", ""}, // odd length
		{"deadbeef", "de:ad:be:ef"},
	}
	for _, tc := range cases {
		got := normaliseSerial(tc.in)
		if got != tc.want {
			t.Errorf("normaliseSerial(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCertHandlerFallsThroughToRequestsAndGrants pins the dispatch order:
// non-/operator-cert paths reach the requests/grants handlers untouched.
func TestCertHandlerFallsThroughToRequestsAndGrants(t *testing.T) {
	caCertPEM, caKeyPEM := mintTestCA(t)
	signer, _ := NewCertSignerFromPEM(caCertPEM, caKeyPEM)

	verifier := stubVerifier{id: pdp.Identity{
		Subject: "u",
		Roles:   []string{"platform_admin"},
	}}
	base := New(nil, verifier, "platform_admin")
	requests := NewRequests(base, nil)
	handler := NewCert(requests, signer)

	// /unknown should land at the base /grants 404 path, not 503.
	req := httptest.NewRequest(http.MethodGet, "/totally-not-a-route", nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("non-cert route should fall through to base 404, got %d", rec.Code)
	}
}
