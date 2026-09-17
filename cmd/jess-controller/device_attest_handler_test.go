// SPDX-License-Identifier: AGPL-3.0-or-later

package main

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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/pdp"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// --- Test doubles ---

// stubTokenVerifier is a test-only pdp.TokenVerifier.
type stubTokenVerifier struct {
	identity pdp.Identity
	err      error
}

func (v *stubTokenVerifier) Verify(_ context.Context, _ string) (pdp.Identity, error) {
	return v.identity, v.err
}

// stubVerifier is a test-only deviceattest.Verifier.
type stubVerifier struct {
	resp deviceattest.VerifyResponse
	err  error
}

func (v *stubVerifier) Verify(_ context.Context, _ deviceattest.VerifyRequest) (deviceattest.VerifyResponse, error) {
	return v.resp, v.err
}

// stubVaultPKISigner is an httptest.Server that mimics Vault's
// POST /v1/<mount>/sign/<role> endpoint.
// It returns a hard-coded signed cert PEM in Vault's JSON envelope.
type stubVaultPKISigner struct {
	srv       *httptest.Server
	callCount int
	forceErr  bool
}

func newStubVaultPKISigner(t *testing.T) *stubVaultPKISigner {
	t.Helper()
	s := &stubVaultPKISigner{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.callCount++
		if s.forceErr {
			http.Error(w, `{"errors":["backend error"]}`, http.StatusInternalServerError)
			return
		}
		// Minimal Vault PKI sign response.
		type vaultData struct {
			Certificate  string   `json:"certificate"`
			IssuingCA    string   `json:"issuing_ca"`
			CAChain      []string `json:"ca_chain"`
			SerialNumber string   `json:"serial_number"`
			Expiration   int64    `json:"expiration"`
		}
		type vaultResp struct {
			Data vaultData `json:"data"`
		}
		resp := vaultResp{
			Data: vaultData{
				Certificate:  "-----BEGIN CERTIFICATE-----\nMIIFakeDeviceCert\n-----END CERTIFICATE-----\n",
				IssuingCA:    "-----BEGIN CERTIFICATE-----\nMIIFakeCA\n-----END CERTIFICATE-----\n",
				SerialNumber: "01:02:03:04",
				Expiration:   1800000000, // 2027 — stable future timestamp
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return s
}

// newTestVaultClient constructs a vaultx.Client pointing at the stub server.
func newTestVaultClient(t *testing.T, s *stubVaultPKISigner) *vaultx.Client {
	t.Helper()
	c, err := vaultx.New(vaultx.Config{
		Addr:  s.srv.URL,
		Token: "test-vault-token",
	})
	if err != nil {
		t.Fatalf("construct test vault client: %v", err)
	}
	return c
}

// --- Helper builders ---

// buildRegistry builds a minimal Registry with the given platform mapped to
// the given verifier.
func buildRegistry(platform string, v deviceattest.Verifier) *deviceattest.Registry {
	reg := deviceattest.NewRegistry()
	reg.Register(platform, v)
	return reg
}

// testEKAndCSR generates a real EC P-256 device key and returns its PKIX
// public-key PEM (the "EK") plus a self-signed PKCS#10 CSR carrying that same
// key — the shape the handler now requires (cert bound to the device key).
func testEKAndCSR(t *testing.T) (ekPubPEM, csrPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	ekPubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device"},
	}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return ekPubPEM, csrPEM
}

// validBody returns a minimal valid AttestRequest JSON body for the given platform.
func validBody(t *testing.T, platform string) []byte {
	ek, csr := testEKAndCSR(t)
	req := AttestRequest{
		Platform:    platform,
		DeviceUUID:  "aaaabbbb-1111-4111-8111-ccccddddeeee",
		EKPubKeyPEM: ek,
		CSRPEM:      csr,
		NonceClient: []byte("nonce"),
	}
	b, _ := json.Marshal(req)
	return b
}

// validBodyWithWitness returns a valid AttestRequest for Path B with a witness.
func validBodyWithWitness(t *testing.T, platform string) []byte {
	ek, csr := testEKAndCSR(t)
	req := AttestRequest{
		Platform:    platform,
		DeviceUUID:  "aaaabbbb-1111-4111-8111-ccccddddeeee",
		EKPubKeyPEM: ek,
		CSRPEM:      csr,
		NonceClient: []byte("nonce"),
		Witness: &AttestWitnessRequest{
			AdminSub:  "ops_alice",
			SignedJWS: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJvcHNfYWxpY2UifQ.sig",
			IssuedAt:  "2026-06-07T12:00:00Z",
		},
	}
	b, _ := json.Marshal(req)
	return b
}

// --- Test cases ---

// TestDeviceCertAttestHandler_HappyPath_PathA tests a successful Path A
// (chain) attestation resulting in a minted TIER_CORP device cert.
func TestDeviceCertAttestHandler_HappyPath_PathA(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	verifier := &stubTokenVerifier{
		identity: pdp.Identity{Subject: "usr_test01"},
	}
	attVerifier := &stubVerifier{
		resp: deviceattest.VerifyResponse{
			Path:    "A_chain",
			Tier:    "TIER_CORP",
			Reasons: []string{"ek_chain_verified", "issuer_infineon_optiga_tpm_rsa_ca"},
		},
	}

	reg := buildRegistry("tpm2-linux", attVerifier)
	vc := newTestVaultClient(t, vaultStub)
	handler := NewDeviceCertAttestHandler(http.NotFoundHandler(), verifier, reg, vc)

	body := validBody(t, "tpm2-linux")
	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-id-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp AttestResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Path != "A_chain" {
		t.Errorf("expected path=A_chain, got %q", resp.Path)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("expected tier=TIER_CORP, got %q", resp.Tier)
	}
	if !strings.HasPrefix(resp.DeviceCertPEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected cert PEM, got: %q", resp.DeviceCertPEM)
	}
	if resp.SerialNumber == "" {
		t.Error("expected non-empty serial_number")
	}
	if vaultStub.callCount != 1 {
		t.Errorf("expected 1 Vault PKI call, got %d", vaultStub.callCount)
	}
}

// TestDeviceCertAttestHandler_HappyPath_PathB tests a successful Path B
// (TOFU) attestation resulting in a minted TIER_BYOD device cert.
func TestDeviceCertAttestHandler_HappyPath_PathB(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	verifier := &stubTokenVerifier{
		identity: pdp.Identity{Subject: "usr_byod_user"},
	}
	attVerifier := &stubVerifier{
		resp: deviceattest.VerifyResponse{
			Path:    "B_tofu",
			Tier:    "TIER_BYOD",
			Reasons: []string{"path_b_tofu_enrollment", "witness_ops_alice"},
		},
	}

	reg := buildRegistry("tpm2-linux", attVerifier)
	vc := newTestVaultClient(t, vaultStub)
	handler := NewDeviceCertAttestHandler(http.NotFoundHandler(), verifier, reg, vc)

	body := validBodyWithWitness(t, "tpm2-linux")
	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-id-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp AttestResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Tier != "TIER_BYOD" {
		t.Errorf("expected tier=TIER_BYOD, got %q", resp.Tier)
	}
}

// TestDeviceCertAttestHandler_MissingToken tests that the handler returns 401
// when no Authorization header is present.
func TestDeviceCertAttestHandler_MissingToken(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{err: errors.New("no token")},
		buildRegistry("tpm2-linux", &stubVerifier{}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(validBody(t, "tpm2-linux")))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceCertAttestHandler_InvalidToken tests that the handler returns 401
// when the Falcon-ID token verification fails.
func TestDeviceCertAttestHandler_InvalidToken(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{err: fmt.Errorf("signature invalid")},
		buildRegistry("tpm2-linux", &stubVerifier{}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(validBody(t, "tpm2-linux")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer bad-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceCertAttestHandler_BadJSON tests that the handler returns 400
// on malformed JSON in the request body.
func TestDeviceCertAttestHandler_BadJSON(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{identity: pdp.Identity{Subject: "usr_test"}},
		buildRegistry("tpm2-linux", &stubVerifier{}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader([]byte("{not valid json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceCertAttestHandler_VerificationFailure tests that a verifier
// returning ErrVerification produces a 403 response.
func TestDeviceCertAttestHandler_VerificationFailure(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	verifyErr := fmt.Errorf("%w: ek chain invalid", deviceattest.ErrVerification)
	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{identity: pdp.Identity{Subject: "usr_test"}},
		buildRegistry("tpm2-linux", &stubVerifier{err: verifyErr}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(validBody(t, "tpm2-linux")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
	// Vault MUST NOT be called when attestation fails.
	if vaultStub.callCount != 0 {
		t.Errorf("vault should not be called when attestation fails, got %d calls", vaultStub.callCount)
	}
}

// TestDeviceCertAttestHandler_VaultSignFailure tests that a Vault PKI error
// produces a 502 response (transient — client should retry).
func TestDeviceCertAttestHandler_VaultSignFailure(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()
	vaultStub.forceErr = true // Vault returns 500

	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{identity: pdp.Identity{Subject: "usr_test"}},
		buildRegistry("tpm2-linux", &stubVerifier{
			resp: deviceattest.VerifyResponse{
				Path: "A_chain", Tier: "TIER_CORP", Reasons: []string{"ok"},
			},
		}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(validBody(t, "tpm2-linux")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("expected 502 on Vault failure, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestDeviceCertAttestHandler_PassthroughNonAttest tests that a request to a
// different path is forwarded to the next handler unchanged.
func TestDeviceCertAttestHandler_PassthroughNonAttest(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusTeapot)
	})

	handler := NewDeviceCertAttestHandler(
		next,
		&stubTokenVerifier{identity: pdp.Identity{Subject: "usr_test"}},
		buildRegistry("tpm2-linux", &stubVerifier{}),
		newTestVaultClient(t, vaultStub),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/grants", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("expected 418 from next handler, got %d", rr.Code)
	}
	if !nextCalled {
		t.Error("next handler was not called for non-attest path")
	}
}

// TestDeviceCertAttestHandler_UnknownPlatform tests that requesting an
// attestation for a platform not in the registry returns 400.
func TestDeviceCertAttestHandler_UnknownPlatform(t *testing.T) {
	vaultStub := newStubVaultPKISigner(t)
	defer vaultStub.srv.Close()

	// Registry only has tpm2-linux; we request unknown-platform.
	handler := NewDeviceCertAttestHandler(
		http.NotFoundHandler(),
		&stubTokenVerifier{identity: pdp.Identity{Subject: "usr_test"}},
		buildRegistry("tpm2-linux", &stubVerifier{}),
		newTestVaultClient(t, vaultStub),
	)

	bodyBytes, _ := json.Marshal(AttestRequest{
		Platform:    "unknown-platform",
		DeviceUUID:  "aaaabbbb-1111-4111-8111-ccccddddeeee",
		EKPubKeyPEM: []byte("-----BEGIN PUBLIC KEY-----\nfoo\n-----END PUBLIC KEY-----"),
	})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/attest",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer valid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown platform, got %d: %s", rr.Code, rr.Body.String())
	}
}
