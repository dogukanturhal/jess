// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicecert"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

const renewTestUUID = "3f9b2c1a-0000-4abc-9def-1234567890ab"

func renewCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jess-device-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func renewLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(devicecert.SPIFFEPrefix + renewTestUUID)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "04ad2960"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	c, _ := x509.ParseCertificate(der)
	return c
}

// freshCSR returns a self-signed PKCS#10 CSR PEM (proof-of-possession).
func freshCSR(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func xfcc(c *x509.Certificate) string {
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	return `Cert="` + url.QueryEscape(p) + `"`
}

// mockVault returns a vaultx.Client whose SignPKICert succeeds, plus the
// captured request body for assertions.
func mockVault(t *testing.T, captured *map[string]any) *vaultx.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sign/") {
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":{"certificate":"-----BEGIN CERTIFICATE-----\nRENEWED\n-----END CERTIFICATE-----","issuing_ca":"ca","serial_number":"0a:0b","expiration":4102444800}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c, err := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newHandler(t *testing.T, ca *x509.Certificate, vc *vaultx.Client) *DeviceRenewHandler {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v, err := devicecert.NewVerifier(pool)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	return NewDeviceRenewHandler(next, v, vc, nil)
}

// newHandlerWithLookup builds a renew handler with the revocation gate wired
// to the given lookup (ADR 0048 hardening).
func newHandlerWithLookup(t *testing.T, ca *x509.Certificate, vc *vaultx.Client, lookup deviceLookup) *DeviceRenewHandler {
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	v, err := devicecert.NewVerifier(pool)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	return NewDeviceRenewHandler(next, v, vc, lookup)
}

// stubLookup is a deviceLookup test double.
type stubLookup struct {
	dev deviceattest.EnrolledDevice
	err error
}

func (s stubLookup) GetByUUID(_ context.Context, _ string) (deviceattest.EnrolledDevice, error) {
	return s.dev, s.err
}

// doRenew issues a renewal request with a valid device cert (XFCC) + fresh
// CSR and returns the recorder.
func doRenew(t *testing.T, h *DeviceRenewHandler, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(RenewRequest{CSRPEM: freshCSR(t)})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/renew", strings.NewReader(string(body)))
	req.Header.Set("X-Forwarded-Client-Cert", xfcc(renewLeaf(t, ca, caKey)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRenew_RevocationGate_ActiveAllows(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	// Active device: UUID present, DisabledAt zero.
	lookup := stubLookup{dev: deviceattest.EnrolledDevice{DeviceUUID: renewTestUUID}}
	h := newHandlerWithLookup(t, ca, mockVault(t, &captured), lookup)
	rec := doRenew(t, h, ca, caKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("active device must renew: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRenew_RevocationGate_RevokedDenied(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	lookup := stubLookup{dev: deviceattest.EnrolledDevice{DeviceUUID: renewTestUUID, DisabledAt: time.Now().Add(-time.Hour)}}
	h := newHandlerWithLookup(t, ca, mockVault(t, &captured), lookup)
	rec := doRenew(t, h, ca, caKey)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("revoked device must be denied: status=%d", rec.Code)
	}
	if len(captured) != 0 {
		t.Errorf("revoked device must NOT reach Vault sign; captured=%v", captured)
	}
}

func TestRenew_RevocationGate_NotEnrolledDenied(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	// 404 maps to zero-value device (empty DeviceUUID) + nil error.
	lookup := stubLookup{dev: deviceattest.EnrolledDevice{}}
	h := newHandlerWithLookup(t, ca, mockVault(t, &captured), lookup)
	rec := doRenew(t, h, ca, caKey)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unenrolled device must be denied: status=%d", rec.Code)
	}
}

func TestRenew_RevocationGate_TransientErrorSoftFails(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	// Transient lookup error → soft-fail → renewal proceeds (cert is short-
	// lived; a Falcon-ID blip must not mass-expire the fleet).
	lookup := stubLookup{err: io.ErrUnexpectedEOF}
	h := newHandlerWithLookup(t, ca, mockVault(t, &captured), lookup)
	rec := doRenew(t, h, ca, caKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("transient lookup error must soft-fail (allow): status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRenew_HappyPath(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	h := newHandler(t, ca, mockVault(t, &captured))

	body, _ := json.Marshal(RenewRequest{CSRPEM: freshCSR(t)})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/renew", strings.NewReader(string(body)))
	req.Header.Set("X-Forwarded-Client-Cert", xfcc(renewLeaf(t, ca, caKey)))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp RenewResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !strings.Contains(resp.DeviceCertPEM, "RENEWED") {
		t.Errorf("device_cert_pem=%q", resp.DeviceCertPEM)
	}
	// Server-trusted identity flows into the mint, not the CSR's claims.
	if cn, _ := captured["common_name"].(string); cn != "04ad2960" {
		t.Errorf("common_name=%q want 04ad2960 (from cert CN)", cn)
	}
	if us, _ := captured["uri_sans"].(string); us != devicecert.SPIFFEPrefix+renewTestUUID {
		t.Errorf("uri_sans=%q want spiffe device uuid", us)
	}
}

func TestRenew_NoCert401(t *testing.T) {
	ca, _ := renewCA(t)
	captured := map[string]any{}
	h := newHandler(t, ca, mockVault(t, &captured))
	body, _ := json.Marshal(RenewRequest{CSRPEM: freshCSR(t)})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/renew", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
}

func TestRenew_BadCSR400(t *testing.T) {
	ca, caKey := renewCA(t)
	captured := map[string]any{}
	h := newHandler(t, ca, mockVault(t, &captured))
	body, _ := json.Marshal(RenewRequest{CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nnotvalid\n-----END CERTIFICATE REQUEST-----")})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/renew", strings.NewReader(string(body)))
	req.Header.Set("X-Forwarded-Client-Cert", xfcc(renewLeaf(t, ca, caKey)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
}

func TestRenew_NonMatchingPathPassesThrough(t *testing.T) {
	ca, _ := renewCA(t)
	captured := map[string]any{}
	h := newHandler(t, ca, mockVault(t, &captured))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound { // our `next` returns 404
		t.Fatalf("status=%d want passthrough 404", rec.Code)
	}
}
