// SPDX-License-Identifier: AGPL-3.0-or-later

package devicecrl

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- fakes ---------------------------------------------------------

type fakeVault struct {
	pemBody     []byte
	readErr     error
	ocspStatus  int
	ocspBody    []byte
	ocspCT      string
	ocspErr     error
	readCalls   int
	ocspCalls   int
	lastOCSPReq []byte
}

func (f *fakeVault) ReadRawPEM(_ context.Context, _ string) ([]byte, error) {
	f.readCalls++
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.pemBody, nil
}

func (f *fakeVault) OCSPPost(_ context.Context, _ string, _ string, body []byte) (int, []byte, string, error) {
	f.ocspCalls++
	f.lastOCSPReq = body
	if f.ocspErr != nil {
		return 0, nil, "", f.ocspErr
	}
	return f.ocspStatus, f.ocspBody, f.ocspCT, nil
}

func samplePEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	// Hand-rolled valid PEM block with DER body = 5 bytes of 0x42.
	der := []byte{0x42, 0x42, 0x42, 0x42, 0x42}
	b64 := base64.StdEncoding.EncodeToString(der)
	pem := []byte("-----BEGIN X509 CRL-----\n" + b64 + "\n-----END X509 CRL-----\n")
	return pem, der
}

// --- tests ---------------------------------------------------------

func TestCRL_PEM(t *testing.T) {
	t.Parallel()
	pem, _ := samplePEM(t)
	r := New(Config{Vault: &fakeVault{pemBody: pem}, Mount: "jess-device-ca"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl.pem", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), pem) {
		t.Fatalf("body mismatch")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("Content-Type: want application/x-pem-file, got %q", ct)
	}
}

func TestCRL_DER(t *testing.T) {
	t.Parallel()
	pem, der := samplePEM(t)
	r := New(Config{Vault: &fakeVault{pemBody: pem}, Mount: "jess-device-ca"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl.der", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), der) {
		t.Fatalf("DER body: want %x, got %x", der, w.Body.Bytes())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type: want application/pkix-crl, got %q", ct)
	}
}

func TestCRL_Cached(t *testing.T) {
	t.Parallel()
	pem, _ := samplePEM(t)
	fv := &fakeVault{pemBody: pem}
	r := New(Config{Vault: fv, Mount: "jess-device-ca", CacheTTL: 30 * time.Second})
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl.pem", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status: %d body=%s (i=%d)", w.Code, w.Body.String(), i)
		}
	}
	if fv.readCalls != 1 {
		t.Errorf("cache should collapse 3 requests to 1 Vault fetch — got %d", fv.readCalls)
	}
}

func TestCRL_VaultError_BadGateway(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{readErr: errVault}, Mount: "jess-device-ca"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl.pem", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: want 502, got %d", w.Code)
	}
}

func TestCRL_EmptyBody_BadGateway(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{pemBody: nil}, Mount: "jess-device-ca"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/crl.pem", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: want 502, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestOCSP_Post_ContentTypeRequired(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{}, Mount: "jess-device-ca"})
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader("x"))
	// No Content-Type set.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415, got %d", w.Code)
	}
}

func TestOCSP_Post_EmptyBody(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{}, Mount: "jess-device-ca"})
	req := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestOCSP_Post_Proxies(t *testing.T) {
	t.Parallel()
	fv := &fakeVault{
		ocspStatus: http.StatusOK,
		ocspBody:   []byte{0xAB, 0xCD},
		ocspCT:     "application/ocsp-response",
	}
	r := New(Config{Vault: fv, Mount: "jess-device-ca"})
	req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader([]byte{0x01, 0x02}))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), []byte{0xAB, 0xCD}) {
		t.Fatalf("body mismatch")
	}
	if fv.ocspCalls != 1 {
		t.Errorf("expected 1 Vault OCSP call, got %d", fv.ocspCalls)
	}
	if !bytes.Equal(fv.lastOCSPReq, []byte{0x01, 0x02}) {
		t.Errorf("forwarded body mismatch")
	}
}

func TestOCSP_Get_Base64Path(t *testing.T) {
	t.Parallel()
	fv := &fakeVault{
		ocspStatus: http.StatusOK,
		ocspBody:   []byte{0xFE, 0xED},
		ocspCT:     "application/ocsp-response",
	}
	r := New(Config{Vault: fv, Mount: "jess-device-ca"})
	body := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	b64 := base64.StdEncoding.EncodeToString(body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ocsp/"+b64, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	if !bytes.Equal(fv.lastOCSPReq, body) {
		t.Errorf("decoded body mismatch: want %x got %x", body, fv.lastOCSPReq)
	}
}

func TestOCSP_Get_BadBase64(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{}, Mount: "jess-device-ca"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ocsp/not!base64!!", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestPemToDER_Roundtrip(t *testing.T) {
	t.Parallel()
	der := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	pem := []byte("-----BEGIN X509 CRL-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END X509 CRL-----\n")
	got, err := pemToDER(pem)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Errorf("round-trip mismatch: want %x got %x", der, got)
	}
}

func TestPemToDER_MissingBegin(t *testing.T) {
	t.Parallel()
	if _, err := pemToDER([]byte("no marker here")); err == nil {
		t.Fatal("want error on missing BEGIN")
	}
}

func TestPemToDER_MissingEnd(t *testing.T) {
	t.Parallel()
	if _, err := pemToDER([]byte("-----BEGIN X-----\nQUFB\n")); err == nil {
		t.Fatal("want error on missing END")
	}
}

func TestPemToDER_MultilineBase64(t *testing.T) {
	t.Parallel()
	// gofpdf/openssl-style PEM splits the base64 body across 64-char lines;
	// the decoder must strip the newlines + spaces before decoding.
	der := bytes.Repeat([]byte{0xAB}, 64)
	b64 := base64.StdEncoding.EncodeToString(der)
	var split strings.Builder
	for i := 0; i < len(b64); i += 32 {
		end := i + 32
		if end > len(b64) {
			end = len(b64)
		}
		split.WriteString(b64[i:end])
		split.WriteByte('\n')
	}
	pem := []byte("-----BEGIN X509 CRL-----\n" + split.String() + "-----END X509 CRL-----\n")
	got, err := pemToDER(pem)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Errorf("multiline round-trip mismatch")
	}
}

func TestNotFound(t *testing.T) {
	t.Parallel()
	r := New(Config{Vault: &fakeVault{}, Mount: "jess-device-ca"})
	for _, p := range []string{"/", "/something", "/crl"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("path %q: want 404, got %d", p, w.Code)
		}
	}
}

// errVault is a sentinel so the test fakes can return a stable error.
type errVaultT struct{}

func (errVaultT) Error() string { return "fake vault error" }

var errVault = errVaultT{}
