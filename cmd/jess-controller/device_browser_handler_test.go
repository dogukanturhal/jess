// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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

	"github.com/dogukanturhal/jess/internal/devicecert"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// signingVault is a fake Vault PKI that really signs the posted CSR with the
// test CA, applying the browser-role constraints (so the handler's post-sign
// shape check is exercised on a real cert). eku overrides the issued EKU to
// simulate a misconfigured role.
func signingVault(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, eku []x509.ExtKeyUsage, role *string) *vaultx.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/sign/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if role != nil {
			*role = r.URL.Path
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		blk, _ := pem.Decode([]byte(body["csr"]))
		csr, _ := x509.ParseCertificateRequest(blk.Bytes)
		var uris []*url.URL
		for _, s := range strings.Split(body["uri_sans"], ",") {
			u, _ := url.Parse(s)
			uris = append(uris, u)
		}
		notAfter := time.Now().Add(24 * time.Hour)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: body["common_name"]},
			NotBefore:    time.Now().Add(-time.Minute), NotAfter: notAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, URIs: uris,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, csr.PublicKey, caKey)
		certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		out, _ := json.Marshal(map[string]any{"data": map[string]any{
			"certificate": certPEM, "issuing_ca": "CA-PEM", "serial_number": "0a:0b", "expiration": notAfter.Unix(),
		}})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	c, err := vaultx.New(vaultx.Config{Addr: srv.URL, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leafWith(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey, browser bool) *x509.Certificate {
	t.Helper()
	u, _ := url.Parse(devicecert.SPIFFEPrefix + renewTestUUID)
	uris := []*url.URL{u}
	if browser {
		k, _ := url.Parse(devicecert.BrowserKindURI)
		uris = append(uris, k)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "04ad2960"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: uris,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	c, _ := x509.ParseCertificate(der)
	return c
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func postBrowser(h http.Handler, leaf *x509.Certificate, csr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(BrowserRequest{CSRPEM: csr})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/browser", strings.NewReader(string(body)))
	req.Header.Set("X-Forwarded-Client-Cert", xfcc(leaf))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBrowser_HappyPath(t *testing.T) {
	ca, caKey := renewCA(t)
	var path string
	h := newHandler(t, ca, signingVault(t, ca, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, &path))
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	brKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rec := postBrowser(h, leafWith(t, ca, caKey, devKey, false), csrFor(t, brKey))
	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.HasSuffix(path, "/sign/browser-cert") {
		t.Fatalf("vault path %q", path)
	}
	var resp BrowserResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	blk, _ := pem.Decode([]byte(resp.CertPEM))
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != renewTestUUID+"-browser" {
		t.Errorf("CN=%q", c.Subject.CommonName)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU=%v", c.ExtKeyUsage)
	}
	got := map[string]bool{}
	for _, u := range c.URIs {
		got[u.String()] = true
	}
	if len(c.URIs) != 2 || !got[devicecert.SPIFFEPrefix+renewTestUUID] || !got[devicecert.BrowserKindURI] {
		t.Errorf("URIs=%v", c.URIs)
	}
	if resp.ChainPEM == "" || resp.NotAfter == "" {
		t.Errorf("resp=%+v", resp)
	}
	if time.Until(c.NotAfter) > 24*time.Hour+time.Minute {
		t.Errorf("lifetime too long")
	}
}

func TestBrowser_BrowserCallerRejectedOnBothEndpoints(t *testing.T) {
	ca, caKey := renewCA(t)
	h := newHandler(t, ca, signingVault(t, ca, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil))
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	brKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := leafWith(t, ca, caKey, devKey, true)
	if rec := postBrowser(h, leaf, csrFor(t, brKey)); rec.Code != 403 {
		t.Errorf("browser endpoint: code=%d", rec.Code)
	}
	body, _ := json.Marshal(RenewRequest{CSRPEM: freshCSR(t)})
	req := httptest.NewRequest(http.MethodPost, "/device-cert/renew", strings.NewReader(string(body)))
	req.Header.Set("X-Forwarded-Client-Cert", xfcc(leaf))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("renew endpoint: code=%d", rec.Code)
	}
}

func TestBrowser_SameKeyCSRRejected(t *testing.T) {
	ca, caKey := renewCA(t)
	h := newHandler(t, ca, signingVault(t, ca, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil))
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rec := postBrowser(h, leafWith(t, ca, caKey, devKey, false), csrFor(t, devKey))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "differ") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestBrowser_RateLimit(t *testing.T) {
	ca, caKey := renewCA(t)
	h := newHandler(t, ca, signingVault(t, ca, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil))
	now := time.Now()
	h.browserRL.now = func() time.Time { return now }
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := leafWith(t, ca, caKey, devKey, false)
	for i := 0; i < 6; i++ {
		brKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if rec := postBrowser(h, leaf, csrFor(t, brKey)); rec.Code != 200 {
			t.Fatalf("issue %d: code=%d", i, rec.Code)
		}
	}
	brKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if rec := postBrowser(h, leaf, csrFor(t, brKey)); rec.Code != 429 {
		t.Fatalf("7th: code=%d", rec.Code)
	}
	now = now.Add(61 * time.Minute)
	if rec := postBrowser(h, leaf, csrFor(t, brKey)); rec.Code != 200 {
		t.Fatalf("after window: code=%d", rec.Code)
	}
}

func TestBrowser_MisconfiguredRoleEKURejected(t *testing.T) {
	ca, caKey := renewCA(t)
	h := newHandler(t, ca, signingVault(t, ca, caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, nil))
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	brKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if rec := postBrowser(h, leafWith(t, ca, caKey, devKey, false), csrFor(t, brKey)); rec.Code != 502 {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestBrowser_NoCert401(t *testing.T) {
	ca, caKey := renewCA(t)
	h := newHandler(t, ca, signingVault(t, ca, caKey, nil, nil))
	req := httptest.NewRequest(http.MethodPost, "/device-cert/browser", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("code=%d", rec.Code)
	}
}
