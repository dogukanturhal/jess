// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devicecrl exposes the jess-device-ca CRL + OCSP responder
// over an authenticated HTTP surface, so Talon's edge mTLS verifier
// (and the device-cert clients themselves) can validate revocation
// state without dialing Vault directly.
//
// Task #131. Closes the revocation distribution gap noted in the
// jess-device-ca rotation runbook ("Failure modes NOT in scope:
// Compromise of the old root key — issue a CRL covering every
// outstanding leaf, push to Talon's CRL bundle, force re-attestation
// across the fleet. CRL distribution is task #131 (pending)").
//
// Endpoints (mounted on the jess admin HTTP listener — same Bearer
// + role gate as /grants and /devices):
//
//	GET  /crl.pem         — PEM-encoded CRL for jess-device-ca. Cached
//	                          in-memory for 5min to absorb Vault load
//	                          when many edge verifiers refresh in
//	                          parallel (Talon proxies poll ~60s).
//
//	GET  /crl.der         — DER-encoded variant. Most TLS stacks
//	                          (Go crypto/x509, OpenSSL, Rust rustls)
//	                          parse DER natively; PEM requires an
//	                          extra base64 strip.
//
//	POST /ocsp            — OCSP responder per RFC 6960. Body is the
//	                          binary OCSP request (Content-Type:
//	                          application/ocsp-request). We proxy to
//	                          Vault's /v1/<mount>/ocsp, which signs
//	                          the response with the issuer key.
//	                          Response body is the binary OCSP
//	                          response (Content-Type:
//	                          application/ocsp-response).
//
//	GET  /ocsp/{b64}      — RFC 6960 §A.1.1 GET form for the OCSP
//	                          request (base64-encoded), provided so
//	                          intermediate proxies that can't carry a
//	                          binary POST body (e.g. some load
//	                          balancers' strict modes) still work.
//
// Why proxy through jess instead of letting clients hit Vault
// directly:
//   - Vault is in a separate trust domain (vault.example.com, root
//     namespace). Operators are NOT given Vault tokens; jess holds
//     the only path.
//   - Talon's edge mTLS verifier already trusts jess (talon!108 added
//     the operator-cert chain validation against jess-ca). Re-using
//     that same trust path for the device-cert revocation lookup
//     keeps the trust-graph minimal.
//   - Caching at the jess layer absorbs cluster-internal verifier
//     load. Vault's PKI CRL endpoint regenerates the CRL on every
//     hit when revocations are recent; the cache layer cuts that to
//     N requests per cache TTL.
package devicecrl

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// defaultCRLCacheTTL is the in-memory CRL cache lifetime. Conservative:
// Vault PKI CRL regeneration is expensive when a sudden mass-revocation
// hits; the 5-minute cache means each edge verifier polling at 60s
// sees the same CRL for ~5 ticks before jess refreshes. Operators
// running a mass-revocation should bust the cache via the
// /admin/crl/refresh route (TBD task #142).
const defaultCRLCacheTTL = 5 * time.Minute

// VaultClient is the subset of vaultx.Client this package needs.
// Defined as an interface so tests can wire a fake without standing
// up Vault.
type VaultClient interface {
	ReadRawPEM(ctx context.Context, path string) ([]byte, error)
	// RoundTrip is the OCSP proxy path: sends the inbound OCSP request
	// body to Vault's /v1/<mount>/ocsp and returns the raw response
	// body. The fake in tests just echoes a canned response so the
	// handler can be unit-tested without a real Vault.
	OCSPPost(ctx context.Context, path string, contentType string, body []byte) (status int, respBody []byte, respCT string, err error)
}

// Config wires the responder. Mount must NOT have a trailing slash
// (jess-device-ca, not jess-device-ca/) — VaultClient.ReadRawPEM
// concatenates "/v1/<mount>/crl/pem" so a trailing slash would yield
// a double-slash URL Vault rejects.
type Config struct {
	Vault    VaultClient
	Mount    string        // e.g. "jess-device-ca"
	CacheTTL time.Duration // 0 = use defaultCRLCacheTTL
}

// Responder is the HTTP handler. Construct with New and mount on the
// admin Handler via WithCRLResponder (sibling MR adds that helper).
type Responder struct {
	cfg Config

	// CRL cache
	mu           sync.RWMutex
	crlPEM       []byte
	crlDER       []byte
	crlFetchedAt time.Time
}

// New constructs a Responder with the supplied config.
func New(cfg Config) *Responder {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = defaultCRLCacheTTL
	}
	cfg.Mount = strings.Trim(cfg.Mount, "/")
	return &Responder{cfg: cfg}
}

// ServeHTTP dispatches to the per-route handlers.
func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/crl.pem":
		r.serveCRL(w, req, "application/x-pem-file", true)
	case req.Method == http.MethodGet && req.URL.Path == "/crl.der":
		r.serveCRL(w, req, "application/pkix-crl", false)
	case req.Method == http.MethodPost && req.URL.Path == "/ocsp":
		r.serveOCSPPost(w, req)
	case req.Method == http.MethodGet && strings.HasPrefix(req.URL.Path, "/ocsp/"):
		r.serveOCSPGet(w, req, strings.TrimPrefix(req.URL.Path, "/ocsp/"))
	default:
		http.NotFound(w, req)
	}
}

// serveCRL returns the cached CRL in the requested encoding.
func (r *Responder) serveCRL(w http.ResponseWriter, req *http.Request, contentType string, pemMode bool) {
	pem, der, err := r.fetchCRL(req.Context())
	if err != nil {
		http.Error(w, "crl fetch: "+err.Error(), http.StatusBadGateway)
		return
	}
	body := pem
	if !pemMode {
		body = der
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(r.cfg.CacheTTL.Seconds())))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// serveOCSPPost proxies a binary OCSP request body to Vault.
func (r *Responder) serveOCSPPost(w http.ResponseWriter, req *http.Request) {
	ct := req.Header.Get("Content-Type")
	if ct != "application/ocsp-request" {
		http.Error(w, "Content-Type must be application/ocsp-request", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<14)) // 16 KiB OCSP request cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty OCSP request body", http.StatusBadRequest)
		return
	}
	r.proxyOCSP(w, req.Context(), body)
}

// serveOCSPGet decodes the base64-URL form (RFC 6960 §A.1.1) and
// proxies to Vault.
func (r *Responder) serveOCSPGet(w http.ResponseWriter, req *http.Request, b64 string) {
	if b64 == "" {
		http.Error(w, "OCSP request base64 missing", http.StatusBadRequest)
		return
	}
	// RFC 6960 §A.1.1 says base64-encoded; the URL form most clients
	// emit is the standard alphabet (not URL-safe), but operator
	// scripts sometimes pass URL-safe. Tolerate both.
	body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		body, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "OCSP request not valid base64: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if len(body) == 0 {
		http.Error(w, "OCSP request decoded to zero bytes", http.StatusBadRequest)
		return
	}
	r.proxyOCSP(w, req.Context(), body)
}

// proxyOCSP forwards the OCSP request to Vault's responder + writes
// the response back to the client.
func (r *Responder) proxyOCSP(w http.ResponseWriter, ctx context.Context, body []byte) {
	path := "/v1/" + r.cfg.Mount + "/ocsp"
	status, respBody, respCT, err := r.cfg.Vault.OCSPPost(ctx, path, "application/ocsp-request", body)
	if err != nil {
		http.Error(w, "ocsp proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	if respCT == "" {
		respCT = "application/ocsp-response"
	}
	w.Header().Set("Content-Type", respCT)
	// RFC 6960 §5: OCSP responses have their own validity window in
	// the response body (nextUpdate). Don't add a Cache-Control header
	// here — let intermediaries honour the OCSP response's own
	// freshness.
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// fetchCRL returns the CRL in both PEM + DER encodings. Cached for
// cfg.CacheTTL; first call AFTER expiry refetches via Vault.
func (r *Responder) fetchCRL(ctx context.Context) ([]byte, []byte, error) {
	r.mu.RLock()
	if len(r.crlPEM) > 0 && time.Since(r.crlFetchedAt) < r.cfg.CacheTTL {
		pem, der := r.crlPEM, r.crlDER
		r.mu.RUnlock()
		return pem, der, nil
	}
	r.mu.RUnlock()

	// Slow path — re-fetch. Single-flight guard via the write lock; if
	// two callers hit the slow path simultaneously, the second sees a
	// fresh cache after the first's fetch completes.
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.crlPEM) > 0 && time.Since(r.crlFetchedAt) < r.cfg.CacheTTL {
		return r.crlPEM, r.crlDER, nil
	}
	pemBody, err := r.cfg.Vault.ReadRawPEM(ctx, "/v1/"+r.cfg.Mount+"/crl/pem")
	if err != nil {
		return nil, nil, fmt.Errorf("read /v1/%s/crl/pem: %w", r.cfg.Mount, err)
	}
	if len(pemBody) == 0 {
		return nil, nil, errors.New("vault returned empty CRL PEM body")
	}
	// Vault returns PEM by default; DER is just the base64-decoded
	// body between the BEGIN/END markers. We parse so a malformed
	// upstream response surfaces here, not at the client.
	der, err := pemToDER(pemBody)
	if err != nil {
		return nil, nil, fmt.Errorf("convert CRL PEM to DER: %w", err)
	}
	r.crlPEM = pemBody
	r.crlDER = der
	r.crlFetchedAt = time.Now()
	return r.crlPEM, r.crlDER, nil
}

// pemToDER strips the PEM armour and base64-decodes the body. Surfaces
// a clear error for malformed inputs (missing BEGIN/END, non-base64).
func pemToDER(pemBody []byte) ([]byte, error) {
	// Find the BEGIN line + grab the rest of the body up to END.
	src := string(pemBody)
	beginIdx := strings.Index(src, "-----BEGIN ")
	if beginIdx < 0 {
		return nil, errors.New("missing -----BEGIN marker")
	}
	// Skip past BEGIN line.
	rest := src[beginIdx:]
	endIdx := strings.Index(rest, "-----END ")
	if endIdx < 0 {
		return nil, errors.New("missing -----END marker")
	}
	body := rest[:endIdx]
	// Drop the BEGIN line (up to first newline).
	if nl := strings.Index(body, "\n"); nl >= 0 {
		body = body[nl+1:]
	}
	// Now body is the base64-encoded DER, possibly with line breaks.
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.ReplaceAll(body, "\r", "")
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return der, nil
}

// vaultx.Client satisfies VaultClient directly via the OCSPPost method
// added in vaultx.go alongside ReadRawPEM. Pass `&Config{Vault: vc, ...}`
// where `vc` is *vaultx.Client; no adapter struct needed.
