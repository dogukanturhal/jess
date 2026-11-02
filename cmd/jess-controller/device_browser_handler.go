// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// device_browser_handler.go — POST /device-cert/browser (ZTNA no-WireGuard C2).
//
// Mints a short-lived (24h) browser client cert for a device that already
// holds a valid kind=device cert. The cert is signed by the SAME jess device
// CA (a dedicated Vault role pins KeyUsage=digitalSignature, EKU=clientAuth
// only and the allowed URI SANs). The browser key lives in the user's Chrome
// NSS DB, never the root-owned device key, so a browser cert is deliberately
// NOT renewable and NOT able to mint anything: /device-cert/renew and this
// endpoint both refuse a browser-kind caller (403).
//
//	POST /device-cert/browser       (Envoy mTLS → XFCC)
//	{ "csr_pem": "<PKCS#10 PEM>" }
//	200 { "cert_pem", "chain_pem", "not_after" }
//	400 bad CSR / CSR key equals the device key
//	401 no/invalid device cert
//	403 browser-kind caller, device revoked / not enrolled, expired device cert
//	429 more than 6 issuances per device per hour
//	502 Vault PKI failure / issued cert failed the post-sign shape check

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/devicecert"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

const (
	// browserCertVaultRole is the Vault PKI role (mount jess-device-ca) used
	// for browser certs; override with JESS_BROWSER_CERT_VAULT_ROLE.
	browserCertVaultRole = "browser-cert"
	browserCertTTL       = 24 * time.Hour
	browserCertRateLimit = 6 // per device per hour
	maxBrowserBodyBytes  = 16 << 10
)

// BrowserRequest / BrowserResponse are the C2 wire shapes (csr_pem is a
// plain PEM string here, unlike renew's base64 bytes).
type BrowserRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type BrowserResponse struct {
	CertPEM  string `json:"cert_pem"`
	ChainPEM string `json:"chain_pem"`
	NotAfter string `json:"not_after"`
}

// issueLimiter is a per-key sliding-window limiter (in-process; with N
// controller replicas the effective cap is N x limit).
type issueLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	hits   map[string][]time.Time
}

func newIssueLimiter(limit int, window time.Duration) *issueLimiter {
	return &issueLimiter{limit: limit, window: window, now: time.Now, hits: map[string][]time.Time{}}
}

// allow records an issuance attempt for key and reports whether it is within
// the limit.
func (l *issueLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

func (h *DeviceRenewHandler) handleBrowser(w http.ResponseWriter, r *http.Request) {
	id, err := h.verifier.VerifyRequest(r)
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, devicecert.ErrExpired), errors.Is(err, devicecert.ErrSANMissing):
			status = http.StatusForbidden
		case errors.Is(err, devicecert.ErrXFCCMalformed), errors.Is(err, devicecert.ErrXFCCMissingCrt):
			status = http.StatusBadRequest
		}
		writeRenewError(w, status, err.Error())
		return
	}
	if id.Browser {
		log.Printf("device_browser_handler: DENIED device=%s — browser-kind caller", id.DeviceUUID)
		writeRenewError(w, http.StatusForbidden, "browser certificates cannot request browser certificates")
		return
	}
	if !h.checkEnrolled(r.Context(), w, id.DeviceUUID, "browser cert") {
		return
	}

	var req BrowserRequest
	if derr := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBrowserBodyBytes)).Decode(&req); derr != nil {
		writeRenewError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON body: %v", derr))
		return
	}
	if req.CSRPEM == "" {
		writeRenewError(w, http.StatusBadRequest, "csr_pem is required")
		return
	}
	if verr := validateBrowserCSR([]byte(req.CSRPEM), id.Leaf); verr != nil {
		writeRenewError(w, http.StatusBadRequest, verr.Error())
		return
	}

	// Rate limit only well-formed, authorised requests so garbage cannot burn
	// a legitimate device's budget.
	if !h.browserRL.allow(id.DeviceUUID) {
		log.Printf("device_browser_handler: RATE-LIMITED device=%s", id.DeviceUUID)
		w.Header().Set("Retry-After", "3600")
		writeRenewError(w, http.StatusTooManyRequests, "browser certificate issuance limit reached (6/hour/device)")
		return
	}

	signResp, serr := h.vaultClient.SignPKICert(r.Context(), deviceCertVaultMount, h.browserRole,
		vaultx.PKISignRequest{
			CSRPEM:     req.CSRPEM,
			CommonName: id.DeviceUUID + "-browser",
			TTL:        browserCertTTL,
			URISans:    []string{spiffeURIPrefix + id.DeviceUUID, devicecert.BrowserKindURI},
		})
	if serr != nil {
		log.Printf("device_browser_handler: vault sign failed device=%s: %v", id.DeviceUUID, serr)
		writeRenewError(w, http.StatusBadGateway, fmt.Sprintf("browser certificate issuance failed (Vault PKI): %v", serr))
		return
	}
	// Defence in depth: never hand back a cert that is not exactly C1, even
	// if the Vault role is misconfigured (e.g. extra EKU).
	if cerr := checkBrowserCertShape(signResp.Certificate, id.DeviceUUID); cerr != nil {
		log.Printf("device_browser_handler: REJECTED issued cert device=%s serial=%s: %v", id.DeviceUUID, signResp.SerialNumber, cerr)
		writeRenewError(w, http.StatusBadGateway, "issued browser certificate failed policy check")
		return
	}

	notAfter := signResp.Expiration.UTC().Format(time.RFC3339)
	log.Printf("device_browser_handler: AUDIT issued browser cert device=%s user=%s serial=%s not_after=%s",
		id.DeviceUUID, id.UserSub, signResp.SerialNumber, notAfter)
	chain := signResp.IssuingCA
	if len(signResp.CAChain) > 0 {
		chain = strings.Join(signResp.CAChain, "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(BrowserResponse{CertPEM: signResp.Certificate, ChainPEM: chain, NotAfter: notAfter})
}

// validateBrowserCSR checks PEM/PoP, key type, and that the key differs from
// the caller's device-cert key.
func validateBrowserCSR(csrPEM []byte, deviceLeaf *x509.Certificate) error {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errors.New("csr_pem is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse csr_pem: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("csr self-signature invalid (proof-of-possession failed): %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return errors.New("csr key must be ECDSA P-256 or RSA >= 2048")
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return errors.New("csr key must be ECDSA P-256 or RSA >= 2048")
		}
	default:
		return errors.New("csr key must be ECDSA P-256 or RSA >= 2048")
	}
	if eq, ok := deviceLeaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && eq.Equal(csr.PublicKey) {
		return errors.New("csr key must differ from the device certificate key")
	}
	return nil
}

// checkBrowserCertShape verifies a freshly issued cert matches C1 exactly.
func checkBrowserCertShape(certPEM, deviceUUID string) error {
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		return errors.New("issued cert is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued cert: %w", err)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(c.UnknownExtKeyUsage) != 0 {
		return errors.New("EKU is not clientAuth only")
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		return errors.New("KeyUsage is not digitalSignature only")
	}
	if c.Subject.CommonName != deviceUUID+"-browser" {
		return errors.New("unexpected subject CN")
	}
	if len(c.URIs) != 2 {
		return fmt.Errorf("expected 2 URI SANs, got %d", len(c.URIs))
	}
	var haveDev, haveKind bool
	for _, u := range c.URIs {
		switch u.String() {
		case spiffeURIPrefix + deviceUUID:
			haveDev = true
		case devicecert.BrowserKindURI:
			haveKind = true
		}
	}
	if !haveDev || !haveKind {
		return errors.New("URI SANs are not {device spiffe, browser kind}")
	}
	if d := time.Until(c.NotAfter); d > browserCertTTL+5*time.Minute {
		return fmt.Errorf("lifetime %s exceeds 24h", d)
	}
	return nil
}
