// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"
)

// Signer abstracts the two CA backends: in-process signing against a
// file-mounted CA (LocalSigner, was CertSigner) and Vault-PKI-mount signing
// (VaultSigner). The handler picks one at startup based on env config;
// runtime behaviour from the operator's perspective is identical.
type Signer interface {
	// SignCSR returns a PEM-encoded leaf certificate. callerSubject is
	// stamped as the cert's CN (CSR's claimed CN is ignored) — RFC 8705
	// §2.1 tls_client_auth binding to the verified IdP identity.
	SignCSR(ctx context.Context, csrPEM []byte, callerSubject, callerEmail string, ttl time.Duration) ([]byte, error)
	// CAPem returns the PEM-encoded CA cert (issuing CA + chain) the
	// CLI bundles with the operator cert for first-time setup.
	CAPem() []byte
}

// Revoker is the optional companion to Signer for backends that can
// publish a CRL entry against a previously-issued serial. VaultSigner
// implements it (Vault PKI mount has a /revoke endpoint that flips the
// serial into the next signed CRL); LocalSigner does NOT (file-mount CA
// has no CRL machinery — revoke is "wait for expiry"). The CertHandler
// type-asserts on Revoker before exposing POST /operator-cert/revoke and
// returns 501 if the active signer can't revoke.
type Revoker interface {
	// RevokeSerial flips the given cert serial into the CA's CRL. Idempotent:
	// revoking an already-revoked or unknown serial is not an error (matches
	// Vault PKI /revoke semantics). The serial may carry openssl-style colons
	// or be raw hex — implementations normalise.
	RevokeSerial(ctx context.Context, serial string) error
}

// CertSigner loads the operator-CA cert + key from disk once on construction
// and signs CSRs against it. The CA private key never leaves this process;
// the file mount is the only at-rest location (same risk profile as the
// existing operator-TLS server key already mounted at /etc/jess/operator-tls).
//
// All issued certs carry:
//   - Subject.CommonName = the verified caller's Falcon-ID subject (NOT what
//     the CSR claimed) — this is the BINDING property RFC 8705 §2.1
//     tls_client_auth needs.
//   - Subject.Organization = "HexxLock-Operator"
//   - ExtKeyUsage = clientAuth
//   - KeyUsage = digitalSignature + keyEncipherment
//   - NotAfter = now + ttl (8h ceiling)
type CertSigner struct {
	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  any // *ecdsa.PrivateKey or *rsa.PrivateKey
	caPEM  []byte
	maxTTL time.Duration
}

// MaxOperatorCertTTL is the ceiling for issued operator certs. An operator's
// session-day is bounded by it — re-mint once per day, not "long enough that
// it's still valid next week". Aligns with the runbook's `-days 1` default
// and the ssh-admin role's 30m max_ttl + JIT-grant 24h ceiling.
const MaxOperatorCertTTL = 8 * time.Hour

// NewCertSigner reads the CA cert + key from the given file paths and parses
// them. Returns an error if either file is missing, unreadable, or contains
// no usable PEM block. Acceptable key types: ECDSA, RSA.
func NewCertSigner(caCertPath, caKeyPath string) (*CertSigner, error) {
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %q: %w", caCertPath, err)
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %q: %w", caKeyPath, err)
	}
	return NewCertSignerFromPEM(certPEM, keyPEM)
}

// NewCertSignerFromPEM is the in-memory constructor used by tests.
func NewCertSignerFromPEM(certPEM, keyPEM []byte) (*CertSigner, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("CA cert PEM is empty or malformed")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("CA key PEM is empty or malformed")
	}
	caKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CertSigner{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  certPEM,
		maxTTL: MaxOperatorCertTTL,
	}, nil
}

// parsePrivateKey accepts the three common encodings produced by openssl /
// Vault: PKCS#8 (any algorithm), traditional EC, traditional RSA.
func parsePrivateKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch k.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS#8 key type %T", k)
		}
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("CA key is not PKCS#8 / EC / RSA")
}

// SignCSR validates the CSR and signs it with the CA, producing a PEM-encoded
// client certificate. callerSubject is taken from the verified Falcon-ID
// token and becomes the cert's CN — what the CSR claimed in its own subject
// is ignored. The ctx param is accepted to satisfy the Signer interface;
// in-process signing doesn't make network calls so it's currently unused.
func (s *CertSigner) SignCSR(_ context.Context, csrPEM []byte, callerSubject, callerEmail string, ttl time.Duration) ([]byte, error) {
	if ttl <= 0 || ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("csr is empty or not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject, // start with what the CSR offered; CN is overridden below.
		// Override the subject's CN + O so the cert's identity is the verified
		// Falcon-ID subject, not whatever the operator put in their CSR.
		NotBefore:   now.Add(-1 * time.Minute), // clock-skew tolerance
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// Stamp the operator email into the cert (auditable, surfaces in
		// `openssl x509 -text`). The subject's CN is the binding identity.
	}
	tmpl.Subject.CommonName = callerSubject
	tmpl.Subject.Organization = []string{"HexxLock-Operator"}
	if callerEmail != "" {
		tmpl.EmailAddresses = []string{callerEmail}
	}

	s.mu.RLock()
	caCert, caKey := s.caCert, s.caKey
	s.mu.RUnlock()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CAPem returns the PEM-encoded CA cert so the CLI can write it alongside
// the operator cert for first-time setup.
func (s *CertSigner) CAPem() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]byte, len(s.caPEM))
	copy(out, s.caPEM)
	return out
}

// OperatorCertRevokeRequest is the POST /operator-cert/revoke body.
type OperatorCertRevokeRequest struct {
	// Serial is the cert serial to revoke. Hex form, openssl-style colons
	// optional. The server normalises before calling the backend.
	Serial string `json:"serial"`
}

// OperatorCertRevokeResponse echoes the normalised serial + a server-side
// timestamp so the caller can correlate against Vault audit logs.
type OperatorCertRevokeResponse struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
}

// OperatorCertRequest is the POST /operator-cert body.
type OperatorCertRequest struct {
	// CSR is a PEM-encoded PKCS#10 certificate request. The CSR's CN is
	// ignored — the server stamps the verified Falcon-ID subject in.
	CSR string `json:"csr_pem"`
	// TTLSeconds defaults to 8h (the server ceiling) when 0.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// OperatorCertResponse returns the signed cert + the CA cert (so the CLI can
// drop both at $HOME/.config/jess/ in one round-trip).
type OperatorCertResponse struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
	// NotAfter is the cert expiry — the CLI surfaces it so the operator
	// knows when to re-mint without parsing the cert themselves.
	NotAfter time.Time `json:"not_after"`
}

// CertHandler adds POST /operator-cert on top of RequestsHandler. Only
// callers with the admin role can mint (matches the existing admin model);
// every issuance is bound to the caller's Falcon-ID identity. The signer
// is pluggable (Signer interface) — in-process file-mount CA or Vault PKI
// mount, picked at controller startup by env config.
type CertHandler struct {
	*RequestsHandler // delegates non-cert routes back to grants/requests
	signer           Signer
}

// NewCert wires the operator-cert handler. Pass nil signer to leave the
// endpoint unconfigured (returns 503 on /operator-cert, other routes work).
func NewCert(base *RequestsHandler, signer Signer) *CertHandler {
	return &CertHandler{RequestsHandler: base, signer: signer}
}

// ServeHTTP intercepts /operator-cert + /operator-cert/revoke; everything
// else falls through to the existing requests/grants stack.
func (h *CertHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/operator-cert" && r.Method == http.MethodPost {
		h.handleSign(w, r)
		return
	}
	if r.URL.Path == "/operator-cert/revoke" && r.Method == http.MethodPost {
		h.handleRevoke(w, r)
		return
	}
	h.RequestsHandler.ServeHTTP(w, r)
}

func (h *CertHandler) handleSign(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	if h.signer == nil {
		writeErr(w, http.StatusServiceUnavailable, "operator-cert endpoint not configured (CA cert/key paths unset)")
		return
	}
	var req OperatorCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if req.CSR == "" {
		writeErr(w, http.StatusBadRequest, "csr_pem required")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	certPEM, err := h.signer.SignCSR(r.Context(), []byte(req.CSR), id.Subject, id.Email, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "sign csr: "+err.Error())
		return
	}
	// Extract NotAfter from the just-signed cert so the CLI can surface it.
	notAfter := time.Now().Add(MaxOperatorCertTTL)
	if block, _ := pem.Decode(certPEM); block != nil {
		if c, perr := x509.ParseCertificate(block.Bytes); perr == nil {
			notAfter = c.NotAfter
		}
	}
	writeJSON(w, http.StatusCreated, OperatorCertResponse{
		CertPEM:  string(certPEM),
		CAPEM:    string(h.signer.CAPem()),
		NotAfter: notAfter,
	})
}

// handleRevoke implements POST /operator-cert/revoke. Admin-only; flips the
// caller-supplied cert serial into the CA's CRL via the backing Signer's
// Revoker (Vault PKI mount in prod). The CA private key never leaves the
// backend; Vault's own audit log captures the revoke event with the
// controller's K8s-auth identity, and the controller log captures the
// caller's verified Falcon-ID subject for the operator audit trail.
//
// The signer-side guarantees:
//   - Idempotent: revoking an already-revoked or unknown serial succeeds.
//   - Effective revocation latency = min(cert TTL, next-CRL-publish gap).
//     With operator certs capped at 8h (MaxOperatorCertTTL) and Vault's
//     default CRL refresh ~3d, the worst-case window in practice is the
//     8h cert TTL — the canonical "short-lived cert + CRL backstop" pattern
//     (Teleport, Boundary, AWS IAM Roles Anywhere).
func (h *CertHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if !id.HasRole(h.adminRole) {
		writeErr(w, http.StatusForbidden, "role "+h.adminRole+" required")
		return
	}
	if h.signer == nil {
		writeErr(w, http.StatusServiceUnavailable, "operator-cert endpoint not configured")
		return
	}
	revoker, ok := h.signer.(Revoker)
	if !ok {
		// LocalSigner (file-mount CA) lacks CRL machinery — short-cert
		// expiry is the only revocation path on that backend.
		writeErr(w, http.StatusNotImplemented, "active signer does not support revoke (file-mount CA — wait for cert TTL expiry, or switch controller to Vault PKI signer)")
		return
	}
	var req OperatorCertRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	serial := normaliseSerial(req.Serial)
	if serial == "" {
		writeErr(w, http.StatusBadRequest, "serial required (hex, openssl-style colons optional)")
		return
	}
	if err := revoker.RevokeSerial(r.Context(), serial); err != nil {
		writeErr(w, http.StatusBadGateway, "revoke: "+err.Error())
		return
	}
	// Audit at info level — Vault audits the revoke against the controller's
	// own k8s-auth identity; this line ties the action to the operator who
	// asked for it (id.Subject is the verified Falcon-ID sub).
	log.Printf("operator-cert revoked: serial=%s by=%s email=%s", serial, id.Subject, id.Email)
	writeJSON(w, http.StatusOK, OperatorCertRevokeResponse{
		Serial:    serial,
		RevokedAt: time.Now().UTC(),
	})
}

// normaliseSerial strips openssl-style colons + uppercases hex so the
// downstream Vault call doesn't choke on either input form. Empty in,
// empty out — handler validates non-empty.
func normaliseSerial(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':' || c == ' ':
			continue
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			out = append(out, c)
		case c >= 'a' && c <= 'f':
			out = append(out, c-32) // upper-case
		default:
			// Any non-hex (non-colon, non-space) character invalidates the
			// whole serial. Return empty so the handler rejects with 400.
			return ""
		}
	}
	// Re-insert colon separators between every byte (Vault accepts both
	// forms but the colon-separated form is what its audit log records,
	// so emit that for log-grep parity).
	if len(out) == 0 || len(out)%2 != 0 {
		return ""
	}
	withColons := make([]byte, 0, len(out)+len(out)/2)
	for i := 0; i < len(out); i += 2 {
		if i > 0 {
			withColons = append(withColons, ':')
		}
		withColons = append(withColons, out[i], out[i+1])
	}
	// Lower-case the hex back out — matches openssl x509 -serial default.
	for i := range withColons {
		if withColons[i] >= 'A' && withColons[i] <= 'F' {
			withColons[i] += 32
		}
	}
	return string(withColons)
}
