// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devicecert verifies a HexxLock device leaf certificate presented
// over Envoy device-cert mTLS and forwarded to jess-controller as the
// X-Forwarded-Client-Cert (XFCC) header. It is the auth primitive for the
// silent-renewal endpoint (ADR 0048): a device that still holds a valid,
// unexpired, jess-device-ca-signed cert may renew it without OIDC/witness.
//
// This mirrors talon's posture-signer verifier (jess cannot import talon),
// keeping one canonical behaviour: XFCC-first (production behind Envoy),
// r.TLS fallback (dev/test), fail-closed on a malformed XFCC.
package devicecert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SPIFFEPrefix is the device-identity SPIFFE SAN prefix (ADR 0040 D-005):
// spiffe://hexxlock.com/device/<device-uuid>.
const SPIFFEPrefix = "spiffe://hexxlock.com/device/"

// Sentinel errors — callers map these to HTTP status codes.
var (
	ErrNoCert         = errors.New("devicecert: no client certificate presented")
	ErrChainInvalid   = errors.New("devicecert: certificate chain validation failed")
	ErrExpired        = errors.New("devicecert: certificate is expired")
	ErrMissingEKU     = errors.New("devicecert: certificate missing ClientAuth EKU")
	ErrSANMissing     = errors.New("devicecert: no spiffe://hexxlock.com/device/* SAN URI")
	ErrXFCCMissing    = errors.New("devicecert: X-Forwarded-Client-Cert header absent")
	ErrXFCCMalformed  = errors.New("devicecert: X-Forwarded-Client-Cert is malformed")
	ErrXFCCMissingCrt = errors.New("devicecert: X-Forwarded-Client-Cert lacks Cert= field")
)

// Verifier validates the device leaf against the jess-device-ca pool and
// extracts its SPIFFE device-UUID + CN (user_sub).
type Verifier struct {
	pool *x509.CertPool
	now  func() time.Time
}

// NewVerifier builds a Verifier backed by the jess-device-ca trust pool.
func NewVerifier(pool *x509.CertPool) (*Verifier, error) {
	if pool == nil {
		return nil, errors.New("devicecert: nil trust pool")
	}
	return &Verifier{pool: pool, now: time.Now}, nil
}

// Identity is the verified device identity extracted from the leaf.
type Identity struct {
	Leaf       *x509.Certificate
	DeviceUUID string // from the SPIFFE SAN
	UserSub    string // from the leaf CN
	SPIFFE     string // full spiffe:// URI
}

// VerifyRequest extracts the device cert from XFCC (production) or r.TLS
// (dev/test), validates chain + EKU + expiry, and returns the identity.
func (v *Verifier) VerifyRequest(r *http.Request) (*Identity, error) {
	if r == nil {
		return nil, errors.New("devicecert: nil request")
	}
	if xfcc := r.Header.Get("X-Forwarded-Client-Cert"); xfcc != "" {
		leaf, err := parseXFCC(xfcc)
		if err != nil {
			return nil, err // fail closed — do NOT fall back to r.TLS
		}
		return v.verify(leaf)
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, ErrNoCert
	}
	return v.verify(r.TLS.PeerCertificates[0])
}

func (v *Verifier) verify(leaf *x509.Certificate) (*Identity, error) {
	if !hasClientAuth(leaf) {
		return nil, fmt.Errorf("%w: CN=%q", ErrMissingEKU, leaf.Subject.CommonName)
	}
	opts := x509.VerifyOptions{
		Roots:       v.pool,
		CurrentTime: v.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		var ce x509.CertificateInvalidError
		if errors.As(err, &ce) && ce.Reason == x509.Expired {
			return nil, fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrChainInvalid, err)
	}
	spiffe, err := extractSPIFFE(leaf)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Leaf:       leaf,
		DeviceUUID: strings.TrimPrefix(spiffe, SPIFFEPrefix),
		UserSub:    leaf.Subject.CommonName,
		SPIFFE:     spiffe,
	}, nil
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func extractSPIFFE(c *x509.Certificate) (string, error) {
	var found []string
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" && u.Host == "hexxlock.com" && strings.HasPrefix(u.Path, "/device/") {
			found = append(found, u.String())
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", fmt.Errorf("%w in cert CN=%q", ErrSANMissing, c.Subject.CommonName)
	default:
		return "", fmt.Errorf("%w: %d device SPIFFE URIs (ambiguous)", ErrSANMissing, len(found))
	}
}

// parseXFCC extracts the leaf cert from an Envoy XFCC header (last element,
// Cert= URL-encoded PEM). Mirrors talon posture-signer ParseXFCC.
func parseXFCC(header string) (*x509.Certificate, error) {
	if strings.TrimSpace(header) == "" {
		return nil, ErrXFCCMissing
	}
	fields, err := parseElement(lastElement(header))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrXFCCMalformed, err)
	}
	enc, ok := fields["cert"]
	if !ok || enc == "" {
		return nil, ErrXFCCMissingCrt
	}
	decoded, err := url.QueryUnescape(enc)
	if err != nil {
		return nil, fmt.Errorf("%w: url-decode Cert=: %w", ErrXFCCMalformed, err)
	}
	block, _ := pem.Decode([]byte(decoded))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: Cert= is not a CERTIFICATE PEM", ErrXFCCMalformed)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: x509 parse: %w", ErrXFCCMalformed, err)
	}
	return leaf, nil
}

// lastElement returns the last comma-separated XFCC element, ignoring
// commas inside double-quoted regions (Subject= DER can contain commas).
func lastElement(h string) string {
	h = strings.TrimSpace(h)
	depth, start := 0, 0
	for i := 0; i < len(h); i++ {
		switch h[i] {
		case '"':
			depth ^= 1
		case ',':
			if depth == 0 {
				start = i + 1
			}
		}
	}
	return strings.TrimSpace(h[start:])
}

// parseElement parses one XFCC element (semicolon-separated key=value),
// lowercasing keys and stripping surrounding quotes from values.
func parseElement(el string) (map[string]string, error) {
	out := make(map[string]string, 7)
	depth, start := 0, 0
	var pairs []string
	for i := 0; i < len(el); i++ {
		switch el[i] {
		case '"':
			depth ^= 1
		case ';':
			if depth == 0 {
				pairs = append(pairs, el[start:i])
				start = i + 1
			}
		}
	}
	pairs = append(pairs, el[start:])
	for _, p := range pairs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("malformed pair %q", p)
		}
		k := strings.ToLower(strings.TrimSpace(p[:eq]))
		val := strings.TrimSpace(p[eq+1:])
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		out[k] = val
	}
	return out, nil
}

// ConnState wraps a leaf into a tls.ConnectionState for callers that want
// to reuse standard-library shapes in tests.
func ConnState(leaf *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
}
