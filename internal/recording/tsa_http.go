// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

// tsa_http.go is the real RFC 3161 TimeStampProtocol client that the
// tsa.go scaffold (gap audit #8) deferred: it turns the NoopTSAClient
// stub into a working TSAClient so a WORM chain-head digest can be
// stamped by an external Time-Stamp Authority and the token persisted
// for later verification.
//
// It is built on github.com/digitorus/timestamp (the maintained OSS Go
// RFC 3161 implementation) rather than hand-rolled ASN.1/CMS: the
// library marshals the TimeStampReq from our pre-computed digest
// (Request.Marshal — no re-hashing), and ParseResponse verifies the
// CMS signature over the returned TimeStampToken when the TSA embeds
// its signing certificate.
//
// Trust posture. The client (a) binds the returned token to OUR request
// by checking the echoed messageImprint == the digest we sent and the
// nonce == the random nonce we generated (RFC 3161 §2.4.1 replay
// defence), and (b) OPTIONALLY validates the TSA signing chain against a
// configured root bundle (JESS_TSA_CA_FILE) with the timestamping EKU.
// The Ed25519 cross-session hash chain remains the load-bearing
// integrity layer; the TSA is external reinforcement, so a slow/absent
// TSA fails fast (short timeout) rather than blocking a session seal.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	// Register the digest algorithms so crypto.Hash.Available() is true
	// even if no other package in the binary pulls them in.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/digitorus/timestamp"
)

const (
	tsaContentTypeQuery = "application/timestamp-query"
	tsaContentTypeReply = "application/timestamp-reply"
	// DefaultTSATimeout bounds a single stamp round-trip. TSA is optional
	// reinforcement of the hash chain, so we fail fast rather than block a
	// seal on a slow authority.
	DefaultTSATimeout = 10 * time.Second
	// tsaNonceBits sizes the RFC 3161 §2.4.1 replay-detection nonce.
	tsaNonceBits = 96
	// tsaMaxResponseBytes caps the TSA reply we will read (a TimeStampResp
	// is a few KB; the cap stops a hostile/broken endpoint from streaming).
	tsaMaxResponseBytes = 1 << 20 // 1 MiB
)

// HTTPTSAClient is a real RFC 3161 TSAClient over HTTP.
type HTTPTSAClient struct {
	url       string
	hash      crypto.Hash
	policyOID asn1.ObjectIdentifier // optional requested TSA policy
	roots     *x509.CertPool        // optional; when set, the signing chain is verified
	http      *http.Client
}

// TSAConfig parameterises NewTSAClient.
type TSAConfig struct {
	// URL is the RFC 3161 TSA endpoint. Empty => NewTSAClient returns the
	// NoopTSAClient (feature off).
	URL string
	// Hash is the digest algorithm; 0 => SHA-256 (matches the chain's
	// sha256 row_hash).
	Hash crypto.Hash
	// PolicyOID, if set (dotted form, e.g. "1.3.6.1.4.1.4146.2.3"), requests
	// a specific TSA policy.
	PolicyOID string
	// CAFile is an optional PEM bundle; when set, the TSA signing chain is
	// verified against it (timestamping EKU) on every stamp.
	CAFile string
	// Timeout bounds one stamp round-trip; 0 => DefaultTSATimeout.
	Timeout time.Duration
}

// NewTSAClient builds a TSAClient from cfg. An empty URL yields the
// NoopTSAClient so callers can wire this unconditionally and let config
// decide whether stamping is active.
func NewTSAClient(cfg TSAConfig) (TSAClient, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return NoopTSAClient{}, nil
	}
	h := cfg.Hash
	if h == 0 {
		h = crypto.SHA256
	}
	if !h.Available() {
		return nil, fmt.Errorf("recording/tsa: hash %v unavailable (missing import)", h)
	}
	c := &HTTPTSAClient{
		url:  cfg.URL,
		hash: h,
		http: &http.Client{Timeout: firstDuration(cfg.Timeout, DefaultTSATimeout)},
	}
	if cfg.PolicyOID != "" {
		oid, err := parseDottedOID(cfg.PolicyOID)
		if err != nil {
			return nil, fmt.Errorf("recording/tsa: JESS_TSA_POLICY_OID %q: %w", cfg.PolicyOID, err)
		}
		c.policyOID = oid
	}
	if cfg.CAFile != "" {
		pemBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("recording/tsa: read JESS_TSA_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("recording/tsa: JESS_TSA_CA_FILE contained no PEM certificates")
		}
		c.roots = pool
	}
	return c, nil
}

// TSAClientFromEnv builds a TSAClient from JESS_TSA_* environment
// variables: JESS_TSA_URL (required to enable; empty => Noop),
// JESS_TSA_POLICY_OID, JESS_TSA_CA_FILE, JESS_TSA_TIMEOUT_SECONDS.
func TSAClientFromEnv() (TSAClient, error) {
	to := DefaultTSATimeout
	if s := os.Getenv("JESS_TSA_TIMEOUT_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			to = time.Duration(n) * time.Second
		}
	}
	return NewTSAClient(TSAConfig{
		URL:       os.Getenv("JESS_TSA_URL"),
		PolicyOID: os.Getenv("JESS_TSA_POLICY_OID"),
		CAFile:    os.Getenv("JESS_TSA_CA_FILE"),
		Timeout:   to,
	})
}

// Stamp submits req.Digest to the TSA and returns the verified token.
func (c *HTTPTSAClient) Stamp(ctx context.Context, req TSARequest) (TSAResponse, error) {
	if len(req.Digest) != c.hash.Size() {
		return TSAResponse{}, fmt.Errorf("recording/tsa: digest length %d != %s size %d",
			len(req.Digest), c.hash, c.hash.Size())
	}
	nonce, err := randomNonce()
	if err != nil {
		return TSAResponse{}, fmt.Errorf("recording/tsa: nonce: %w", err)
	}

	tsReq := &timestamp.Request{
		HashAlgorithm: c.hash,
		HashedMessage: req.Digest,
		Certificates:  true, // embed the signing cert so the token verifies offline
		Nonce:         nonce,
		TSAPolicyOID:  c.policyOID,
	}
	der, err := tsReq.Marshal()
	if err != nil {
		return TSAResponse{}, fmt.Errorf("recording/tsa: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(der))
	if err != nil {
		return TSAResponse{}, err
	}
	httpReq.Header.Set("Content-Type", tsaContentTypeQuery)
	httpReq.Header.Set("Accept", tsaContentTypeReply)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return TSAResponse{}, fmt.Errorf("recording/tsa: POST %s: %w", c.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, tsaMaxResponseBytes))
	if err != nil {
		return TSAResponse{}, fmt.Errorf("recording/tsa: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return TSAResponse{}, fmt.Errorf("recording/tsa: TSA returned HTTP %d", resp.StatusCode)
	}

	// ParseResponse decodes the TimeStampResp and verifies the CMS signature
	// over the token when the signing cert is embedded (it is — we asked).
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return TSAResponse{}, fmt.Errorf("recording/tsa: parse/verify response: %w", err)
	}

	// Bind the token to THIS request: a token whose messageImprint or nonce
	// doesn't echo ours is either for a different digest or a replay.
	if !bytes.Equal(ts.HashedMessage, req.Digest) {
		return TSAResponse{}, errors.New("recording/tsa: token messageImprint != request digest")
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return TSAResponse{}, errors.New("recording/tsa: token nonce mismatch (possible replay)")
	}
	// Optional: pin the TSA signing chain to a configured trust root.
	if c.roots != nil {
		if err := verifyTSAChain(ts.Certificates, c.roots, ts.Time); err != nil {
			return TSAResponse{}, fmt.Errorf("recording/tsa: signing-chain verify: %w", err)
		}
	}

	out := TSAResponse{
		Status:    TSAStatusGranted,
		Token:     ts.RawToken,
		GenTime:   ts.Time,
		PolicyOID: oidString(ts.Policy),
	}
	if ts.SerialNumber != nil {
		out.SerialNumber = ts.SerialNumber.Bytes()
	}
	if signer := timestampSigner(ts.Certificates); signer != nil {
		out.TSACertSerial = signer.SerialNumber.String()
	}
	return out, nil
}

// randomNonce returns a large random nonce for RFC 3161 replay detection.
func randomNonce() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), tsaNonceBits)
	return rand.Int(rand.Reader, limit)
}

// verifyTSAChain checks that some embedded certificate chains to a
// configured root with the timestamping EKU as of the token's genTime.
// Every embedded cert is offered as an intermediate so leaf/intermediate
// ordering in the CMS does not matter.
func verifyTSAChain(certs []*x509.Certificate, roots *x509.CertPool, at time.Time) error {
	if len(certs) == 0 {
		return errors.New("no TSA certificate embedded to verify")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		intermediates.AddCert(cert)
	}
	var lastErr error
	for _, leaf := range certs {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
			CurrentTime:   at,
		}); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("no embedded cert chains to a configured root with timestamping EKU: %w", lastErr)
}

// timestampSigner returns the embedded cert bearing the timestamping EKU
// (the TSA signing leaf), or the first cert as a fallback.
func timestampSigner(certs []*x509.Certificate) *x509.Certificate {
	for _, cert := range certs {
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageTimeStamping {
				return cert
			}
		}
	}
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// parseDottedOID parses a dotted OID string into an asn1.ObjectIdentifier.
func parseDottedOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid OID arc %q", p)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, errors.New("OID must have at least two arcs")
	}
	return oid, nil
}

// oidString renders an OID for audit/UI; empty for a nil OID.
func oidString(oid asn1.ObjectIdentifier) string {
	if len(oid) == 0 {
		return ""
	}
	return oid.String()
}

func firstDuration(a, b time.Duration) time.Duration {
	if a > 0 {
		return a
	}
	return b
}
