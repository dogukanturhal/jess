// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

func TestNewTSAClient_EmptyURLIsNoop(t *testing.T) {
	c, err := NewTSAClient(TSAConfig{URL: ""})
	if err != nil {
		t.Fatalf("NewTSAClient: %v", err)
	}
	if _, ok := c.(NoopTSAClient); !ok {
		t.Fatalf("empty URL must yield NoopTSAClient, got %T", c)
	}
}

func TestNewTSAClient_BadPolicyOID(t *testing.T) {
	if _, err := NewTSAClient(TSAConfig{URL: "http://tsa.example", PolicyOID: "1.x.3"}); err == nil {
		t.Fatal("expected error for a non-numeric policy OID")
	}
}

func TestHTTPTSAClient_DigestLengthMismatch(t *testing.T) {
	c, err := NewTSAClient(TSAConfig{URL: "http://tsa.example"}) // SHA-256 default
	if err != nil {
		t.Fatalf("NewTSAClient: %v", err)
	}
	// Wrong-length digest must fail before any network call.
	if _, err := c.Stamp(context.Background(), TSARequest{Digest: []byte("too-short")}); err == nil {
		t.Fatal("expected a digest-length error")
	}
}

func TestParseDottedOID(t *testing.T) {
	if _, err := parseDottedOID("1.3.6.1.4.1.4146.2.3"); err != nil {
		t.Fatalf("valid OID rejected: %v", err)
	}
	if _, err := parseDottedOID("1"); err == nil {
		t.Fatal("single-arc OID must error")
	}
	if _, err := parseDottedOID("1.x"); err == nil {
		t.Fatal("non-numeric arc must error")
	}
}

// TestHTTPTSAClient_RoundTripAgainstLocalTSA exercises the full client path
// against an in-test RFC 3161 responder built with the same library: request
// marshal → POST (correct content-type) → ParseResponse (CMS signature verify)
// → messageImprint + nonce binding → optional signing-chain pin → token fields.
func TestHTTPTSAClient_RoundTripAgainstLocalTSA(t *testing.T) {
	cert, key := genTimestampingCert(t)
	policy := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 3}

	var sawContentType string
	var sawDigest []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		parsed, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sawDigest = parsed.HashedMessage
		ts := timestamp.Timestamp{
			HashAlgorithm:     parsed.HashAlgorithm,
			HashedMessage:     parsed.HashedMessage,
			Time:              time.Now(),
			Nonce:             parsed.Nonce,
			Policy:            policy,
			Certificates:      []*x509.Certificate{cert},
			AddTSACertificate: true,
		}
		respDER, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", tsaContentTypeReply)
		_, _ = w.Write(respDER)
	}))
	defer srv.Close()

	c, err := NewTSAClient(TSAConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewTSAClient: %v", err)
	}
	// Exercise the optional signing-chain pin against our self-signed root.
	hc := c.(*HTTPTSAClient)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	hc.roots = pool

	digest := sha256.Sum256([]byte("chain-head-row-hash"))
	resp, err := hc.Stamp(context.Background(), TSARequest{Digest: digest[:]})
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}

	if sawContentType != tsaContentTypeQuery {
		t.Errorf("TSA saw Content-Type %q, want %q", sawContentType, tsaContentTypeQuery)
	}
	if !bytes.Equal(sawDigest, digest[:]) {
		t.Error("TSA received a digest different from the one we sent")
	}
	if resp.Status != TSAStatusGranted {
		t.Errorf("status=%v, want granted", resp.Status)
	}
	if len(resp.Token) == 0 {
		t.Error("empty timestamp token")
	}
	if resp.GenTime.IsZero() {
		t.Error("zero genTime")
	}
	if resp.PolicyOID != policy.String() {
		t.Errorf("policy=%q, want %q", resp.PolicyOID, policy.String())
	}
	if resp.TSACertSerial == "" {
		t.Error("missing TSA cert serial")
	}
}

// TestHTTPTSAClient_ChainPinRejectsUntrusted: a token signed by a cert that
// does NOT chain to the configured root is rejected even though its CMS
// signature is self-consistent.
func TestHTTPTSAClient_ChainPinRejectsUntrusted(t *testing.T) {
	signCert, signKey := genTimestampingCert(t)
	otherRoot, _ := genTimestampingCert(t) // a DIFFERENT, untrusted root

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ts := timestamp.Timestamp{
			HashAlgorithm:     parsed.HashAlgorithm,
			HashedMessage:     parsed.HashedMessage,
			Time:              time.Now(),
			Nonce:             parsed.Nonce,
			Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 4146, 2, 3},
			Certificates:      []*x509.Certificate{signCert},
			AddTSACertificate: true,
		}
		respDER, err := ts.CreateResponseWithOpts(signCert, signKey, crypto.SHA256)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", tsaContentTypeReply)
		_, _ = w.Write(respDER)
	}))
	defer srv.Close()

	c, err := NewTSAClient(TSAConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewTSAClient: %v", err)
	}
	hc := c.(*HTTPTSAClient)
	pool := x509.NewCertPool()
	pool.AddCert(otherRoot) // pin to a root the token does NOT chain to
	hc.roots = pool

	digest := sha256.Sum256([]byte("chain-head"))
	if _, err := hc.Stamp(context.Background(), TSARequest{Digest: digest[:]}); err == nil {
		t.Fatal("expected chain-verify rejection for an untrusted signing cert")
	}
}

// genTimestampingCert makes a self-signed cert (usable as its own root) with
// the timestamping EKU + private key, for the in-test TSA responder.
func genTimestampingCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "jess-test-tsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}
