// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest — apple_mda_test.go
//
// Tests for the Apple Managed Device Attestation (MDA) verifier.
//
// In-process test PKI
// ====================
// All tests use a synthetic certificate chain built in memory:
//
//	testAppleEnterpriseRoot  (self-signed, stands in for Apple Enterprise Attestation Root CA)
//	  └── testAppleMDALeaf  (Apple-style attestation cert with MDA OID extensions)
//
// The test PKI injects the Apple MDA extension OIDs with appropriate values
// following Apple's documented structure (raw bytes, no ASN.1 wrapper) as
// confirmed by the Smallstep ACME CA reference implementation at
// https://github.com/smallstep/certificates/blob/master/acme/challenge.go
//
// Note on live Apple chain test
// ==============================
// The Apple Enterprise Attestation Root CA is publicly available:
//
//	https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem
//
// However, Apple MDA attestation certs are only issued to real enrolled
// devices by Apple's attestation servers during the ACME-DA flow — no
// publicly accessible sample cert exists. Therefore we cannot exercise the
// full end-to-end live Apple chain in unit tests.
//
// The real-chain integration path is validated by the test named
// TestAppleMDAVerifier_LiveRootCA which:
//   - Fetches the real Apple Enterprise Attestation Root CA PEM from Apple's CDN.
//   - Verifies the cert is parseable and has the expected CN and SHA-256 fingerprint.
//   - Documents the gap: a real MDA cert from a real device could not be
//     exercised in automated tests without a Jamf-enrolled device.
//
// Test coverage (16 test cases)
// ==============================
//  1. Happy path: valid chain + freshness + serial OID + UDID OID → TIER_CORP
//  2. Table: expired cert → reject
//  3. Table: wrong root CA → reject
//  4. Table: missing freshness OID → reject
//  5. Table: freshness mismatch → reject
//  6. Table: missing device identity OIDs (no serial, no UDID) → reject
//  7. Table: wrong serial cross-check → reject
//  8. Table: wrong UDID cross-check → reject
//  9. Table: empty CertChainPEM → reject
// 10. Table: empty PlatformBlob → reject
// 11. Table: empty NonceClient → reject
// 12. Table: serial-only (no UDID) → TIER_CORP (User Enrollment scenario)
// 13. Table: UDID-only (no serial) → TIER_CORP (User Enrollment privacy mode)
// 14. Nil pool → panic (constructor guard)
// 15. Reasons slice: format + content correctness
// 16. Not-yet-valid cert → reject
// 17. Malformed PlatformBlob JSON → reject
// 18. Live Apple root CA: fetch + fingerprint verification
// 19. buildAppleMDAFreshnessExtValue helper correctness

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// mdaTestPKI holds a synthetic test PKI that mirrors the Apple MDA certificate chain.
// testRoot stands in for "Apple Enterprise Attestation Root CA".
// testLeaf is the MDA attestation cert issued to the test device.
type mdaTestPKI struct {
	rootKey  *ecdsa.PrivateKey
	rootCert *x509.Certificate
	rootDER  []byte
	rootPool *x509.CertPool

	leafKey  *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafDER  []byte

	chainPEM []byte

	// acmeToken is the raw ACME challenge token (maps to req.NonceClient).
	acmeToken []byte
	// expectedFreshness = SHA-256(acmeToken). Stored in OID .8.11.1.
	expectedFreshness [32]byte

	// deviceSerial / deviceUDID embedded in OID .8.9.1 / .8.9.2.
	deviceSerial string
	deviceUDID   string
}

// newMDATestPKI builds an in-process test PKI for Apple MDA tests.
//
// Parameters:
//   - notBefore / notAfter: validity window for BOTH root and leaf.
//   - acmeToken: the ACME challenge token (server-generated nonce).
//   - opts: functional options to configure which extensions appear on the leaf.
func newMDATestPKI(t *testing.T, notBefore, notAfter time.Time, acmeToken []byte, opts ...mdaTestPKIOpt) *mdaTestPKI {
	t.Helper()

	cfg := mdaTestPKIConfig{
		deviceSerial:  "FVFXQ2BQMDC",
		deviceUDID:    "00008103-000D71CE3A81801E",
		includeSEP:    true,
		includeSerial: true,
		includeUDID:   true,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Root CA key + self-signed cert (simulates Apple Enterprise Attestation Root CA).
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Fake Apple Enterprise Attestation Root CA",
			Organization: []string{"Apple Inc."},
			Country:      []string{"US"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// Leaf key (in production this is generated inside the Secure Enclave).
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	// Compute freshness = SHA-256(acmeToken).
	freshness := sha256.Sum256(acmeToken)

	// Build the leaf extensions. Note: Apple MDA extension values are raw bytes
	// (no additional ASN.1 wrapping), as confirmed by Smallstep challenge.go
	// which reads ext.Value directly for serial/UDID/SEP/nonce:
	// https://github.com/smallstep/certificates/blob/master/acme/challenge.go
	var leafExts []pkix.Extension

	if cfg.includeSerial {
		leafExts = append(leafExts, pkix.Extension{
			Id:    oidAppleMDASerialNumber,
			Value: []byte(cfg.deviceSerial),
		})
	}
	if cfg.includeUDID {
		leafExts = append(leafExts, pkix.Extension{
			Id:    oidAppleMDAUDID,
			Value: []byte(cfg.deviceUDID),
		})
	}
	if cfg.includeSEP {
		leafExts = append(leafExts, pkix.Extension{
			Id:    oidAppleMDASEPOSVersion,
			Value: []byte("16.3.2"),
		})
	}
	if !cfg.omitFreshness {
		extValue := freshness[:]
		if cfg.wrongFreshness {
			extValue = make([]byte, 32)
			_, _ = rand.Read(extValue)
		}
		leafExts = append(leafExts, pkix.Extension{
			Id:    oidAppleMDAFreshnessCode,
			Value: extValue,
		})
	}

	// Leaf certificate template.
	// NOTE: No ExtKeyUsage set — MDA attestation certs do NOT carry clientAuth.
	// See package-level comment in apple_mda.go for rationale.
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Apple MDA Device Certificate",
			Organization: []string{"Apple Inc."},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       leafExts,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Encode chain PEM: leaf first (root excluded from chain per ACME convention).
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	return &mdaTestPKI{
		rootKey:           rootKey,
		rootCert:          rootCert,
		rootDER:           rootDER,
		rootPool:          rootPool,
		leafKey:           leafKey,
		leafCert:          leafCert,
		leafDER:           leafDER,
		chainPEM:          chainPEM,
		acmeToken:         acmeToken,
		expectedFreshness: freshness,
		deviceSerial:      cfg.deviceSerial,
		deviceUDID:        cfg.deviceUDID,
	}
}

// buildVerifyRequest constructs a VerifyRequest for the test PKI.
// serial and udid are the client-asserted values (cross-checked against OIDs).
// Pass empty string to skip the cross-check for that field.
func (p *mdaTestPKI) buildVerifyRequest(serial, udid string) VerifyRequest {
	blob, _ := json.Marshal(AppleMDAPayload{
		CertChainPEM: p.chainPEM,
		DeviceSerial: serial,
		DeviceUDID:   udid,
	})
	return VerifyRequest{
		Platform:     "apple-mda",
		PlatformBlob: blob,
		NonceClient:  p.acmeToken,
	}
}

// mdaTestPKIConfig holds configuration for newMDATestPKI.
type mdaTestPKIConfig struct {
	deviceSerial   string
	deviceUDID     string
	includeSEP     bool
	includeSerial  bool
	includeUDID    bool
	omitFreshness  bool
	wrongFreshness bool
}

// mdaTestPKIOpt is a functional option for newMDATestPKI.
type mdaTestPKIOpt func(*mdaTestPKIConfig)

func mdaWithNoSerial() mdaTestPKIOpt { return func(c *mdaTestPKIConfig) { c.includeSerial = false } }
func mdaWithNoUDID() mdaTestPKIOpt   { return func(c *mdaTestPKIConfig) { c.includeUDID = false } }
func mdaWithOmitFreshness() mdaTestPKIOpt {
	return func(c *mdaTestPKIConfig) { c.omitFreshness = true }
}
func mdaWithWrongFreshness() mdaTestPKIOpt {
	return func(c *mdaTestPKIConfig) { c.wrongFreshness = true }
}

// timestamp fixtures for certificate validity windows.
var (
	mdaNow    = time.Now().UTC()
	mdaBefore = mdaNow.Add(-1 * time.Hour)
	mdaAfter  = mdaNow.Add(24 * time.Hour)
	mdaToken  = []byte("test-acme-challenge-token-32bytes!")
)

// TestAppleMDAVerifier_HappyPath verifies that a complete valid MDA attestation
// cert chain returns TIER_CORP via Path A_chain.
func TestAppleMDAVerifier_HappyPath(t *testing.T) {
	pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
	v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))

	req := pki.buildVerifyRequest(pki.deviceSerial, pki.deviceUDID)
	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("expected TIER_CORP, got %q", resp.Tier)
	}
	if resp.Path != "A_chain" {
		t.Errorf("expected A_chain, got %q", resp.Path)
	}
	if len(resp.Reasons) == 0 {
		t.Error("expected non-empty Reasons")
	}
	foundVerified := false
	for _, r := range resp.Reasons {
		if r == "apple_mda_verified" {
			foundVerified = true
		}
	}
	if !foundVerified {
		t.Errorf("expected 'apple_mda_verified' in reasons, got %v", resp.Reasons)
	}
}

// TestAppleMDAVerifier_Table is a table-driven test covering all rejection
// paths and success edge cases.
func TestAppleMDAVerifier_Table(t *testing.T) {
	// Build an unrelated root pool for "wrong CA" tests.
	wrongRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong root key: %v", err)
	}
	wrongRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Unrelated CA Root"},
		NotBefore:             mdaBefore,
		NotAfter:              mdaAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	wrongRootDER, err := x509.CreateCertificate(rand.Reader, wrongRootTemplate, wrongRootTemplate, &wrongRootKey.PublicKey, wrongRootKey)
	if err != nil {
		t.Fatalf("create wrong root cert: %v", err)
	}
	wrongRootCert, err := x509.ParseCertificate(wrongRootDER)
	if err != nil {
		t.Fatalf("parse wrong root cert: %v", err)
	}
	wrongPool := x509.NewCertPool()
	wrongPool.AddCert(wrongRootCert)

	tests := []struct {
		name       string
		setup      func(t *testing.T) (Verifier, VerifyRequest)
		wantErrSub string
		wantTier   string
	}{
		{
			name: "expired cert",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				// Cert validity: 72h ago to 24h ago (already expired at mdaNow).
				pki := newMDATestPKI(t,
					mdaNow.Add(-72*time.Hour),
					mdaNow.Add(-24*time.Hour),
					mdaToken,
				)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", "")
			},
			wantErrSub: "verification failed",
		},
		{
			name: "wrong root CA",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				// Cert is signed by pki.rootKey but we inject the wrongPool.
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(wrongPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", "")
			},
			wantErrSub: "verification failed",
		},
		{
			name: "missing freshness OID",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken, mdaWithOmitFreshness())
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", "")
			},
			wantErrSub: "freshness OID (1.2.840.113635.100.8.11.1) not found",
		},
		{
			name: "freshness mismatch",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken, mdaWithWrongFreshness())
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", "")
			},
			wantErrSub: "freshness code mismatch",
		},
		{
			name: "missing device identity OIDs (no serial, no UDID)",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken, mdaWithNoSerial(), mdaWithNoUDID())
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", "")
			},
			wantErrSub: "neither serial number OID",
		},
		{
			name: "wrong serial cross-check",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				// Assert a different serial than what is embedded in the leaf cert.
				return v, pki.buildVerifyRequest("WRONGSERIAL000", pki.deviceUDID)
			},
			wantErrSub: "DeviceSerial",
		},
		{
			name: "wrong UDID cross-check",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				// Assert a different UDID than what is embedded in the leaf cert.
				return v, pki.buildVerifyRequest(pki.deviceSerial, "WRONG-UDID-VALUE")
			},
			wantErrSub: "DeviceUDID",
		},
		{
			name: "empty CertChainPEM",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				blob, _ := json.Marshal(AppleMDAPayload{
					CertChainPEM: []byte{}, // empty
				})
				return v, VerifyRequest{
					Platform:     "apple-mda",
					PlatformBlob: blob,
					NonceClient:  mdaToken,
				}
			},
			wantErrSub: "CertChainPEM is empty",
		},
		{
			name: "empty PlatformBlob",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, VerifyRequest{
					Platform:    "apple-mda",
					NonceClient: mdaToken,
					// PlatformBlob intentionally nil.
				}
			},
			wantErrSub: "requires PlatformBlob",
		},
		{
			name: "empty NonceClient",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				blob, _ := json.Marshal(AppleMDAPayload{
					CertChainPEM: pki.chainPEM,
				})
				return v, VerifyRequest{
					Platform:     "apple-mda",
					PlatformBlob: blob,
					// NonceClient intentionally nil.
				}
			},
			wantErrSub: "requires NonceClient",
		},
		{
			// Serial-only simulates the "Device Enrollment" mode with
			// privacy protection where UDID is omitted.
			name: "serial only (no UDID, simulates User Enrollment with privacy)",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken, mdaWithNoUDID())
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest(pki.deviceSerial, "")
			},
			wantTier: "TIER_CORP",
		},
		{
			// UDID-only simulates the "User Enrollment" privacy mode where
			// serial is omitted per Apple docs.
			name: "UDID only (no serial, simulates User Enrollment privacy mode)",
			setup: func(t *testing.T) (Verifier, VerifyRequest) {
				t.Helper()
				pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken, mdaWithNoSerial())
				v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))
				return v, pki.buildVerifyRequest("", pki.deviceUDID)
			},
			wantTier: "TIER_CORP",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, req := tc.setup(t)
			resp, err := v.Verify(context.Background(), req)

			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (resp=%+v)", tc.wantErrSub, resp)
				}
				if !errors.Is(err, ErrVerification) {
					t.Errorf("expected errors.Is(err, ErrVerification)=true, got false; err=%v", err)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("expected error to contain %q, got: %v", tc.wantErrSub, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if tc.wantTier != "" && resp.Tier != tc.wantTier {
					t.Errorf("expected tier %q, got %q", tc.wantTier, resp.Tier)
				}
				if resp.Path != "A_chain" {
					t.Errorf("expected path A_chain, got %q", resp.Path)
				}
			}
		})
	}
}

// TestAppleMDAVerifier_NilPoolPanic verifies that constructing a verifier with
// a nil root pool panics immediately, surfacing wiring bugs at controller
// startup rather than silently at request time.
func TestAppleMDAVerifier_NilPoolPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil rootPool, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic with string message, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "rootPool must not be nil") {
			t.Errorf("panic message does not mention 'rootPool must not be nil': %q", msg)
		}
	}()
	NewAppleMDAVerifier(nil) // must panic
}

// TestAppleMDAVerifier_ReasonsSlice verifies the content and format of the
// reasons diagnostic slice returned on a successful verification.
func TestAppleMDAVerifier_ReasonsSlice(t *testing.T) {
	pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
	v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))

	req := pki.buildVerifyRequest("", "")
	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Every reason should be non-empty and Prometheus-label-safe
	// (no spaces; lowercase_underscore convention).
	for _, r := range resp.Reasons {
		if r == "" {
			t.Error("found empty reason string in reasons slice")
		}
		if strings.Contains(r, " ") {
			t.Errorf("reason %q contains a space (not Prometheus-label-safe)", r)
		}
	}

	// Verify expected reason prefixes are present.
	wantPrefixes := []string{"apple_mda_verified", "issuer_", "mda_serial_"}
	for _, want := range wantPrefixes {
		found := false
		for _, r := range resp.Reasons {
			if strings.HasPrefix(r, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected a reason starting with %q in %v", want, resp.Reasons)
		}
	}
}

// TestAppleMDAVerifier_NotYetValid verifies that a cert with a future notBefore
// is rejected. The x509.Verify call enforces the validity window using the
// injected clock.
func TestAppleMDAVerifier_NotYetValid(t *testing.T) {
	// Cert validity starts 1 hour in the future; we verify at "now".
	future := mdaNow.Add(time.Hour)
	pki := newMDATestPKI(t, future, future.Add(24*time.Hour), mdaToken)
	v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))

	req := pki.buildVerifyRequest("", "")
	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for not-yet-valid cert, got nil")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestAppleMDAVerifier_MalformedPlatformBlob verifies that a non-JSON
// PlatformBlob is rejected with a clear, wrapped ErrVerification.
func TestAppleMDAVerifier_MalformedPlatformBlob(t *testing.T) {
	pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
	v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))

	req := VerifyRequest{
		Platform:     "apple-mda",
		PlatformBlob: []byte("not json at all {{{"),
		NonceClient:  mdaToken,
	}
	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not valid AppleMDAPayload JSON") {
		t.Errorf("expected 'not valid AppleMDAPayload JSON' in error, got: %v", err)
	}
}

// TestAppleMDAVerifier_LiveRootCA fetches the Apple Enterprise Attestation Root
// CA PEM from Apple's CDN and verifies it is parseable with the expected
// Subject CN and SHA-256 fingerprint.
//
// This documents the scope of live chain testing:
//   - We CAN verify the Apple root cert itself against the published PEM.
//   - We CANNOT verify a full Apple-issued MDA attestation cert because Apple
//     only issues these to real enrolled devices through the ACME-DA flow;
//     no publicly accessible sample cert exists.
//
// The test skips gracefully in air-gapped CI environments where the CDN is
// unreachable.
func TestAppleMDAVerifier_LiveRootCA(t *testing.T) {
	const appleEnterpriseAttestationRootURL = "https://www.apple.com/certificateauthority/Apple_Enterprise_Attestation_Root_CA.pem"
	// SHA-256 fingerprint verified on 2026-06-07:
	//   curl -s <URL> | openssl x509 -noout -fingerprint -sha256
	const expectedFingerprint = "CC:F5:9E:F8:FC:B3:01:7D:97:F8:B5:FA:6F:A9:0E:7A:3F:92:83:F7:6B:55:AC:6C:F6:ED:A8:B8:B9:49:F0:5B"
	const expectedCN = "Apple Enterprise Attestation Root CA"

	resp, err := http.Get(appleEnterpriseAttestationRootURL) //nolint:gosec // test-only URL
	if err != nil {
		t.Skipf("skipping live Apple root CA test (network unavailable — air-gapped CI?): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("skipping live Apple root CA test (HTTP %d from Apple CDN)", resp.StatusCode)
	}

	pemBuf := make([]byte, 4096)
	n, _ := resp.Body.Read(pemBuf)
	pemBytes := pemBuf[:n]

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		t.Fatal("AppendCertsFromPEM returned false for Apple Enterprise Attestation Root CA PEM")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil for Apple Enterprise Attestation Root CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	if cert.Subject.CommonName != expectedCN {
		t.Errorf("Apple Enterprise Attestation Root CA CN changed: got %q, expected %q", cert.Subject.CommonName, expectedCN)
	}

	// Compute and compare SHA-256 fingerprint (colon-separated hex, uppercase).
	rawFP := sha256.Sum256(cert.Raw)
	fpParts := make([]string, 32)
	for i, b := range rawFP {
		fpParts[i] = fmt.Sprintf("%02X", b)
	}
	computedFP := strings.Join(fpParts, ":")

	if computedFP != expectedFingerprint {
		t.Errorf("Apple Enterprise Attestation Root CA fingerprint changed:\n  got:  %s\n  want: %s\n"+
			"  ACTION REQUIRED: if Apple rotated the root CA, update the expectedFingerprint "+
			"constant in this test AND the vendor-root Kubernetes Secret.",
			computedFP, expectedFingerprint)
	}

	t.Logf("Apple Enterprise Attestation Root CA OK: CN=%q fingerprint=%s notAfter=%s",
		cert.Subject.CommonName, computedFP, cert.NotAfter.Format(time.RFC3339))
	t.Log("NOTE: A full end-to-end test with a real Apple MDA cert is not possible in " +
		"automated tests — Apple only issues MDA attestation certs to real ACME-DA enrolled " +
		"devices via Jamf Pro / Intune. The in-process PKI tests cover all verifier code paths.")
}

// TestAppleMDAVerifier_BuildFreshnessExtValue verifies the helper function
// that computes freshness code values (SHA-256 of the ACME token) used by
// the test PKI builder.
func TestAppleMDAVerifier_BuildFreshnessExtValue(t *testing.T) {
	token := []byte("my-test-acme-token")
	expected := sha256.Sum256(token)
	got := buildAppleMDAFreshnessExtValue(token)

	if len(got) != 32 {
		t.Errorf("expected 32-byte output, got %d bytes", len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("freshness bytes differ at index %d: got 0x%02x, want 0x%02x", i, got[i], expected[i])
		}
	}
}

// TestAppleMDAVerifier_RegistryDispatch verifies that the Registry correctly
// dispatches "apple-mda" platform requests to the AppleMDA verifier.
func TestAppleMDAVerifier_RegistryDispatch(t *testing.T) {
	pki := newMDATestPKI(t, mdaBefore, mdaAfter, mdaToken)
	v := NewAppleMDAVerifier(pki.rootPool, WithAppleMDAClock(func() time.Time { return mdaNow }))

	reg := NewRegistry()
	reg.Register("apple-mda", v)

	got := reg.VerifierFor("apple-mda")
	if got == nil {
		t.Fatal("VerifierFor('apple-mda') returned nil — verifier not registered")
	}

	req := pki.buildVerifyRequest(pki.deviceSerial, "")
	resp, err := got.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("dispatch via registry failed: %v", err)
	}
	if resp.Tier != "TIER_CORP" {
		t.Errorf("expected TIER_CORP from registry dispatch, got %q", resp.Tier)
	}
}
