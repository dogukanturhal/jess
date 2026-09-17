// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// mdmTestPKI holds a CA + a leaf client cert simulating an MDM identity cert.
type mdmTestPKI struct {
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	caDER    []byte
	caPool   *x509.CertPool
	leafKey  *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafDER  []byte
	chainPEM []byte
}

// newMDMTestPKI builds:
//   - A self-signed MDM CA cert.
//   - A leaf client cert signed by the CA, with id-kp-clientAuth in ExtKeyUsage
//     and a non-empty CN (simulating Jamf/Kandji/Mosyle identity cert).
func newMDMTestPKI(t *testing.T, notBefore, notAfter time.Time, deviceCN string) *mdmTestPKI {
	t.Helper()

	// CA key + cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test MDM CA Root"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Leaf client cert with id-kp-clientAuth.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: deviceCN},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	// Encode chain PEM: leaf first, CA last (chain including root for completeness).
	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)

	return &mdmTestPKI{
		caKey:    caKey,
		caCert:   caCert,
		caDER:    caDER,
		caPool:   caPool,
		leafKey:  leafKey,
		leafCert: leafCert,
		leafDER:  leafDER,
		chainPEM: chainPEM,
	}
}

// makeMDMPayload marshals a MacOSMDMPayload to JSON.
func makeMDMPayload(t *testing.T, chainPEM []byte) []byte {
	t.Helper()
	p := MacOSMDMPayload{ClientCertPEM: chainPEM}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal MacOSMDMPayload: %v", err)
	}
	return b
}

// -- tests ------------------------------------------------------------------

func TestMacOSMDM_ValidCert_TIER_BYOD(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "MacBook-Pro-AB1234")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, pki.chainPEM),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("valid MDM cert verification failed: %v", err)
	}
	// MDM is TIER_BYOD, NOT TIER_CORP.
	if resp.Tier != "TIER_BYOD" {
		t.Errorf("Tier = %q, want TIER_BYOD", resp.Tier)
	}
	if resp.Path != "B_tofu" {
		t.Errorf("Path = %q, want B_tofu", resp.Path)
	}
	// Check 'macos_mdm_cert_verified' in reasons.
	found := false
	for _, r := range resp.Reasons {
		if r == "macos_mdm_cert_verified" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'macos_mdm_cert_verified' in Reasons: %v", resp.Reasons)
	}
}

// TestMacOSMDM_NoClientAuthEKU_Rejected verifies that a cert without
// id-kp-clientAuth in ExtKeyUsage is rejected, even if it chains to the MDM CA.
// This prevents non-MDM certs (server, code-signing) from being accepted.
func TestMacOSMDM_NoClientAuthEKU_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	// Build a CA + leaf cert WITHOUT ExtKeyUsage (no clientAuth).
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MDM CA No EKU"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// No ExtKeyUsage field — missing id-kp-clientAuth.
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Device-Without-ClientAuth"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// ExtKeyUsage intentionally omitted.
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)

	v := NewMacOSMDMVerifier(caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cert without id-kp-clientAuth")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_EmptyCN_Rejected verifies that a cert with an empty
// Subject CommonName is rejected — MDM identity certs always have a CN.
func TestMacOSMDM_EmptyCN_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MDM CA Empty CN Test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// CN is empty string — rejected by guard 4.
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: ""}, // empty CN
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)

	v := NewMacOSMDMVerifier(caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty Subject CommonName")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_WrongCA_Rejected verifies that a cert chaining to a different
// CA (not the org's MDM CA) is rejected.
func TestMacOSMDM_WrongCA_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pkiA := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "DeviceA")
	pkiB := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "DeviceB")

	// Use pkiB's root pool but pkiA's cert.
	v := NewMacOSMDMVerifier(pkiB.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, pkiA.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cert from wrong CA")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_ExpiredCert_Rejected verifies that an expired MDM cert is
// rejected.
func TestMacOSMDM_ExpiredCert_Rejected(t *testing.T) {
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	pki := newMDMTestPKI(t, past, certNotAfter, "ExpiredDevice")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, pki.chainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired MDM certificate")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_MissingPlatformBlob_Rejected verifies guard condition.
func TestMacOSMDM_MissingPlatformBlob_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "Device123")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform: "macos-mdm",
		// PlatformBlob: nil
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_InvalidJSON_Rejected verifies that non-JSON PlatformBlob is
// rejected.
func TestMacOSMDM_InvalidJSON_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "Device123")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: []byte("not json"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for non-JSON PlatformBlob")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_InvalidPEMContent_Rejected verifies that a PEM payload with
// invalid cert DER is rejected during chain parse.
func TestMacOSMDM_InvalidPEMContent_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "Device123")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	// Valid PEM block type but garbled DER bytes.
	garbledPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid DER certificate"),
	})

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, garbledPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid DER in PEM")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

// TestMacOSMDM_SelfSignedCert_Rejected verifies that a self-signed MDM-style
// cert (valid EKU + CN) is rejected when it doesn't chain to the MDM root pool.
func TestMacOSMDM_SelfSignedCert_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "OtherDevice")

	// Build a self-signed cert with clientAuth EKU — valid format but not
	// in our MDM CA root pool.
	selfKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	selfTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "SelfSignedDevice"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	selfDER, _ := x509.CreateCertificate(rand.Reader, selfTemplate, selfTemplate, &selfKey.PublicKey, selfKey)
	selfChainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfDER})

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, selfChainPEM),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for self-signed cert not in MDM root pool")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewMacOSMDMVerifier_NilPool_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil mdmRootPool")
		}
	}()
	NewMacOSMDMVerifier(nil)
}

// TestMacOSMDM_TierIsByod verifies that even a fully valid MDM cert produces
// TIER_BYOD, not TIER_CORP — the ceiling is explicitly BYOD per ADR 0040 D-006.
func TestMacOSMDM_TierIsByod(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	pki := newMDMTestPKI(t, now.Add(-time.Hour), now.Add(24*time.Hour), "CorporateMacBookPro")

	v := NewMacOSMDMVerifier(pki.caPool, WithMacOSMDMClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:     "macos-mdm",
		PlatformBlob: makeMDMPayload(t, pki.chainPEM),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("MDM verification failed: %v", err)
	}
	if resp.Tier != "TIER_BYOD" {
		t.Errorf("Tier = %q, want TIER_BYOD (MDM is BYOD ceiling per ADR 0040 D-006)", resp.Tier)
	}
	// Verify device CN is sanitized and included in reasons.
	found := false
	for _, r := range resp.Reasons {
		if r == "mdm_device_cn_corporatemacbookpro" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'mdm_device_cn_corporatemacbookpro' in Reasons: %v", resp.Reasons)
	}
}
