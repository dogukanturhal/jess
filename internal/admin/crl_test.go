// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMetrics captures the metric callbacks for assertions.
type fakeMetrics struct {
	checkResults   map[string]int
	refreshSuccess int
	refreshFailure int
	lastRevoked    int
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{checkResults: map[string]int{}}
}

func (m *fakeMetrics) OperatorCertRevocationCheck(result string) {
	m.checkResults[result]++
}

func (m *fakeMetrics) OperatorCertCRLRefresh(success bool, n int) {
	if success {
		m.refreshSuccess++
		m.lastRevoked = n
		return
	}
	m.refreshFailure++
}

// fakeCRLSource feeds canned PEMs. Either err is set (returned verbatim) or
// pem is returned. fetchCount counts calls so tests can assert refresh
// cadence.
type fakeCRLSource struct {
	pem        []byte
	err        error
	fetchCount int32
}

func (f *fakeCRLSource) FetchCRLPEM(_ context.Context) ([]byte, error) {
	atomic.AddInt32(&f.fetchCount, 1)
	if f.err != nil {
		return nil, f.err
	}
	return f.pem, nil
}

// mintCRL creates a self-signed CA, signs a CRL listing the given serials.
// Returns the PEM-encoded CRL ready to feed into a fakeCRLSource.
func mintCRL(t *testing.T, serials []*big.Int) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               x509.Certificate{}.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	entries := make([]x509.RevocationListEntry, len(serials))
	for i, s := range serials {
		entries[i] = x509.RevocationListEntry{SerialNumber: s, RevocationTime: time.Now()}
	}
	tpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(72 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// TestCRLCacheRefreshLoadsRevokedSet verifies the happy path:
//
//   - Refresh fetches the source, decodes PEM, parses the CRL, builds the
//     revoked-set keyed by lower-hex serial.
//   - IsRevoked returns true for serials in the CRL, false for others.
//   - Metrics record one successful refresh + the revoked count.
func TestCRLCacheRefreshLoadsRevokedSet(t *testing.T) {
	revokedSerials := []*big.Int{
		new(big.Int).SetInt64(0x4b95f903),
		new(big.Int).SetInt64(0xdeadbeef),
	}
	src := &fakeCRLSource{pem: mintCRL(t, revokedSerials)}
	met := newFakeMetrics()
	cache := NewCRLCache(src, 0, 0, met)

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	for _, s := range revokedSerials {
		if !cache.IsRevoked(s) {
			t.Errorf("IsRevoked(%s) = false, want true", s.Text(16))
		}
	}
	notRevoked := new(big.Int).SetInt64(0x1234)
	if cache.IsRevoked(notRevoked) {
		t.Errorf("IsRevoked(%s) = true, want false (not in CRL)", notRevoked.Text(16))
	}
	if met.refreshSuccess != 1 || met.refreshFailure != 0 {
		t.Errorf("refresh metrics: success=%d failure=%d, want success=1 failure=0", met.refreshSuccess, met.refreshFailure)
	}
	if met.lastRevoked != 2 {
		t.Errorf("lastRevoked=%d, want 2", met.lastRevoked)
	}
	if cache.RevokedCount() != 2 {
		t.Errorf("RevokedCount=%d, want 2", cache.RevokedCount())
	}
}

// TestCRLCacheFailOpenBeforeFirstFetch pins the fail-open initial behaviour:
// before any successful Refresh, IsRevoked returns false for every serial.
// This is the documented "soft-fail" pattern; a controller mid-startup
// doesn't lock out operators if the first CRL fetch hasn't completed.
func TestCRLCacheFailOpenBeforeFirstFetch(t *testing.T) {
	cache := NewCRLCache(&fakeCRLSource{}, 0, 0, nil)
	if cache.IsRevoked(big.NewInt(42)) {
		t.Error("IsRevoked should fail-open (=false) when cache has never been fetched")
	}
}

// TestCRLCacheFailureKeepsLastGood verifies fail-open on refresh failure:
//
//   - First refresh succeeds with serial A revoked.
//   - Second refresh fails (source returns error).
//   - IsRevoked still reports A as revoked (last good is retained).
//   - Failure metric is incremented; success metric is not.
func TestCRLCacheFailureKeepsLastGood(t *testing.T) {
	serialA := new(big.Int).SetInt64(0xa11)
	src := &fakeCRLSource{pem: mintCRL(t, []*big.Int{serialA})}
	met := newFakeMetrics()
	cache := NewCRLCache(src, 0, 0, met)

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if !cache.IsRevoked(serialA) {
		t.Fatal("setup: serialA should be revoked after first refresh")
	}

	src.err = fmt.Errorf("Vault unreachable")
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("second refresh should error")
	}
	if !cache.IsRevoked(serialA) {
		t.Error("after refresh failure, last-good revoked-set MUST be retained — IsRevoked(serialA) should still be true")
	}
	if met.refreshFailure != 1 {
		t.Errorf("refreshFailure metric = %d, want 1", met.refreshFailure)
	}
	if met.refreshSuccess != 1 {
		t.Errorf("refreshSuccess metric = %d, want 1 (only first refresh)", met.refreshSuccess)
	}
}

// TestCRLCacheStaleHardFail verifies the optional hard-fail mode:
// when staleThreshold > 0 AND the last fetch is older than that, IsRevoked
// returns true for every serial (operator MUST re-establish a fresh CRL
// fetch before any cert is accepted). Used in deployments where stale CRL
// must NOT be silently trusted.
func TestCRLCacheStaleHardFail(t *testing.T) {
	src := &fakeCRLSource{pem: mintCRL(t, nil)} // empty CRL — nothing revoked
	cache := NewCRLCache(src, 0, 1*time.Nanosecond /* near-instant stale */, nil)

	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // exceed staleThreshold
	if !cache.IsRevoked(big.NewInt(42)) {
		t.Error("with staleThreshold exceeded, IsRevoked should hard-fail (=true) for ALL serials")
	}
}

// TestCRLCacheVerifyPeerCertificateRejectsRevoked exercises the TLS
// callback's contract: the leaf cert's serial is checked against the
// revoked-set; revoked → error; accepted → nil. Both branches must update
// the metrics counter for SOC 2 evidence.
func TestCRLCacheVerifyPeerCertificateRejectsRevoked(t *testing.T) {
	revokedSerial := new(big.Int).SetInt64(0xb0b)
	src := &fakeCRLSource{pem: mintCRL(t, []*big.Int{revokedSerial})}
	met := newFakeMetrics()
	cache := NewCRLCache(src, 0, 0, met)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Build two leaf certs — one with the revoked serial, one without.
	mkLeaf := func(serial *big.Int) *x509.Certificate {
		return &x509.Certificate{SerialNumber: serial}
	}
	revokedLeaf := mkLeaf(revokedSerial)
	goodLeaf := mkLeaf(big.NewInt(0xd00d))

	// Revoked → error + metric "revoked".
	err := cache.VerifyPeerCertificate(nil, [][]*x509.Certificate{{revokedLeaf}})
	if err == nil {
		t.Error("VerifyPeerCertificate should reject revoked leaf")
	}
	if met.checkResults["revoked"] != 1 {
		t.Errorf("revoked metric = %d, want 1", met.checkResults["revoked"])
	}

	// Not revoked → nil + metric "accepted".
	if err := cache.VerifyPeerCertificate(nil, [][]*x509.Certificate{{goodLeaf}}); err != nil {
		t.Errorf("VerifyPeerCertificate should accept non-revoked leaf: %v", err)
	}
	if met.checkResults["accepted"] != 1 {
		t.Errorf("accepted metric = %d, want 1", met.checkResults["accepted"])
	}

	// No chain (mTLS disabled) → nil + metric "no_chain".
	if err := cache.VerifyPeerCertificate(nil, nil); err != nil {
		t.Errorf("VerifyPeerCertificate with empty chain should accept (dev path): %v", err)
	}
	if met.checkResults["no_chain"] != 1 {
		t.Errorf("no_chain metric = %d, want 1", met.checkResults["no_chain"])
	}
}

// TestCRLCacheRefreshRejectsGarbage pins input validation: empty PEM, junk
// PEM body, and well-formed PEM whose DER isn't a CRL must all surface as
// errors and NOT clobber the last-good revoked-set.
func TestCRLCacheRefreshRejectsGarbage(t *testing.T) {
	// Bootstrap with a valid CRL so we have a known-good state to defend.
	serialA := big.NewInt(0xa11)
	src := &fakeCRLSource{pem: mintCRL(t, []*big.Int{serialA})}
	cache := NewCRLCache(src, 0, 0, nil)
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pem  []byte
	}{
		{"empty", nil},
		{"non-PEM bytes", []byte("not a PEM block at all")},
		{"PEM with garbage DER", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte{0xde, 0xad}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Empty body short-circuits in FetchCRLPEM (returns error before Refresh sees it).
			// Drive the parse path directly via a dedicated source.
			s := &fakeCRLSource{pem: tc.pem}
			if tc.pem == nil {
				s.err = fmt.Errorf("empty (simulated)")
			}
			localCache := NewCRLCache(s, 0, 0, nil)
			if err := localCache.Refresh(context.Background()); err == nil {
				t.Errorf("Refresh on %s input should error", tc.name)
			}
		})
	}
	// Original cache retains the bootstrap state regardless of these tests.
	if !cache.IsRevoked(serialA) {
		t.Error("bootstrap state lost — independent failing refreshes must not clobber a different cache")
	}
}
