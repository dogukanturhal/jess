// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"
)

// testNonce32 returns a deterministic 32-byte nonce derived from the
// label. Mirrors the TPM2_Certify ExtraData size constraint enforced
// by the production tofuVerifier (Guard 3, >= 32 bytes). Per-test
// labels keep nonces distinct across cases so any cross-test leakage
// would surface as a freshness failure rather than a silent reuse.
func testNonce32(t *testing.T, label string) []byte {
	t.Helper()
	const want = 32
	out := make([]byte, want)
	for i := range out {
		if i < len(label) {
			out[i] = label[i]
		} else {
			out[i] = byte('0' + (i % 10))
		}
	}
	return out
}

// -- fakes ---------------------------------------------------------------

type fakeEnrollmentStore struct {
	records     map[string]EnrolledDevice // keyed by EKPubkeyHash
	registerErr error
	lookupErr   error
}

func newFakeStore() *fakeEnrollmentStore {
	return &fakeEnrollmentStore{records: make(map[string]EnrolledDevice)}
}

func (f *fakeEnrollmentStore) Register(_ context.Context, row EnrolledDevice) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	// Idempotency: if same hash + same UUID already exists, no-op.
	if existing, ok := f.records[row.EKPubkeyHash]; ok {
		if existing.DeviceUUID != row.DeviceUUID {
			return fmt.Errorf("%w: duplicate EK pubkey with different device_uuid", ErrVerification)
		}
		return nil
	}
	f.records[row.EKPubkeyHash] = row
	return nil
}

func (f *fakeEnrollmentStore) GetByEKPubkeyHash(_ context.Context, hash string) (EnrolledDevice, error) {
	if f.lookupErr != nil {
		return EnrolledDevice{}, f.lookupErr
	}
	return f.records[hash], nil
}

// List returns the in-memory records ordered by EnrolledAt desc to satisfy
// the EnrollmentStore contract "most recently enrolled first". A real
// pgx implementation does this in SQL via ORDER BY enrolled_at DESC.
func (f *fakeEnrollmentStore) List(_ context.Context, filter EnrollmentFilter) ([]EnrolledDevice, error) {
	if filter.Limit < 0 {
		return nil, fmt.Errorf("invalid filter: negative limit")
	}
	out := make([]EnrolledDevice, 0, len(f.records))
	for _, r := range f.records {
		if filter.UserSub != "" && r.UserSub != filter.UserSub {
			continue
		}
		if filter.Tier != "" && r.Tier != filter.Tier {
			continue
		}
		if filter.Platform != "" && r.Platform != filter.Platform {
			continue
		}
		if !filter.IncludeDisabled && !r.DisabledAt.IsZero() {
			continue
		}
		out = append(out, r)
	}
	// Stable ordering: EnrolledAt desc, fall back to DeviceUUID for ties
	// (test determinism — production uses the db-side ORDER BY).
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].EnrolledAt.Equal(out[j].EnrolledAt) {
			return out[i].EnrolledAt.After(out[j].EnrolledAt)
		}
		return out[i].DeviceUUID < out[j].DeviceUUID
	})
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return []EnrolledDevice{}, nil
		}
		out = out[filter.Offset:]
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 200 // matches FalconIDEnrollmentStore default
	}
	if limit < len(out) {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeEnrollmentStore) UpdateLastSeen(_ context.Context, deviceUUID string, t time.Time) error {
	for k, r := range f.records {
		if r.DeviceUUID == deviceUUID {
			r.LastSeenAt = t
			f.records[k] = r
			return nil
		}
	}
	// Heartbeat-without-enrollment: no error, just a no-op per contract.
	return nil
}

func (f *fakeEnrollmentStore) Disable(_ context.Context, deviceUUID, _ string) error {
	for k, r := range f.records {
		if r.DeviceUUID == deviceUUID {
			if r.DisabledAt.IsZero() {
				r.DisabledAt = time.Now().UTC()
			}
			f.records[k] = r
			return nil
		}
	}
	return fmt.Errorf("disable: device %q not found", deviceUUID)
}

type fakeWitnessVerifier struct {
	err error
}

func (f *fakeWitnessVerifier) Verify(_ context.Context, _ WitnessBundle, _ string) error {
	return f.err
}

// -- helpers --------------------------------------------------------------

// generateEKPubKeyPEM produces a fresh ECDSA P-256 public key in PEM form.
// Real EK keys are RSA-2048 or ECC-P256; for test purposes ECDSA P-256
// is sufficient — the verifier only parses the PEM and hashes the bytes.
func generateEKPubKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func validWitness(issuedAt time.Time) *WitnessBundle {
	return &WitnessBundle{
		AdminSub:  "ops@example.com",
		SignedJWS: []byte("fake.jws.payload"),
		IssuedAt:  issuedAt,
	}
}

// -- tests ----------------------------------------------------------------

func TestTOFUVerifier_FirstEnrollment(t *testing.T) {
	store := newFakeStore()
	witness := &fakeWitnessVerifier{}
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	ekPEM := generateEKPubKeyPEM(t)
	req := VerifyRequest{
		Platform:     "tpm2-linux",
		Manufacturer: "AMD",
		Kind:         "firmware",
		EKPubKeyPEM:  ekPEM,
		UserSub:      "user@example.com",
		DeviceUUID:   "550e8400-e29b-41d4-a716-446655440000",
		NonceClient:  testNonce32(t, "fresh"),
		Witness:      validWitness(now.Add(-1 * time.Minute)),
	}

	resp, err := v.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}
	if resp.Path != "B_tofu" {
		t.Errorf("Path = %q, want B_tofu", resp.Path)
	}
	if resp.Tier != "TIER_BYOD" {
		t.Errorf("Tier = %q, want TIER_BYOD", resp.Tier)
	}
	if len(resp.Reasons) == 0 {
		t.Error("Reasons is empty")
	}

	// Verify store was written.
	if len(store.records) != 1 {
		t.Errorf("expected 1 enrollment record, got %d", len(store.records))
	}
	for _, rec := range store.records {
		if rec.DeviceUUID != req.DeviceUUID {
			t.Errorf("stored DeviceUUID = %q, want %q", rec.DeviceUUID, req.DeviceUUID)
		}
		if rec.AttestationPath != "B_tofu" {
			t.Errorf("stored AttestationPath = %q, want B_tofu", rec.AttestationPath)
		}
		if rec.WitnessAdminSub != "ops@example.com" {
			t.Errorf("stored WitnessAdminSub = %q, want ops@example.com", rec.WitnessAdminSub)
		}
	}
}

func TestTOFUVerifier_ReturningDevice(t *testing.T) {
	store := newFakeStore()
	witness := &fakeWitnessVerifier{}
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	ekPEM := generateEKPubKeyPEM(t)
	req := VerifyRequest{
		Platform:     "tpm2-linux",
		Manufacturer: "AMD",
		Kind:         "firmware",
		EKPubKeyPEM:  ekPEM,
		UserSub:      "user@example.com",
		DeviceUUID:   "550e8400-e29b-41d4-a716-446655440000",
		NonceClient:  testNonce32(t, "n1"),
		Witness:      validWitness(now.Add(-1 * time.Minute)),
	}

	// First enrollment.
	if _, err := v.Verify(context.Background(), req); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}

	// Second call: same EK pubkey, no witness required for returning device.
	req2 := req
	req2.Witness = nil
	req2.NonceClient = testNonce32(t, "n2")

	resp, err := v.Verify(context.Background(), req2)
	if err != nil {
		t.Fatalf("returning device verification failed: %v", err)
	}
	if resp.Path != "B_tofu" {
		t.Errorf("Path = %q, want B_tofu", resp.Path)
	}
	if resp.Tier != "TIER_BYOD" {
		t.Errorf("Tier = %q, want TIER_BYOD", resp.Tier)
	}
}

func TestTOFUVerifier_EKCertPresent_Rejected(t *testing.T) {
	store := newFakeStore()
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		EKCertPEM:   []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"),
		NonceClient: testNonce32(t, "default"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when EKCertPEM is set on Path B verifier")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_EmptyEKPubKey_Rejected(t *testing.T) {
	store := newFakeStore()
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: nil,
		NonceClient: testNonce32(t, "default"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty EKPubKeyPEM")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_MissingNonce_Rejected(t *testing.T) {
	store := newFakeStore()
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness)

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		NonceClient: nil, // missing
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing NonceClient")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_WitnessFail_Rejected(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	witnessErr := errors.New("webauthn signature invalid")
	witness := &fakeWitnessVerifier{err: witnessErr}
	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "550e8400-e29b-41d4-a716-446655440001",
		UserSub:     "user@example.com",
		NonceClient: testNonce32(t, "default"),
		Witness:     validWitness(now.Add(-1 * time.Minute)),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when witness verification fails")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
	// Store should be empty — we never wrote an enrollment.
	if len(store.records) != 0 {
		t.Errorf("expected no records in store after witness failure, got %d", len(store.records))
	}
}

func TestTOFUVerifier_StoreRegisterError_Propagated(t *testing.T) {
	store := newFakeStore()
	store.registerErr = errors.New("pg: connection refused")
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "550e8400-e29b-41d4-a716-446655440002",
		UserSub:     "user@example.com",
		NonceClient: testNonce32(t, "default"),
		Witness:     validWitness(now.Add(-1 * time.Minute)),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when store.Register fails")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_StoreLookupError_Propagated(t *testing.T) {
	store := newFakeStore()
	store.lookupErr = errors.New("pg: timeout")
	v := NewTOFUVerifier("tpm2-linux", store, &fakeWitnessVerifier{})

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		NonceClient: testNonce32(t, "default"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when store.GetByEKPubkeyHash fails")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_DeviceUUIDMismatch_Rejected(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	ekPEM := generateEKPubKeyPEM(t)

	// First enrollment with UUID A.
	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: ekPEM,
		DeviceUUID:  "uuid-aaa-aaa",
		UserSub:     "user@example.com",
		NonceClient: testNonce32(t, "default"),
		Witness:     validWitness(now.Add(-1 * time.Minute)),
	}
	if _, err := v.Verify(context.Background(), req); err != nil {
		t.Fatalf("first enrollment: %v", err)
	}

	// Re-verify with same EK pubkey but different UUID — impersonation attempt.
	req2 := req
	req2.DeviceUUID = "uuid-bbb-bbb" // drift
	req2.Witness = nil
	req2.NonceClient = testNonce32(t, "n2")

	_, err := v.Verify(context.Background(), req2)
	if err == nil {
		t.Fatal("expected error on device_uuid mismatch for enrolled EK pubkey")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_NoWitnessOnFirstEnrollment_Rejected(t *testing.T) {
	store := newFakeStore()
	v := NewTOFUVerifier("tpm2-linux", store, &fakeWitnessVerifier{})

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "550e8400-e29b-41d4-a716-446655440003",
		UserSub:     "user@example.com",
		NonceClient: testNonce32(t, "default"),
		Witness:     nil, // no witness on first enrollment
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when no witness on first enrollment")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_StaleWitness_Rejected(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	witness := &fakeWitnessVerifier{}
	v := NewTOFUVerifier("tpm2-linux", store, witness, WithTOFUClock(func() time.Time { return now }))

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "550e8400-e29b-41d4-a716-446655440004",
		UserSub:     "user@example.com",
		NonceClient: testNonce32(t, "default"),
		// Witness issued 20 minutes ago — exceeds 10-minute pre-check window.
		Witness: validWitness(now.Add(-20 * time.Minute)),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for stale witness")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestTOFUVerifier_InvalidPEM_Rejected(t *testing.T) {
	store := newFakeStore()
	v := NewTOFUVerifier("tpm2-linux", store, &fakeWitnessVerifier{})

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: []byte("not-valid-pem-at-all"),
		NonceClient: testNonce32(t, "default"),
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("expected ErrVerification, got: %v", err)
	}
}

func TestNewTOFUVerifier_NilStore_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil store")
		}
	}()
	NewTOFUVerifier("tpm2-linux", nil, &fakeWitnessVerifier{})
}

func TestNewTOFUVerifier_NilWitness_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil witness")
		}
	}()
	NewTOFUVerifier("tpm2-linux", newFakeStore(), nil)
}

// TestTOFU_ShortNonce_Rejected locks Guard 3's minimum-length check.
// A NonceClient shorter than 32 bytes cannot represent the
// TPM2_Certify ExtraData (TCG TPM 2.0 Part 3 §32.2 nominal 32-byte
// challenge) and is unambiguously a test fixture or weak input. Per-
// platform verifiers downstream BIND the nonce to a TPM quote; the
// substrate enforces only the size floor here.
func TestTOFU_ShortNonce_Rejected(t *testing.T) {
	store := newFakeStore()
	v := NewTOFUVerifier("tpm2-linux", store, &fakeWitnessVerifier{})

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "11111111-1111-1111-1111-111111111111",
		UserSub:     "user-a",
		NonceClient: []byte("too-short"), // 9 bytes < 32 floor
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected rejection of short NonceClient (< 32 bytes)")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("err = %v, want ErrVerification", err)
	}
	if !contains(err.Error(), "32 bytes") {
		t.Errorf("err message should mention 32-byte floor; got: %v", err)
	}
}

// TestTOFU_ForwardDatedWitness_Rejected locks the negative-skew guard.
// A WitnessBundle with IssuedAt in the future (beyond honest NTP slop)
// would have negative `age`; without this guard, both the substrate
// pre-check (age > 10m) and the upstream WitnessVerifier's age
// comparison silently pass, leaving the JWS valid arbitrarily far
// into the future and defeating freshness entirely.
func TestTOFU_ForwardDatedWitness_Rejected(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	store := newFakeStore()
	v := NewTOFUVerifier("tpm2-linux", store, &fakeWitnessVerifier{},
		WithTOFUClock(func() time.Time { return now }))

	// IssuedAt 5 minutes in the future = beyond the 30s clock-skew tolerance.
	futureWitness := WitnessBundle{
		IssuedAt:  now.Add(5 * time.Minute),
		AdminSub:  "ops@example.com",
		SignedJWS: []byte("jws.placeholder.payload"),
	}

	req := VerifyRequest{
		Platform:    "tpm2-linux",
		EKPubKeyPEM: generateEKPubKeyPEM(t),
		DeviceUUID:  "22222222-2222-2222-2222-222222222222",
		UserSub:     "user-b",
		NonceClient: testNonce32(t, "future-witness-attack"),
		Witness:     &futureWitness,
	}

	_, err := v.Verify(context.Background(), req)
	if err == nil {
		t.Fatal("expected rejection of forward-dated WitnessBundle")
	}
	if !errors.Is(err, ErrVerification) {
		t.Errorf("err = %v, want ErrVerification", err)
	}
	if !contains(err.Error(), "future") {
		t.Errorf("err message should mention 'future'; got: %v", err)
	}
}
