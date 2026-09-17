// SPDX-License-Identifier: AGPL-3.0-or-later

package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/deviceattest"
)

// testEnrolledDevice returns a deterministic EnrolledDevice for use in tests.
func testEnrolledDevice() deviceattest.EnrolledDevice {
	return deviceattest.EnrolledDevice{
		DeviceUUID:      "11111111-2222-4333-8444-555555555555",
		UserSub:         "usr_test01",
		Platform:        "tpm2-linux",
		AttestationPath: "B_tofu",
		Tier:            "TIER_BYOD",
		// 64 hex chars — a valid SHA-256 hex string.
		EKPubkeyHash:    strings.Repeat("a", 64),
		TPMManufacturer: "AMD",
		TPMKind:         "firmware",
		WitnessAdminSub: "ops_alice",
		EnrolledAt:      time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC),
	}
}

// TestFalconIDEnrollmentStore_Register_HappyPath tests successful enrollment
// via the Falcon-ID internal API (201 Created).
func TestFalconIDEnrollmentStore_Register_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != enrollDevicePath {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", auth)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req falconIDEnrollRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.DeviceUUID != "11111111-2222-4333-8444-555555555555" {
			t.Errorf("unexpected device_uuid: %s", req.DeviceUUID)
		}
		if req.TPMManufacturer == nil || *req.TPMManufacturer != "AMD" {
			t.Errorf("expected tpm_manufacturer=AMD")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(falconIDEnrollResponse{DeviceUUID: req.DeviceUUID})
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "test-token",
		WithEnrollmentHTTPClient(srv.Client()))

	if err := store.Register(context.Background(), testEnrolledDevice()); err != nil {
		t.Fatalf("Register returned unexpected error: %v", err)
	}
}

// TestFalconIDEnrollmentStore_Register_IdempotentReenrollment tests that a 200
// response (re-enrollment of the same device) is also treated as success.
func TestFalconIDEnrollmentStore_Register_IdempotentReenrollment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(falconIDEnrollResponse{DeviceUUID: "11111111-2222-4333-8444-555555555555"})
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "test-token",
		WithEnrollmentHTTPClient(srv.Client()))

	if err := store.Register(context.Background(), testEnrolledDevice()); err != nil {
		t.Fatalf("idempotent re-enrollment should succeed, got: %v", err)
	}
}

// TestFalconIDEnrollmentStore_Register_UUIDConflict tests that a 409 conflict
// (device_uuid belongs to a different EK key) returns an error wrapping
// ErrVerification — so the controller surfaces a 403 to the client.
func TestFalconIDEnrollmentStore_Register_UUIDConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(falconIDErrorResponse{Error: "device_uuid already registered under a different EK key"})
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "test-token",
		WithEnrollmentHTTPClient(srv.Client()))

	err := store.Register(context.Background(), testEnrolledDevice())
	if err == nil {
		t.Fatal("expected error on 409, got nil")
	}
	// The returned error MUST wrap ErrVerification so the controller can map it to 403.
	if !isErrVerification(err) {
		t.Errorf("expected error wrapping ErrVerification, got: %v", err)
	}
}

// TestFalconIDEnrollmentStore_Register_TransientError tests that a 503 response
// from Falcon-ID surfaces as an error without wrapping ErrVerification (the
// controller maps this to 502, not 403).
func TestFalconIDEnrollmentStore_Register_TransientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"postgres unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "test-token",
		WithEnrollmentHTTPClient(srv.Client()))

	err := store.Register(context.Background(), testEnrolledDevice())
	if err == nil {
		t.Fatal("expected error on 503, got nil")
	}
	if isErrVerification(err) {
		t.Errorf("503 transport error should NOT wrap ErrVerification, got: %v", err)
	}
}

// TestFalconIDEnrollmentStore_GetByEKPubkeyHash_Found tests the happy path
// where the Falcon-ID server returns a device row for the given EK hash.
func TestFalconIDEnrollmentStore_GetByEKPubkeyHash_Found(t *testing.T) {
	hash := strings.Repeat("b", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		expectedPath := getByEKHashPathPrefix + "/" + hash
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: got %s, want %s", r.URL.Path, expectedPath)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Errorf("unexpected auth: %s", auth)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mfr := "AMD"
		kind := "firmware"
		admin := "ops_bob"
		resp := falconIDGetByEKResponse{
			DeviceUUID:      "aaaa0000-0000-4000-8000-000000000001",
			UserSub:         "usr_test02",
			Platform:        "tpm2-linux",
			AttestationPath: "B_tofu",
			Tier:            "TIER_BYOD",
			EKPubkeyHash:    hash,
			TPMManufacturer: &mfr,
			TPMKind:         &kind,
			WitnessAdminSub: &admin,
			EnrolledAt:      "2026-06-07T12:00:00Z",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "tok",
		WithEnrollmentHTTPClient(srv.Client()))

	got, err := store.GetByEKPubkeyHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceUUID == "" {
		t.Fatal("expected non-empty DeviceUUID")
	}
	if got.TPMManufacturer != "AMD" {
		t.Errorf("expected TPMManufacturer=AMD, got %q", got.TPMManufacturer)
	}
	if got.WitnessAdminSub != "ops_bob" {
		t.Errorf("expected WitnessAdminSub=ops_bob, got %q", got.WitnessAdminSub)
	}
	if got.EnrolledAt.IsZero() {
		t.Error("expected non-zero EnrolledAt")
	}
}

// TestFalconIDEnrollmentStore_GetByEKPubkeyHash_NotFound tests the first-
// enrollment path where Falcon-ID returns 404, signalling no prior enrollment.
// The store must return a zero EnrolledDevice (empty DeviceUUID) with nil error.
func TestFalconIDEnrollmentStore_GetByEKPubkeyHash_NotFound(t *testing.T) {
	hash := strings.Repeat("c", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "tok",
		WithEnrollmentHTTPClient(srv.Client()))

	got, err := store.GetByEKPubkeyHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("not-found should return nil error, got: %v", err)
	}
	if got.DeviceUUID != "" {
		t.Errorf("not-found should return zero EnrolledDevice, DeviceUUID=%q", got.DeviceUUID)
	}
}

// TestFalconIDEnrollmentStore_GetByEKPubkeyHash_InvalidHash tests that a
// malformed hash is rejected without a network call.
func TestFalconIDEnrollmentStore_GetByEKPubkeyHash_InvalidHash(t *testing.T) {
	cases := []struct {
		name string
		hash string
	}{
		{"too_short", strings.Repeat("a", 32)},
		{"not_hex", strings.Repeat("z", 64)},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct with a dummy server that should NOT be called.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("server should not be called for invalid hash %q", tc.hash)
				http.Error(w, "unreachable", http.StatusInternalServerError)
			}))
			defer srv.Close()

			store := NewFalconIDEnrollmentStore(srv.URL, "tok",
				WithEnrollmentHTTPClient(srv.Client()))

			_, err := store.GetByEKPubkeyHash(context.Background(), tc.hash)
			if err == nil {
				t.Errorf("expected error for invalid hash %q, got nil", tc.hash)
			}
		})
	}
}

// TestFalconIDEnrollmentStore_GetByEKPubkeyHash_TransportError tests that a
// connection-level failure surfaces as an error.
func TestFalconIDEnrollmentStore_GetByEKPubkeyHash_TransportError(t *testing.T) {
	// Point at a URL that is not listening.
	store := NewFalconIDEnrollmentStore("http://127.0.0.1:1", "tok")

	hash := strings.Repeat("d", 64)
	_, err := store.GetByEKPubkeyHash(context.Background(), hash)
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
	if !strings.Contains(err.Error(), "transport error") {
		t.Errorf("expected 'transport error' in message, got: %v", err)
	}
}

// isErrVerification reports whether err wraps deviceattest.ErrVerification.
func isErrVerification(err error) bool {
	return strings.Contains(err.Error(), deviceattest.ErrVerification.Error())
}

// mutableTokenSource is a TokenSource whose returned token can change between
// calls. It proves the store resolves the Bearer header live on every request
// (the property that lets the svctoken-refresher rotate the token without a
// pod restart) rather than capturing it once at construction.
type mutableTokenSource struct {
	mu    sync.Mutex
	tok   string
	calls int
}

func (m *mutableTokenSource) set(t string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tok = t
}

func (m *mutableTokenSource) Token(context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.tok, nil
}

// TestFalconIDEnrollmentStore_TokenSource_LiveRotation verifies that a token
// rotation between two requests is reflected in the second request's
// Authorization header — i.e. the store reads the TokenSource per request.
// This is the core property that breaks the Reloader feedback loop: jess no
// longer needs a pod bounce to pick up a freshly minted s2s token.
func TestFalconIDEnrollmentStore_TokenSource_LiveRotation(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNotFound) // not-found: zero device, nil error
	}))
	defer srv.Close()

	src := &mutableTokenSource{tok: "token-A"}
	store := NewFalconIDEnrollmentStoreWithSource(srv.URL, src,
		WithEnrollmentHTTPClient(srv.Client()))

	hash := strings.Repeat("a", 64)
	if _, err := store.GetByEKPubkeyHash(context.Background(), hash); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	src.set("token-B") // svctoken-refresher rotates the token in place
	if _, err := store.GetByEKPubkeyHash(context.Background(), hash); err != nil {
		t.Fatalf("second lookup: %v", err)
	}

	if len(gotAuth) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(gotAuth))
	}
	if gotAuth[0] != "Bearer token-A" {
		t.Errorf("first request Authorization = %q, want %q", gotAuth[0], "Bearer token-A")
	}
	if gotAuth[1] != "Bearer token-B" {
		t.Errorf("second request Authorization = %q, want %q (live rotation not picked up)", gotAuth[1], "Bearer token-B")
	}
	if src.calls != 2 {
		t.Errorf("token source consulted %d times, want 2 (once per request)", src.calls)
	}
}

// errTokenSource always fails — models the shared token file being briefly
// empty mid-atomic-write.
type errTokenSource struct{}

func (errTokenSource) Token(context.Context) (string, error) {
	return "", errors.New("token file is empty")
}

// TestFalconIDEnrollmentStore_TokenSourceError_Surfaced verifies that a token-
// source failure aborts the request (surfaced as an error) rather than sending
// an unauthenticated request that would 401.
func TestFalconIDEnrollmentStore_TokenSourceError_Surfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be called when the token source errors")
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStoreWithSource(srv.URL, errTokenSource{},
		WithEnrollmentHTTPClient(srv.Client()))

	_, err := store.GetByEKPubkeyHash(context.Background(), strings.Repeat("a", 64))
	if err == nil {
		t.Fatal("expected an error when the token source fails, got nil")
	}
	if !strings.Contains(err.Error(), "resolve bearer token") {
		t.Errorf("error %q should wrap the token-source failure", err.Error())
	}
}

// TestFalconIDEnrollmentStore_StaticConstructor_BackwardCompatible verifies the
// legacy NewFalconIDEnrollmentStore(baseURL, token) path still stamps the
// fixed Bearer token, keeping the env-token fallback wiring working.
func TestFalconIDEnrollmentStore_StaticConstructor_BackwardCompatible(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := NewFalconIDEnrollmentStore(srv.URL, "legacy-token",
		WithEnrollmentHTTPClient(srv.Client()))
	if _, err := store.GetByEKPubkeyHash(context.Background(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if gotAuth != "Bearer legacy-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer legacy-token")
	}
}
