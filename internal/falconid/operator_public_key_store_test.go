// SPDX-License-Identifier: AGPL-3.0-or-later

package falconid_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dogukanturhal/jess/internal/devicepolicy"
	"github.com/dogukanturhal/jess/internal/falconid"
)

// buildJWKS generates a JWKS JSON body from the provided ECDSA public keys.
func buildJWKS(t *testing.T, keys ...*ecdsa.PublicKey) []byte {
	t.Helper()
	jwks := jose.JSONWebKeySet{}
	for i, k := range keys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:       k,
			KeyID:     fmt.Sprintf("key-%d", i),
			Algorithm: string(jose.ES256),
			Use:       "sig",
		})
	}
	b, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("buildJWKS: marshal: %v", err)
	}
	return b
}

// TestLookupPublicKey_HappyPath verifies that LookupPublicKey returns a usable
// ECDSA public key when the JWKS endpoint serves a valid key set.
func TestLookupPublicKey_HappyPath(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildJWKS(t, &priv.PublicKey))
	}))
	defer srv.Close()

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
	)

	got, err := store.LookupPublicKey(context.Background(), "any-sub-is-ignored")
	if err != nil {
		t.Fatalf("LookupPublicKey: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("LookupPublicKey returned nil key")
	}
	ecKey, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", got)
	}
	if !ecKey.Equal(&priv.PublicKey) {
		t.Error("returned key does not match the key served by the JWKS endpoint")
	}
}

// TestLookupPublicKey_SubIgnored verifies that two calls with different sub
// values return the same key (sub is intentionally ignored per trust model).
func TestLookupPublicKey_SubIgnored(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildJWKS(t, &priv.PublicKey))
	}))
	defer srv.Close()

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
	)

	key1, err1 := store.LookupPublicKey(context.Background(), "operator-alice")
	key2, err2 := store.LookupPublicKey(context.Background(), "operator-bob")
	if err1 != nil || err2 != nil {
		t.Fatalf("LookupPublicKey errors: %v / %v", err1, err2)
	}
	if key1 != key2 {
		// Both calls hit the cache after the first fetch; they should return
		// the exact same pointer.
		t.Error("second call returned a different pointer (cache not used?)")
	}
}

// TestLookupPublicKey_EmptyJWKS verifies that ErrOperatorNotFound is returned
// when the JWKS endpoint serves an empty key set (degenerate misconfiguration).
func TestLookupPublicKey_EmptyJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
	)

	_, err := store.LookupPublicKey(context.Background(), "any")
	if err == nil {
		t.Fatal("expected error for empty JWKS, got nil")
	}
	if !errors.Is(err, devicepolicy.ErrOperatorNotFound) {
		t.Errorf("expected ErrOperatorNotFound, got: %v", err)
	}
}

// TestLookupPublicKey_CacheHit verifies that the JWKS endpoint is only called
// once within the cache TTL, even when LookupPublicKey is called multiple times.
func TestLookupPublicKey_CacheHit(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildJWKS(t, &priv.PublicKey))
	}))
	defer srv.Close()

	// Use a frozen clock so the cache never expires during the test.
	frozen := time.Now()
	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
		falconid.WithClockForTest(func() time.Time { return frozen }),
	)

	for i := 0; i < 5; i++ {
		if _, err := store.LookupPublicKey(context.Background(), "sub"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if callCount != 1 {
		t.Errorf("expected 1 JWKS fetch (cache hit), got %d", callCount)
	}
}

// TestLookupPublicKey_CacheExpiry verifies that a new fetch is issued when the
// cache TTL has elapsed.  We use a simple bool to flip "before expiry" vs
// "after expiry" rather than counting clock calls, which are implementation-
// internal and brittle to count.
func TestLookupPublicKey_CacheExpiry(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildJWKS(t, &priv.PublicKey))
	}))
	defer srv.Close()

	base := time.Now()
	afterExpiry := false
	clockFn := func() time.Time {
		if afterExpiry {
			return base.Add(10 * time.Minute)
		}
		return base
	}

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
		falconid.WithClockForTest(clockFn),
	)

	// First call: populates the cache.
	if _, err := store.LookupPublicKey(context.Background(), "sub"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 JWKS fetch after first call, got %d", callCount)
	}

	// Advance the simulated clock past the TTL.
	afterExpiry = true

	// Second call: cache is expired → new fetch.
	if _, err := store.LookupPublicKey(context.Background(), "sub"); err != nil {
		t.Fatalf("second call (after expiry): %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 JWKS fetches (expiry re-fetch), got %d", callCount)
	}
}

// TestLookupPublicKey_HTTPError verifies that a network error is propagated
// when no stale cache is available.
func TestLookupPublicKey_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
	)

	_, err := store.LookupPublicKey(context.Background(), "sub")
	if err == nil {
		t.Fatal("expected error on HTTP 503, got nil")
	}
}

// TestLookupPublicKey_StaleCache verifies that a stale cache entry is returned
// when the JWKS endpoint is temporarily unavailable.
func TestLookupPublicKey_StaleCache(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	available := true

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildJWKS(t, &priv.PublicKey))
	}))
	defer srv.Close()

	base := time.Now()
	afterExpiry := false
	clockFn := func() time.Time {
		if afterExpiry {
			return base.Add(10 * time.Minute)
		}
		return base
	}

	store := falconid.NewFalconIDOperatorPublicKeyStore(
		srv.URL+"/.well-known/jwks.json",
		falconid.WithHTTPClient(srv.Client()),
		falconid.WithClockForTest(clockFn),
	)

	// First call: populate cache.
	if _, err := store.LookupPublicKey(context.Background(), "sub"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Simulate endpoint going down after cache is populated.
	available = false
	// Advance past TTL so next call triggers a re-fetch attempt.
	afterExpiry = true

	// Second call after TTL expiry: fetch fails but stale cache is returned.
	key, err := store.LookupPublicKey(context.Background(), "sub")
	if err != nil {
		t.Fatalf("expected stale cache fallback, got error: %v", err)
	}
	if key == nil {
		t.Fatal("stale cache returned nil key")
	}
}
