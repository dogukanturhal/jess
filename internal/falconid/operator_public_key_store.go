// SPDX-License-Identifier: AGPL-3.0-or-later

// Package falconid provides jess-controller adapters that talk to the Falcon-ID
// IdP without duplicating the PDP token-verification path.
//
// # FalconIDOperatorPublicKeyStore — trust model
//
// The WebAuthn witness JWS on HexxLock is signed by Falcon-ID's OIDC issuer
// key, not by a per-operator FIDO2 credential public key directly.  The flow
// is: operator completes a WebAuthn step-up challenge inside Falcon-ID; Falcon-
// ID mints a compact JWS signed with its own OIDC JWT signing key, embedding
// the operator's sub and the device_uuid being witnessed.  Jess verifies the
// JWS by fetching the current signing key from Falcon-ID's JWKS endpoint.
//
// This means LookupPublicKey IGNORES the sub parameter and always returns the
// current JWKS signing key.  The sub-claim binding is enforced inside
// devicepolicy.WebAuthnWitnessVerifier, which verifies:
//
//  1. The JWS signature against the key returned here (proves the IdP signed it).
//  2. The JWS sub claim matches bundle.AdminSub (proves which operator was
//     vouched for by the IdP).
//
// Placing the sub check after the signature check is correct: we first confirm
// the JWS was signed by the trusted IdP, then we assert which operator the IdP
// vouched for.  A stolen JWS for operator A cannot be accepted as operator B's
// witness because the sub claim check rejects it.
//
// Threat model:
//   - A compromised Falcon-ID signing key could forge witness JWSes for any
//     operator.  This is the same trust level as the existing OIDC-based
//     operator token verification, adding no new attack surface.
//   - JWKS rotation: keys are cached for defaultCacheTTL (3 min).  A key
//     rotation at Falcon-ID becomes effective within one cache window.
//   - Zero-key JWKS: LookupPublicKey returns ErrOperatorNotFound rather than
//     silently accepting, surfacing the misconfiguration immediately.
package falconid

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dogukanturhal/jess/internal/devicepolicy"
)

const (
	// defaultCacheTTL is the minimum time between JWKS re-fetches.
	// go-oidc uses a similar 3-minute window; 5-minute jitter is added
	// by the remote key set implementation there but 3 min is safe here.
	defaultCacheTTL = 3 * time.Minute
)

// FalconIDOperatorPublicKeyStore implements devicepolicy.OperatorPublicKeyStore
// by fetching the current signing key from Falcon-ID's JWKS endpoint.
//
// The sub parameter to LookupPublicKey is intentionally unused; see the
// package-level godoc for the trust-model rationale.
//
// Thread-safe: all mutable state is protected by mu.
type FalconIDOperatorPublicKeyStore struct {
	jwksURL  string
	hc       *http.Client
	cacheTTL time.Duration
	nowFn    func() time.Time

	mu          sync.Mutex
	cachedKeys  []crypto.PublicKey
	cacheExpiry time.Time
}

// FalconIDOperatorPublicKeyStoreOption configures a FalconIDOperatorPublicKeyStore.
type FalconIDOperatorPublicKeyStoreOption func(*FalconIDOperatorPublicKeyStore)

// WithHTTPClient replaces the default http.Client used for JWKS fetches.
// Used in tests to inject an httptest.Server transport.
func WithHTTPClient(hc *http.Client) FalconIDOperatorPublicKeyStoreOption {
	return func(s *FalconIDOperatorPublicKeyStore) { s.hc = hc }
}

// WithClockForTest replaces the clock used for cache expiry decisions.
// This option is exported for use in _test packages; production code
// should not use it.
func WithClockForTest(fn func() time.Time) FalconIDOperatorPublicKeyStoreOption {
	return func(s *FalconIDOperatorPublicKeyStore) { s.nowFn = fn }
}

// NewFalconIDOperatorPublicKeyStore constructs a store that fetches the JWKS
// from jwksURL.  No network call is made at construction time; the first
// LookupPublicKey triggers the initial fetch.
//
// jwksURL must be the full HTTPS URL of the JWKS endpoint, e.g.
// "https://id.hexxlock.com/.well-known/jwks.json".
//
// Panics if jwksURL is empty so the misconfiguration is caught at controller
// startup, not at the first enrollment request.
func NewFalconIDOperatorPublicKeyStore(jwksURL string, opts ...FalconIDOperatorPublicKeyStoreOption) *FalconIDOperatorPublicKeyStore {
	if jwksURL == "" {
		panic("falconid: NewFalconIDOperatorPublicKeyStore: jwksURL must not be empty")
	}
	s := &FalconIDOperatorPublicKeyStore{
		jwksURL:  jwksURL,
		hc:       &http.Client{Timeout: 10 * time.Second},
		cacheTTL: defaultCacheTTL,
		nowFn:    time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// LookupPublicKey returns the first public key from Falcon-ID's JWKS endpoint.
//
// The sub parameter is intentionally unused — see package-level godoc.
//
// Returns devicepolicy.ErrOperatorNotFound when the JWKS contains zero keys,
// which signals a Falcon-ID configuration problem that the operator must fix
// before any witness JWS can be verified.
//
// The JWKS response is cached for cacheTTL (default 3 minutes).  Concurrent
// callers during a cache miss serialize on the internal mutex; only one fetch
// is issued.
//
// Implements devicepolicy.OperatorPublicKeyStore.
func (s *FalconIDOperatorPublicKeyStore) LookupPublicKey(ctx context.Context, _ string) (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFn()
	if len(s.cachedKeys) > 0 && now.Before(s.cacheExpiry) {
		return s.cachedKeys[0], nil
	}

	keys, err := s.fetchJWKS(ctx)
	if err != nil {
		// If we have a stale cache, prefer it over a failed fetch rather
		// than returning an error that could block all witness verifications
		// during a transient Falcon-ID network hiccup.  This is the same
		// "soft-fail until first successful fetch" posture used throughout
		// the controller (CRL cache, CAEP subscriber, etc.).
		if len(s.cachedKeys) > 0 {
			return s.cachedKeys[0], nil
		}
		return nil, fmt.Errorf("falconid operator_public_key_store: fetch JWKS: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("falconid operator_public_key_store: %w (JWKS at %s returned zero keys — check Falcon-ID OIDC signing key configuration)",
			devicepolicy.ErrOperatorNotFound, s.jwksURL)
	}

	s.cachedKeys = keys
	s.cacheExpiry = now.Add(s.cacheTTL)
	return keys[0], nil
}

// fetchJWKS performs a plain HTTP GET of s.jwksURL and returns the parsed
// public keys.  Called with s.mu held.
func (s *FalconIDOperatorPublicKeyStore) fetchJWKS(ctx context.Context) ([]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", s.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<17)) // 128 KiB cap
	if err != nil {
		return nil, fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshal JWKS JSON: %w", err)
	}

	out := make([]crypto.PublicKey, 0, len(jwks.Keys))
	for i, jwk := range jwks.Keys {
		if !jwk.Valid() {
			continue
		}
		pub := jwk.Public()
		if pub.Key == nil {
			continue
		}
		cpk, ok := pub.Key.(crypto.PublicKey)
		if !ok {
			return nil, fmt.Errorf("JWKS key[%d] type %T is not a crypto.PublicKey", i, pub.Key)
		}
		out = append(out, cpk)
	}
	return out, nil
}
