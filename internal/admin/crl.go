// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// CRLMetricsSink is the optional surface for Phase 4 full telemetry. Nil-safe
// — a CRLCache with no sink records nothing. The controller passes its
// metrics.Metrics in prod; tests pass a fake.
type CRLMetricsSink interface {
	OperatorCertRevocationCheck(result string)
	OperatorCertCRLRefresh(success bool, revokedCount int)
}

// CRLSource abstracts the fetch path so tests can inject canned CRLs without
// a Vault server. Prod uses VaultCRLSource (defined below) backed by
// vaultx.Client.ReadRawPEM.
type CRLSource interface {
	FetchCRLPEM(ctx context.Context) ([]byte, error)
}

// VaultCRLSource fetches /v1/<mount>/crl/pem from the configured Vault PKI
// mount. The endpoint is unauthenticated per Vault PKI spec — the controller
// happens to send its token in the header but Vault ignores it for /crl, so
// no policy expansion is needed beyond what the operator-cert sign role
// already grants. Pairs with NewVaultSigner / NewVaultCRLSource using the
// same mount string for consistency.
type VaultCRLSource struct {
	vc    *vaultx.Client
	mount string
}

// NewVaultCRLSource constructs the prod CRLSource.
func NewVaultCRLSource(vc *vaultx.Client, mount string) *VaultCRLSource {
	return &VaultCRLSource{vc: vc, mount: strings.Trim(mount, "/")}
}

// FetchCRLPEM fetches /v1/<mount>/crl/pem. Returns the raw PEM body or an
// error. Empty body is surfaced as an error so callers don't silently treat
// "no CRL" as "empty CRL".
func (s *VaultCRLSource) FetchCRLPEM(ctx context.Context) ([]byte, error) {
	pemBytes, err := s.vc.ReadRawPEM(ctx, "/v1/"+s.mount+"/crl/pem")
	if err != nil {
		return nil, err
	}
	if len(pemBytes) == 0 {
		return nil, errors.New("CRL endpoint returned empty body")
	}
	return pemBytes, nil
}

// DefaultCRLRefreshInterval is the conservative poll cadence for the CRL
// cache. 5 minutes balances revocation latency (worst-case = this interval
// + half the network RTT to Vault) against Vault load (the CRL endpoint is
// cached server-side but the controller still does a network round-trip).
// Industry benchmarks: Teleport/Boundary use 5m-15m; AWS IAM Roles Anywhere
// recommends 5m. Configurable via NewCRLCache's refreshInterval arg.
const DefaultCRLRefreshInterval = 5 * time.Minute

// CRLCache holds the latest fetched CRL + provides revocation checks for the
// TLS VerifyPeerCertificate callback. Fail-open until first successful fetch
// — initial state IsRevoked=false even for serials that ARE on the CRL,
// because the cache has nothing to compare against. After first success the
// cache is authoritative for the snapshot until the next refresh; failures
// keep the last good snapshot (don't reset to empty).
//
// This matches the "soft-fail" CRL pattern Chrome/Firefox/OpenSSL all use:
// a Vault outage during a controller window doesn't lock out every operator,
// but a successfully-fetched CRL is enforced. Hard-fail (reject if CRL is
// stale or absent) is available via the StaleThreshold field — when the
// last-good fetch is older than that, IsRevoked returns true for all
// serials. Zero StaleThreshold disables hard-fail.
type CRLCache struct {
	src             CRLSource
	refreshInterval time.Duration
	staleThreshold  time.Duration // 0 = no hard-fail; positive = reject all when last fetch older than this
	metrics         CRLMetricsSink

	mu          sync.RWMutex
	revoked     map[string]struct{} // serial hex (lower) -> revoked
	lastRefresh time.Time
	loaded      bool // distinguishes "never fetched" from "fetched empty"

	stop chan struct{}
}

// NewCRLCache builds a cache. Doesn't fetch — call Start() to kick off the
// initial fetch + background refresh goroutine, or call Refresh() yourself
// for synchronous control (the controller does Start at boot so the first
// fetch fires before the listener accepts connections).
//
// refreshInterval=0 uses DefaultCRLRefreshInterval. staleThreshold=0
// disables hard-fail (cache stays usable indefinitely past last refresh).
func NewCRLCache(src CRLSource, refreshInterval, staleThreshold time.Duration, m CRLMetricsSink) *CRLCache {
	if refreshInterval == 0 {
		refreshInterval = DefaultCRLRefreshInterval
	}
	return &CRLCache{
		src:             src,
		refreshInterval: refreshInterval,
		staleThreshold:  staleThreshold,
		metrics:         m,
		stop:            make(chan struct{}),
	}
}

// Refresh fetches + parses the CRL once. Stores the revoked-set on success;
// keeps the previous set on failure (fail-open with metric).
func (c *CRLCache) Refresh(ctx context.Context) error {
	pemBytes, err := c.src.FetchCRLPEM(ctx)
	if err != nil {
		if c.metrics != nil {
			c.metrics.OperatorCertCRLRefresh(false, 0)
		}
		return fmt.Errorf("fetch CRL: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		if c.metrics != nil {
			c.metrics.OperatorCertCRLRefresh(false, 0)
		}
		return errors.New("CRL: PEM decode produced no block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		if c.metrics != nil {
			c.metrics.OperatorCertCRLRefresh(false, 0)
		}
		return fmt.Errorf("parse CRL: %w", err)
	}
	revoked := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, r := range crl.RevokedCertificateEntries {
		// Lower-hex normalisation matches normaliseSerial() in
		// operator_cert.go so revoked-set membership tests align with the
		// serial form the revoke handler stored against.
		revoked[r.SerialNumber.Text(16)] = struct{}{}
	}
	c.mu.Lock()
	c.revoked = revoked
	c.lastRefresh = time.Now()
	c.loaded = true
	c.mu.Unlock()
	if c.metrics != nil {
		c.metrics.OperatorCertCRLRefresh(true, len(revoked))
	}
	return nil
}

// Start kicks off an initial synchronous Refresh + the background refresher
// goroutine. The synchronous initial fetch ensures the first connection
// after Start returns sees a real CRL state (assuming the fetch succeeds).
// Failure of the initial fetch is logged + the cache stays in fail-open
// state; subsequent refreshes will fix it.
func (c *CRLCache) Start(ctx context.Context) {
	if err := c.Refresh(ctx); err != nil {
		log.Printf("CRLCache: initial fetch failed (fail-open until next refresh): %v", err)
	}
	go func() {
		t := time.NewTicker(c.refreshInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := c.Refresh(rctx); err != nil {
					log.Printf("CRLCache: refresh failed (keeping last good): %v", err)
				}
				cancel()
			case <-c.stop:
				return
			}
		}
	}()
}

// Stop shuts down the refresh goroutine. Safe to call multiple times; safe
// to call before Start() (no-op).
func (c *CRLCache) Stop() {
	select {
	case <-c.stop:
		// already stopped
	default:
		close(c.stop)
	}
}

// IsRevoked returns true iff serial is in the latest fetched CRL. Returns
// false (accept) when the cache hasn't successfully loaded yet (fail-open
// initial). When staleThreshold > 0 AND the last fetch is older than that,
// returns true for all serials (hard-fail — operator must establish a fresh
// CRL fetch before any cert is accepted).
func (c *CRLCache) IsRevoked(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loaded {
		return false // never fetched → fail-open
	}
	if c.staleThreshold > 0 && time.Since(c.lastRefresh) > c.staleThreshold {
		return true // last fetch too old → hard-fail
	}
	_, found := c.revoked[serial.Text(16)]
	return found
}

// VerifyPeerCertificate is the TLS callback that runs AFTER chain validation
// (so verifiedChains has already been built and the trust anchor matched).
// Inspects the leaf and rejects when its serial is revoked. Used by the
// controller for both operator-port (:7101) and admin-port (:7103)
// tls.Config.VerifyPeerCertificate.
func (c *CRLCache) VerifyPeerCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		// No verified chain — handshake-level chain validation didn't run
		// (e.g. ClientAuth=NoClientCert). Nothing for us to check; accept.
		// This is only reached when mTLS is intentionally off; the operator
		// + admin ports both enforce RequireAndVerifyClientCert in prod, so
		// this branch is dev-mode only.
		if c.metrics != nil {
			c.metrics.OperatorCertRevocationCheck("no_chain")
		}
		return nil
	}
	leaf := verifiedChains[0][0]
	if c.IsRevoked(leaf.SerialNumber) {
		if c.metrics != nil {
			c.metrics.OperatorCertRevocationCheck("revoked")
		}
		// Surface the serial in the error so the controller log captures
		// which cert was rejected (joins back to the revoke audit line).
		return fmt.Errorf("operator cert revoked (serial=%s)", leaf.SerialNumber.Text(16))
	}
	if c.metrics != nil {
		c.metrics.OperatorCertRevocationCheck("accepted")
	}
	return nil
}

// LastRefresh returns the timestamp of the last successful CRL fetch (zero
// when never loaded). For metrics export.
func (c *CRLCache) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastRefresh
}

// RevokedCount returns the current revoked-set size. For metrics export.
func (c *CRLCache) RevokedCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.revoked)
}
