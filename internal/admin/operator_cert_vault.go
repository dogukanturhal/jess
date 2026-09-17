// SPDX-License-Identifier: AGPL-3.0-or-later

package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// VaultSigner is the Vault-PKI-mount backed Signer. Every issuance lands in
// Vault's audit log (with the verified Falcon-ID subject in the CN claim);
// the CA private key never leaves Vault; revocation works via
// `vault write <mount>/revoke serial=...`. Pairs with the iac PR that
// declares the mount + sign role (jess-ca + operator-cert).
//
// The trust bundle (CA cert + chain) is fetched once at construction time
// from /v1/<mount>/cert/ca + ca_chain so CAPem() is a fast in-memory copy
// — operator clients calling /operator-cert get the bundle on every mint
// without a per-request Vault round-trip.
type VaultSigner struct {
	vc     *vaultx.Client
	mount  string // e.g. "jess-ca"
	role   string // e.g. "operator-cert"
	maxTTL time.Duration

	mu        sync.RWMutex
	bundle    []byte // CA cert + chain, PEM-concatenated
	fetchedAt time.Time
}

// NewVaultSigner builds a signer backed by the given Vault PKI mount + role.
// Fetches the CA trust bundle at construction so subsequent SignCSR calls
// don't pay the round-trip; the bundle is re-fetched lazily once an hour
// in case the mount rotates (extremely rare; the resource is
// ignore_changes=all in TF).
func NewVaultSigner(ctx context.Context, vc *vaultx.Client, mount, role string) (*VaultSigner, error) {
	if vc == nil {
		return nil, errors.New("vault client nil")
	}
	if mount == "" || role == "" {
		return nil, errors.New("vault PKI mount + role required")
	}
	s := &VaultSigner{vc: vc, mount: strings.Trim(mount, "/"), role: role, maxTTL: MaxOperatorCertTTL}
	if err := s.refreshBundle(ctx); err != nil {
		return nil, fmt.Errorf("fetch CA bundle: %w", err)
	}
	return s, nil
}

// caBundleTTL is how long the in-memory CA-bundle copy is trusted before
// being re-fetched. 1h is plenty — the CA + chain rotates ~yearly per the
// iac TF, never on a fast cadence.
const caBundleTTL = 1 * time.Hour

func (s *VaultSigner) refreshBundle(ctx context.Context) error {
	// /v1/<mount>/ca/pem returns the CA cert (no chain) in raw PEM form,
	// which is what we want. /cert/ca returns JSON-wrapped. PEM is simpler.
	pem, err := s.vc.ReadRawPEM(ctx, "/v1/"+s.mount+"/ca/pem")
	if err != nil {
		return err
	}
	// Try to append the CA chain too (intermediates). Empty result is fine
	// for single-root mounts (the jess-ca root we just declared in iac).
	chainPEM, _ := s.vc.ReadRawPEM(ctx, "/v1/"+s.mount+"/ca_chain")
	out := append([]byte{}, pem...)
	if len(chainPEM) > 0 {
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, chainPEM...)
	}
	s.mu.Lock()
	s.bundle = out
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	return nil
}

// SignCSR satisfies the Signer interface — calls Vault PKI sign with the
// caller's verified subject as the CN. Per the role config (iac), Vault
// honours the supplied common_name (use_csr_common_name=false) so the
// CSR's claimed CN is dropped — same RFC 8705 §2.1 binding the in-process
// LocalSigner enforces.
func (s *VaultSigner) SignCSR(ctx context.Context, csrPEM []byte, callerSubject, callerEmail string, ttl time.Duration) ([]byte, error) {
	if ttl <= 0 || ttl > s.maxTTL {
		ttl = s.maxTTL
	}
	if callerSubject == "" {
		return nil, errors.New("callerSubject empty (refusing to sign cert with no CN)")
	}
	resp, err := s.vc.SignPKICert(ctx, s.mount, s.role, vaultx.PKISignRequest{
		CSRPEM:     string(csrPEM),
		CommonName: callerSubject,
		TTL:        ttl,
		// Email goes into otherSANs as an rfc822Name (otherName-encoded so
		// Vault role's allowed_other_sans gates it). For Phase 2 we omit
		// it — the role doesn't allow_email currently; uncomment when the
		// role config is widened. The LocalSigner stamps EmailAddresses
		// directly; the parity gap is acceptable for the migration window.
	})
	if err != nil {
		return nil, err
	}
	// The signed leaf cert ONLY. The CA bundle is exposed separately via
	// CAPem() so callers don't get the CA mixed into the leaf cert.
	return []byte(resp.Certificate), nil
}

// RevokeSerial implements the Revoker interface — flips the supplied
// cert serial into the CA's CRL via /v1/<mount>/revoke. The CA private
// key never leaves Vault. Every revoke lands in Vault's audit log under
// the controller's K8s-auth identity; the calling operator's Falcon-ID
// subject is captured separately by the CertHandler.handleRevoke log
// line so the operator audit trail joins back to the Vault audit log.
//
// Idempotent: revoking an already-revoked or unknown serial succeeds
// (Vault's /revoke endpoint echoes the existing revocation_time).
func (s *VaultSigner) RevokeSerial(ctx context.Context, serial string) error {
	return s.vc.RevokePKICert(ctx, s.mount, serial)
}

// CAPem returns the cached CA + chain bundle. Refreshes lazily once per
// caBundleTTL so a CA rotation propagates without a controller restart.
func (s *VaultSigner) CAPem() []byte {
	s.mu.RLock()
	stale := time.Since(s.fetchedAt) > caBundleTTL
	s.mu.RUnlock()
	if stale {
		// Best-effort refresh; on failure, return the cached bundle (better
		// than failing the request). Bounded with a short ctx so a hung
		// Vault doesn't stall the calling /operator-cert request.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.refreshBundle(ctx)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]byte, len(s.bundle))
	copy(out, s.bundle)
	return out
}
