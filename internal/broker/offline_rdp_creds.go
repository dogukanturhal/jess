// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

// offline_rdp_creds — the DDIL P3.8 bridge between the RDP session-credential
// seam and the generic internal/offlinecreds manager. It gives the live RDP
// console a governed-degrade credential source: while Vault is reachable it is a
// transparent pass-through to the per-session Vault mint AND it drives the
// pre-positioning of an eligible target's short-TTL credential; only when Vault
// is UNREACHABLE (partition, not a 4xx rejection) does it serve the
// pre-positioned credential, and only within the manager's signed budget +
// max-uses. Authorization (the JIT grant gate + recorder gate) is enforced
// upstream in the handler and is untouched — this swaps only the credential
// SOURCE, never the authz.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/offlinecreds"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// rdpPrepositioner mints a short-TTL NLA credential for pre-positioning,
// returning the lease id for later revoke. Satisfied by *vaultRDPCredBroker.
type rdpPrepositioner interface {
	IssueForPreposition(ctx context.Context, targetID string) (RDPSecret, string, time.Duration, error)
}

// RDPCredBrokerWithPreposition is the exported facade over the production Vault
// RDP credential broker: it is BOTH the online per-session mint
// (RDPSessionCredBroker) and the offline pre-position minter. *vaultRDPCredBroker
// satisfies it. Wiring code (cmd/jess-web) types the Vault broker as this so it
// can hand the same value to both NewRDPOfflineMinter and NewOfflineRDPCredBroker
// without naming the unexported concrete type.
type RDPCredBrokerWithPreposition interface {
	RDPSessionCredBroker
	IssueForPreposition(ctx context.Context, targetID string) (RDPSecret, string, time.Duration, error)
}

// rdpOfflineMinter adapts an rdpPrepositioner into an offlinecreds.Minter by
// marshaling the RDPSecret into an opaque JSON payload the manager seals at rest.
type rdpOfflineMinter struct{ p rdpPrepositioner }

// NewRDPOfflineMinter wraps an rdpPrepositioner (the Vault RDP broker) as the
// offlinecreds.Minter that the pre-position refresh loop calls while online.
func NewRDPOfflineMinter(p rdpPrepositioner) offlinecreds.Minter { return rdpOfflineMinter{p: p} }

func (m rdpOfflineMinter) Mint(ctx context.Context, targetID string) (offlinecreds.MintResult, error) {
	sec, leaseID, ttl, err := m.p.IssueForPreposition(ctx, targetID)
	if err != nil {
		return offlinecreds.MintResult{}, err
	}
	payload, err := json.Marshal(sec)
	if err != nil {
		return offlinecreds.MintResult{}, fmt.Errorf("rdp offline creds: marshal pre-positioned credential: %w", err)
	}
	return offlinecreds.MintResult{Payload: payload, TTL: ttl, LeaseID: leaseID}, nil
}

// leaseRevoker force-revokes a Vault lease by id. Satisfied by *vaultx.Client.
type leaseRevoker interface {
	RevokeLease(ctx context.Context, leaseID string) error
}

// vaultLeaseRevoker adapts a Vault client into an offlinecreds.Revoker so
// pre-positioned dynamic credentials are emergency-revoked on reconnect.
type vaultLeaseRevoker struct{ rl leaseRevoker }

// NewVaultLeaseRevoker wraps a Vault client as the offlinecreds.Revoker.
func NewVaultLeaseRevoker(rl leaseRevoker) offlinecreds.Revoker { return vaultLeaseRevoker{rl: rl} }

// Revoke satisfies offlinecreds.Revoker by adapting to the Vault client's
// RevokeLease name.
func (r vaultLeaseRevoker) Revoke(ctx context.Context, leaseID string) error {
	return r.rl.RevokeLease(ctx, leaseID)
}

// OfflineRDPCredBroker wraps the production Vault RDP credential broker with the
// P3.8 pre-position/contingency path. It satisfies RDPSessionCredBroker so it
// drops into the existing rdpLiveConfig.vaultCreds seam unchanged.
type OfflineRDPCredBroker struct {
	inner RDPSessionCredBroker
	mgr   *offlinecreds.Manager

	// unreachable classifies an inner-mint error as a Vault PARTITION (⇒ try the
	// pre-positioned credential) vs a genuine rejection (⇒ fail closed). Defaults
	// to vaultx.IsUnreachable; overridable in tests.
	unreachable func(error) bool

	warnMu      sync.Mutex
	tier0Warned map[string]struct{}
}

// NewOfflineRDPCredBroker composes the online Vault mint (inner) with the
// offline-credentials manager (mgr). Both are required.
func NewOfflineRDPCredBroker(inner RDPSessionCredBroker, mgr *offlinecreds.Manager) (*OfflineRDPCredBroker, error) {
	if inner == nil {
		return nil, fmt.Errorf("rdp offline creds: nil inner credential broker")
	}
	if mgr == nil {
		return nil, fmt.Errorf("rdp offline creds: nil offline-credentials manager")
	}
	return &OfflineRDPCredBroker{
		inner:       inner,
		mgr:         mgr,
		unreachable: vaultx.IsUnreachable,
		tier0Warned: map[string]struct{}{},
	}, nil
}

// RegisterTarget opts a resolved target into pre-positioning when its CRD says
// so and it is not Tier-0. Idempotent + cheap; the handler calls it on each
// session open so the set of pre-positioned targets tracks recently-used,
// opted-in, non-Tier-0 targets. A Tier-0 target that (mis-)opted in is refused
// un-overridably by the manager and surfaced once here.
func (b *OfflineRDPCredBroker) RegisterTarget(t *catalog.Target) {
	if t == nil {
		return
	}
	tp := offlinecreds.TargetPolicy{
		TargetID:    t.ID,
		Criticality: t.Criticality,
		Policy:      offlinePolicyFromTarget(t),
	}
	if err := b.mgr.Register(tp); errors.Is(err, offlinecreds.ErrTier0Excluded) {
		b.warnTier0Once(t.ID)
	}
}

// warnTier0Once logs a crown-jewels opt-in rejection at most once per target.
func (b *OfflineRDPCredBroker) warnTier0Once(targetID string) {
	b.warnMu.Lock()
	_, seen := b.tier0Warned[targetID]
	if !seen {
		b.tier0Warned[targetID] = struct{}{}
	}
	b.warnMu.Unlock()
	if !seen {
		log.Printf("rdp offline creds: REFUSED offline-credential opt-in for Tier-0 target %s (criticality=critical) — crown-jewels rule, never eligible (ADR 0062/0052)", targetID)
	}
}

// IssueForOperator tries the online Vault mint first. On success it is a
// transparent pass-through (and marks Vault reachable). On a GENUINE rejection
// (4xx) it fails closed. Only on an UNREACHABLE Vault (transport/5xx) does it
// consult the manager for a pre-positioned credential, which itself fails closed
// unless within budget + max-uses. The authorizing grant was already asserted
// upstream by the caller, so an offline credential never bypasses authz.
func (b *OfflineRDPCredBroker) IssueForOperator(ctx context.Context, targetID, operatorSub string) (RDPSecret, time.Duration, error) {
	sec, ttl, err := b.inner.IssueForOperator(ctx, targetID, operatorSub)
	if err == nil {
		b.mgr.NotifyReachable(true)
		return sec, ttl, nil
	}
	if !b.unreachable(err) {
		// Real rejection (bad role / permission / bad request): fail closed,
		// never mask a "you are not allowed" as a partition.
		return RDPSecret{}, 0, err
	}
	b.mgr.NotifyReachable(false)

	payload, meta, cerr := b.mgr.Contingency(ctx, targetID, operatorSub)
	if cerr != nil {
		// Not eligible / no pre-positioned cred / out of budget / over max-uses:
		// fail closed exactly as today, surfacing both the offline reason and the
		// underlying Vault error.
		return RDPSecret{}, 0, fmt.Errorf("rdp offline creds: %w (vault unreachable: %v)", cerr, err)
	}
	var sec2 RDPSecret
	if uerr := json.Unmarshal(payload, &sec2); uerr != nil {
		return RDPSecret{}, 0, fmt.Errorf("rdp offline creds: decode pre-positioned credential: %w", uerr)
	}
	// Bound the session to the credential's remaining lease.
	remaining := time.Until(meta.CredExpiry)
	if remaining < 0 {
		remaining = 0
	}
	log.Printf("rdp offline creds: SERVED pre-positioned credential target=%s sub=%s cache=%s prepositioned_at=%s use=%d/%d budget_until=%s (Vault UNREACHABLE) — offline_credential=true",
		targetID, operatorSub, meta.CacheID, meta.PrepositionedAt.UTC().Format(time.RFC3339),
		meta.Use, meta.MaxUses, meta.BudgetValidUntil.UTC().Format(time.RFC3339))
	return sec2, remaining, nil
}

// offlinePolicyFromTarget maps the catalog CRD opt-in to the manager policy. A
// nil OfflineCredentials ⇒ zero policy (Enabled=false ⇒ not eligible).
func offlinePolicyFromTarget(t *catalog.Target) offlinecreds.Policy {
	if t == nil || t.OfflineCredentials == nil {
		return offlinecreds.Policy{}
	}
	return offlinecreds.Policy{
		Enabled: t.OfflineCredentials.Enabled,
		MaxTTL:  t.OfflineCredentials.MaxTTL,
		MaxUses: t.OfflineCredentials.MaxUses,
	}
}

// compile-time guards: the offline broker satisfies the web session-cred seam,
// and the Vault RDP broker satisfies the combined preposition facade.
var (
	_ RDPSessionCredBroker         = (*OfflineRDPCredBroker)(nil)
	_ RDPCredBrokerWithPreposition = (*vaultRDPCredBroker)(nil)
)
