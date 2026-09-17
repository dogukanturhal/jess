// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

// rdp_vault_creds — the PRODUCTION RDPCredentialBroker. It replaces the
// dev-only env-creds path with a Vault-minted, short-lived, per-session NLA
// credential, so the live RDP console (cmd/jess-web/ws_rdp_live.go) and the
// worker RDP broker (rdp.go) both terminate NLA/CredSSP at the broker using a
// credential that NEVER existed before the session and is auto-revoked after
// it.
//
// MECHANISM — Vault LDAP secrets engine, DYNAMIC credentials
// (GET /v1/<mount>/creds/<role>). This is the engine HashiCorp now ships in
// place of the deprecated `ad` secrets engine; it is directory-agnostic
// (works against AD or any LDAP) and returns a username/password pair that
// maps 1:1 to an NLA credential — exactly the RDPSecretADCredential shape the
// session_live subprocess consumes (RDP_USER/RDP_PASS/RDP_DOMAIN). The engine
// CREATES an ephemeral account scoped to the role's creation_ldif on each
// mint and DELETES it at lease end, so there is no standing AD credential.
// This mirrors how jess already mints dynamic Postgres/MySQL creds
// (vaultx.DBCredentials → dbproxy/mysqlproxy CredsFor), keeping one credential
// pattern across protocols.
//
// CONFIG — every Vault coordinate is env/config-driven, never hardcoded:
//
//	JESS_RDP_VAULT_MOUNT   LDAP secrets-engine mount    (e.g. "ldap")    [required to enable]
//	JESS_RDP_VAULT_ROLE    shared dynamic role, or ""   → fall back to the target ID
//	                       (one Vault role per RDP target — same convention as
//	                       vaultRDPRole / the DB brokers).
//	JESS_RDP_VAULT_DOMAIN  AD domain stamped into the NLA credential (RDP_DOMAIN);
//	                       the LDAP engine returns user/pass but not the NT domain,
//	                       so the deploy declares it here. Empty = no domain.
//	JESS_RDP_CRED_TTL      max session-bind TTL hint (the Vault role's TTL is the
//	                       real authority; this is the value Issue reports back).
//
// AUDIT — every mint is bound to the real operator sub (passed in by the web
// handler) and logged WITHOUT the secret; Vault's own audit log records the
// lease against jess's token. The password is never logged here.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dogukanturhal/jess/internal/vaultx"
)

// vaultLDAPClient is the slice of the vaultx client the RDP cred broker needs.
// Narrow interface so tests inject a fake without a live Vault.
type vaultLDAPClient interface {
	LDAPDynamicCredential(ctx context.Context, ldapMount, role string) (vaultx.LDAPCredential, error)
}

// VaultRDPCredsConfig configures the Vault-backed RDP credential broker. Mount
// is required (it gates the whole feature); the rest are optional knobs.
type VaultRDPCredsConfig struct {
	// Mount is the Vault LDAP secrets-engine mount path (e.g. "ldap"). Required.
	Mount string
	// Role is the fixed dynamic role for ALL RDP targets, or "" to use the
	// per-target role (the target ID) — the same 1:1 convention as the DB
	// brokers and vaultRDPRole.
	Role string
	// Domain is the AD domain stamped onto the minted NLA credential
	// (RDP_DOMAIN). The LDAP engine returns user/pass but not the NT domain.
	Domain string
	// TTL is the session-bind TTL hint Issue reports back. The Vault role's
	// own TTL is the real authority; 0 here means "trust the lease TTL".
	TTL time.Duration
}

// RDPSessionCredBroker is the WEB seam (cmd/jess-web/ws_rdp_live.go): it mints
// a per-session NLA credential for a target, binding the mint to the real
// operator sub for audit. It is the production replacement for the dev env
// credential. *vaultRDPCredBroker satisfies it.
type RDPSessionCredBroker interface {
	// IssueForOperator mints a short-lived AD credential scoped to the target,
	// audit-bound to operatorSub. It returns the credential + the lease TTL the
	// caller can use to bound the session.
	IssueForOperator(ctx context.Context, targetID, operatorSub string) (RDPSecret, time.Duration, error)
}

// vaultRDPCredBroker mints short-lived NLA credentials from Vault's LDAP
// secrets engine. It implements RDPCredentialBroker (the worker-broker seam)
// AND RDPSessionCredBroker (the web seam, with operator-sub audit binding).
type vaultRDPCredBroker struct {
	vc  vaultLDAPClient
	cfg VaultRDPCredsConfig
}

// NewVaultRDPCredBroker builds the production RDP credential broker over the
// vaultx client. Returns an error if the LDAP mount is not configured — the
// caller decides whether that is fatal (production) or a fall-through to the
// dev path. vc must be non-nil. The concrete type satisfies BOTH the worker
// (RDPCredentialBroker) and web (RDPSessionCredBroker) seams.
func NewVaultRDPCredBroker(vc vaultLDAPClient, cfg VaultRDPCredsConfig) (*vaultRDPCredBroker, error) {
	if vc == nil {
		return nil, fmt.Errorf("rdp vault creds: nil vault client")
	}
	if cfg.Mount == "" {
		return nil, fmt.Errorf("rdp vault creds: LDAP secrets-engine mount required (set JESS_RDP_VAULT_MOUNT)")
	}
	return &vaultRDPCredBroker{vc: vc, cfg: cfg}, nil
}

// roleFor resolves the Vault role for a target ID: the fixed role if configured,
// else the target ID (per-target role). A non-empty role is required so the
// mint has an addressable Vault endpoint.
func (b *vaultRDPCredBroker) roleFor(targetID string) (string, error) {
	if b.cfg.Role != "" {
		return b.cfg.Role, nil
	}
	if targetID == "" {
		return "", fmt.Errorf("rdp vault creds: no fixed role configured and target has no ID (cannot resolve Vault role)")
	}
	return targetID, nil
}

// IssueRDPCredential implements RDPCredentialBroker — the worker-broker seam.
// It mints from Vault using the role the worker derived (vaultRDPRole). The
// operator-sub binding for the worker path is carried by the AccessGrant the
// worker already threads through Mint; this method keeps the existing seam
// signature so the worker wiring is unchanged.
func (b *vaultRDPCredBroker) IssueRDPCredential(ctx context.Context, role string) (RDPSecret, error) {
	return b.mint(ctx, role, "")
}

// IssueForOperator is the WEB seam: it mints a per-session NLA credential for a
// specific target, binding the mint to the real operator sub for audit. The
// returned RDPSecret carries the AD credential; lease TTL is logged + returned
// via leaseTTL so the caller can scope the session.
func (b *vaultRDPCredBroker) IssueForOperator(ctx context.Context, targetID, operatorSub string) (RDPSecret, time.Duration, error) {
	role, err := b.roleFor(targetID)
	if err != nil {
		return RDPSecret{}, 0, err
	}
	sec, ttl, err := b.mintWithTTL(ctx, role, operatorSub)
	if err != nil {
		return RDPSecret{}, 0, err
	}
	return sec, ttl, nil
}

// mint resolves a role string straight through (worker path) and discards the
// TTL (the worker scopes by its own grant lifetime).
func (b *vaultRDPCredBroker) mint(ctx context.Context, role, operatorSub string) (RDPSecret, error) {
	sec, _, _, err := b.mintFull(ctx, role, operatorSub)
	return sec, err
}

// mintWithTTL is the web-seam shape: credential + lease TTL (lease id discarded).
func (b *vaultRDPCredBroker) mintWithTTL(ctx context.Context, role, operatorSub string) (RDPSecret, time.Duration, error) {
	sec, _, ttl, err := b.mintFull(ctx, role, operatorSub)
	return sec, ttl, err
}

// mintFull performs the Vault LDAP dynamic-credential read and shapes it into an
// RDPSecret, ALSO returning the Vault lease id so the offline-credentials
// pre-position path can emergency-revoke the lease on reconnect. It NEVER logs
// the password. operatorSub may be "" (worker / pre-position path); when set it
// is recorded for audit binding.
func (b *vaultRDPCredBroker) mintFull(ctx context.Context, role, operatorSub string) (RDPSecret, string, time.Duration, error) {
	if role == "" {
		return RDPSecret{}, "", 0, fmt.Errorf("rdp vault creds: empty Vault role (fail-closed)")
	}
	cred, err := b.vc.LDAPDynamicCredential(ctx, b.cfg.Mount, role)
	if err != nil {
		return RDPSecret{}, "", 0, fmt.Errorf("rdp vault creds: mint (mount=%s role=%s sub=%s): %w", b.cfg.Mount, role, operatorSub, err)
	}
	ttl := cred.LeaseTTL
	if b.cfg.TTL > 0 && (ttl == 0 || b.cfg.TTL < ttl) {
		ttl = b.cfg.TTL
	}
	// Audit line — sub + role + lease TTL, NO secret.
	log.Printf("rdp vault creds: minted NLA credential mount=%s role=%s sub=%s user=%s lease_ttl=%s lease_id=%s",
		b.cfg.Mount, role, redactSub(operatorSub), cred.Username, ttl, cred.LeaseID)
	return RDPSecret{
		Kind:     RDPSecretADCredential,
		Username: cred.Username,
		Password: cred.Password,
		Domain:   b.cfg.Domain,
	}, cred.LeaseID, ttl, nil
}

// IssueForPreposition mints a short-TTL NLA credential for DDIL P3.8
// pre-positioning (NOT bound to an operator — the mint is done by the jess
// service identity while online, and the operator is bound at USE time). It
// returns the lease id + lease TTL so the offline-credentials manager can seal
// it, bound its budget, and emergency-revoke the lease on reconnect.
func (b *vaultRDPCredBroker) IssueForPreposition(ctx context.Context, targetID string) (RDPSecret, string, time.Duration, error) {
	role, err := b.roleFor(targetID)
	if err != nil {
		return RDPSecret{}, "", 0, err
	}
	return b.mintFull(ctx, role, "")
}

// redactSub returns the operator sub for the audit line, or a placeholder when
// the worker path supplied none (the AccessGrant carries the sub there instead).
func redactSub(sub string) string {
	if sub == "" {
		return "(worker-grant-bound)"
	}
	return sub
}

// compile-time guards: the Vault broker satisfies both the worker-broker seam
// and the web session-cred seam.
var (
	_ RDPCredentialBroker  = (*vaultRDPCredBroker)(nil)
	_ RDPSessionCredBroker = (*vaultRDPCredBroker)(nil)
)
