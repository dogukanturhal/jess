// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog is the registry of brokered targets (ADR 0030 Phase 5).
//
// Phase 7 (this commit) adds the DiscoveryProvider interface + Aggregator
// substrate that lets multiple providers (Kubernetes node watch, Proxmox
// cluster resources, AWS EC2 describe, …) feed a single in-memory catalog
// alongside the existing static JSON provider. Design:
// docs/adr/0030-phase-7-dynamic-catalog.md.
package catalog

import (
	"context"
	"time"
)

// Protocol is the wire protocol Jess brokers for a target.
type Protocol string

const (
	ProtoTCP      Protocol = "tcp"
	ProtoSSH      Protocol = "ssh"
	ProtoPostgres Protocol = "postgres"
	ProtoMySQL    Protocol = "mysql"
	ProtoRDP      Protocol = "rdp"
	// ProtoK8s brokers Kubernetes apiserver streaming verbs (exec / attach /
	// logs / port-forward) for a target, minting a short-lived impersonation
	// credential bound to the operator's Falcon-ID identity so the cluster's
	// own RBAC applies (no parallel authz). ADR 0049 Phase 1.
	ProtoK8s Protocol = "k8s"
)

// Target is an infrastructure endpoint Jess can broker access to. The Address
// is reachable only from a worker — never directly from the operator.
type Target struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Protocol      Protocol `json:"protocol"`
	Address       string   `json:"address"`                  // host:port (worker-side reachable)
	Region        string   `json:"region,omitempty"`         // multi-region dimension; matched against the identity's region scope
	RequiredRoles []string `json:"required_roles,omitempty"` // Falcon-ID roles permitted (PDP enforces; empty = deny)
	Recorded      bool     `json:"recorded,omitempty"`       // session must be recorded (fail-closed if no recorder)
	// HostKey pins the target's SSH host public key (authorized_keys line). Empty
	// = trust-on-first-use (DEV ONLY) — UNLESS HostKeyCASigned is true, in
	// which case the worker validates the target's presented host certificate
	// against the configured SSH host-CA trust anchor (ADR 0044). Production
	// SSH targets MUST set EITHER HostKey OR HostKeyCASigned=true; bare-string
	// empty + CASigned=false is rejected at session-open time.
	HostKey string `json:"host_key,omitempty"`
	// HostKeyCASigned switches the worker's host-key validation from per-host
	// pinning to CA-mode: the target presents an OpenSSH host certificate
	// signed by jess-ssh-host-ca (Vault SSH mount), and the worker verifies
	// the certificate's signing CA matches its configured trust anchor and
	// the cert's ValidPrincipals contains the dialed hostname. Eliminates the
	// per-host TOFU bootstrap step entirely for any target enrolled via the
	// `scripts/configure-node-ssh-host-cert.sh` flow. When true, the HostKey
	// field may be empty. When false (default), HostKey is the pinning
	// authority and CA mode is not consulted. ADR 0044.
	HostKeyCASigned bool `json:"host_key_ca_signed,omitempty"`
	// RDPTLSCASigned switches the RDP broker's host trust from TOFU/accept-any
	// to AD-CS chain validation (ADR 0047 future-work → ADR 0062, P2.4). When
	// true, the broker pre-flights the RDS host's presented TLS certificate:
	// it must chain to the configured AD-CS trust anchors (JESS_RDP_TLS_CA_PEM),
	// its SAN must match the dialed host, it must be inside its validity window,
	// and it must not be revoked (CRL / fingerprint deny-list) — else the
	// session-open FAILS CLOSED. The x.509 primitive is the RDP analog of the
	// SSH HostKeyCASigned flag (which validates a Vault-signed OpenSSH host
	// cert); the two are NOT interchangeable (see ADR 0047). Ignored for
	// non-RDP protocols. When the worker's global JESS_RDP_TLS_ENFORCE is on,
	// every RDP target is validated regardless of this per-target flag; this
	// field opts a single target in while global enforce is off (migration).
	RDPTLSCASigned bool `json:"rdp_tls_ca_signed,omitempty"`
	// SSHLoginUser overrides the worker's default JESS_SSH_LOGIN_USER for
	// this target. The cert that worker signs at session-open carries this
	// as the cert's valid_principal AND the SSH User: header. Use case:
	// Windows AD DCs where the canonical operator account is `Administrator`
	// (not `hexxlock`), while Linux nodes default to the worker's env
	// (typically `hexxlock`). Empty = use worker env default.
	//
	// Vault SSH role must permit the username in allowed_users — by default
	// ssh-admin allows "hexxlock,Administrator". Adding a new login user
	// here without extending the Vault role's allowed_users yields a 400
	// at sign time with a clear "unallowed user" error.
	SSHLoginUser string `json:"ssh_login_user,omitempty"`
	// Database is the default database/schema for DB protocols (ProtoPostgres,
	// ProtoMySQL). For Postgres, the Vault dynamic user has no matching default
	// db so it must be set here. For MySQL it's the default schema for the
	// brokered session. Ignored for non-DB protocols.
	Database string `json:"database,omitempty"`

	// RequireSessionMFA is the per-target step-up tier (ADR 0037, P2.5): one of
	// "none" (default), "standard", or "elevated". A non-none tier demands a
	// FRESH strong-auth assertion in the operator's token — evaluated at
	// session-open AND continuously by the grant-watch, so a session whose
	// step-up has aged out is torn down mid-flight (fail-closed):
	//   - standard — amr ∈ {mfa,otp,totp,hwk,webauthn,piv,cac} within StepUpTTL
	//     (default 1h).
	//   - elevated — amr ∈ {hwk,webauthn,piv,cac} (phishing-resistant ONLY, no
	//     TOTP) within a tighter StepUpTTL (default 5min). Prod DB targets,
	//     root-shell SSH, infra control planes.
	// Empty/"none" preserves pre-P2.5 behaviour. The controller's global
	// JESS_STEP_UP_DEFAULT_POLICY applies a fleet-wide floor when this is empty.
	//
	// +kubebuilder:validation:Enum=none;standard;elevated
	// +optional
	RequireSessionMFA string `json:"require_session_mfa,omitempty"`
	// StepUpTTLSeconds overrides the step-up freshness window for this target
	// (seconds). Zero = the tier default (standard 1h, elevated 5min). Example:
	// a customer prod DB may pin 300 (re-tap every 5min); a low-risk catalog
	// browser may pin a longer window for ergonomics. Ignored when
	// RequireSessionMFA is none.
	StepUpTTLSeconds int `json:"step_up_ttl_seconds,omitempty"`

	// Criticality classifies the blast radius of operations on this target.
	// Drives Phase 5h-4 risk-scored auto-approval — low-criticality targets
	// on business hours may auto-approve; critical targets always require
	// human review. Empty string == "medium" (the safe default — neither
	// auto-approves nor requires extra MFA).
	//
	// Levels (lowest → highest blast radius):
	//   "low"       — read-only / non-prod (jess-pg-db itself; sandbox targets)
	//   "medium"    — workload-tier (node-app-01 SSH, hexxlock_business DB)
	//   "high"      — control-plane (node-cp-01, jess-controller DB)
	//   "critical"  — root-of-trust (vault, dc-identity, falcon-id DB)
	//
	// +kubebuilder:validation:Enum=low;medium;high;critical
	// +optional
	Criticality string `json:"criticality,omitempty"`

	// Tags carries operator-meaningful labels (e.g. ["production",
	// "soc2-in-scope", "team:platform-data"]) that the risk-score
	// evaluator can match against. Reserved name prefixes:
	//   "team:<name>"    — owning team (alerts route here)
	//   "compliance:<x>" — frameworks the target is in-scope for
	// No semantics enforced here; the catalog is the bag-of-strings,
	// the evaluator is the policy.
	Tags []string `json:"tags,omitempty"`

	// OfflineCredentials is the per-target opt-in for DDIL P3.8 pre-positioned
	// offline session credentials. When absent or Enabled=false (the default),
	// the target is NOT eligible: a Vault outage halts new privileged sessions
	// to it exactly as before (fail closed). When an operator explicitly opts a
	// non-Tier-0 target in, jess proactively pre-fetches + caches a short-TTL
	// Vault-minted credential while online and, only if Vault becomes
	// unreachable, may serve that cached credential within a signed, time-boxed
	// budget (MaxTTL), bounded by MaxUses, then fails closed.
	//
	// SECURITY: a Tier-0 target (criticality=="critical" — Domain Controllers /
	// the crown-jewels set, ADR 0052) is NEVER eligible even if this opts it in;
	// the exclusion is enforced un-overridably in internal/offlinecreds
	// (registration refused + prewarm suppressed + use-time backstop), mirroring
	// the Tier-0 RDP hard-guard. See ADR 0062.
	//
	// Empty/nil = not eligible (the safe default).
	OfflineCredentials *OfflineCredentialsPolicy `json:"offline_credentials,omitempty"`

	// RequireDeviceClaims is the per-target device-posture wall
	// (Phase 5h-5). Mirrors talon/api/v1alpha1.TalonRoute's same-
	// named field so an operator with a non-compliant laptop sees
	// the same denial on the L4 path (this) as on the L7 path
	// (Talon). Every requirement is AND-combined; ValuesAnyOf is
	// OR-combined within a requirement; missing claim in the
	// operator's JWT FAILS CLOSED.
	//
	// Empty/nil = no device gate. Production posture: high- and
	// critical-criticality targets SHOULD set at minimum:
	//   [{Claim: "device_compliant", ValuesAnyOf: ["true"]},
	//    {Claim: "device_managed_by_mdm", ValuesAnyOf: ["true"]}]
	//
	// Canonical claim names mirrored in
	// internal/devicepolicy/devicepolicy.go::CanonicalClaimNames.
	RequireDeviceClaims []DeviceClaimRequirement `json:"require_device_claims,omitempty"`

	// Source names the DiscoveryProvider that surfaced this target
	// (Phase 7a). "static" for the JSON ConfigMap, "k8s-nodes" for
	// the Kubernetes provider, "proxmox" for the Proxmox provider,
	// "aws-ec2" for AWS, "admin-api" for ad-hoc additions via
	// jessctl admin target add, etc. Audit events stamp this field
	// so a SOC2 trail can answer "which provider added/removed
	// target X at time T?".
	//
	// Empty = unknown source (legacy targets; never written by the
	// aggregator). Operators reading the catalog should treat
	// empty as "static, pre-Phase-7".
	Source string `json:"source,omitempty"`

	// LastSeen is wall-clock time of the most recent successful
	// discovery refresh that included this target. The aggregator
	// updates this on every refresh; consumers can use it to spot
	// targets that were once discovered but have gone stale (e.g. a
	// provider's connection broke 30min ago — the targets are still
	// in the last-known-good cache, but their LastSeen freezes at
	// the last successful refresh).
	//
	// Static and admin-api targets carry the timestamp of their
	// last config load (effectively "always fresh" until removed).
	LastSeen time.Time `json:"last_seen,omitempty"`
}

// DeviceClaimRequirement is one (claim, values-any-of) pair.
// Cross-PEP shape match with talon/api/v1alpha1.DeviceClaimRequirement.
type DeviceClaimRequirement struct {
	Claim       string   `json:"claim"`
	ValuesAnyOf []string `json:"valuesAnyOf"`
}

// OfflineCredentialsPolicy is the JessTarget opt-in for DDIL P3.8 pre-positioned
// offline session credentials (ADR 0062). It is a plain data carrier — the
// eligibility rules, Tier-0 hard-exclusion, staleness budget, and use accounting
// live in internal/offlinecreds, which is the single authoritative enforcement
// point. The catalog only surfaces the operator's declared intent.
//
// The zero value (Enabled=false) means NOT eligible: nothing changes for a
// target until an operator explicitly sets Enabled=true.
type OfflineCredentialsPolicy struct {
	// Enabled opts this target in. Default false ⇒ not eligible (safe default).
	Enabled bool `json:"enabled,omitempty"`
	// MaxTTL bounds how long a pre-positioned credential may be honoured offline
	// after it was pre-positioned, independent of the credential's own lease TTL.
	// 0 ⇒ the manager's configured default (4h). Clamped to the global cap
	// (JESS_OFFLINE_CREDS_MAX_TTL).
	MaxTTL time.Duration `json:"max_ttl,omitempty"`
	// MaxUses caps how many offline sessions one pre-positioned credential may
	// back before it fails closed. 0 ⇒ the manager's small default (3). Clamped
	// to the global cap (JESS_OFFLINE_CREDS_MAX_USES).
	MaxUses int `json:"max_uses,omitempty"`
}

// Catalog resolves targets. Implementations: in-cluster CRD / config / DB.
type Catalog interface {
	Lookup(ctx context.Context, id string) (*Target, error)
	List(ctx context.Context, region string) ([]*Target, error)
}
