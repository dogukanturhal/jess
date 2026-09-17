// SPDX-License-Identifier: AGPL-3.0-or-later

// Package offlinecreds implements DDIL P3.8 — pre-positioned offline session
// credentials for the jess ZTNA broker.
//
// Problem
// =======
// Every privileged session mints its credential from Vault per-session (SSH
// cert / AD/DB dynamic secret). Vault is therefore a hard dependency: if Vault
// is unreachable, ALL new privileged sessions halt (fail closed at t=0). The
// DDIL degraded-mode operating spec (PACE Contingency tier, row 5) requires a
// governed-degrade path for DESIGNATED tiers instead of a total halt.
//
// Design (secure-by-default; see ADR 0062)
// ========================================
//  1. OPT-IN PER TARGET. A target is eligible only if an operator explicitly set
//     OfflineCredentials.Enabled=true on its JessTarget CRD. Absent/false ⇒ not
//     eligible; nothing changes until opted in.
//  2. TIER-0 HARD EXCLUSION. A Tier-0 target (criticality=="critical" — Domain
//     Controllers / crown jewels, ADR 0052) is NEVER eligible, even if the CRD
//     opts it in. Enforced un-overridably in THREE layers mirroring the Tier-0
//     RDP hard-guard: registration refused (source), prewarm suppressed
//     (policy), and a use-time backstop (broker) — so a mis-set CRD, a stray
//     tag, or a single bad edit can never expose a DC to offline creds.
//  3. PRE-POSITION WHILE ONLINE. For each eligible target the manager proactively
//     mints a SHORT-TTL Vault credential and refreshes it before expiry, so a
//     still-valid cached credential exists at outage time. The credential is
//     sealed at rest (AES-256-GCM, seal.go) — never a long-lived plaintext
//     secret. This is "pre-positioned" = proactively-cached short-TTL creds, NOT
//     standing creds.
//  4. CONTINGENCY USE. When Vault is unreachable, an already-authorized session
//     to an eligible target may use the cached credential IFF (a) it is still
//     within its lease TTL, (b) within a govdecision signed, time-boxed budget
//     (MaxTTL), and (c) under MaxUses. Otherwise it FAILS CLOSED (deny) — the
//     same posture as today.
//  5. NEVER BYPASS AUTHZ. The JIT grant, the grant re-check, and the recording
//     requirement STILL apply — offline creds replace only the CREDENTIAL SOURCE,
//     never the authorization. This package has no authz entry point.
//  6. AUDIT. Every lifecycle moment (preposition / used / denied / rotated) is
//     emitted through the Auditor with an explicit OfflineCredential=true marker,
//     the pre-position timestamp, and the cache id.
//  7. RECONNECT. On Vault reachability restored after offline use, pre-positioned
//     creds are emergency-rotated (best-effort lease revoke + discard + re-mint).
//
// Standards: NIST SP 800-207 (fail closed, continuous verification), SP 800-53
// CP-7 (equivalent security at the alternate site), and the PACE-for-identity
// "pre-sync, don't pre-share; time-bound creds that expire without refresh"
// best practice for DDIL islands of trust.
package offlinecreds

import (
	"errors"
	"strings"
	"time"
)

// Defaults for the per-target policy. Adversary-aware: short window, few uses.
const (
	// DefaultMaxTTL bounds how long a pre-positioned credential may be honoured
	// offline after it was pre-positioned (the DDIL spec proposal for the
	// privileged-session-credential row).
	DefaultMaxTTL = 4 * time.Hour
	// DefaultMaxUses caps how many offline sessions one pre-positioned credential
	// may back. Small by default — single-digit, not unbounded.
	DefaultMaxUses = 3
)

// Tier0Criticality is the target criticality class that is UNCONDITIONALLY
// excluded from offline credentials — the crown-jewels rule. It matches the
// Tier-0 boundary the RDP hard-guard uses (ADR 0052: DC OU ⇒ criticality
// "critical").
const Tier0Criticality = "critical"

// Tier1Criticality is the HIGHEST-ASSURANCE tier that is ELIGIBLE for offline
// credentials (2026-07-23 decision, ADR-0062): ONLY Tier-1 ("high") targets may
// hold pre-positioned creds. Tier-0 ("critical") is the crown-jewels exclusion
// above; Tier-2+ ("medium"/"low") are excluded below to keep the offline-cred
// surface minimal (survive a Vault outage only for the highest-assurance tier).
const Tier1Criticality = "high"

// offlineCredSubject is the issuer/subject stamped into the govdecision budget
// for a pre-positioned credential. The budget is per-target (Resource=targetID);
// the operator identity is bound at USE time in the audit event, not the budget.
const offlineCredSubject = "jess/offline-creds"

var (
	// ErrNotEligible is returned when a target is not opted in (or is Tier-0).
	ErrNotEligible = errors.New("offlinecreds: target not eligible for offline credentials")
	// ErrTier0Excluded is the crown-jewels rejection: a Tier-0 target may never
	// be registered or served, regardless of its CRD opt-in.
	ErrTier0Excluded = errors.New("offlinecreds: Tier-0 target is hard-excluded from offline credentials")
	// ErrNoPrepositioned is returned by Contingency when no valid pre-positioned
	// credential exists for the target (never minted, or discarded) ⇒ fail closed.
	ErrNoPrepositioned = errors.New("offlinecreds: no pre-positioned credential (fail closed)")
	// ErrBudgetExpired is returned when the signed staleness budget (MaxTTL) has
	// elapsed ⇒ fail closed.
	ErrBudgetExpired = errors.New("offlinecreds: pre-positioned credential budget expired (fail closed)")
	// ErrCredExpired is returned when the credential's own lease TTL has elapsed
	// ⇒ fail closed.
	ErrCredExpired = errors.New("offlinecreds: pre-positioned credential lease expired (fail closed)")
	// ErrMaxUsesExceeded is returned when the credential has already backed
	// MaxUses offline sessions ⇒ fail closed.
	ErrMaxUsesExceeded = errors.New("offlinecreds: pre-positioned credential max-uses exceeded (fail closed)")
	// ErrTamperedBudget is returned when the cached budget fails signature
	// verification ⇒ fail closed (no unsigned local trust).
	ErrTamperedBudget = errors.New("offlinecreds: pre-positioned budget signature invalid (fail closed)")
)

// Policy is the per-target opt-in, sourced from the JessTarget CRD
// (catalog.OfflineCredentialsPolicy) and normalized against the manager's
// configured caps.
type Policy struct {
	// Enabled opts the target in. False (zero value) ⇒ not eligible.
	Enabled bool
	// MaxTTL bounds the offline-honour window after pre-positioning.
	MaxTTL time.Duration
	// MaxUses caps offline sessions per pre-positioned credential.
	MaxUses int
}

// TargetPolicy binds a target's identity + blast-radius classification + policy.
// Criticality drives the Tier-0 hard-exclusion; the manager never trusts an
// Enabled flag alone.
type TargetPolicy struct {
	TargetID    string
	Criticality string
	Policy      Policy
}

// Caps are the global upper bounds every per-target Policy is clamped to,
// sourced from process config (JESS_OFFLINE_CREDS_MAX_TTL / _MAX_USES). They
// stop a permissive CRD from widening the window beyond the operator-set
// ceiling.
type Caps struct {
	MaxTTL  time.Duration
	MaxUses int
}

// DefaultCaps returns the built-in ceilings (4h / 3 uses).
func DefaultCaps() Caps { return Caps{MaxTTL: DefaultMaxTTL, MaxUses: DefaultMaxUses} }

// normalize resolves absent per-target values to defaults and clamps everything
// to the caps. It never widens beyond the caps and never returns a non-positive
// TTL / use count for an enabled policy.
func (p Policy) normalize(caps Caps) Policy {
	if caps.MaxTTL <= 0 {
		caps.MaxTTL = DefaultMaxTTL
	}
	if caps.MaxUses <= 0 {
		caps.MaxUses = DefaultMaxUses
	}
	out := p
	if out.MaxTTL <= 0 {
		out.MaxTTL = DefaultMaxTTL
	}
	if out.MaxTTL > caps.MaxTTL {
		out.MaxTTL = caps.MaxTTL
	}
	if out.MaxUses <= 0 {
		out.MaxUses = DefaultMaxUses
	}
	if out.MaxUses > caps.MaxUses {
		out.MaxUses = caps.MaxUses
	}
	return out
}

// Tier0Guard decides whether a target is Tier-0 (crown jewels) and therefore
// hard-excluded from offline credentials. It is the single authoritative
// exclusion used at every layer (registration, prewarm, use-time backstop). A
// target is Tier-0 if its criticality is "critical" OR it is named in the
// explicit deny set (JESS_OFFLINE_CREDS_TIER0_DENY — a defence-in-depth backstop
// for operators who want to pin specific IDs out regardless of criticality).
type Tier0Guard struct {
	denyTargetIDs map[string]struct{}
}

// NewTier0Guard builds a guard. denyTargetIDs are additional target IDs pinned
// out (in ADDITION to the un-overridable criticality=="critical" rule).
func NewTier0Guard(denyTargetIDs []string) Tier0Guard {
	m := make(map[string]struct{}, len(denyTargetIDs))
	for _, id := range denyTargetIDs {
		if id = strings.TrimSpace(id); id != "" {
			m[id] = struct{}{}
		}
	}
	return Tier0Guard{denyTargetIDs: m}
}

// IsTier0 reports whether tp is a crown-jewels target that may NEVER receive
// offline credentials. The criticality test is case-insensitive and cannot be
// disabled; the deny set only adds to it.
func (g Tier0Guard) IsTier0(tp TargetPolicy) bool {
	if strings.EqualFold(strings.TrimSpace(tp.Criticality), Tier0Criticality) {
		return true
	}
	if _, ok := g.denyTargetIDs[tp.TargetID]; ok {
		return true
	}
	return false
}

// IsTier1 reports whether tp is the highest-assurance ELIGIBLE tier — criticality
// "high". Per the 2026-07-23 decision this is the ONLY tier that may hold
// pre-positioned offline credentials (Tier-0 is hard-excluded above; Tier-2+
// "medium"/"low" are excluded).
func (g Tier0Guard) IsTier1(tp TargetPolicy) bool {
	return strings.EqualFold(strings.TrimSpace(tp.Criticality), Tier1Criticality)
}

// Eligible reports whether tp is opted in AND is the highest-assurance tier
// (Tier-1) AND not Tier-0. Full eligibility predicate: NOT eligible by default
// (Enabled=false), NEVER for Tier-0 (incl. the deny-list), and — per the
// 2026-07-23 decision — ONLY for Tier-1 ("high"); Tier-2+ (medium/low) are not
// eligible even when Enabled=true.
func (g Tier0Guard) Eligible(tp TargetPolicy) bool {
	return tp.Policy.Enabled && !g.IsTier0(tp) && g.IsTier1(tp)
}

// Event is one auditable moment in the offline-credential lifecycle. It always
// carries OfflineCredential=true so a WORM query can isolate every session that
// used (or was denied) a pre-positioned credential.
type Event struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // preposition | used | denied | expired | rotated
	TargetID string    `json:"target_id"`
	Subject  string    `json:"subject,omitempty"` // operator sub (used/denied); "" for preposition/rotated
	// OfflineCredential is ALWAYS true — the explicit marker DDIL P3.8 requires.
	OfflineCredential bool      `json:"offline_credential"`
	PrepositionedAt   time.Time `json:"prepositioned_at,omitempty"`
	CacheID           string    `json:"cache_id,omitempty"`
	Criticality       string    `json:"criticality,omitempty"`
	BudgetValidUntil  time.Time `json:"budget_valid_until,omitempty"`
	Use               int       `json:"use,omitempty"` // 1-based use ordinal for "used"
	MaxUses           int       `json:"max_uses,omitempty"`
	Reason            string    `json:"reason,omitempty"` // deny/rotate reason
	Err               string    `json:"err,omitempty"`
}

// ContingencyMeta is the non-secret metadata returned alongside a served
// pre-positioned credential so the caller can audit the source and bound the
// session lifetime.
type ContingencyMeta struct {
	PrepositionedAt  time.Time
	CacheID          string
	Use              int // 1-based ordinal of this use
	MaxUses          int
	BudgetValidUntil time.Time
	CredExpiry       time.Time
}
