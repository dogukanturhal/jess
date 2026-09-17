# ADR 0062 — DDIL P3.8: pre-positioned offline session credentials

**Status:** Accepted — 2026-07-20. Implemented in `internal/offlinecreds`
(generic manager) + `internal/broker/offline_rdp_creds.go` (RDP integration) +
`internal/vaultx` (error classifier + lease revoke) + the `JessTarget` CRD
opt-in. Wired into the live RDP console (`cmd/jess-web`), OFF by default.
**Phase:** DDIL Phase 3 (P3.8). **Builds on:** the DDIL degraded-mode operating
spec (`platform/docs/2026-07-19-ddil-degraded-mode-operating-spec.md`, row 5 —
privileged session credential, PACE Contingency tier), ADR 0052 (Tier-0 RDP
hard-guard), ADR 0049 (no standing credentials), and
`hexx-pep-core/pkg/govdecision` (signed, time-boxed staleness budget).

## Context

Every privileged jess session mints its credential from Vault per-session (SSH
cert 15–30 min; AD/DB dynamic secret). Vault is therefore a **hard dependency**:
if Vault is unreachable, **all** new privileged sessions halt — "disconnected =
denied at t=0". The DDIL spec requires a *governed-degrade* path for **designated
tiers only** (row 5): pre-positioned, policy-governed, short-TTL creds, audited,
single-use where possible, auto-revoked on reconnect. Explicitly NOT standing
creds, and Tier-0 DCs excluded.

Web-verified best practice for DDIL "islands of trust" (PACE-for-identity;
UberEther / Strata / DoD ZT guidance) converges on the same shape: **pre-sync,
don't pre-share**; keep least privilege enforced locally; use **time-bound
credentials that expire without refresh**; **revalidate on reconnect**. The
anti-pattern this replaces — operators improvising shared credentials / bypassed
controls / emergency grants during an outage — is exactly what a governed
pre-position path prevents.

## Decision

Add an **opt-in, Tier-0-excluded, pre-positioned short-TTL credential** path,
secure-by-default, enforced un-overridably in the broker.

### 1. Opt-in per target (default: not eligible)
`JessTarget.spec.offline_credentials = { enabled(false), max_ttl(4h),
max_uses(3) }`. Absent/`enabled:false` ⇒ the target is NOT eligible; a Vault
outage halts new sessions to it exactly as today. Nothing changes until an
operator explicitly opts a target in.

### 2. Tier-0 hard exclusion (crown-jewels rule)
A Tier-0 target (`criticality:critical` — DCs / the ADR 0052 hard-guard set) is
**NEVER** eligible, even if its CRD opts it in. Enforced in **three layers**
mirroring the RDP Tier-0 guard (provider suppress + un-overridable policy +
broker backstop):
- **source** — `Manager.Register` refuses a Tier-0 target and, on a target
  reclassified *up* to critical, evicts its registration AND revokes its cached
  credential;
- **policy** — `Manager.Prewarm` refuses to mint for a Tier-0 target;
- **backstop** — `Manager.Contingency` re-checks criticality at use time; and a
  Tier-0 target is never in the cache to begin with.

The exclusion keys off the same `criticality == "critical"` boundary the RDP
guard uses, plus an optional `JESS_OFFLINE_CREDS_TIER0_DENY` pin-list. It cannot
be disabled.

### 3. Pre-position while online
For each opted-in, non-Tier-0 target the manager proactively mints a short-TTL
Vault credential (`IssueForPreposition`) and refreshes it before half-life, so a
still-valid cached credential exists at outage time. The credential is **sealed
at rest** (AES-256-GCM; ephemeral per-process key by default, or a scoped/HW key
via `JESS_OFFLINE_CREDS_SEAL_KEY`) — never a long-lived plaintext secret.
Registration is driven lazily by the operator initiating a session (that moment
is, by definition, online), so no fleet-wide target enumeration is needed in the
web tier.

### 4. Contingency use (goverened, then fail closed)
When Vault is unreachable (transport/5xx/429 — classified by
`vaultx.IsUnreachable`; a genuine **4xx rejection fails closed and is never
masked as a partition**), an already-authorized session may use the cached
credential IFF: (a) within its lease TTL, (b) within a **`govdecision` signed
time-boxed budget** (`max_ttl`), and (c) under `max_uses`. Otherwise DENY —
identical to today.

### 5. Never bypass authorization
The JIT grant, the grant re-check, and the recording requirement are unchanged
and run **upstream** of the credential source (`assertGrantActive` →
`openRecorder` → `credentialFor`). Offline creds swap only the *credential
source*; `internal/offlinecreds` has no authz entry point.

### 6. Audit
Every lifecycle moment (`preposition` / `used` / `denied` / `rotated`) is
emitted through an `Auditor` with an explicit `offline_credential=true` marker,
the pre-position timestamp, and the cache id (which cached cred). The session
itself is still WORM-recorded by the existing recorder gate.

### 7. Reconnect
On Vault reachability restored after offline use, pre-positioned creds are
emergency-rotated: best-effort lease revoke (`sys/leases/revoke`) + discard +
re-mint on the next refresh tick.

## Security tradeoff (explicit)

A pre-positioned short-TTL credential **is a small, bounded standing secret** for
the window it exists — a genuine departure from ADR 0049's "no standing
credentials". We accept it ONLY because the exposure is tightly bounded and the
default is to have none:

| Mitigation | Effect on the exposure |
|---|---|
| **Opt-in per target** | Zero exposure by default; only operator-designated, non-crown-jewels targets ever hold a cached cred. |
| **Tier-0 hard-exclusion** | The crown jewels (DCs) can NEVER hold one, un-overridably, even under a mis-set CRD / stray tag / single bad edit. |
| **Short TTL + refresh** | The cached cred is a *rotating* short-lived Vault lease, not a fixed secret; its blast-radius window is `min(lease TTL, max_ttl ≤ 4h)`. |
| **Signed budget (govdecision)** | Offline honour is bounded by a signed `valid_until` a PEP verifies offline; no unsigned local trust, and the window can't be forged by editing the cache. |
| **max_uses** | One cached cred backs only a few offline sessions before failing closed — caps replay/abuse during a long partition. |
| **Sealed at rest (AES-256-GCM)** | The plaintext never lives in a struct field / heap dump verbatim; default ephemeral key means the cache dies with the process and is portable to no other host. |
| **Fail closed everywhere else** | Expired / over-budget / over-uses / tampered / not-eligible / Tier-0 / genuine-4xx all DENY, exactly as today. |
| **Auth unchanged** | The JIT grant + recording gates still fully apply; offline creds are a credential source, not an authorization. |
| **Auto-revoke on reconnect** | The moment Vault returns, used pre-positioned leases are revoked and rotated. |
| **Full audit** | Every use carries `offline_credential=true` + provenance, so a partition's offline sessions are fully reconstructable. |

Net: the exposure is `{opted-in, non-Tier-0 targets} × {≤4h window} × {≤3 uses} ×
{sealed, auto-revoked}` — a deliberately small island of trust that keeps
disconnected privileged operations *governed* instead of forcing operators into
un-audited workarounds, which is the strictly-more-secure posture in a real DDIL
event.

## Config (documented defaults)

| Env | Default | Meaning |
|---|---|---|
| `JESS_OFFLINE_CREDS_ENABLED` | `off` | Master switch (secure default OFF). |
| `JESS_OFFLINE_CREDS_MAX_TTL` | `4h` | Global cap on per-target `max_ttl`. |
| `JESS_OFFLINE_CREDS_MAX_USES` | `3` | Global cap on per-target `max_uses`. |
| `JESS_OFFLINE_CREDS_REFRESH_INTERVAL` | `60s` | Pre-position refresh tick. |
| `JESS_OFFLINE_CREDS_SEAL_KEY` | ephemeral | base64 32-byte at-rest seal key (else in-memory ephemeral). |
| `JESS_OFFLINE_CREDS_TIER0_DENY` | none | Extra target IDs pinned out (criticality=critical always excluded). |

Per-target: `JessTarget.spec.offline_credentials.{enabled, max_ttl, max_uses}`.

## Consequences

**Positive:** designated tiers survive a Vault outage on a governed short-TTL
cred instead of a total halt; Tier-0 provably excluded; full audit + auto-revoke;
one reusable primitive (`internal/offlinecreds`) that SSH/DB brokers can adopt
next via the same Minter/Contingency seams.

**Negative:** a bounded standing secret exists for opted-in targets (mitigated
above); the RDP integration is the first consumer — SSH/DB are follow-ons;
`internal/offlinecreds` ↔ `catalog.OfflineCredentialsPolicy` fields must be
extended in lockstep with the CRD (as with the rest of `catalog.Target`).

**Neutral:** OFF by default — no behaviour change until an operator flips the
master switch AND opts a target in. The RDP grant + recording gates are
untouched.

## References
- DDIL degraded-mode operating spec (row 5; PACE Contingency), NIST SP 800-207,
  SP 800-53 CP-7.
- ADR 0052 (Tier-0 RDP hard-guard — the three-layer exclusion pattern mirrored
  here), ADR 0049 (no standing credentials — the invariant this consciously
  bounds), `hexx-pep-core/pkg/govdecision` (signed staleness budget), P3.6
  recording store-and-forward (the transient-vs-4xx classification pattern).
