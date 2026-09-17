# ADR 0042 — ZTNA Talon Integration (Phase 2 + Phase 4 receiver-side)

**Status:** Proposed — Phase 0 of the ZTNA program locked in Talon ADR 0040. Sibling ADRs queued: jess 0043 (device-cert profile, Phase 3); falcon-id 0009 (CAEP outbox, Phase 6 — shipped 2026-06-06 substrate).

**Date:** 2026-06-06
**Owners:** jess maintainers + Talon maintainers
**Phase:** ZTNA Phase 2 + Phase 4 (receiver side)

**Inputs**:
- Talon ADR 0040 (ZTNA Platform master)
- Talon ADR 0040-A (Threat Model)
- Talon ADR 0040-B (Decision Register, D-001..D-007)
- jess ADRs 0030 (dynamic catalog), 0033 (Rust IronRDP bridge), 0034 (tier-1 ZTNA catalog), 0035 (hardware-bound operator keys), 0038 (SPIRE worker mTLS), 0041 (gap-audit 2026-06-06 roadmap)
- jess shipped state: Phase 5 (SSH brokering via Vault SSH-CA `ssh-client-signer`, role `ssh-admin`, 15min cert TTL), Phase 5b (JIT request→approve→grant), Phase 5g (continuous grant verification), Phase 5h-3 (device-posture wall at session-open), Phase 5h-6 (CAEP subscriber for IdP-driven session revocation), Phase 4 (operator-cert revocation via CRLCache + VerifyPeerCertificate)

## Context

Talon's ZTNA Phase 2 ("Jess SSH broker") was scoped as greenfield SSH brokering, but jess SHIPPED SSH brokering in Phase 5 of its own roadmap. The actual Phase 2 deliverable is the **cross-product wiring + contract documentation** that aligns jess's existing SSH path with Talon's PDP/PEP model.

Phase 4 ("Device posture agent") has a receiver side that jess already implements (Phase 5h-3 device-posture wall). This ADR locks the receiver-side contract so the Phase 4 agent's posture JWT format is wire-compatible.

## Decision

### Phase 2 — Talon-fronted Jess SSH broker

#### 2.1 Edge routing

- Jess admin port `:7103` continues to expose `/api/...` for `jessctl admin`.
- Jess operator port `:7101` continues to expose RFC 8705 mTLS for operator-cert holders.
- **NEW**: introduce edge path `jess-internal.example.com` fronted by Talon (admin tier). Talon evaluates the ZTNA Rego baseline (Talon ADR 0040 Phase 5) on every request:
  - User identity → Falcon-ID OIDC token (existing)
  - Device cert → Phase 3 jess-device-ca mTLS at edge listener (gated on Phase 3 delivery)
  - Posture freshness → X-Talon-Posture JWT (existing ADR 0011)
  - Trust tier → derived from device-cert SAN (`tier=TIER_CORP|TIER_BYOD`)
  - Allow rule → ZTNA baseline matrix (Talon `docs/policy/ztna/ztna_baseline.rego`)
- Talon ext_authz response carries `X-Forwarded-Jess-Tier`, `X-Forwarded-Jess-AAL`, `X-Forwarded-Jess-Sub` for jess to use as input to SSH cert minting.

#### 2.2 SpiceDB principal derivation

Today's Vault SSH-CA role `ssh-admin` allows `*` user principals + `*` extensions (Phase 5 dev posture). Tier-1 requires per-user, per-target-allowlist principals derived from SpiceDB.

- Add SpiceDB schema `ssh_target/<principal>/<viewer|editor|owner>` mirroring the existing route ReBAC.
- Jess at mint-time fetches `permission_lookup(subject, ssh_target/*, viewer)` from SpiceDB, returns the resulting list of target hostnames as the cert's `principals` field.
- Vault SSH-CA role updated to `allowed_users` = `{{identity.entity.aliases.<accessor>.metadata.principals}}` interpolation (Vault 1.18+ identity templating).
- Cert TTL reduced from 15min → 10min for AAL3 / 5min for AAL2 (mirrors device-cert 24h vs posture 5min cadence ratio).

#### 2.3 Posture wall contract

jess's `internal/risk` posture wall consumes a JWT today via `JESS_POSTURE_JWKS_URL`. Lock the claim shape so Phase 4's HexxLock Access agent produces wire-compatible JWTs:

```jsonc
{
  // RFC 7519 standard
  "iss": "https://posture.hexxlock.com",  // posture-signer service, distinct from id.hexxlock.com
  "sub": "spiffe://hexxlock.com/device/<device-uuid>",  // Talon ADR 0040 D-005 SPIFFE-aligned naming
  "aud": ["talon", "jess"],
  "iat": 1717689600,
  "exp": 1717689900,  // 5 min cadence per Talon ADR 0040 D-003 (TIER_CORP)
  "jti": "01HZZ...",

  // ADR 0011 + Talon ZTNA baseline expected fields
  "compliance": {
    "tier": "TIER_CORP",                // D-006
    "device_cert_valid": true,          // Phase 3 device-cert chain validation
    "device_cert_fingerprint": "sha256:abcd…",
    "network_class": "trusted",         // corp | vpn | trusted | internet
    "route_sensitivity": "medium",      // operator-set on the TalonRoute spec
    "disk_encryption": true,            // posture probe
    "screen_lock_enabled": true,
    "os": "linux",
    "os_version": "Ubuntu 24.04",
    "edr_running": true,
    "last_reboot": "2026-06-05T12:00:00Z",
    "hardware_id_match": true
  }
}
```

The JWT is signed by `jess-posture-ca` (a new Vault PKI mount, sibling of `jess-ca` and `jess-device-ca`). Trust chain:
- TIER_CORP posture is signed by a device-cert subordinate of `jess-device-ca`
- TIER_BYOD posture is signed by a WebAuthn assertion attestation (no device cert)

#### 2.4 Continuous verification cross-ref

When Talon revokes a session (via CAEP), jess's existing Phase 5h-6 CAEP subscriber receives the SET and kills any in-flight SSH session for the same subject. **No new code needed** — the CAEP receiver is already shipped; Talon's CAEP transmitter is wave-2 + Phase 6 outbox (this ADR's sibling).

### Phase 4 — Posture agent contract (receiver side)

Jess receiver-side is already shipped (Phase 5h-3 device-posture wall). The agent side (new `hexxlock-access` repo) emits JWTs matching §2.3 to:

- `https://id.hexxlock.com/posture/heartbeat` (every 5 min for TIER_CORP, 15 min for TIER_BYOD)
- `https://posture.hexxlock.com/heartbeat` if the heartbeat path moves to a dedicated subdomain

Falcon-ID stores the latest posture JWT per device in a Redis cache with TTL = 2× cadence. On every request, Talon's posture verifier fetches the latest posture from Falcon-ID and projects it into `RegoInputPosture` (Talon `internal/policy.rego.go:93`).

The posture-signer service is a NEW component:
- Issuer: `https://posture.hexxlock.com` (Cloudflare-fronted, Linkerd-meshed in-cluster)
- Verifies the agent's WebAuthn-or-device-cert authentication
- Re-signs the posture claims with `jess-posture-ca` so receivers verify against ONE JWKS
- Runs as a `talon-adjacent` service (in `talon` namespace, sharing the Falcon-ID OIDC RP)

## Consequences

### Positive

- Phase 2 ships in WEEKS not months — most substrate exists in jess Phase 5+
- ZTNA Rego baseline (Talon Phase 5) gates Jess access without jess code changes
- Existing CAEP subscriber (jess Phase 5h-6) gives continuous verification "for free"
- SpiceDB-derived SSH principals close the `allow_users='*'` tier-1 gap from jess Phase 5
- Wire-compatible posture JWT contract lets the Phase 4 agent target both Talon AND Jess

### Negative

- New `jess-posture-ca` Vault PKI mount needs Atlantis MR + Phase 9 DR drill
- New `posture-signer` service in talon namespace adds an operational surface
- SSH cert TTL reduction (15min → 5min for AAL2) increases SSH-CA mint rate ~3×
- SpiceDB `ssh_target` schema expansion needs Phase 5.b reconciler MR
- Tier-1 audit log gains a new event class `posture.heartbeat` (Phase 8 scope)

### Open questions

| # | Question | Lock by |
|---|----------|---------|
| Q1 | Posture-signer location: dedicated namespace or in talon ns? | Phase 4 design |
| Q2 | Falcon-ID posture cache: Redis or in-PG? | Phase 4 implementation |
| Q3 | SSH cert recency window vs WebAuthn: align with the 1h step-up budget? | Phase 5.b implementation |
| Q4 | BYOD SSH access at all: deny by default vs allow via WebAuthn-only path? | Phase 5.b decision |

## Implementation phases

| Sub-phase | What | Effort |
|-----------|------|--------|
| 2.a | Talon route `jess-internal.example.com` + Rego ZTNA baseline + ext_authz claim forwarding | 1-2d |
| 2.b | Jess SpiceDB principal derivation at mint-time + `allowed_users` Vault role update | 3-4d |
| 2.c | `jess-posture-ca` Vault mount + Atlantis MR + Linkerd policy | 1d |
| 2.d | posture-signer service scaffold (Go, in talon namespace) | 3-4d |
| 2.e | jess posture-wall contract update — accept the §2.3 JWT shape | 1d |
| 2.f | End-to-end test: kubectl-oidc-login + posture JWT + jessctl ssh + Talon ZTNA baseline → SSH session opens with derived principals | 1d |

**Total**: ~2 weeks. Tracks Phase 0 sequencing; ships in parallel with Phase 3 device-cert.

## References

- Talon ADR 0040 — ZTNA Platform (master)
- Talon ADR 0040-B — Decision Register D-005 (SPIFFE), D-006 (tiers)
- jess ADR 0034 — Tier-1 ZTNA catalog (verified findings)
- jess ADR 0038 — SPIRE worker mTLS
- jess ADR 0041 — Gap-audit roadmap (L+ items)
- OpenID CAEP 1.0 Final §3.1 session-revoked
- RFC 7519 (JWT) — posture JWT claim conventions
- HashiCorp Vault SSH-CA — secrets/ssh
