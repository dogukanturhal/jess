# Cross-session WORM audit chain — jess differentiator

| | |
|---|---|
| **Phase** | 5e-16 (substrate) + 5e-18 (chain integrity monitor) + 5j-1 (SPA badge) |
| **Tier-1 industry context** | ADR 0034 priority #8 ("productize as differentiator") |
| **Status** | Live in production since 2026-05-30; SPA chain-health badge added 2026-06-03 |

## What it is

Every brokered session row in `jit_sessions` carries two extra columns:

- **`row_hash`** — canonical hash of `(id, subject, target_id, started_at, prev_row_hash)`
- **`prev_row_hash`** — the previous session's `row_hash`

Combined: a tamper-evident chain across **every session ever brokered**, not just per-session integrity. Deleting or modifying any row breaks the chain at that position. The `VerifyChain` endpoint walks the chain in `started_at` order and reports every break.

The chain is computed in a Postgres transaction with `SELECT ... FOR UPDATE` on the chain head so concurrent `OpenSession` calls under multiple controllers can't race-pick the same predecessor.

## Why this matters (industry comparison from ADR 0034)

| Product | Per-session integrity | Cross-session chain |
|---|---|---|
| **jess (Phase 5e + 5e-16)** | **Ed25519 via Vault Transit** | **YES — chain** |
| HashiCorp Boundary BSR | Ed25519 (BSR private key) | per-directory SHA256SUMS only |
| Teleport | encrypted (age-based encryption) | per-session only |
| Apache Guacamole 1.6.0 | **None** (verified negative finding) | None |
| StrongDM | uniform stream log | unconfirmed in surviving sources |
| CyberArk PSM | PSM video | integrity scheme unconfirmed |

**jess is the only stack in the surveyed comparator set that combines per-session signing AND cross-session chain.** Boundary has per-directory hashes but no chain. Teleport has per-session encryption but no chain. Guacamole has nothing at all.

This is a real AU-10 (Non-Repudiation) advantage. Per the SOC 2 CC6 mapping (`docs/compliance/soc2-cc6-mapping.md`), CC6.7 evidence is significantly strengthened by being able to prove "the audit log was not modified between session-close and audit-pull".

## Where it surfaces in the product

1. **SPA admin hero badge** (Phase 5j-1, added 2026-06-03) — `ChainHealthBadge` auto-refreshes every 5 minutes and shows status front-and-center on the `/admin` route. Three states:
   - ✅ `chain intact · N session rows · checked HH:MM:SS` (green pill)
   - ⚠ `CHAIN BROKEN · X/N rows flagged · checked HH:MM:SS` (red pill, `role=alert`)
   - ⚠ `chain status unavailable — <err>` (red pill on transport error)
2. **SPA `ChainVerifyCard`** (Phase 5e-19) — on-demand deep verify with per-break details (session_id, position, expected vs got hash). Use this when the badge flips red.
3. **jessctl admin chain-verify** (Phase 5e-19) — CLI parity, `--json` flag for cron-driven compliance checks; exit code 1 on break, 2 on transport error.
4. **Prometheus** — `jess_chain_intact` gauge (1/0/-1) + `jess_chain_breaks_total` counter + `jess_chain_total_rows` gauge. The Phase 5e-18 chain integrity monitor goroutine runs `VerifyChain` every 5 minutes and updates these metrics so the SRE alert fires within ~5 min of any tampering.

## Operator messaging (marketing-tier wording for site / sales deck)

> jess records every brokered session into a Write-Once-Read-Many (WORM) store with two layers of cryptographic integrity: every session bundle is signed Ed25519 by Vault Transit, AND every session row is linked into a cross-session hash chain. Combined, an attacker who compromises the storage layer cannot:
>
> 1. Modify a single recording (per-bundle signature breaks).
> 2. Delete a session row to hide a session occurred (chain breaks at that position).
> 3. Re-order sessions (chain breaks).
> 4. Inject a forged session (chain doesn't link back).
>
> The chain is verified continuously in-product (5-minute auto-refresh badge on the admin console) and on-demand via `jessctl admin chain-verify`. Every audit export is therefore provably from an untampered chain.
>
> No surveyed competitor in the privileged access broker market (Teleport, HashiCorp Boundary, StrongDM, CyberArk PSM, BeyondTrust PRA, Apache Guacamole) ships an equivalent cross-session chain. Per-segment integrity is common; per-session-row chain is unique to jess.

## Implementation references

- `internal/jit/postgres.go` — `OpenSession` + `VerifyChain` + `ComputeRowHash`.
- `internal/jit/chain.go` — `ComputeRowHash`, `ChainReport`, `ChainBreak`.
- `internal/admin/sessions.go` — admin endpoint `/audit/chain/verify`.
- `cmd/jessctl/admin_verify.go` — `jessctl admin chain-verify` + `bundle-verify` CLI.
- `cmd/jess-web/web/src/pages/Admin.tsx` — `<ChainHealthBadge>` (Phase 5j-1) + `<ChainVerifyCard>` (Phase 5e-19) + `<ChainVerdict>`.
- `internal/metrics/metrics.go` — `chain_breaks_total`, `chain_intact`, `chain_total_rows` collectors.
- `cmd/jess-controller/main.go` — `runChainMonitor` goroutine.

## Cross-references

- ADR 0034 §"Architecture findings" / "Session-recording integrity comparison" — vendor matrix.
- `docs/compliance/soc2-cc6-mapping.md` — CC6.7 evidence section cites this feature.
- `docs/compliance/cisa-ztmm-v2-mapping.md` — Data pillar + Visibility & Analytics cross-cutter both cite this as evidence of "Advanced" maturity.
