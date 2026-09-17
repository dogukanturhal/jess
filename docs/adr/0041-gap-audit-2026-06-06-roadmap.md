# ADR 0041 — Gap-audit 2026-06-06 roadmap + L-effort items

| | |
|---|---|
| **Status** | Accepted — S-batch + M-batch CODE shipped 2026-06-06 (branches `feat/gap-audit-s-batch` + `feat/gap-audit-m-batch`); L+ items documented here for sequenced delivery |
| **Phase** | n/a — informational roadmap |
| **Owners** | Platform / jess maintainers |
| **Inputs** | Deep-research workflow `wf_680f8112-4d1` (108 agents, 26 sources, 24 confirmed claims), 2026-06-06 |
| **Date** | 2026-06-06 |

## Context

A deep-research workflow ran the jess shipped-inventory against 2025-2026 tier-1 PAM / ZTNA product state + NIST / OpenID / Boundary primary sources and surfaced 12 ranked gaps. Six were S-effort and were shipped in `feat/gap-audit-s-batch` (4f971c5):

1. Gap #3 — NIST SP 800-63B-4 §3.2.5 phishing-resistant AMR enforcement.
2. Gap #5 — CAEP 1.0 Final + SSF 1.0 §4.1.6 receiver upgrade.
3. Gap #6 — AAL3 inactivity timeout (15min SHOULD).
4. Gap #9 (partial — guardrail) — SSRF guard on admin-API target registration.
5. Gap #12 — SIGTERM drain handler.
6. Side gap — direct-connect TTL env.

Three M-effort items were shipped in `feat/gap-audit-m-batch`:

7. Gap #9 (drift half) — catalog drift / health prober.
8. Gap #12 (dry-run half) — `/admin/policy/simulate` endpoint.
9. Gap #8 (scaffold half) — RFC 3161 TSA + Merkle tree scaffolds in `internal/recording/tsa.go`.

This ADR documents the remaining L+ items with sequencing, dependency notes, and effort estimates that account for the M-batch scaffolds already in place.

## L+ items

### L1 — Gap #1: In-session SSH command ACL

**What's missing:** JumpServer-style command filters with Deny/Accept/Review/Alert actions evaluated on every PTY frame. Today jess gates only at session-open via locks + grants; an approved SSH session can run any command.

**Design:**
- Add `sshproxy.CommandHook` interface: `Inspect(line string, sess SessionContext) Action`.
- Reuse the existing SSH multiplexer in `internal/sshproxy` — tap PTY output going operator→worker.
- Line-buffer until newline OR session timeout (handle bracketed paste).
- Route the line to a Rego policy (`data.jess.ssh.command`) via the existing OPA bundle the risk-score evaluator uses.
- New tables: `jit_command_decisions (session_id, line, decision, decision_id, decided_at)` for SOC trail.
- Recording sidechain: write the decision alongside the asciicast frame so replay shows the deny/review action.

**Effort:** L (4-6 weeks). The OPA bundle infra is already shipped (Phase 5h-4a). The hot-path tap on the SSH multiplexer needs careful testing — wrong-line splits break the Rego policy.

**Blast radius if deferred:** HIGH. JumpServer ships this in OSS Community Edition; tier-1 customers will compare directly.

### L2 — Gap #10: Controller HA + per-tenant isolation

**What's missing:** `replicas=1`, no PDB, no topology-spread, no tenant model. Any controller restart drops in-flight sessions.

**Design (Boundary-pattern leader election via Postgres advisory lock):**
- Add `jess_controller_leader (id, hostname, last_heartbeat_at)` with `pg_advisory_lock(<jess-namespace-hash>)` held by the leader.
- Workers register against EVERY controller replica (already shipped); only the leader handles non-session-affined writes (locks expirer, grant minting requires Postgres anyway → no contention).
- For session-affinity: include `controller_id` in `jit_sessions` (already shipped); on watchGrant the OTHER replicas can take over by reading the session row's controller_id field on a heartbeat-loss event.
- Drain handler (already shipped from S-batch) makes graceful failover possible — when leader restarts, follower picks up the lock + the leader's in-flight sessions reach their own close via existing watchGrant tick.
- Multi-tenancy: add `tenant_id` to JWT claim → `jit_grants.tenant_id` → catalog providers can be per-tenant. Per-tenant ServiceAccount stays the operational boundary (one jess deployment per tenant for serious isolation).

**Effort:** L (4-6 weeks). Postgres-coordinated HA is well-understood; tenant boundary is the bigger engineering call.

**Blast radius if deferred:** HIGH for production deployments. Rolling jess-controller upgrades drop every session today.

### L3 — Gap #7: Hardware-bound operator keys (Teleport pattern)

**What's missing:** PIV-slot policy binding (slot 9a `hardware_key`, 9c `touch`, 9d `touch+pin`, 9e `pin`) and attestation-root pinning. Today operator-cert is software-bound.

**Design:**
- New `internal/admin/operator_cert_piv.go`: PIV CSR generation via `github.com/go-piv/piv-go`.
- `jessctl admin operator-cert mint --hardware --slot=9c` generates the keypair on-device, presents the attestation cert chain (Yubico OEM root → Yubico attestation intermediate → leaf attestation cert) alongside the CSR.
- Controller-side verifier accepts X.509 operator certs only when:
  - The CSR carries a Yubico (or other pinned vendor) attestation cert chain.
  - The attestation cert's UPN/SAN matches the verified Falcon-ID subject.
  - The slot policy in the attestation extension (1.3.6.1.4.1.41482.3.8) matches the role policy (`platform_admin` requires `9c` minimum).
- Attestation roots pinned: Yubico, Solo, Google Titan, Apple Secure Enclave. Open question (deep-research finding): exact list needs vendor confirmation per the open-questions follow-up.

**Effort:** L (4-6 weeks). The piv-go library exists; testing across vendors + attestation root acquisition is the slow part.

**Blast radius if deferred:** HIGH. Software-bound operator certs are extractable from a compromised laptop; the 8h cap + CRL narrows the window but doesn't close the non-exportability gap NIST §3.1.6.1 normative SHALL.

### L4 — Gap #4: ECDSA P-256 rotation for `jess-recordings` Transit key (FIPS 140-3 path)

**What's missing:** Vault FIPS 140-3 Inside prohibits Ed25519 in Transit. Current `jess-recordings` key is Ed25519. Operator-action needed to rotate.

**Design (runbook-shape):**
- New iac MR adds a SECOND key version: `vault_transit_secret_backend_key.jess_recordings_ecdsa` (type=ecdsa-p256).
- jess `internal/recording/signer.go` already structures key selection via env — add `JESS_RECORDING_KEY_NAME` env (default `jess-recordings`).
- Rotation runbook:
  1. iac apply creates `jess-recordings-ecdsa`.
  2. Set `JESS_RECORDING_KEY_NAME=jess-recordings-ecdsa` on jess-worker.
  3. Roll worker; new sessions sign with ECDSA.
  4. Old recordings keep their Ed25519 sig — verifier accepts both key types via Vault's verify-by-key-version.
  5. After retention period (7y SOC 2) the old key can be deleted.
- FIPS-mode container variant: `GODEBUG=fips140=on` env on jess-controller / jess-worker / jess-web. Requires Go 1.24+ (already pinned).

**Effort:** M (2-3 weeks). Code change is small; live rotation drill is the bulk of the work.

**Blast radius if deferred:** MED-HIGH. Locks out federal / regulated customers from any FIPS-mode deployment.

### L5 — Gap #2: Full RDP brokering — CredSSP relay, smart-card, recording, Wasm client

**What's missing:** Phase 5f-8b thin-tunnel ship (2026-06-06) gives raw WS↔TCP bridge but no CredSSP relay, no smart-card cert flow, no server-side recording, no in-browser Wasm RDP client.

**Sub-design:** see ADR 0033 §"2026-06-06 update" + the original ADR 0033 body — that's the canonical sub-design. This ADR points at it.

**Effort:** XL (8-12 weeks across all four; can stage). 5f-8b-1 (CredSSP relay) is the long pole; 5f-8b-4 (recording) can ship first as graphics-blind audit.

**Blast radius if deferred:** MED-HIGH. Cloudflare's browser-RDP went GA 2025-09-22 with NTLM-only — even tier-1 vendors find CredSSP relay non-trivial. Browser-RDP from the SPA stays disabled (RDP rows show "CLI for now" tooltip).

### L6 — Gap #11: RFC 8693 token-exchange for service-to-service delegation

**What's missing:** Controller → worker presents the original Falcon-ID Bearer unchanged. No `act` claim chain to prove "jess-controller acting for X to call jess-worker" — accountability chain weakens.

**Design:**
- Falcon-ID adds `/oauth/token` `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` support (separate work, falcon-id side).
- jess-controller mints a delegated token per worker hop: subject_token = operator's original Bearer, actor_token = controller's svc-cert, resulting token carries `act.sub=jess-controller, act.act.sub=<operator>` claim chain.
- jess-worker validates the `act` chain in `internal/pdp/verify.go` — operator subject is the deepest `act.sub`; controller subject is the wrapping `act.sub`; both verified via JWKS.

**Effort:** M (2-3 weeks jess-side; falcon-id work is its own track).

**Blast radius if deferred:** MED. Audit shows "user X opened session" but cannot prove "controller acted for X". Standards-track but not yet a regulatory blocker.

## Sequencing recommendation

| Order | Item | Why this order |
|---|---|---|
| 1 | L4 ECDSA rotation | M-effort, unblocks any FIPS-mode customer conversation, depends on nothing else |
| 2 | L2 Controller HA | Unblocks any further per-operator change (hardware keys, command ACL) without dropping every session on each rollout |
| 3 | L1 SSH command ACL | Tier-1 JumpServer-OSS parity; reuses existing OPA bundle infra |
| 4 | L3 Hardware-bound keys | Per-operator change; HA prerequisite from #2 minimizes rollout disruption |
| 5 | L6 RFC 8693 act-chain | Standards-track; depends on falcon-id work, can run parallel |
| 6 | L5 Full RDP (5f-8b-1..4) | Multi-quarter scope; ship as four staged sub-MRs |

## Status / non-goals

- **Deliberate scope choices** from the gap audit (CyberArk PSM password rotation; BeyondTrust vendor-PRA workflow; FedRAMP SSP authoring; PQC hybrid X25519MLKEM768 per Go #78298) remain out-of-scope by design. Do not re-litigate.

- The deep-research workflow's open questions (Teleport's attestation-root pinning depth; Falcon-ID's CAEP 1.0 event-type emission; CredSSP version 6 minimum-safe; backup cadence retention SLA) need product-side decisions before the corresponding L items can ship; this ADR flags them but does not answer them.
