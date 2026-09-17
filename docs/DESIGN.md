# Jess — Design (ADR 0030 Phase 5)

> Skeleton spec, refined by the 2026-05-27 deep-research pass (3 agents:
> gateway-build, OSS-reference-impls, Go-implementation). Jess is the L4 Policy
> Enforcement Point for HexxLock zero-trust operator access — companion to
> `talon` (HTTP PEP) and `falcon-id` (Policy Decision Point / IdP). **The
> browser RDP/SSH recording gateway ("build-our-own Guacamole") is a worker
> CLASS within Jess (`jess-web`), not a separate product.**

## NIST SP 800-207 mapping

| Logical component | Realized by |
|---|---|
| Policy Engine + Administrator (PDP) | **Falcon-ID** + shared policy core (extracted from Talon) |
| PEP, HTTP | **Talon** (unchanged) |
| PEP, L4/SSH/DB/TCP/RDP | **Jess** controller + worker classes (this repo) |
| Workload identity / east-west | SPIFFE/Linkerd mesh |
| Credential authority | **Vault** (SSH CA sign, dynamic DB creds) |

## Topology — one brain, worker classes (not separate products)

```
operator (jessctl / browser / ssh client)
   │  mTLS/SPIFFE  +  Falcon-ID OIDC (authz decision)
   ▼
jess-controller (Go)  ── PDP → Falcon-ID + shared policy core
   │  - JIT grant store (NO session without an active grant)
   │  - yamux session pool (controller = server side; opens streams INTO workers)
   │  - audit envelope → Loki/Tempo, correlated by grant_id
   │  reverse tunnel: workers dial HOME (outbound-only); controller opens streams down
   ├───────────────┬───────────────────┬───────────────────────────┐
   ▼               ▼                   ▼                           ▼
jess-worker      jess-worker         jess-web                   (future classes)
(SSH / TCP)      (DB)                (RDP / web-SSH render+record)
 x/crypto/ssh     pgproto3 MitM       Go shim + sandboxed Rust IronRDP worker
 asciicast v2     query audit +       drawing-stream → browser canvas; xterm.js SSH
 Vault ssh/sign   Vault dyn DB creds  Vault-brokered target cred (virtual smart card)
   │                 │                   │
   ▼                 ▼                   ▼
 SSH nodes        Postgres/MySQL       RDP hosts (AD DC) / SSH
   └─────── recordings (asciicast + drawing dump) → MinIO Object-Lock WORM (grant_id) ──────┘
```

- **Outbound-only workers** (yamux over SPIFFE-mTLS): workers `tls.Dial` the
  controller; the controller (`yamux.Server`) `Open()`s a stream into the worker
  per authorized session. No inbound ports on the target network (Boundary
  egress-worker / Teleport reverse-tunnel model). `hashicorp/yamux` is the lib.
- **`jess-web` = build-our-own browser gateway**, but as a Jess worker class:
  it authorizes through the same PDP, is routed over the same tunnel, and emits
  the same audit envelope. It never makes its own access decision.

## jess-web — build-our-own clientless gateway

Display-agnostic model (Guacamole / Teleport-TDP): the backend protocol is
decoded server-side and the browser receives only generic **drawing
instructions** (canvas) or a **terminal stream** (xterm.js) — the browser never
speaks RDP/VNC. This makes recording trivial (tee the instruction stream) and
lets one player replay every protocol.

| Path | Engine | Browser | Recording |
|---|---|---|---|
| SSH (web) | `golang.org/x/crypto/ssh` (Go) | xterm.js | asciicast v2 |
| VNC | noVNC + Go RFB proxy | noVNC | FBS / drawing dump |
| **RDP** | **Devolutions IronRDP (Rust)**, server-side, sandboxed | canvas (PNG/draw ops) | drawing dump → video re-render |

**Why a Rust render worker, not Go:** the only memory-safe, maintained RDP
engine is IronRDP (Rust); FreeRDP (C) had 61 CVEs in 2026; pure-Go RDP is
immature. The Rust `rdp-render` worker runs **one process per session** in a
locked-down sandbox (gVisor / seccomp, non-root, read-only rootfs, egress
NetworkPolicy to only that one target) — the process boundary IS the sandbox,
so we avoid cgo and contain any parser RCE to one ephemeral, credential-less
session. Go ↔ Rust over a local UDS/gRPC, not FFI. See `rust/rdp-render/`.

**Credentials:** operators never get target passwords. Falcon-ID OIDC → a
short-lived cert brokered from Vault, presented to RDP as a **virtual smart
card** (Teleport model); DB via Vault dynamic creds injected at the proxy.

## Recording + tamper-evidence (Boundary-BSR model)

- Terminal → **asciicast v2** (NDJSON, streamable). Graphical → drawing-instruction
  dump (replayable in-browser; re-renderable to MPEG-4).
- Bundle per session: `SHA256SUMS` + detached **ed25519 signature via Vault
  Transit**, a hash-chain across chunks (truncation-evident), and a
  self-describing `session-meta.json` (subject/target/grant_id/worker).
- Stored on **MinIO Object-Lock (compliance mode), 7-yr** (the `audit-archive`
  bucket). **Fail-closed**: if the recorder/MinIO is unreachable, the session is
  refused/killed (Teleport sync-mode) — a pausable/deletable recording is
  worthless for SOC 2.

## Security model

- operator↔controller and worker↔controller links: mTLS with SPIFFE SVIDs
  (reuse the mesh). Falcon-ID token carries the authz decision.
- Continuous re-authorization: the controller re-checks the PDP periodically and
  tears the session down on revocation (Pomerium model); short Vault TTLs mean
  credentials self-expire (zero standing privilege).
- `grant_id` is stamped into the SSH cert extensions / DB lease metadata and
  every audit line + recording, so a session is traceable end to end.
- RFC 8705 token↔SVID binding is a Phase-6 hardening layer, NOT v1 critical path
  (short SVID rotation breaks naive binding — bind to the worker identity or keep
  token TTL ≤ SVID TTL).

## Go library choices (from research)

| Concern | Library | License |
|---|---|---|
| SSH front (operator) | `charmbracelet/wish` + `gliderlabs/ssh` | MIT |
| SSH core / backend dial | `golang.org/x/crypto/ssh` | BSD-3 |
| Postgres wire proxy | `jackc/pgx/v5/pgproto3` (NOT v4 — EOL) | MIT |
| Reverse-tunnel mux | `hashicorp/yamux` | MPL-2.0 |
| Vault (SSH CA + dyn DB) | `hashicorp/vault/api` | MPL-2.0 |
| SPIFFE / mTLS | `spiffe/go-spiffe/v2` | Apache-2.0 |
| Terminal recording | asciicast v2 (own writer) | — |
| RDP engine (Rust worker) | `Devolutions/IronRDP` | MIT/Apache-2.0 |

## Build plan (5a–5e, research-refined)

- **5a — spine:** controller + generic worker; **yamux over SPIFFE-mTLS** reverse
  tunnel (workers dial home, controller opens streams); raw TCP passthrough;
  JIT grant gate stub (enforce "no session without grant" from day 1); audit
  envelope → Loki/Tempo. *Riskiest integration — do first.*
- **5b — SSH record-proxy:** `wish`/`gliderlabs` front + `x/crypto/ssh` back;
  `ssh.CertChecker` pinned to the Vault SSH CA; asciicast v2 recorder;
  agent-forwarding deny-by-default; per-session `ssh/sign` cert.
- **5c — Postgres broker:** `pgx/v5/pgproto3` MitM + Vault dynamic-cred injection
  (operator never sees the password) + query audit. MySQL later (`go-mysql`).
- **5d — JIT engine:** request→approve→time-boxed→revoke; bind `grant_id` into
  certs + DB lease metadata; Vault lease TTL == grant TTL; revoke kills live creds.
- **5e — jess-web:** Go shim worker + sandboxed Rust IronRDP `rdp-render` (RDP) +
  xterm.js (web-SSH) + noVNC (VNC); drawing-stream to browser; tamper-evident
  recording to WORM. The "build-our-own Guacamole" deliverable.

## Benchmark

Validate each milestone against **HashiCorp Boundary CE** (the free yardstick)
and study **Warpgate** (admin UX, replay player, crate decomposition) and
**Teleport** (TDP, desktop-access, reverse tunnel) — borrow patterns, fork neither.
