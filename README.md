# Jess — HexxLock zero-trust infrastructure access broker

> **A first-party HexxLock product** — sibling to **Talon** (HTTP IAP) and
> **Falcon-ID** (OIDC IdP). Owned and built in-house; productizable as a future
> HexxLock SKU (zero-trust infrastructure access + session recording).
>
> **Status (ADR 0030 Phase 5), all race-tested green:** 5a spine + 5b SSH
> record-proxy + hardening: **Falcon-ID OIDC operator auth + role-based authz**
> (default-deny), **tamper-evident hash-chained audit**, **continuous-auth**
> (kill session on grant expiry/revoke), SSH MitM (Vault-CA cert auth, deny-by-
> default channel requests, target host-key pinning, algorithm pinning) +
> asciicast v2 recording, **Postgres-backed durable grants**, and **multi-
> controller HA** (workers dial all controllers behind an LB). Parser fuzzing.
> 5c (DB brokering), 5e (jess-web/IronRDP), and metrics/WORM-recording are `TODO`.
> Benchmark against HashiCorp Boundary CE; borrow from Warpgate + Teleport (fork neither).

Jess is the **L4/SSH/DB/TCP/RDP Policy Enforcement Point** for HexxLock operator
access — the non-HTTP counterpart to Talon. It brokers identity-gated,
per-session, short-lived access to infrastructure targets (SSH, Postgres/CNPG,
Vault/OPNsense/Proxmox APIs, raw TCP, and RDP via the browser) with **no standing
network reachability**, federated to **Falcon-ID** (the Policy Decision Point),
crediting from **Vault**, recorded to **MinIO WORM**.

A *jess* is the tether a falconer uses to control a hawk — apt for a broker that
tethers operator access.

## One product, worker classes (not separate products)

ADR 0030 + the 2026-05-27 research settled the architecture: **one control plane,
one policy core, one audit domain**, with worker *classes* per protocol. The
"build-our-own Guacamole" browser RDP/SSH recording gateway is the **`jess-web`**
worker class within Jess — NOT a separate product. RDP decoding is delegated to a
sandboxed Rust **IronRDP** worker (`rust/rdp-render`); everything else is Go.

```
cmd/
  jess-controller/   # control plane: PDP (Falcon-ID), JIT grants, yamux session pool, audit fan-in
  jess-worker/       # data plane (SSH / DB / raw TCP); outbound-only, dials home
  jess-web/          # data plane: browser RDP/web-SSH/VNC render + recording (build-our-own gateway)
  jessctl/           # operator CLI: `jessctl connect <target>` (Falcon-ID OIDC)
internal/
  pdp/               # Policy Decision Point client (Falcon-ID identity + authz)
  tunnel/            # reverse-tunnel fabric: yamux over SPIFFE-mTLS (workers dial home)
  broker/            # session brokering: SSH (Vault SSH CA), DB (Vault dyn-creds), TCP
  render/            # jess-web browser rendering (drawing-instruction stream / xterm.js)
  recording/         # tamper-evident recordings (asciicast v2 / drawing dump) -> MinIO WORM
  catalog/           # target registry (with region dimension)
  audit/             # structured session-event sink -> Loki/Tempo (shared funnel)
  jit/               # just-in-time: request -> approve -> time-boxed grant -> revoke
rust/
  rdp-render/        # sandboxed Rust IronRDP RDP decode worker (the only non-Go component)
docs/
  DESIGN.md          # architecture + NIST 800-207 mapping + library choices + roadmap
```

## Build plan (ADR 0030 Phase 5)

- [x] **5a spine — DONE** (race-tested): controller + worker + **yamux/SPIFFE reverse tunnel** + raw-TCP brokering + JIT gate + audit. Run `go test -race ./internal/spine/`.
- [x] **5b SSH record-proxy — DONE** (race-tested): worker = SSH server (Vault-CA cert auth) + SSH client to target; channel/request piping; **asciicast v2** recording. `internal/sshproxy`. Run `go test -race ./internal/sshproxy/`.
- [ ] 5c Postgres broker (`pgx/v5/pgproto3` + Vault dynamic-cred injection + query audit)
- [ ] 5d JIT engine (request→approve→time-boxed→revoke; `grant_id` bound into creds)
- [ ] 5e **jess-web** (build-our-own gateway: Rust IronRDP RDP + xterm.js web-SSH + noVNC) + WORM recording

See `docs/DESIGN.md`.
