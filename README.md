# Jess

[![CI](https://github.com/dogukanturhal/jess/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/jess/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/jess.svg)](https://pkg.go.dev/github.com/dogukanturhal/jess)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dogukanturhal/jess/badge)](https://scorecard.dev/viewer/?uri=github.com/dogukanturhal/jess)

An access broker for SSH, databases and RDP: operators get short-lived,
identity-bound access to infrastructure that has no standing network path to
them, and every session is recorded and written to an audit trail.

## Who it is for

Teams that give people shell, database or Windows desktop access to
production and want to answer "who was on that box, with which grant, and what
did they do" without handing out long-lived keys or opening VPN access to the
whole network. It suits you if you already run an OIDC identity provider and
HashiCorp Vault (or are willing to), and want to read and change the broker's
code.

If you need Kubernetes, web application or cloud console access today, or a
vendor to call, look at the alternatives below first. Jess is pre-1.0.

## Features

Each item below exists in the code. "Status and limitations" lists what is
partial.

**Access model**

- **Identity from a verified OIDC token.** The controller verifies the
  operator's token (signature, issuer, audience) and reads subject, `roles`,
  `groups` and `amr` from it. Authorization is role membership against the
  target's `required_roles`; a target with no roles denies everyone.
- **Grants.** No session opens without an unexpired grant that belongs to the
  token's subject. Grants come from `jessctl request` and an approver, or
  from an admin. Automatic approval for low-risk targets is opt-in
  (`JESS_RISK_AUTO_APPROVAL=true`), using built-in rules or an OPA policy
  such as `deploy/policies/risk.rego`.
- **Continuous authorization.** While a session is open the controller
  re-checks the grant, kill switches (locks on a subject, target, certificate
  serial or MFA device) and, optionally, an idle timeout; it closes the
  session when one fails. A CAEP subscriber ends a subject's grants when the
  identity provider reports a revoked session.
- **Step-up MFA per target** (`require_session_mfa`, with a freshness window
  on `auth_time`), device posture claims in the token, and device attestation
  (TPM 2.0, Apple, AWS, Azure) for enrolled devices.
- **Outbound-only workers.** Workers dial the controller over mTLS (file
  certificates, or SPIFFE SVIDs when SPIRE is present) and the controller
  opens streams down the connection. Several controllers can sit behind a
  load balancer; workers connect to all of them.

**Protocols**

- **SSH.** The worker is an SSH server to the operator (certificate signed by
  a Vault SSH CA) and an SSH client to the target, using a new short-lived
  Vault-signed certificate for each session. Target host keys are pinned or
  validated against a host CA. Channel requests are deny-by-default: agent
  forwarding, X11 and port forwarding are refused. Output is recorded as
  asciicast v2.
- **PostgreSQL and MySQL.** The worker speaks the wire protocol to the
  operator and connects to the database with a Vault dynamic credential the
  operator never sees. Statement text goes to the audit log, and the relay
  has a per-statement policy seam (read-only, table allow-list).
- **Raw TCP.**
- **RDP, in the browser.** `jess-web` serves a React console; for RDP it
  starts the Rust broker in `services/ironrdp-broker` (built on
  [IronRDP](https://github.com/Devolutions/IronRDP)), which does CredSSP,
  checks the host certificate against an AD CS trust anchor if configured,
  and streams frames to the browser. RDP sessions are recorded and can be
  replayed in the console.
- **Web terminal, HTTP proxy and database console** in `jess-web`, going
  through the same controller checks.

**Evidence**

- **Signed recordings.** At the end of a session the worker writes the
  recording, a manifest with its SHA-256, and an Ed25519 signature from a
  Vault transit key (the key stays in Vault) to an S3 bucket with Object Lock
  (MinIO tested). If the store is unreachable, a local store-and-forward spool
  holds the bundle and uploads it later.
- **Audit events** for authorize, open, close, deny and each query, as
  hash-chained JSON lines; plus a hash chain across session rows in Postgres
  with a verifier endpoint and Prometheus metrics for chain breaks.
- **Metrics and health:** `/metrics`, `/healthz` and `/readyz` on the
  controller; `/healthz` and `/readyz` on the worker.

**Catalog**

Targets come from a JSON file, Kubernetes custom resources
(`deploy/crd`), Kubernetes node and service discovery, Proxmox, LDAP, or an
admin API. Discovered targets can wait in a pending state for approval before
they are brokered. The worker probes targets with the same code path it uses
for sessions, to spot drift.

## Quickstart (about 5 minutes)

Needs Docker with the compose plugin. The full walkthrough, including the
Postgres target and how to check a recording's signature, is in
[demo/README.md](demo/README.md).

```sh
git clone https://github.com/dogukanturhal/jess && cd jess/demo

docker compose up -d --build            # Vault, MinIO, mock OIDC, controller, worker, targets
docker compose logs -f controller worker # wait until the worker has connected

docker compose run --rm grant            # one-hour grant for the demo operator
docker compose run --rm operator         # ssh to the target through the broker; type, then exit

docker compose run --rm mc ls --recursive local/audit-archive   # recording, manifest, signature
```

Replay the recording with `asciinema play` after copying it out; the commands
are in the demo README. The demo uses fixed development credentials and a
plaintext operator port. Do not run it anywhere reachable.

## How it compares

- **[Teleport](https://goteleport.com).** The most complete option: SSH,
  Kubernetes, databases, desktops, web apps, its own CA and UI, and a company
  behind it. Much larger and more mature than Jess. Check the licence of the
  edition you would run. Jess is smaller, delegates identity to your OIDC
  provider and credentials to Vault rather than running its own CA, and is
  easier to read end to end.
- **[HashiCorp Boundary](https://www.boundaryproject.io).** Closest in
  shape: controllers, outbound workers, Vault credential brokering. Its
  community edition is source-available (BSL) and session recording is an
  enterprise feature. Jess records SSH, database and RDP sessions in the open
  code but covers fewer target types and has no Kubernetes brokering.
- **[Warpgate](https://github.com/warp-tech/warpgate).** A single Rust
  binary SSH/HTTP/MySQL/Postgres bastion with recording. Simpler to run than
  Jess, no separate controller and worker, no Vault integration or RDP.
- **[Apache Guacamole](https://guacamole.apache.org).** Browser RDP, SSH and
  VNC with recording, but no grants, no per-session credentials and no tamper
  evidence. Jess's browser RDP covers part of what Guacamole does.
- **Commercial PAM (CyberArk, StrongDM and similar).** Support, UI polish and
  audit paperwork Jess does not have.

## Architecture

```
                      OIDC provider (tokens, roles)
                              │ verify
 operator ── jessctl ──┐      ▼
 (ssh, psql)           ├──► jess-controller ──── Postgres (grants, sessions,
 browser ── jess-web ──┘      │   │                        audit chain)
       │                      │   └─ catalog (file / CRDs / discovery)
       │ spawns               │ streams over yamux, mTLS
       ▼                      │ (workers dial in; outbound only)
  session_live (Rust)         ▼
  RDP ──► Windows         jess-worker ──► SSH / Postgres / MySQL / TCP targets
                              │
                              ├─► Vault: SSH CA, dynamic DB credentials,
                              │          transit key (signs recordings)
                              └─► MinIO / S3 (Object Lock): recordings,
                                     manifests, signatures
```

Design notes are in [docs/DESIGN.md](docs/DESIGN.md) and the decision records
in [docs/adr](docs/adr).

## Status and limitations

Pre-1.0 and not independently audited. It brokers operator access at
[HexxLock](https://hexxlock.com), the author's company; there are no
published third-party deployments. The command-line flags, environment
variables and the admin API may change between releases.

Known gaps, so you do not find them the hard way:

- **Recordings are buffered in memory until the session closes.** SSH and
  database recordings are written to the store when the session ends, not as
  it runs. A long session costs memory, and a worker that dies mid-session
  loses that recording (the audit events up to that point are not lost).
- **A failure when sealing the recording is not enforced.** "Fail closed"
  applies when the session opens: a target marked `recorded` is refused if no
  recorder is configured or it cannot be created. It does not check that the
  store is reachable at that point, and the error from sealing at close is
  discarded by the worker (`defer rc.Close()`). The spool covers an
  unreachable store; a failed signature or a full local disk can still leave a
  session without a complete bundle.
- **Recording needs Vault.** The only signer wired into the worker is Vault
  transit. There is no local-key mode. Recording is switched on by setting
  `JESS_REC_S3_ENDPOINT`; without it, the worker still brokers, and only
  targets marked `recorded` are refused.
- **No trusted timestamps yet.** An RFC 3161 client exists
  (`internal/recording/tsa_http.go`) but nothing calls it, so chain heads are
  not timestamped.
- **No Kubernetes brokering.** `internal/broker/kubernetes.go` implements
  `exec` and `port-forward` over an impersonation credential, but the worker
  does not register it. Kubernetes appears only as a source of targets.
- **Plaintext operator port by default.** The controller logs a warning and
  serves the operator port without TLS until `JESS_OPERATOR_TLS_CERT` and
  `JESS_OPERATOR_TLS_KEY` are set. The bearer token travels on that port.
- **In-memory grants unless `JESS_DB_DSN` is set.** That is fine for one
  process; workers re-check grants in the same store, so use Postgres for
  anything else.
- **Defaults name one vendor's identity provider.** `JESS_OIDC_ISSUER`
  defaults to HexxLock's own issuer. Set it. Any OIDC provider that puts
  `roles` in the token works; the demo uses a mock server.
- **RDP is the youngest part.** It needs Windows hosts with NLA (CredSSP),
  runs in a separate Rust process that `jess-web` starts, and has had less
  testing than SSH and Postgres. Pre-positioned credentials for RDP when
  Vault is down (`internal/offlinecreds`) are new.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off. Changes
are listed in [CHANGELOG.md](CHANGELOG.md).

## License

AGPL-3.0-or-later ([LICENSE](LICENSE)). The vendored IronRDP connector under
`services/ironrdp-broker/vendor/` keeps its upstream MIT / Apache-2.0
licences.

The name: a jess is the short strap a falconer uses to hold a hawk.
