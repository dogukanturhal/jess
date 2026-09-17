# ADR 0047 — RDP host trust uses x.509 (AD CA), not SSH-CA — explicit scope note

**Status:** Accepted — 2026-06-12.
**Type:** Scope-clarifying ADR.
**Related:** ADR 0033 (Rust ironrdp bridge), ADR 0044 (SSH-CA host
certs), ADR 0030 Phase 5f (RDP broker).
**Closes:** Phase A-* "task #51 — RDP host-cert path scope decision".

## Context

After the Phase A-* program shipped (host-CA cert flip for node-cp-01,
node-app-01, dc01 — all SSH targets), the catalog still has two RDP
entries (`dc01-rdp`, `exchange-01-rdp`) that show as `pin` mode in
`host_key_ca_signed` audits. Operators looking at the catalog ask: why
aren't RDP targets also flipped to CA mode?

Answer: **RDP uses a different cert primitive**. SSH host-CA cert
validation (ADR 0044) signs the target's `ssh-ed25519`/`ssh-rsa` host
key via Vault's SSH backend. RDP doesn't expose an SSH host key — it
exposes an **x.509 TLS certificate** at the RDS host's TLS layer
(typically auto-enrolled from a Windows Active Directory Certificate
Services CA via Group Policy).

The two trust primitives are not interchangeable:

| | SSH host cert | RDP TLS cert |
|---|---|---|
| Wire format | OpenSSH `ssh-ed25519-cert-v01@openssh.com` | x.509 v3 PKIX |
| Issuer | Vault SSH backend (`jess-ssh-host-ca`) | AD CS Enterprise CA |
| Signed object | host's ssh public key | host's TLS public key |
| Operator install path | `scripts/configure-{node,windows}-ssh-host-cert.*` + Ansible role `jess_ssh_host_enroll` | Group Policy + AD CS auto-enrollment |
| jess broker validation | `internal/sshproxy.CAHostKey()` + `Target.HostKeyCASigned` | **not implemented** — current state is TOFU |

## Decision

1. **Leave the RDP catalog entries in `host_key_ca_signed: false`
   (default).** Setting it to `true` would be a lie — the field is
   SSH-only and the worker never consults it for `ProtoRDP`.
2. **Do not populate `host_key` on RDP entries.** The field is unused
   for RDP and would be misleading. Confirmed by code search: neither
   `internal/rdpprobe/` nor `services/ironrdp-broker/src/` reference
   `Target.HostKey` or `Target.HostKeyCASigned`.
3. **The configmap header gets an explicit `RDP host trust:` note**
   (see companion the GitOps repository MR) so operators reading the
   catalog don't expect the SSH-CA flow to apply.
4. **The RDP TLS-CA validation path is a tracked future ADR (0048+),
   not silently deferred.** Scope sketch below.

## Update — IMPLEMENTED (P2.4, 2026-07)

The future-work sketch below is now shipped as the Phase-2 hardening item
P2.4. The Go broker validates the RDS host's TLS certificate against
configured AD-CS trust anchors instead of TOFU:

- **Package** `internal/rdphosttrust` — a pre-flight validator. The RDP wire
  TLS is terminated in the Rust `session_live` subprocess, so the Go engine
  performs the MS-RDPBCGR X.224 negotiation (reusing `internal/rdpprobe`),
  upgrades the socket to TLS, captures the presented chain, and validates it
  (chain to anchors + SAN/hostname + validity window + revocation) BEFORE
  spawning the subprocess. Failure ⇒ session-open fails closed.
- **Catalog** `Target.RDPTLSCASigned` (`rdp_tls_ca_signed`) — the per-target
  opt-in, the x.509 analog of `HostKeyCASigned`.
- **Config keys** (worker / jess-web env):
  `JESS_RDP_TLS_CA_PEM` (anchor PEM path/inline — the trust anchors),
  `JESS_RDP_TLS_ENFORCE` (default **true** once anchors are set — every RDP
  target validated; `false` ⇒ per-target opt-in only),
  `JESS_RDP_TLS_TOFU` (**off-by-default** migration escape hatch),
  `JESS_RDP_TLS_CRL_PEM` (host-cert CRL) + `JESS_RDP_TLS_REVOKED_FINGERPRINTS`
  (RevokedKeys-style leaf deny-list), `JESS_RDP_TLS_SERVER_NAME` (override).
- **Default flips from TOFU to CA-validated** once anchors are configured. The
  anchor path is forwarded to the subprocess env so the Rust side can enforce
  the equivalent (defense-in-depth for the pre-flight TOCTOU window).

The scope sketch that motivated it follows.

## Future work — RDP TLS-CA validation (ADR 0048 candidate)

Bringing RDP to parity with SSH-CA means:

### Catalog surface

Add to `internal/catalog/target.go`:

```go
// RDPTLSCASigned switches the RDP broker's TLS validation from
// TOFU/accept-all to chain-validation against the configured AD CA
// root. When true, the broker verifies the RDS host's leaf cert chains
// to TLSCARoot and that the cert's SAN/CN matches the dialed hostname.
RDPTLSCASigned bool `json:"rdp_tls_ca_signed,omitempty"`
```

Vault doesn't sign these — Windows AD CS does, via group policy auto-
enrollment. So this is **trust-anchor distribution + chain validation**,
not a sign-flow. The CA root cert lives in a configmap mounted into the
worker pod (or fetched from Vault KV).

### Worker code

`internal/rdpproxy/` (currently `internal/rdpprobe/` plus the Rust
`services/ironrdp-broker/`) needs a TLS validator that:
- Loads the AD CA root from `JESS_RDP_TLS_CA_PEM` env (or Vault
  KV path)
- Wraps the outbound TLS dial with `tls.Config{ RootCAs: pool,
  ServerName: <hostname-from-address> }`
- Rejects the session on chain failure with a clear audit event

The Rust ironrdp-broker side needs the equivalent — currently
`accept_invalid_certs: true` per ADR 0033 Phase 5f.

### Operator workflow

The Windows AD CS root cert is fetched once via `certutil.exe -ca.cert`
and committed to the GitOps repository as the configmap source of truth.
Rotation cadence: matches AD CA root rotation, typically multi-year.
The `roles/jess_ssh_user_ca_trust` role can be extended (or sibling
`roles/jess_rdp_tls_ca_trust` built) to keep the trust file in sync
on operator workstations.

### Audit posture

Same pattern as SSH-CA: every session-open logs the validated cert's
SAN + serial + AD CA fingerprint. Failed validations carry a precise
reason ("cert chain incomplete", "SAN mismatch", "expired", "revoked
per CRL/OCSP").

### Why not now

Three reasons defer this past the Phase A-* SSH program:

1. **Operator scope creep**: Phase A-* targeted the SSH primitive
   end-to-end. RDP TLS is a separate ADR-level decision with its own
   tradeoffs (CRL vs OCSP, embedded vs external trust store, Wasm-side
   trust on the browser RDP client per ADR 0033 Phase 5f-8b).
2. **Group Policy bootstrap**: AD CS auto-enrollment needs the
   computer to be domain-joined with the right cert template
   permissions. exchange-01 is already joined; future hosts may
   not be (e.g., bastion-only Windows). A non-domain path
   ("self-signed + manual pin") needs designing.
3. **Reversibility cost**: getting Vault SSH-CA wrong is recoverable
   (rotate the CA, re-enroll hosts). Getting RDP TLS-CA wrong can
   leave operators unable to admin the AD DC itself — the same
   target whose trust just got broken. The bootstrap path needs
   careful design before code.

## Consequences

**Positive:**
- Operators reading the catalog have an explicit answer for "why isn't
  RDP on CA mode?".
- Future ADR 0048 work has a documented starting point and a
  catalog field shape that doesn't accidentally collide with
  `HostKeyCASigned`.
- No code changes for this ADR — pure documentation.

**Negative:**
- RDP host trust remains effectively TOFU until ADR 0048 ships. Per
  ADR 0033 Phase 5f-8b, ironrdp-broker accepts the RDS host's TLS
  cert without chain validation. Mitigations in production: the
  RDP target's address is fixed by operators (no DNS surprise);
  the Talon IAP gates all admin RDP sessions; the AD DC's TLS cert
  rotates infrequently. The risk is bounded but acknowledged.

## Refs

- ADR 0030 Phase 5f — original RDP broker design
- ADR 0033 — Rust ironrdp bridge (Phase 5f-8b thin-tunnel)
- ADR 0044 — SSH host-CA certificates
- `internal/catalog/target.go::Target.HostKeyCASigned`
- `internal/sshproxy/hostkey.go::CAHostKey`
- `services/ironrdp-broker/src/` (Rust, ADR 0033)
- the GitOps repository `platform/jess/configmap-targets.yaml` header
  (companion MR adds the RDP host-trust note)
