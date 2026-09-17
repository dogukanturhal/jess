# ADR 0044 — SSH host-CA certificates (kill TOFU)

**Status:** Accepted — 2026-06-06
**Phase:** 7-c (auto-discovery enabler) — Pattern 1 of the 5-pattern
auto-discovery program ([deep-research synthesis 2026-06-06]).
**Supersedes (partially):** per-host `host_key` pinning requirement for
catalog entries enrolled in the SSH host-CA mount.

## Context

Today every SSH target in `internal/catalog/Target` carries a pinned
`HostKey` field — the byte-exact authorized_keys-form public key that
`internal/sshproxy.PinnedHostKey` compares against on every session
open. The pinning is correct (constant-time, algorithm-locked) and
caught the 2026-06-04 `dc01` host-key rotation cleanly. The problem
is the cost-per-target:

1. Operator SSH'es to the new host (or asks someone else to).
2. Reads `/etc/ssh/ssh_host_ed25519_key.pub`.
3. Pastes the verbatim authorized_keys line into `configmap-targets.yaml`.
4. Opens an MR, waits for review + merge, waits for Argo sync.
5. Worker restart picks up the new target.

For a 6-target catalog this is a quarterly chore. For a 60-target
catalog driven by AD/LDAP / Proxmox / k8s Service discovery (the
Phase 7-c source plugins) it is the bottleneck. Every discovery
cycle that surfaces a new host would FAIL CLOSED in the worker
("no `HostKey` pinned, rejecting") until step (3) happens.

The auto-discovery research (deep-research workflow
`wf_eeb3aa50-3b5`, 2026-06-06, 24 sources, 21/25 claims confirmed)
found that the cleanest answer in tier-1 PAM is to use **OpenSSH
host certificates** — a standard primitive supported by both
OpenSSH and `golang.org/x/crypto/ssh`. Teleport's auto-discovery
ships exactly this; HashiCorp Vault's SSH secrets engine ships the
primitive directly (`vault write <mount>/sign/<role>
cert_type=host`).

In CA mode the worker trusts a single CA public key (the
`jess-ssh-host-ca` mount's signing key). Every target host is
enrolled via a bootstrap script that asks Vault to sign the host's
existing SSH host key with `cert_type=host valid_principals=
<fqdn>,<short>,<ip>`, writes the resulting cert next to the host
key, and adds `HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub`
to sshd_config. The worker's `HostKeyCallback` then validates:

- presented host key is an `*ssh.Certificate`
- `cert.CertType == ssh.HostCert`
- `cert.SignatureKey` matches the configured CA (constant-time)
- `cert.ValidPrincipals` contains the dialed hostname
- cert validity window is current

The pinned per-host `HostKey` field becomes optional for any target
with `HostKeyCASigned=true`.

## Decision

Add a separate Vault SSH mount (`jess-ssh-host-ca`) dedicated to host
cert signing. Worker reads the CA's `public_key` on startup and accepts
CA-signed host certs for targets that opt in via a new boolean
`Target.HostKeyCASigned`.

### Why a separate mount, not the existing `ssh-client-signer`?

- **Different trust domain.** Rotating the operator USER CA shouldn't
  invalidate every host's trust anchor (and vice-versa). One incident
  shouldn't compromise both halves of the mTLS-equivalent for SSH.
- **Different role surface.** USER cert role caps TTL at 30m,
  restricts logins to `hexxlock,Administrator`, sets `permit-pty`.
  HOST cert role allows 1y TTL, no user list (host certs don't carry
  logins), no extensions. Mixing them violates least-privilege.
- **Different policy.** Bootstrap operators get
  `jess-ssh-host-ca-signer` (sign + read public_key on the host
  mount only) — they can't accidentally mint operator user certs.
- **Different revocation cadence.** USER CAs are rotated cluster-wide
  on personnel changes; HOST CAs are rotated only on key-compromise
  events. Coupling them forces the more aggressive cadence on both.

### Why not just leave `HostKey` mandatory and document the manual capture step?

The auto-discovery research confirmed that this is the single
highest-leverage finding for the 5-pattern program. Without it,
Pattern 3 (AD/LDAP), Pattern 4 (k8s Service), and Pattern 5
(Pending + Rego auto-promote) all stall on the same operator-driven
host-key capture step — the discovery half automates 9 lines of
configmap, the operator still has to do the 10th by hand. With it,
the whole pipeline runs end-to-end: AD surfaces a new Windows host
→ bootstrap script enrolls it → worker accepts it on first dial.

### Worker behavior matrix

| `HostKey` | `HostKeyCASigned` | Worker behavior |
|-----------|-------------------|-----------------|
| set       | false             | Pin against `HostKey` (pre-2026-06-06 behavior — unchanged) |
| empty     | false             | Reject session ("no host-key pin, no CA trust") |
| any       | true (worker has CA loaded) | Validate presented host cert against CA + `valid_principals` contains hostname |
| any       | true (worker has no CA loaded) | Reject session ("host_key_ca_signed=true but worker has no SSH host-CA trust anchor configured") |

The empty + false case is the only behavior change: previously the
worker accepted with a "TOFU dev-mode" warning. Production catalogs
have never set this combination (all entries today pin
`HostKey`); the safer fail-closed posture is correct for the broker.

## Consequences

### Positive

- New targets join the catalog with zero operator interaction once
  bootstrap is done. Pattern 3/4/5 auto-discovery becomes feasible.
- Compromised single-host private key surfaces a cert-validation
  failure cluster-wide (cert revocation can be modeled, future work).
- CA rotation is a single Vault operation + 1 bootstrap re-run per
  host, not 60 individual `host_key` field rewrites.
- Per-host blast radius is decoupled: revoking trust in target X
  doesn't touch targets A-W.

### Negative

- Adds a Vault dependency to the SSH dial path (one read at worker
  startup; cached for the worker's lifetime). If Vault is down at
  worker startup AND the configured mount path is set, the worker
  logs a warning and falls back to pinning-only — CA-signed targets
  will then fail at session-open with a clear error. Not a fail-open
  regression.
- Adds an operational step ("run bootstrap script") that didn't
  exist before. Mitigated by shipping
  `scripts/configure-node-ssh-host-cert.sh` (Linux) and
  `scripts/configure-windows-ssh-host-cert.ps1` (Windows) and
  documenting them next to the existing `configure-node-sshca.sh`.
- Host certs are LONG-LIVED (1y by default). OpenSSH does not
  natively expose cert-revocation via OCSP/CRL the way X.509 PKI
  does. The mitigation paths are: (a) sshd
  `RevokedKeys` file — Phase 7-c-2 backlog; (b) CA rotation to
  invalidate all certs at once.

### Neutral

- `Target.HostKey` field remains in the API for backwards-compat with
  pinned targets. `HostKeyCASigned` is opt-in per-target — no forced
  migration. CRD schema gains the new boolean; existing CRs are
  unaffected.

## Implementation surface

### Terraform (`infrastructure-iac/datacenters/eu-west-1/vault/`)

- `vault-jess-ssh-host-ca.tf` — new file. Declares:
  - `vault_mount.jess_ssh_host_ca` (type=ssh, path=jess-ssh-host-ca)
  - `vault_ssh_secret_backend_ca.jess_ssh_host_ca` (`generate_signing_key=true`)
  - `vault_ssh_secret_backend_role.jess_ssh_host` (allow_host_certificates=true,
    allowed_domains=internal.hexxlock.com,internal.example.com,hexxlock.com,
    allow_subdomains=true, ttl=8760h)
  - `vault_policy.jess_ssh_host_ca_worker` (read public_key)
  - `vault_policy.jess_ssh_host_ca_signer` (sign + read public_key,
    operator-tier only)
  - `vault_kubernetes_auth_backend_role.jess_worker_ssh_host_ca` (binds
    the worker policy to the jess SA)
- `policies/jess-ssh-host-ca-worker.hcl` — read-only on `public_key`
  + `config/ca`.
- `policies/jess-ssh-host-ca-signer.hcl` — write on `sign/host`,
  read on `public_key`, no other surface.
- `policies/atlantis-tf-runner.hcl` — adds mount-management grants
  for `sys/mounts/jess-ssh-host-ca` + role paths.

### jess (`internal/`, `cmd/jess-worker/`, `deploy/crd/`,
`scripts/`)

- `internal/sshproxy/hostkey.go` — new `CAHostKey(ca ssh.PublicKey)`
  function returning `(algos []string, cb ssh.HostKeyCallback, err
  error)`. Algos pinned to cert-form variants (no bare host key
  acceptance possible).
- `internal/sshproxy/hostkey_test.go` — new. Six cases: accept valid
  cert, reject principal mismatch, reject bare host key, reject
  rogue-CA-signed cert, reject user cert (cert_type=user), reject
  nil CA.
- `internal/catalog/target.go` — adds `HostKeyCASigned bool`.
- `internal/catalog/providers/jesstargetcrd/provider.go` — reads
  `spec.host_key_ca_signed` from unstructured.
- `deploy/crd/jesstargets.jess.hexxlock.com.yaml` — adds
  `host_key_ca_signed: boolean (default false)` to the spec schema.
- `cmd/jess-worker/vault_wiring.go`:
  - `loadSSHHostCAPublicKey()` — reads from
    `JESS_SSH_HOST_CA_VAULT_MOUNT`/public_key, parses as
    authorized_keys, logs trust anchor on success.
  - `sshDialTarget()` — per-target branch: CA mode iff
    `t.HostKeyCASigned`, else pinned mode.
- `scripts/configure-node-ssh-host-cert.sh` — Linux enrollment.
- `scripts/configure-windows-ssh-host-cert.ps1` — Windows enrollment.

### Manifests (`<gitops-repo>/jess/`)

- `controller.yaml` + `worker.yaml` — add
  `JESS_SSH_HOST_CA_VAULT_MOUNT=jess-ssh-host-ca` env.
- `configmap-targets.yaml` — NO entries flipped to `host_key_ca_signed:
  true` in this MR. Per-host flips happen after each host has been
  enrolled with the bootstrap script (one-by-one operator action,
  not a manifest change).

## Rollout

1. **Land IaC** (Atlantis-applied separately). Vault mount + role +
   policies exist; no consumers yet.
2. **Land jess code + CRD + manifests** in lockstep. Worker reads
   `JESS_SSH_HOST_CA_VAULT_MOUNT`; if unset (or read fails), behavior
   is identical to today. No catalog target sets
   `HostKeyCASigned=true` yet.
3. **Operator enrolls hosts one-by-one** via bootstrap script. After
   each, flip that target's `host_key_ca_signed: true` (and remove
   the now-redundant `host_key` field).
4. **Auto-discovery phases (B-E) consume the CA primitive.** New
   AD/LDAP/k8s-Services-surfaced targets land with
   `host_key_ca_signed: true` by default — operator runs the
   bootstrap script on the new host, target promotes from pending.

## References

- [deep-research workflow `wf_eeb3aa50-3b5`, 2026-06-06] —
  vendor-capability matrix, TOFU patterns across Teleport / Boundary
  / StrongDM / CyberArk / BeyondTrust / Delinea.
- HashiCorp Vault SSH secrets engine — Signed SSH Certificates:
  https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates
- Teleport agent host certificate model:
  https://goteleport.com/docs/reference/architecture/agents/
- ADR 0030 — original ZTNA broker architecture (operator USER cert CA).
- ADR 0041 — gap-audit roadmap; this ADR closes gap #11 ("manual host
  key capture is the auto-discovery bottleneck").

## Open follow-ups

- **Cert revocation surface.** OpenSSH RevokedKeys file is the
  standard primitive; jess can write to a configmap-mounted
  RevokedKeys list per host and reload sshd. Phase 7-c-2 backlog.
- **Per-target principal enforcement.** Today the bootstrap script
  signs a cert valid for `<fqdn>,<short>,<ip>`. If the target's IP
  changes (DHCP), the cert silently goes stale on the IP principal
  but the FQDN principal stays valid. Document the rotation
  cadence; consider DNS-only principals for non-static-IP hosts.
- **Host CA pubkey distribution to operator endpoints.** Operators
  who SSH directly (out-of-broker) still need to trust the host CA
  to skip TOFU on those flows. Configmap-publish CA pub +
  `@cert-authority` line; ship to operator workstations via the
  existing platform-tools onboarding.
