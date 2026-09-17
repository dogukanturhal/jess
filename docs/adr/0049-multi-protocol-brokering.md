# ADR 0049 — Multi-Protocol Brokering (RDP / Database / Kubernetes)

Status: Proposed (design only — multi-phase build)
Date: 2026-06-18
Related: ADR 0030 (SSH session recording / WORM), ADR 0044 (SSH CA host
certificates), ADR 0043 (device-cert profile), ADR 0042 (Talon
integration), ADR 0046 (pending target lifecycle), talon ADR 0044
(clientless browser access), talon ADR 0040 (ZTNA platform)

## Context

jess is HexxLock's access broker + session-recording authority. Today it
brokers **SSH** end-to-end: short-lived SSH CA host/user certs (ADR 0044),
device-cert + posture-gated access, and tamper-evident **WORM session
recording** (ADR 0030) of every keystroke/stream into the audit-archive
bucket. The target catalog (`internal/catalog`), JIT approval
(`internal/jit`), risk scoring (`internal/riskscore`), and CAEP
revocation (`internal/caep`) are all already built and protocol-agnostic.

The remaining ZTNA breadth gap is **other protocols**: SSH is brokered +
recorded, but **RDP, databases (PostgreSQL/MySQL), and Kubernetes
(apiserver exec/logs/port-forward)** are not. Teleport's core value is
exactly this multi-protocol brokering with unified audit; it is the
blueprint. Without it, privileged RDP/DB/k8s access bypasses the broker
(no recording, no JIT, no device gate) — the biggest hole in the audit
story for regulated buyers.

## Decision

Generalize jess from "SSH broker" to a **protocol-pluggable broker** that
applies the SAME spine to every protocol:

```
auth (device-cert mTLS + posture JWS)  →  policy (catalog + JIT + risk + Rego)
   →  short-lived credential mint (per-protocol)  →  proxy/relay
   →  WORM session recording (ADR 0030 chain)  →  CAEP-revocable session
```

Only the **credential mint** and the **wire relay** are protocol-specific;
everything else (identity, policy, JIT, recording chain, revocation, the
catalog target model, the pending-target lifecycle of ADR 0046) is reused
unchanged. We introduce a `Broker` interface so each protocol is an
implementation, not a fork.

```go
// internal/broker (new): one implementation per protocol.
type Broker interface {
    Protocol() string                      // "ssh" | "rdp" | "postgres" | "k8s"
    // Mint issues the short-lived backend credential for an approved
    // session (SSH cert, ephemeral DB role, k8s impersonation token, …).
    Mint(ctx, AccessGrant) (Credential, error)
    // Dial opens the backend connection and returns a RecordedConn whose
    // reads/writes are teed into the WORM recorder (ADR 0030).
    Dial(ctx, Target, Credential) (RecordedConn, error)
}
```

### Per-protocol mint + relay

- **SSH (exists)** — refactor the current path behind `Broker` as the
  reference implementation. No behaviour change.
- **RDP** — relay via an `ironrdp`-based broker (Rust `crates/ironrdp-bridge`
  on the client side for the desktop agent; server-side a Go/Rust RDP
  proxy for clientless). Mint = short-lived AD credential or a gateway
  ticket; NLA/CredSSP terminated at the broker. Record the RDP graphics +
  input channel (or a metadata + periodic-screenshot track where full
  pixel recording is too heavy) into the WORM chain. Clipboard / drive
  redirection / printer channels are policy-gated at the relay.
- **PostgreSQL / MySQL** — the broker speaks the DB wire protocol, mints
  an **ephemeral DB role/credential** (Vault database secrets engine,
  short TTL) scoped to the target + grant, and records every statement
  (query log) into the WORM chain. Per-statement policy (read-only,
  table allow-list) enforceable at the relay — a capability direct DB
  access lacks.
- **Kubernetes** — broker fronts the apiserver for `exec` / `attach` /
  `logs` / `port-forward`; mints a short-lived **impersonation token** or
  a per-session client cert bound to the operator's Falcon-ID identity +
  RBAC; records the exec stream into the WORM chain. Integrates with the
  cluster's existing RBAC (no parallel authz).

### Reused spine (unchanged)

- **Identity/posture**: device-cert mTLS + posture JWS (agent path) OR
  the clientless channel (talon ADR 0044) for browser access.
- **Policy**: `internal/catalog` targets, `internal/jit` approval +
  grants, `internal/riskscore` (OPA), Rego baseline. A grant is
  protocol-agnostic; the broker mints the matching credential.
- **Recording**: ADR 0030 Merkle WORM chain — every protocol's stream
  tees through the same recorder, so the 7-year tamper-evident audit
  covers RDP/DB/k8s identically to SSH. This is the headline win.
- **Revocation**: CAEP session-revoked (ADR 0011/0043) tears down any
  live brokered session, any protocol.

### OCSF export

Each brokered session start/stop + (for DB) per-statement events map to
OCSF and flow to the SIEM via the audit-archiver OCSF exporter
(platform-tools) — unified SIEM visibility across all protocols.

## Security considerations

- **No standing credentials**: every backend credential is minted per
  approved session, short-lived, and scoped — never a shared service
  account.
- **Recording is non-bypassable**: access is ONLY via the broker; direct
  network paths to targets are firewalled off (the broker is the only
  route). This is what makes the audit complete.
- **Policy at the relay**: per-statement (DB), per-channel (RDP
  clipboard/drive), per-verb (k8s) controls the broker can enforce that
  endpoint-only access cannot.
- **Blast radius**: JIT + risk score + short TTL + device/posture (or
  clientless AAL cap) bound every session.

## Consequences

- Closes the multi-protocol audit gap; makes jess Teleport-class on
  brokering breadth (we are already ahead on device-cert provenance).
- Significant new surface: 3 new protocol relays + per-protocol
  credential mints (Vault DB engine, k8s impersonation, RDP gateway).
  Each is weeks of work + protocol-specific security review.
- Recording volume grows (RDP graphics especially) — needs the bundling/
  retention tuning already proven for SSH (ADR 0030) and a pixel-vs-
  metadata recording-fidelity knob per target sensitivity.

## Phased plan

- **Phase 0 — refactor (small):** extract the existing SSH path behind the
  `Broker` interface; no behaviour change; lands the seam.
- **Phase 1 — k8s exec/logs (weeks):** highest value-to-effort (reuses
  apiserver RBAC + impersonation; stream recording like SSH).
- **Phase 2 — PostgreSQL (weeks):** Vault DB ephemeral roles + statement
  recording + per-statement policy.
- **Phase 3 — RDP (weeks):** ironrdp relay + graphics/input recording +
  channel policy; pairs with talon ADR 0044 Phase 3 for clientless RDP.
- **Phase 4 — MySQL + k8s port-forward (weeks).**

Phase 0 + Phase 1 are the recommended next concrete build (smallest seam,
highest value). RDP is the heaviest and should come after the DB/k8s
brokers prove the spine.
