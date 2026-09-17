# ADR 0051 — IronRDP / CredSSP build plan for clientless RDP

Status: Proposed (R&D kickoff — design + first spike only; NOT shipped)
Date: 2026-06-20
Related: ADR 0033 (Phase 5f Rust IronRDP bridge), ADR 0030 (rdp-render
sandboxed worker / WORM recording), ADR 0049 (multi-protocol brokering),
ADR 0050 (clientless-operator credentials), ADR 0042 (Talon integration)

## Context

The `jess-ironrdp-broker` substrate (ADR 0033, Phases 5f-1..5f-8a) is built and
green, but the RDP session path is **handshake-only**:

- `services/ironrdp-broker/crates/proxy-core/src/x224.rs` hand-rolls the X.224 +
  RDP_NEG_REQ/RSP framing as a raw **reachability probe** (mirrors the Go
  `cmd/jessctl/rdp_probe.go` byte-for-byte). No `ironrdp` crate is used.
- `crates/broker-bin/src/handlers.rs::handle_socket` accepts the operator
  WebSocket, runs that probe against the grant's target, sends one status
  frame, and **closes the WS with reason `"phase 5f-8a handshake-only"`**.
- The pinned `ironrdp = 0.15` / `ironrdp-pdu = 0.8` / `ironrdp-connector = 0.9`
  / `ironrdp-svc = 0.7` dependencies are **declared but never `use`d** — kept in
  the graph so link-time gotchas surface early (per the `lib.rs` 5f-1 header).
- `rust/rdp-render/README.md` is an independent ADR-0030 scaffold for a
  *server-side-decoding* render worker (port of IronRDP's `screenshot.rs`:
  `connect → ActiveStage → DecodedImage → drawing-instruction stream`). It has
  no code.

So today the operator gets a reachability result and **no pixels**. Turning this
into a usable session is genuinely multi-week (ADR 0033 estimates 7-10 weeks
single-engineer; CredSSP/AD is the long pole). This ADR is the **honest R&D
kickoff**: it resolves a latent architectural fork, fixes the CredSSP approach,
lays out the phased build, and names the week-1 gating spike. It ships **one**
piece of code — a feature-gated connector spike (see "First spike" below) — and
nothing else.

## The fork this ADR must resolve: raw-relay vs server-side-decode

There are two incompatible frame models latent in the tree, and they cannot both
be the broker's contract:

1. **Raw fastpath relay.** ADR 0033's slice 5f-8b-1 + the `jess-rdp-recording-v1`
   container (ADR 0033 §5f-8b-4) describe the broker as a **dumb byte pipe**:
   `WS Binary ↔ TCP`, capturing *raw, undecoded* RDP fastpath bytes to MinIO and
   shipping a separate Rust replayer that re-implements the RDP renderer at
   replay time. Cheap on the hot path; lossless; but every consumer (the browser
   canvas, the replayer, any future MP4 transcoder) must contain a full RDP
   decoder.
2. **Server-side decode.** ADR 0030 / `rdp-render` describe the broker (or a
   sibling render worker) as a **decoding client**: IronRDP `ActiveStage` decodes
   the RDP graphics server-side into a `DecodedImage` / drawing-instruction
   stream, the browser renders display-agnostic draw ops, and the recorder tees
   the *decoded* stream.

These disagree on what crosses the WebSocket and what lands in WORM. ADR 0033's
own §5f-8b-4 even hedges ("Decoded-frame format `v2` deferred until we have a
real consumer"). Talon, separately, expects **server-side-decoded frames**
(ADR 0049 §"NLA/CredSSP terminated at the broker") — and that is the binding
constraint, because **WORM recording requires decode**.

### Decision: server-side decode (resolves the fork)

**The broker decodes server-side.** It runs a full IronRDP client
(`ironrdp-connector` → `ironrdp-session::ActiveStage`), decodes graphics into
`DecodedImage` frames, emits a display-agnostic drawing-instruction stream over
the WebSocket, and tees that **decoded** stream to the WORM recorder.

Rationale:

- **WORM recording requires it.** A tamper-evident audit recording must be a
  faithful, *inspectable* record of what the operator saw. Raw fastpath bytes
  are an opaque, codec-versioned blob that no auditor can read and that rots the
  moment a codec (RemoteFX/EGFX/NSCodec) changes — and AD DCs commonly *require*
  RemoteFX (`rdp-render` README). A decoded drawing stream is self-describing,
  greppable-at-the-frame-boundary, and survives codec churn. "Lost recordings =
  lost evidence" (ADR 0033 OQ #3) cuts toward *decoding now*, not toward an
  un-replayable raw blob.
- **One decoder, server-side, sandboxed.** Decoding untrusted bytes from a
  privileged target is the dangerous part. ADR 0030's posture — one
  decode-process per session, gVisor/seccomp, non-root, read-only rootfs,
  egress-locked to the single target — contains any IronRDP parser RCE to one
  ephemeral, credential-less session. Raw-relay pushes that same untrusted-byte
  decode into *every* consumer (the browser, the replayer), multiplying the
  attack surface.
- **It's the pattern IronRDP is built for** and that Teleport/Cloudflare ship
  (`rdp-render` README): `screenshot.rs` is already `connect → ActiveStage →
  DecodedImage`. We are not inventing anything.
- **Aligns the two scaffolds.** `rdp-render` (ADR 0030) and the broker (ADR
  0033) stop disagreeing: the broker *is* the decoding client; `rdp-render`'s
  decode loop is the broker's active-stage loop (whether in-process or as the
  sibling worker over UDS is an implementation detail deferred to the bridge
  phase).

Cost we accept: per-frame decode CPU on the broker path and a richer WS codec
(drawing instructions, not opaque bytes). Worth it for an auditable recording
and a single contained decoder.

**Consequences for ADR 0033:** its §5f-8b-4 `jess-rdp-recording-v1` *raw*
container is **superseded** by a decoded drawing-instruction recording
(call it `jess-rdp-recording-v2`, the format ADR 0033 itself deferred). The
standalone "raw replayer that re-implements RDP" (`services/jess-rdp-replay`) is
**dropped** in favour of replaying the decoded drawing stream with the same
renderer the browser uses. The rest of ADR 0033 (smart-card credential posture,
telemetry, sub-phasing) stands.

## CredSSP / NLA approach (the `sspi` crate)

NLA targets (the common case — the probe already detects
`HYBRID_REQUIRED_BY_SERVER`, code 5) require **CredSSP** before the RDP
connection sequence. We do **not** hand-roll CredSSP. `ironrdp-connector`
re-exports and drives the **`sspi`** crate (Devolutions; the connector pins
`sspi 0.21`, see the `Cargo.toml` comment block), which implements the
SPNEGO/NTLM/Kerberos/CredSSP token chain.

Mechanism in the connector state machine (verified against the pinned 0.9
source, `connection.rs`):

- After X.224 nego selects HYBRID, the connector enters
  `ClientConnectorState::Credssp { selected_protocol }`.
- `connector.should_perform_credssp()` gates it; the driver runs the CredSSP
  exchange (sspi assembles the token chain, exchanged inside the TLS-protected
  channel established by the preceding `EnhancedSecurityUpgrade`), then
  `connector.mark_credssp_as_done()`.
- Credentials come from `ironrdp_connector::Credentials`, which has exactly the
  two shapes our credential roadmap needs:
  - `Credentials::UsernamePassword { username, password }` — the operator-typed
    interim path (ADR 0033 §5f-8b-2; NTLM, or Kerberos when a `domain` is set),
    DEV/lab-only, opt-in, never production default.
  - `Credentials::SmartCard { pin, config: Option<SmartCardIdentity> }` where
    `SmartCardIdentity` carries a DER X.509 cert + DER RSA key — the **target
    end-state**: a Vault-minted short-lived smart-card cert (ADR 0033 §5f-8b-3),
    zero Windows passwords anywhere. This is the same posture jess SSH already
    has (Falcon-ID → Vault SSH cert → target).

**CredSSP is the single biggest hazard** (ADR 0033 §industry-survey finding 3:
Teleport spent 60-70% of their Windows-broker effort here, not on framing).
Windows AD edge cases — LDAP referral signing, trust paths, certificate-template
ACLs, smart-card-logon EKU + `msUPN` `otherName` SAN (MS KB 281245), and the
silent-fallback-to-password failure mode — are where weeks go. Hence the
week-1 gating spike below is **CredSSP against real AD**, not RDP framing.

Memory hygiene (carried from ADR 0033 §5f-8b-2): the broker's password `String`
is `zeroize::Zeroizing`; the credential frame is discarded from memory the
instant the CredSSP token is built; the password value is never logged (only
"credential-was-submitted" is audited).

## Phased build

Each phase ships independently and is individually testable. Estimates are
single-engineer wall-clock; CredSSP is the long pole.

```
P0  Connector spike (THIS ADR, shipped)        — done in this commit
      Feature-gated `proxy-core::spike`: construct a real
      ironrdp_connector::ClientConnector (non-NLA Config) and drive
      the X.224 / connection-initiation step offline. Proves the
      pinned 0.9 API links + runs from this workspace.

P1  connector → MCS → finalization (~2 wk)     — legacy/TLS, NO NLA
      Drive the connector past nego through the full MCS/GCC/channel-
      join/license/capability/finalization tail to `Connected`, over
      a real tokio TCP+rustls transport (ironrdp_async driver). Lab
      Windows VM with NLA disabled. Replaces handle_socket's
      handshake-only close. Still no decode — connector only.

P2  fastpath + SERVER-SIDE DECODE (~2 wk)       — pixels + WS codec
      On `Connected`, enter ironrdp_session::ActiveStage; decode
      graphics → DecodedImage; emit the drawing-instruction stream
      over the WS; render in the SPA canvas. This is "first pixels"
      for non-NLA targets, on the decoded frame model (the fork
      decision above). Input events (key/mouse) inbound.

P3  CredSSP / NLA (~3-5 wk, GATING)             — sspi UsernamePassword
      Drive ClientConnectorState::Credssp via sspi (NTLM/Kerberos)
      with operator-typed creds (ADR 0033 §5f-8b-2). DEV/lab-only,
      explicit opt-in, prod-disabled by env flag. Gated by the
      week-1 CredSSP-vs-real-AD spike (below). Smart-card end-state
      (Credentials::SmartCard + Vault PKI, ADR 0033 §5f-8b-3) is the
      follow-on once password CredSSP is proven.

P4  WORM recording (decoded) (~1-2 wk)  — SHIPPED  — jess-rdp-recording-v2
      Tee the DECODED stream to the SAME ADR-0030 signed WORM bundle
      (MinIO Object-Lock + Vault Transit) the SSH/DB recordings use,
      as jess-rdp-recording-v2 (supersedes ADR 0033's raw v1 AND the
      ADR-0049 periodic-screenshot track). Replay reuses the SPA
      canvas renderer — NOT a separate raw replayer.

      DELIVERED:
      - internal/recording/rdpstream.go — RDPStreamWriter +
        FormatRDPStreamV2: NDJSON meta header (binds the REAL operator
        Falcon-ID sub) + one line per DESKTOP_SIZE / decoded FRAME
        (region PNG inline base64) / input (mouse+key) / close, sealed
        into the existing BundleRecorder (same signature/manifest/
        cross-session-chain/VerifyDetail).
      - internal/broker/rdp_live_engine.go — the live engine's
        server→client + client→stdin tees feed the v2 recorder; Close
        SEALS the bundle and surfaces a seal failure.
      - cmd/jess-web/ws_rdp_live.go — opens the v2 bundle bound to the
        real op.Subject BEFORE the engine; FAIL-CLOSED: a Recorded
        target whose recorder can't open/write is DENIED.
      - Replay: cmd/jess-web/rdp_recordings.go (owner-scoped list/
        verify/download) + web RDPReplayCanvas + /rdp/recordings route.
      - Verified: unit (synthetic stream → v2 NDJSON + identity +
        fail-closed) + LIVE (real CredSSP session vs DC 10.0.20.10:
        resize=1, frames=25, 2.26 MB, bundle sig+hash verify OK).
```

Phase ordering note vs ADR 0033: ADR 0033 sequenced recording (its 5f-8b-4)
last and independent. Because the fork decision makes recording consume the
**decoded** stream, P4 now *depends on* P2 (decode) rather than on the raw
bridge — but it still parallelises with P3 (CredSSP), since CredSSP is upstream
of decode and orthogonal to the recording tee.

## Week-1 spike (gating risk): CredSSP against real AD

**The week-1 deliverable is not RDP framing — it is one successful CredSSP/NLA
authentication against a real AD-joined Windows target**, driven by
`ironrdp-connector` + `sspi` from this workspace. Rationale: framing (P1/P2) is
well-trodden IronRDP territory with a working `screenshot.rs` reference;
CredSSP/AD is the 60-70%-of-effort unknown. If `sspi`'s CredSSP path has a
blocker against *our* AD (trust topology, signing policy, cert templates), every
downstream estimate is wrong, and we want to know in week 1.

Spike shape (separate harness — `--ignored` integration test or a throwaway
bin, NOT the shipped broker path):

- Build a `Credentials::UsernamePassword` `Config` with `enable_credssp = true`
  against `~/projects/jess/test-rigs/win-2022-ad-domain/` (the ADR 0033 rig).
- Drive the connector over real tokio TCP + rustls through
  `ClientConnectorState::Credssp` to a successful `Connected` (or a precise
  failure code).
- **Success criterion:** one green CredSSP auth against real AD, with the exact
  `sspi` mode (NTLM vs Kerberos) and any AD-side prerequisites documented.
- **Failure criterion (equally valuable):** a written list of the AD edge cases
  that block, so P3 is re-estimated honestly before any UI work starts.

This spike is **out of scope for this commit** (needs a live AD rig + WG reach);
P0 below is what actually ships now.

## First spike (P0 — shipped in this commit)

`services/ironrdp-broker/crates/proxy-core/src/spike.rs`, behind the new
`ironrdp_spike` cargo feature (OFF by default). It is the **first code in the
repo that `use`s a real `ironrdp_connector` symbol**:

- `spike_config_non_nla()` builds a minimal **non-NLA** `connector::Config`
  (`enable_tls = true`, `enable_credssp = false`, empty creds), mirroring the
  upstream `screenshot.rs` reference construction.
- `drive_connection_initiation()` constructs
  `ironrdp_connector::ClientConnector::new(config, client_addr)` and calls
  `Sequence::step_no_input` once. The connector's first state
  (`ConnectionInitiationSendRequest`) *encodes the X.224 connection-request PDU*
  (TPKT + X.224 CR + RDP_NEG_REQ) into an `ironrdp_core::WriteBuf` and advances
  to `ConnectionInitiationWaitConfirm`. This is **pure encode-into-buffer — no
  socket, no I/O** — so it's a deterministic unit test of the real connector.
- Tests assert the connector emits non-empty, **spec-shaped X.224-over-TPKT
  bytes** (TPKT version `0x03`, BE length covering the packet — the same wire
  shape our hand-rolled `x224.rs` produces, cross-checking the two) and that the
  state machine advanced.
- A `=== CONNECTOR FRONTIER ===` comment block in `spike.rs` marks exactly where
  the state machine stops and what each later phase (transport driver, TLS
  upgrade, **CredSSP**, MCS/finalization, **fastpath + server-side decode**)
  must wire.

Why feature-gated: keeps the **default `cargo build` byte-for-byte the 5f-8a
handshake-only broker** with zero new direct dependencies on the default path.
The feature only adds a direct dep on `ironrdp-core` (already in the locked graph
as a transitive of `ironrdp-connector`, `=0.2.0`) to access `WriteBuf`.

Build/run note: enable via `--features jess-ironrdp-proxy-core/ironrdp_spike` on
the **whole workspace** (not `-p jess-ironrdp-proxy-core` in isolation — Cargo
then fails to unify the `time/parsing` feature `grant.rs` relies on; a
pre-existing workspace feature-resolution quirk, unrelated to the spike).

## What is explicitly NOT done

- No transport driver, TLS upgrade, MCS/GCC/finalization, fastpath, decode,
  CredSSP, recording, or SPA wiring (all P1-P4; the spike stops at the first
  connector step).
- No live AD CredSSP spike (the gating week-1 risk; needs a live rig).
- No change to the live session path: `handle_socket` still closes
  `"phase 5f-8a handshake-only"`.
- `rdp-render` (ADR 0030) remains a scaffold; this ADR only *aligns* it with the
  decode decision, it does not implement it.

## Open questions

1. **In-process decode vs sibling render worker.** The decode loop can live in
   the broker process or in the ADR-0030 `rdp-render` sidecar over UDS. The
   sidecar gives a tighter per-session sandbox; in-process is simpler. Defer to
   P2; the frame-model decision is independent of where decode runs.
2. **`sspi` Kerberos vs NTLM default** against our AD — answered by the week-1
   spike, not by guessing.
3. **Drawing-instruction WS codec shape** (`jess-rdp-recording-v2`) — design at
   P2 once `DecodedImage` diffing is real; do not pre-freeze the format.

## Enterprise-path / best-practice (production hardening)

The phased build above proves the *mechanism* (CredSSP → decode → recording).
This section records the **production correctness rules** the live activation
(infra-iac MR !203 + the GitOps repository MR !989) must follow. These are
non-negotiable for a real deployment even though the lab spike (P4's
"LIVE … vs DC 10.0.20.10" note above) cut corners to prove the loop — that
DC test was a **lab PoC only**; production never brokers RDP to a DC.

### (a) AD tiering — never broker RDP to a Tier-0 DC

Apply Microsoft's administrative-tier model (Tier 0 = identity control plane:
DCs, AD CS, ADFS; Tier 1 = member servers/apps; Tier 2 = workstations). A DC is
**Tier 0**: interactive/RDP logon to it is the highest-value attack target and
must not be exposed through a brokered convenience path. **Brokered RDP targets
are Tier-1 member servers only** (e.g. `mail-server.hexxlock.corp`). The DC is
touched solely for *directory operations* — the Vault LDAPS bind that mints the
ephemeral account — which is normal directory traffic, not an RDP session. The
target catalog and NetworkPolicy enforce this: the former `dc01-rdp`
(10.0.20.10:3389) target is removed; RDP egress goes to the member server only.

Corollary for the ephemeral account: it joins a **dedicated domain group**
(`CN=JessRDPAccess`), **not** builtin `Remote Desktop Users` — the builtin
domain-local group would grant RDP on the DC itself. An operator GPO
(Restricted Groups / Group Policy Preferences) nests `JessRDPAccess` into the
*local* Remote Desktop Users of the Tier-1 targets only.

### (b) Kerberos > NTLM — target by hostname/SPN, never by IP

NLA/CredSSP negotiates Kerberos when the target is reachable by a name that
maps to a service principal name (`TERMSRV/<host>`); an **IP-address target
forces a fallback to NTLM**, which is weaker (no mutual auth, relay/replay
exposure, and on the deprecation path). Therefore RDP targets in the catalog
MUST be the resolvable **FQDN** (`mail-server.hexxlock.corp:3389`), and the
member-server SPN + forward/reverse DNS must resolve **from the broker pod**.
In `sspi`/`ironrdp-connector` terms: set the credential `domain` and dial the
hostname so the SPNEGO chain selects Kerberos; treat an NTLM negotiation in a
production session as a misconfiguration to alarm on, not silently accept.

### (c) Credential non-exposure roadmap

Three tiers, weakest→strongest; the goal is **no reusable password ever reaching
the target**:

1. **Interim — ephemeral password (ZSP / dynamic secret).** Vault's LDAP
   secrets engine mints a per-session AD account that never existed before the
   session and is auto-revoked at lease end (15m/30m). CredSSP submits it once;
   the broker holds it in `zeroize::Zeroizing` and discards it the instant the
   token is built (see "Memory hygiene" above). This is what activation ships:
   no *standing* RDP credential, but a password still transits CredSSP. This is
   the Vault dynamic-secrets / HashiCorp-Boundary-style JIT-credential model.
2. **End-state — smartcard / PKINIT.** `Credentials::SmartCard { pin, config:
   SmartCardIdentity{ DER cert + DER key } }` (already present in
   `ironrdp-connector`, §"CredSSP/NLA approach") drives **Kerberos PKINIT** with
   a short-lived Vault-minted smart-card-logon cert — **no password on the
   target at all**. Feasible with our existing enterprise PKI primitives (the
   same Falcon-ID → Vault → cert posture jess SSH already uses); requires a
   smart-card-logon cert template (EKU `1.3.6.1.4.1.311.20.2.2`, `msUPN`
   `otherName` SAN, MS KB 281245) and a domain trust anchor. This is the target
   end-state once password CredSSP (P3) is proven.
3. **Defense-in-depth — Restricted Admin / Remote Credential Guard.** Where the
   target and clients support it, prefer RDP **Restricted Admin mode** (no
   reusable credential is delegated to the target — network logon only) and/or
   **Remote Credential Guard** (credentials stay on the broker side; Kerberos
   TGT redirection, no NTLM). These reduce blast radius if a target is
   compromised mid-session and are complementary to (1)/(2), not a replacement
   for the ephemeral/JIT model.

### (d) LDAPS always certificate-validated

The Vault→DC bind that mints the ephemeral account runs over **LDAPS with
certificate validation ON** (`insecure_tls = false` + a pinned `certificate`).
Pin the **issuing CA** where an enterprise CA exists; pin the **self-signed leaf**
when the DC presents a self-signed machine cert (our current state — no AD CS;
the DC's `CN=dc-identity.hexxlock.corp` machine cert carries the Server
Authentication EKU and is the trust anchor). Never `insecure_tls = true` in
production: an unvalidated LDAPS bind is MITM-exposed and would leak the bind
account credential. (Operator prereq: LDAPS must be actively bound to that cert
on the DC; at activation audit the DC reset TLS on :636 / returned LDAP code 52
on STARTTLS = LDAPS not yet enabled.)

### References (model)

- Microsoft — Active Directory administrative tier model / Enterprise Access
  Model (Tier 0/1/2; DCs are Tier 0, never a brokered RDP target).
- Microsoft — RDP **Restricted Admin mode** (KB 2871997 / 2973351) and **Remote
  Credential Guard** (no reusable credential delegated to the target).
- Microsoft — smart-card logon / **PKINIT** requirements (cert template EKU
  + `msUPN` `otherName` SAN, KB 281245); Kerberos preferred over NTLM (NTLM
  deprecation guidance).
- HashiCorp — **Vault dynamic secrets** (LDAP/AD secrets engine, lease-bound
  auto-revoked accounts) and **Boundary** session-scoped just-in-time
  credentials — the JIT/ZSP model item (c)(1) implements.
