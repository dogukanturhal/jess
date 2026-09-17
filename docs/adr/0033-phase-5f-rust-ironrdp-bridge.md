# ADR 0033 Phase 5f-8b — Rust IronRDP browser-RDP bridge

| | |
|---|---|
| **Status** | Proposed — design committed 2026-06-02; implementation deferred to a dedicated sprint |
| **Phase** | 5f-8b (continues 5f-8a `feat/phase 5f-8a` merged in commit `e1e5f2b`) |
| **Owners** | Platform / jess maintainers |
| **Supersedes** | none (extends Phase 5f-1..5f-9 substrate) |
| **Required by** | Operator browser-RDP in the jess-web SPA; Phase 5g browser-broker SLO targets for Windows targets |

## Problem

Phases 5f-1 through 5f-9 shipped the *substrate* for browser-RDP:

- **5f-1** — CI lane builds + signs + scans `jess-ironrdp-broker` Rust image (Harbor mirror, Buildkit + Cosign).
- **5f-2a..d** — RDP reachability probe (X.224 + RDP_NEG_REQ/RSP). `jessctl rdp-probe` CLI + controller admin `/rdp-probe` + SPA reachability button + catalog-wide sweep monitor with Prometheus metrics.
- **5f-3** — Helm chart (Deployment, SA, Service, TalonRoute).
- **5f-5** — `svctoken-refresher` sidecar (Falcon-ID JWT → Talon credexchange).
- **5f-7** — Browser RDP renderer scaffold in `cmd/jess-web/web/src/components/RDPCanvas.tsx`.
- **5f-8a** — WS upstream-connect leg: broker accepts the WS upgrade, runs the X.224 + negotiation handshake against the upstream target, returns the result frame, and then **closes the WS with reason `phase 5f-8a handshake-only`**.

Today the operator can request a grant, see in-cluster RDP reachability, open the browser-RDP page, and get a "handshake complete; fastpath bridge not yet wired (5f-8b)" frame. **No pixels.**

Phase 5f-8b is the work that turns the substrate into a usable session: implement the full RDP connector handshake past nego, then bridge fastpath frames between the WebSocket and the upstream TCP connection. This ADR scopes that work.

## Industry survey (2026-06)

Surveyed 7 vendors for browser-RDP credential + bridge patterns. Three dominant shapes:

| Pattern | Vendor | Cred source | Bridge protocol | Recording |
|---|---|---|---|---|
| **Smart-card cert via AD CA** | Teleport Windows Desktop Access (recommended pattern from 2023+) | Falcon-ID OIDC → broker mints short-lived smart-card cert via AD CA → CredSSP w/ cert | RDP fastpath ↔ WebSocket binary frames | RDPGFX → MP4 (server-side ffmpeg pipeline) |
| **Operator-typed creds, broker-relayed** | Apache Guacamole, Pomerium Identity-aware connections | Operator types username/password into browser → broker forwards via CredSSP | Guacamole protocol (custom) | guac native bitmap+events |
| **Saved-credential rotation, broker-injected** | CyberArk PSM, BeyondTrust PRA, HashiCorp Boundary RDP target | Long-lived Windows AD service account or rotated password stored in vault → broker injects at session-open | RDP fastpath ↔ WSS | session video + keystroke log |

Three findings worth carrying:

1. **Teleport's smart-card pattern is the only one with zero plaintext password material handled by the broker.** Operator authenticates via OIDC (Falcon-ID, in our case); broker mints a short-lived (≤8h) X.509 cert with `extendedKeyUsage = smartCardLogon` + `subjectAltName otherName msUPN=<operator>@<domain>` via an AD-trusted CA; broker assembles the CredSSP token using sspi-rs's smart-card flow. Windows AD accepts the cert as the auth factor — no password ever crosses the broker, no AD service account, no rotation burden. This is the same posture jess SSH already has via Vault `ssh-client-signer` (operator Falcon-ID → Vault SSH cert → target SSH).
2. **Recording RDP graphics needs a different format than SSH asciicast.** RDP traffic is binary bitmaps + ordered-graphics commands; capturing the WS frames raw produces a replayable bit-stream but every viewer must reimplement the RDP renderer. Teleport solves this by transcoding to MP4 in a separate pipeline. Apache Guacamole records its own protocol and ships a replayer. **The simplest viable strategy is to record the raw RDP fastpath bytes alongside the existing asciicast (different container) and ship a small Rust renderer for replay.**
3. **The CredSSP code path is the single biggest engineering hazard.** sspi-rs has matured but Windows AD edge cases (LDAP referral signing, AD trust paths, double-hop delegation, certificate template ACLs) take real time to debug. Teleport's engineering blog flags 60-70% of their Windows broker effort as the CredSSP/AD integration, not the RDP framing itself.

## Decision

**Adopt Teleport's smart-card pattern** as the target end-state for Phase 5f-8b. To minimise risk and time-to-pixel, split into four sub-phases that each ship independently:

```
5f-8b-1 (~2 weeks) — ironrdp_connector full handshake + fastpath bridge
                      LEGACY-RDP servers (no NLA, no CredSSP). Target: lab
                      Windows VMs with NLA disabled, ad-hoc test rigs.
                      Closes "no pixels" — operator gets a real Windows
                      session in the browser for non-NLA targets.

5f-8b-2 (~1 week)  — Operator-typed credentials path (CredSSP w/ password)
                      Operator types Windows username/password into the
                      SPA, browser → broker over TLS (still operator-port
                      TLS + mTLS), broker forwards via sspi-rs in
                      CredSSP+NTLM mode. PRAGMATIC interim — NOT a
                      long-term posture (operator handles plaintext
                      Windows password). Time-boxed; flagged as
                      "DEV-MODE ONLY — DO NOT USE FOR PRODUCTION
                      ACCESS" in the SPA.

5f-8b-3 (~3-5 weeks) — Smart-card cert flow (target end-state)
                      Vault PKI mount `jess-smartcard-ca` + AD CA trust
                      (NDES or AD CS root-cross-sign). Broker mints
                      ≤8h smart-card cert per session via Vault sign,
                      with msUPN otherName SAN populated from the
                      Falcon-ID claim that maps Hexx ops to AD UPNs.
                      sspi-rs's smart-card CredSSP flow assembles the
                      SPNEGO+NTLM token from the cert. End-state: zero
                      Windows passwords anywhere in the system.

5f-8b-4 (~1-2 weeks) — RDP graphics recording integration
                      Capture raw RDP fastpath bytes to MinIO bucket
                      `audit-archive/jess-rdp/<session>/` alongside
                      the existing asciicast bucket for SSH. NEW
                      container format `jess-rdp-recording-v1`:
                      newline-delimited JSON header + length-prefixed
                      binary frames. Small Rust replayer in
                      cmd/jess-rdp-replay/ ships as a sibling binary
                      (operator runs locally; broker doesn't render
                      server-side). MP4 transcoding deferred to 5g.
```

**Default credential posture** = 5f-8b-3 (smart-card). 5f-8b-2 (typed password) ships first because it's the path-of-least-resistance for getting *any* NLA Windows target online, but the SPA flow will require an explicit operator opt-in ("I understand this transmits a plaintext Windows password to the broker; my organisation accepts this risk") and the iac side stays inert until the smart-card flow lands.

## Implementation slices

### 5f-8b-1 — ironrdp_connector full handshake + fastpath bridge (legacy RDP)

**Files:** `services/ironrdp-broker/crates/proxy-core/src/connector.rs` (new), `services/ironrdp-broker/crates/proxy-core/src/bridge.rs` (new), `services/ironrdp-broker/crates/broker-bin/src/handlers.rs` (replace `handle_socket` post-handshake close with bridge invocation).

**Sequence after X.224 nego selects `PROTOCOL_RDP` (legacy) or `PROTOCOL_SSL` (TLS-only)**:

1. Upgrade upstream TCP to TLS via `tokio-rustls` if `PROTOCOL_SSL` was selected (Windows server cert chain validates against the system trust store; pinning deferred to 5g for parity with the SSH worker pattern).
2. Build `ironrdp_connector::ClientConnector` with the operator's resolved name/domain (placeholder for non-NLA — Windows accepts empty in legacy mode).
3. Drive the connector state machine: emit Connect Initial → consume Connect Response → emit Erect Domain Request → consume Erect Domain Response → Attach User Request → Attach User Confirm → Channel Join Requests → Channel Join Confirms → consume Server Demand Active → emit Client Confirm Active → SecurityExchange → ClientInfo (with empty creds for legacy) → License → consume Server Synchronize / Control Cooperate / Control Granted / Font Map → bridge enters `ConnectionFinalization::Frame` ready.
4. Bridge: spawn two tasks: `WS Binary → TCP write` and `TCP read → WS Binary`. Each task buffers in 4 KiB chunks with backpressure via `tokio::sync::mpsc` (matches the existing SSH bridge pattern in `internal/sshproxy`).
5. Close handling: either side closing terminates both. WS close on the operator side triggers `socket.send(Close)` on the upstream TCP. Cleanup must not leave the upstream half-open (RDP server doesn't always notice WS-side close).

**Acceptance:**
- Lab Windows VM with NLA disabled (test rig is `~/projects/jess/test-rigs/win-2019-no-nla/` per the existing rdp-probe fixtures).
- Operator opens `https://internal.example.com/rdp/win-test-01` in the SPA; sees the Windows login screen rendered in the canvas; can type into the login screen.
- `jess_sessions_opened_total{protocol="rdp"}` increments.
- Existing 5e-10 byte counters populate for direction=client→server and server→client.

**Risk:** ironrdp_connector internal API changes between minor versions (caught us in 5f-2). Pin both `ironrdp_connector` and `ironrdp_pdu` to exact patch versions in workspace `Cargo.toml`.

### 5f-8b-2 — CredSSP relay with operator-typed creds

**Files:** `services/ironrdp-broker/crates/proxy-core/src/credssp.rs` (new), SPA `cmd/jess-web/web/src/components/RDPLogin.tsx` (new), broker handler accepts an optional `{ "type": "creds", "username": "...", "password": "...", "domain": "..." }` WS frame before the bridge starts.

**Sequence:**

1. Operator opens `/rdp/<target>`; SPA renders the `RDPLogin` form when the target's catalog entry has `nla_required = true`.
2. Operator submits username + password (+ domain); SPA sends the creds in a single WS frame over the already-encrypted operator-TLS channel. Broker discards the frame from memory immediately after the CredSSP token is built.
3. Broker invokes sspi-rs in `NTLM` mode (default for non-domain) or `Kerberos` (when domain is set) — sspi-rs assembles the SPNEGO + NTLM/Kerberos token chain.
4. Token chain runs through CredSSP exchange with the Windows server inside the TLS-protected RDP channel.
5. On success, connector proceeds to ClientInfo (with creds embedded so Windows auto-logs the operator in); on failure, broker closes WS with the Windows-supplied error code.

**Memory hygiene:** the SPA's React state holding the password must zero out on submit (`useEffect` cleanup), and the broker's `String` holding the password must be wrapped in `zeroize::Zeroizing<String>` so the heap allocation is wiped on drop. ESLint rule for the SPA + `#![deny(clippy::ref_string)]` for the broker would catch accidental clones.

**Audit:** the credential frame WAS-SUBMITTED is audited (subject + target + timestamp); the password value is NOT logged.

**Acceptance:**
- Windows AD-joined target with NLA required (test rig `~/projects/jess/test-rigs/win-2022-ad-domain/`).
- Operator opens `/rdp/<target>`; SPA shows the cred form; operator submits creds; browser-RDP shows the operator's desktop.
- `jess_rdp_creds_submitted_total{result="ok"}` increments. Bad creds increment `result="auth_failed"`.

**Risk:** UX confusion if Falcon-ID OIDC creds and Windows AD creds are different. The cred form must clearly label "Windows username/password (not your Hexx OIDC creds)".

### 5f-8b-3 — Smart-card cert flow

**Files:** Vault PKI mount in `infrastructure-iac/datacenters/eu-west-1/vault/vault-jess-smartcard-pki.tf` (new), `services/ironrdp-broker/crates/proxy-core/src/smartcard.rs` (new), sspi-rs integration with smart-card token.

**Pre-reqs:**
- AD CA cross-signs the Vault PKI `jess-smartcard-ca` root (AD-side runbook).
- AD GPO: "Smart card is required for interactive logon" enabled for the brokered-access OU.
- Vault PKI role `jess-smartcard-ca/smartcard-login` with `extended_key_usage = clientAuth, smartCardLogon`, `allow_subject_alternative_name_other_names = msUPN` per Microsoft KB 281245.
- `falcon-id` ServiceClientClaim grants Hexx ops a `windows_upn` claim that maps to their AD UPN (e.g., `dogukanturhal@example.com` → `dogukanturhal@AD.HEXXLOCK.LOCAL`).

**Sequence:**

1. Operator opens `/rdp/<target>`; SPA does NOT render a cred form when the target's catalog entry has `auth_mode = smartcard`.
2. Broker reads the operator's Falcon-ID JWT, extracts the `windows_upn` claim.
3. Broker generates a fresh EC P-256 keypair in memory; builds a CSR with CN = the operator's Hexx sub, SAN otherName = `msUPN = <windows_upn>`.
4. Broker calls `POST /v1/jess-smartcard-ca/sign/smartcard-login` with the CSR; gets back a leaf cert valid ≤30 min (smart-card certs should be SHORT — they're tied to a single session).
5. Broker invokes sspi-rs in `Pku2u` or `Kerberos` mode with the cert + private key; sspi-rs assembles the CredSSP smart-card token chain.
6. Windows AD accepts the cert (via the AD CA cross-trust), the session opens.

**Recording integration is straightforward here** — the cert serial + Windows UPN are both audit-logged at session-open; the recording then captures fastpath bytes as in 5f-8b-1.

**Acceptance:**
- Domain target with smart-card login required.
- Operator opens `/rdp/<target>`; NO cred form rendered; session opens directly; Windows AD audit log shows the smart-card cert serial.
- Vault audit log shows the broker's sign call; cert serial + Hexx sub + Windows UPN are joinable across the three audit chains.

**Risk:** sspi-rs's smart-card path is less battle-tested than its password path. Plan for 1-2 weeks of integration debug; consider sponsoring fixes upstream if blockers surface (sspi-rs maintainers are responsive). AD GPO mistakes will cause silent fall-back to password auth; runbook MUST include a verify step.

### 5f-8b-4 — RDP graphics recording

**Files:** `services/ironrdp-broker/crates/proxy-core/src/recording.rs` (new), `cmd/jess-rdp-replay/main.go` (new — sibling Go binary for replay), `internal/admin/recording.go` extends to recognise `rdp-recording-v1` MIME alongside asciicast.

**Container format `jess-rdp-recording-v1`:**

```
header line (JSON):
  {"version":1,"session_id":"<jit_sessions.id>","operator_sub":"<falcon-id>",
   "target_id":"<catalog>","started_at":"<RFC3339>","tls":<bool>,
   "nla":<bool>,"width":1920,"height":1080,"depth":32,"keyboard":1033,"locale":"en-us"}

repeated frames, each:
  4-byte big-endian length
  4-byte direction tag ("c->s" or "s->c")
  8-byte big-endian nanos-since-start
  N bytes raw RDP fastpath payload (NOT decoded — replay-time decoding only)

footer:
  4-byte zero (sentinel — distinguishes truncated capture from clean close)
```

Raw bytes (not decoded) keeps the capture lossless + cheap (no per-frame parsing on the hot bridge path). Decoded-frame format (`jess-rdp-recording-v2`) deferred until we have a real consumer (mp4 transcoder, etc.).

**Replayer** (`cmd/jess-rdp-replay/`):
- CLI: `jess-rdp-replay --in s3://audit-archive/jess-rdp/<session>/recording.jrdp --listen 127.0.0.1:13389`
- Acts as an RDP server (uses Devolutions `ironrdp` server crate or a small Rust shim — actually it's simpler to ship as a Rust binary, so `cmd/jess-rdp-replay/` is misleading; this should be `services/jess-rdp-replay/` under the Rust workspace).
- Operator opens `mstsc 127.0.0.1:13389` and watches the recorded session replay at the original timing.

**Bucket isolation:** RDP recordings land in `audit-archive/jess-rdp/<session>/` (separate prefix from asciicast at `audit-archive/jess-ssh/<session>/`) so retention policies + replayer routing are cleanly separated.

**Acceptance:**
- Recorded session replayable via `jess-rdp-replay`; mstsc connection shows the same pixels as the original session.
- Replayer respects original frame timing (or a `--speed` multiplier).
- `jess_rdp_recordings_bytes_total` tracks total recorded bytes for capacity planning.

## Cross-cutting concerns

### Cargo dependency pinning

Lock both `ironrdp_connector` and `ironrdp_pdu` to **exact** patch versions in the workspace `Cargo.toml` (not `^` semver). Devolutions ships PDU shape changes in patch releases that have broken our 5f-2 build twice already.

### Testing strategy

- **Unit:** ironrdp_connector state machine driven by fixture byte arrays per phase boundary (Connect Initial, Erect Domain, ChannelJoin, etc.). Existing `proxy-core/src/x224_test.rs` pattern.
- **Integration:** `ironrdp_server` (Devolutions' Rust RDP server) in a tokio test, broker connector dials it, asserts the bridge transfers correctly.
- **e2e:** Windows VM test rigs (lab 10.0.10.30/31, dc01-rdp / win-host-01-rdp). Manual smoke for the milestone; automated nightly once stable.

### Telemetry to add

| Metric | Type | Labels |
|---|---|---|
| `jess_rdp_sessions_opened_total` | counter | result (ok\|x224\|connector\|credssp\|bridge), auth_mode |
| `jess_rdp_session_duration_seconds` | histogram | result |
| `jess_rdp_creds_submitted_total` | counter | result (ok\|auth_failed) (5f-8b-2 only) |
| `jess_rdp_smartcard_mints_total` | counter | result (5f-8b-3 only) |
| `jess_rdp_bytes_total` | counter | direction (c2s\|s2c) — increments per bridge tick |

### Failure modes worth alerting

- CredSSP success rate < 95% over 1h (Windows AD edge case or sspi-rs regression).
- Bridge p99 latency > 500ms (network or upstream Windows degradation).
- Smart-card cert mint rate suddenly drops (Vault PKI mount problem).
- Recording bytes per session falls outside the 1-50 MiB envelope (suspicious capture truncation).

## Out of scope

- **Audio redirection** (`rdpsnd`) — defer until operator demand.
- **Drive mapping** (`rdpdr`) — security-sensitive; defer until access-policy review.
- **Smart-card forwarding** (the OPERATOR's smart card, not the broker-minted one) — different concern from 5f-8b-3.
- **Clipboard redirection** (`cliprdr`) — exfiltration vector; defer until DLP wrapper designed.
- **RemoteApp / Remote Desktop Gateway** support — different RDP variant.
- **RDP MP4 transcoding** — defer to 5g.

## Timeline summary

| Sub-phase | Estimate | Blockers |
|---|---|---|
| 5f-8b-1 | ~2 weeks | none — substrate exists |
| 5f-8b-2 | ~1 week | follows 5f-8b-1 |
| 5f-8b-3 | ~3-5 weeks | AD CA cross-sign runbook + GPO setup |
| 5f-8b-4 | ~1-2 weeks | can run parallel to 5f-8b-1 if a different engineer |

**Realistic total wall-clock:** 7-10 weeks for a single engineer, 4-6 weeks with parallelism. Smart-card flow (5f-8b-3) is the long pole.

## Open questions

1. **AD CA cross-sign vs Vault PKI as primary AD-trusted CA.** Cross-sign is reversible (Vault stays the source-of-truth for our identity); making Vault the primary AD-trust CA is simpler but couples Vault availability to Windows logon for every brokered session. **Recommend cross-sign for now.**
2. **Should 5f-8b-2 (typed-password path) ship to production at all, or only to lab?** Argument for prod: real value while smart-card is built; argument against: introduces a posture downgrade we can't easily walk back. **Recommend lab-only, prod-disabled via env flag.**
3. **Recording format consumer.** Today there's no consumer; should we ship 5f-8b-4 (capture) BEFORE the replayer is real, or wait? **Recommend capture first** (data is not recoverable later; lost recordings = lost evidence).
4. **`windows_upn` claim provenance.** Should Falcon-ID emit this claim from the user record, or compute it from `sub` + a tenant-config domain mapping? **Recommend emit from user record** so it's an explicit operator-controlled value, not a derivation.
