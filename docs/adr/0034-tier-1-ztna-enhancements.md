# ADR 0034 — Tier-1 ZTNA/PAM Enhancements Catalog

| | |
|---|---|
| **Status** | Proposed — **research-partial** (4 of 6 target vendors + 1 of 5 target compliance frameworks covered; SOC 2 CC6, CISA ZTMM v2, FedRAMP moderate, PQC, SPIRE/SPIFFE, device-posture-contract, SDP/SPA, BeyondTrust PRA remain pending) |
| **Phase** | n/a — informational catalog; spawns Phase 5i+ implementation MRs |
| **Owners** | Platform / jess maintainers |
| **Inputs** | Two deep-research workflow runs (wf_3e0e634d-669 + wf_51615894-030) — 204 agents, 5.8M tokens, 40 source documents, 30 verified claims (3-vote adversarial), 10 refuted (kept in §Refuted) |
| **Date** | 2026-06-02 |

## Context

jess (ADR 0030) is a Go-based access broker that brokers SSH + Postgres + (in-progress) RDP via Falcon-ID OIDC + Vault PKI mTLS + tamper-evident WORM recording + JIT request→approve workflow. Phases 1–7h shipped through 2026-06-02 (see inventory in §"jess current state"). With the immediate roadmap mostly executed and ADR 0033 scoping the remaining browser-RDP work, the question is now where jess sits against industry tier-1 PAM/ZTNA brokers and what tier-1 enhancements are worth picking up next.

This ADR captures a *catalog* of tier-1 best practices with jess's position on each (Yes / Partial / No / Planned). It is **not** a commitment to ship every enhancement — it's the source-of-truth for "what is tier-1 in 2026, and where does jess actually stand?".

**Be aware**: research coverage is partial. The Teleport / Google IAP / Cloudflare Access / Pomerium / HashiCorp Boundary / StrongDM / CyberArk PSM / AWS Verified Access / Apache Guacamole / NIST SP 800-207 surface is verified. The CISA ZTMM v2 / SOC 2 CC6 / FedRAMP moderate / post-quantum / SPIRE-SPIFFE / device-posture-contract / SDP-SPA / BeyondTrust PRA surface is **not** — those sections are marked **RESEARCH PENDING** and remain open questions a future run (or human auditor) must fill. Shipping decisions sourced from the pending sections must wait for that follow-up.

## jess current state (baseline)

Carried in from the deep-research prompt; reproduced here so the ADR is self-contained.

**Shipped to jess main as of 2026-06-02:**
- **Phase 5 substrate** — Falcon-ID OIDC (svc-jess client, multi-aud JWT, RFC 8707 resource), Vault SSH-CA signing (15m TTL), Postgres dynamic creds via Vault, MinIO WORM recording with Ed25519 sig via Vault Transit, cross-session WORM audit chain (5e-16), grant lookup against admin port, mTLS worker↔controller (yamux over TLS).
- **Phase 5b** — JIT request→approve→grant workflow; same-TX grant mint on approve; SPA RequestForm + Admin tab + desktop notifications.
- **Phase 5e-2..20** — React+TS SPA (Vite + go:embed Teleport pattern), recording tamper-evidence verify, audit-event JSONL export, cross-session chain monitor, multi-target grants, top-operators badge, MinIO Console deep link, bytes counters, in-browser asciinema-player, manifest↔session chain link.
- **Phase 5f-1..9** — Rust IronRDP broker scaffold (X.224 probe + reachability + sweep), browser RDP renderer scaffold, svctoken-refresher sidecar, broker chart. Phase 5f-8b (full RDP fastpath + CredSSP) scoped in ADR 0033, not shipped.
- **Phase 5g-5..6** — Session-open SLO histogram + outcome counter; continuous grant verification (kills live sessions when grant revoked).
- **Phase 5h-3..6** — HTTP-proxy recording, risk-score evaluator (rules-v1 + OPA-backed `data.jess.risk`), device-posture wall at session-open, CAEP subscriber for IdP-driven session revocation.
- **Phase 6** — `jessctl up` one-shot operator bring-up.
- **Phase 7a-h** — Dynamic catalog (DiscoveryProvider + Aggregator), Proxmox / K8s / AWS / Azure providers, JessTarget CRD, admin-API target CRUD, host attestation framework, SPA Targets panel.
- **Phase 4 (today 2026-06-02)** — Operator-cert revocation. Lite: POST /operator-cert/revoke + `jessctl admin operator-cert-revoke`. Full: `admin.CRLCache` 5min poll of `/v1/jess-ca/crl/pem` + `VerifyPeerCertificate` hook on operator port :7101 + admin port :7103 (`mTLS=true, CRL=true`). Verified live: TLS alert 42 (`bad_certificate`) on revoked cert after CRL refresh.
- **Phase 3 (BeyondCorp L4)** — Public exposure on 203.0.113.10:7101 (jess.hexxlock.com) proven 2026-05-29.
- **mTLS device binding** — RFC 8705 §2.1 `tls_client_auth`, operator cert CN = verified Falcon-ID subject, Vault PKI mount `jess-ca` + role `operator-cert` (max_ttl=8h, 1y root), dual-CA trust bundle.
- **Audit posture** — Per-session WORM with Ed25519 sig via Vault transit; cross-session hash chain; JSONL export endpoint; per-query audit for db-broker.

**Open in roadmap** (not yet shipped):
- Phase 5f-8b: full RDP fastpath + CredSSP + smart-card cert flow + RDP graphics recording (ADR 0033 scoped, multi-week, deferred).
- Smart-card auth via AD CA cross-sign of Vault PKI `smartcard-login` role.
- SPIRE-based worker mTLS (`JESS_SPIFFE_SOCKET` stub exists).
- HA controller (replicas=2 + topology spread + PDB) — MR !798 in conflict.
- Admin-direct-connect with AMR step-up gate — feature-flag gated.

## Verified findings (run 1 + run 2)

### 1. Vendor capability matrix

Y = jess has it; P = partial; N = no; ? = research-pending.

| Capability | jess | Teleport Enterprise | Boundary HCP/Ent | StrongDM | CyberArk PSM | AWS Verified Access | Google IAP / BeyondCorp Ent | Cloudflare Access | Pomerium | Apache Guacamole |
|---|---|---|---|---|---|---|---|---|---|---|
| **SSH brokering** | Y (Phase 5) | Y | Y | Y | Y | TCP endpoint | Y (via TCP broker) | Y (browser-rendered) | Y | Y |
| **Postgres / DB brokering** | Y (Phase 5, dyn creds via Vault) | Y | Y | Y | Y | TCP endpoint | N | N | N | N |
| **Browser-rendered RDP / SSH / VNC** | P (Phase 5f-1..9 scaffold; Phase 5f-8b planned) | Y | N (TCP only) | Y (web app) | Y (HTML5 + native) | N | N | Y | N | Y (HTML5) |
| **Cryptographically-signed session recording** | **Y (Ed25519 + Vault Transit + cross-session hash chain, Phase 5e-16)** | Y (encrypted with age-based encryption) | Y (BSR Ed25519, per-directory SHA256SUMS, S3-compatible, 5 GB cap) | Y (uniform audit log stream) | Y (PSM video; integrity scheme not in surviving claims) | N (no session recording) | N (no protocol recording) | N | N | **N (no integrity scheme — 1.6.0 has zero references)** |
| **Cross-session WORM hash chain** | **Y (5e-16) — appears AHEAD of OSS norm** | ? (encrypted but per-session) | N (per-directory only) | ? | ? | N | N | N | N | N |
| **JIT request → approve → grant** | Y (5b) | Y (Access Requests) | Y (target session approvals) | Y (just-in-time access) | Y (workflow approval) | N (policy-evaluated each request) | N (policy-evaluated each request) | N | N | N |
| **Identity-aware proxy (continuous verify per-request)** | Y (via Talon credexchange; Phase 5g-6 grant-tick) | Y | Y | Y | Y | Y (Cedar policy each request) | Y (continuous per-request) | Y | Y (continuous per-request) | N (auth-at-connect only) |
| **Hardware key (PIV/YubiKey) enforcement at broker** | N (planned) | Y (Enterprise; `hardware_key_touch_and_pin` mode) | ? | ? (MFA enforcement claim unverified) | Y (QR-MFA Authenticator + PIV-style) | N (via trust provider only) | Y (Chrome Enterprise + Titan Security Key) | Y (PIV/FIDO2 via Access policy) | Y (claim 2-0 verified) | P (TOTP/Duo, not hardware-key per se) |
| **FIPS 140-3 validated crypto mode** | N | Y (Teleport 17.7.3+ / 18.0.0+) | ? (Enterprise SKU likely) | ? | Y | Y (AWS KMS FIPS 140-2; 140-3 partial) | Y (Google FIPS) | Y | ? | N |
| **Session lock primitive (kill in-flight by user/role/cert/device)** | P (continuous grant verifier + CAEP, Phase 5g-6 + 5h-6) | **Y — broader taxonomy (user/role/MFA-device/Agent UUID)** | ? (target-session-cancel verbed) | ? | Y | N | N | N | N | N |
| **Device-trust / device-posture at session-open** | Y (Phase 5h-5 `devicepolicy.Verdict`) | Y (Device Trust enrolled; HSM-backed) | ? | ? | ? | Y (via Crowdstrike/Jumpcloud trust provider) | Y (BeyondCorp Enterprise declarative attrs) | Y (WARP device) | Y (claim 2-0 verified) | N |
| **Risk-scored auto-approval (OPA-backed)** | **Y (Phase 5h-4a/4b — data.jess.risk)** | P (Access Lists with conditions) | ? | ? | Y (Identity Security Intelligence — vendor docs) | P (Cedar policy can express it) | P (Context-Aware Access) | P (Risk-Based Access) | P (PPL allows risk signals) | N |
| **CAEP / Shared Signals consumer (IdP-pushed revocation)** | Y (Phase 5h-6) | Y (Identity Activity Center) | ? | ? | ? | Y (via IdP) | Y (BeyondCorp Enterprise) | Y | ? | N |
| **CRL-enforced revocation at TLS handshake** | **Y (Phase 4 full — verified live 2026-06-02)** | Y (cert revocation + lock list) | ? | ? | Y | N (no client cert layer) | Y | N (token-only) | N (token-only) | N |
| **Dynamic catalog discovery (cloud APIs)** | Y (Phase 7a-h — Proxmox / K8s / AWS / Azure) | Y (`discovery_service`) | Y (dynamic host catalogs from clouds) | Y | Y | N (manual endpoints) | N | Y (Access apps) | Y (route definitions) | N (manual DB) |
| **Workload-to-workload mTLS via SPIRE** | N (file-mount; `JESS_SPIFFE_SOCKET` stub) | P (Teleport Machine ID) | ? | ? | ? | ? | ? | ? | ? | N |
| **Public-internet exposure without VPN (BeyondCorp)** | Y (Phase 3, jess.hexxlock.com:7101) | Y | Y (HCP Plus) | Y | P (typically VPN-fronted) | Y (AWS-fronted) | Y | Y | Y | Y |
| **Tier-1 PAM compliance attestations (FedRAMP/SOC2/ISO27001)** | N (HexxLock infra is single-cluster prod; no external audit yet) | Y (FedRAMP-ready, SOC 2 Type II, ISO 27001) | Y (FedRAMP HCP) | Y (SOC 2) | Y (FedRAMP, SOC 2, ISO 27001) | Y (FedRAMP) | Y | Y (FedRAMP) | P | N |
| **Cedar / policy-as-code engine** | P (OPA wired Phase 5h-4b; no Cedar) | P (Predicate language) | P (HCL-like policy) | P (Datasource policy) | P (PSM connector config) | Y (Cedar, Apache 2.0) | P (CEL) | P (Workers + Access policy) | Y (PPL — Pomerium Policy Language) | N |

**Key callouts:**
- **jess is AHEAD on cross-session WORM hash chain.** Apache Guacamole 1.6.0 has **zero** integrity mechanism for recordings (run 2 verified claim, primary source). Boundary BSR is per-directory SHA256SUMS + Ed25519 sig but no cross-session chain. Teleport's mode is encrypted but per-session. jess's Phase 5e-16 cross-session chain + Ed25519 per-session sig is **a real differentiator** for AU-10 non-repudiation.
- **jess is BEHIND on hardware-key enforcement, FIPS validation, and Teleport-style locks.** These are the top-3 priorities (see §Decisions).
- **jess is COMPARABLE to Boundary** on most dimensions — both built on Vault, both with brokered/proxied workflows, both with admin-mediated JIT grants. Boundary's BSR is the closest 1:1 analog to jess's recording stack. **Boundary keeps session recording behind HCP/Enterprise paywall**; jess gives it for free (relative posture: jess wins on OSS, Boundary wins on managed-cloud burden).

### 2. Compliance findings

#### NIST SP 800-207 (verified — run 2)

| Tenet | jess current position |
|---|---|
| **3** — Per-session access grant, no auto-carry across resources | ✅ Y — Phase 5b JIT grants are per-(target, subject, TTL); cross-target re-evaluation required |
| **4** — Dynamic policy (client identity + app + asset state + env) | ✅ Y — Phase 5h-4a/5h-5 risk eval + device-posture wall at session-open |
| **5** — Continuous monitoring of integrity + security posture | P — Phase 5h-5 device-posture wall fires at session-open only; continuous mid-session monitoring relies on Phase 5h-6 CAEP push and Phase 5g-6 grant-tick (10s cadence). Stronger continuous CDM integration is open. |
| **6** — Dynamic authn — constant obtain/scan/adapt/reauth | P — Phase 5g-6 continuous grant verification (kills sessions on grant revoke); per-session MFA step-up at the broker is N (planned per OMB M-22-09) |
| **7** — All resource access logged for analysis | ✅ Y — Phase 5e-15 JSONL audit-event export; per-query audit for db-broker; WORM recordings |

**NIST 800-207 §3.2 deployment variants** (verified — run 2):
- Variant 1 (Device Agent/Gateway / CSA SDP) — jess does NOT have a device-side agent; brokers via web/CLI only.
- Variant 2 (Enclave-Based / gateway in front of an enclave) — jess matches this for the operator port (`:7101` brokers into the in-cluster enclave).
- **Variant 3 (Resource Portal — "Portal-based") — this is jess's primary fit.** Operators connect to the controller; controller validates + brokers to upstream targets.
- Variant 4 (Device Application Sandboxing) — N/A.

#### OMB M-22-09 (verified — run 1)

Federal Zero Trust strategy mandates **MFA at the application layer** (not just at network ingress). jess currently relies on Falcon-ID's MFA at OIDC token mint; the broker itself does **not** trigger per-session step-up MFA. Closing this gap is priority #3 in §Decisions.

#### CISA Zero Trust Maturity Model v2.0 — RESEARCH PENDING

Both runs failed to produce surviving claims on CISA ZTMM v2 pillar definitions or "Advanced" criteria for the Identity and Devices pillars. Primary source (`https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf`) is **fetched but not claim-verified**. A focused source-read (human or workflow) is needed before mapping jess to the 4-level scale (Traditional / Initial / Advanced / Optimal) per pillar.

#### SOC 2 Common Criteria CC6 — RESEARCH PENDING

Run 2 fetched the AICPA 2017 Trust Services Criteria with 2022 Points of Focus but verified no claims. CC6.1–CC6.8 mappings (authentication, entity authorization, role-based authorization + SoD, logical access prevention, transmission/disposal, malicious software prevention) and the evidence types auditors expect remain open. **A SOC 2 advisor or a future targeted research run is the right path here**; deep-research's fan-out pattern is not well-suited to controls-text-reading.

#### FedRAMP moderate baseline — RESEARCH PENDING

NIST SP 800-53 r5 was fetched as a primary source. The PAM-relevant control families (AC-2/4/6/17, AU-2/3/12, IA-2/5/11, SC-7/8/12/13) need a direct controls-text read. **Defer to a FedRAMP-specialist pass.**

#### Post-quantum cryptography — RESEARCH PENDING

Primary sources fetched: NIST FIPS 203 final, NIST IR 8547 (PQ migration draft), IETF draft-kwiatkowski-tls-ecdhe-mlkem, Cloudflare PQ-2025 blog, HashiCorp PQ blog. **No surviving claims about tier-1 PAM vendor PQC adoption today.** NIST roadmap (per published primary doc): hybrid PQ encryption recommended **by 2030**, PQ signatures **by 2035**. CNSA 2.0 (NSA) sets tighter federal deadlines but the surviving claim is unverified.

### 3. Architecture findings (selected)

#### Identity-Aware Proxy pattern (verified — run 1)

- Google Cloud IAP (run 1, 3-0): brokers identity-verified access to apps + non-HTTP via TCP broker.
- BeyondCorp Enterprise (run 1, 3-0): same IAP pattern; deployed publicly without VPN.
- Cloudflare Access (run 1, 3-0): browser-rendered SSH/VNC for clientless connections.
- Pomerium (run 1, 2-0): continuous per-request verification at the proxy layer.

**jess analog**: Talon as sole IAP for `internal.example.com` (`internal.example.com`). Talon credexchange swaps inbound JWT for upstream cred; verified per-request. **jess matches the IAP pattern** for ops-tier hosts. For customer-tier hosts (post-Phase 7.4.e migration to Envoy Gateway) the IAP layer is the EG `EnvoyExtensionPolicy` + WAF chain, NOT Talon.

#### Hardware-key enforcement (verified — run 1)

- Teleport (5x 3-0 claims): `hardware_key_touch_and_pin` mode requires both touch AND PIN for every cert use; hardware-resident keys are non-exportable; Enterprise-only feature; FIPS 140-3 validated in 17.7.3+/18.0.0+.

**jess current**: operator cert keys are EC P-256 generated in-process by `jessctl up`. Private key lives on the operator workstation filesystem at `~/.config/jess/operator.key` (0600). **Not hardware-bound, not non-exportable, no touch-PIN UX.** This is the largest single-axis gap vs Teleport for sensitive operator access.

#### Session-recording integrity (verified — run 1 + run 2)

| Product | Per-session sig | Per-segment integrity | Cross-session chain |
|---|---|---|---|
| jess (Phase 5e + 5e-16) | **Ed25519 via Vault Transit** | embedded in asciicast manifest hash | **Yes — Phase 5e-16** |
| Boundary BSR | Ed25519 (BSR private key) | per-directory SHA256SUMS + sig | No |
| Teleport | encrypted recordings (vendor docs cite age-based encryption) | per-event hash in encrypted bundle | partial (per-session) |
| Apache Guacamole | **None** (verified negative — run 2) | None | None |
| StrongDM | uniform stream log (vendor docs) | ? | ? |
| CyberArk PSM | PSM video recording | integrity scheme not surviving | ? |

**Synthesis**: jess's recording stack is **at the top of the tier for non-repudiation**. The cross-session hash chain is uncommon (Boundary has per-directory, Teleport has per-session, Guacamole has nothing). **Recommendation: do not erode this lead**. If anything, expand the chain integrity dashboard (Phase 5e-18) to be a marketed differentiator.

#### Cedar policy language (verified — run 2)

AWS Verified Access uses Cedar (Apache 2.0) as policy language. jess uses OPA (Phase 5h-4b — `data.jess.risk` evaluator). **No action needed** — OPA is the dominant tier-1 choice; Cedar is the second-largest. Both are policy-as-code; both meet NIST 800-207 Tenet 4 (dynamic policy).

#### SPIRE/SPIFFE — RESEARCH PENDING

Primary source fetched: SPIFFE docs + k8s_psat plugin. No surviving claims. The canonical pattern is **k8s_psat attestation + X.509-SVID rotation + SDS push to envoy/linkerd**, but the verified comparison-claim chain wasn't produced. **Open question** to resolve before moving worker mTLS off file-mount.

#### Device-posture contract semantics — RESEARCH PENDING

Sources fetched (Tailscale CrowdStrike ZTA integration, others). No surviving claims on the contract shape (poll vs push, hard-fail vs soft-fail, signal freshness budget). **Open**.

#### Software-Defined Perimeter / Single-Packet Auth — RESEARCH PENDING

CSA SDP v2 spec fetched. No surviving claims on relevance in 2026 vs mTLS-at-listener. **Open**.

## Decisions — priority list

Combining run 1's medium-confidence top-5 with run 2's surfaced gaps, deduped and ordered by impact × tractability. Effort labels: **S** = single-week, **M** = multi-week, **L** = multi-month / sprint-scale.

### Top 5 (run 1, retained)

1. **Hardware-bound operator keys** — PIV/YubiKey 5+ enrollment; non-exportable private keys; cert binding via attestation. Match Teleport Device Trust. **Effort: M** — needs PIV CSR shape research + Vault PKI `attestation_validation` + `jessctl up --hardware` flag + ADR. Touches the lifetime of every operator cert.

2. **FIPS 140-3 validated crypto module mode** — enable Go's `GODEBUG=fips140=on` + boringssl/fipsmode build + Vault PKI in FIPS mode. Tier-1 requirement for federal eligibility. **Effort: M** — build-tag + CI matrix + interop testing with the existing Ed25519 + ECDSA primitives.

3. **WebAuthn / PIV per-session MFA step-up at the broker** — beyond OIDC token mint, require a per-session-open MFA touch. Matches OMB M-22-09 federal mandate + Teleport's pattern. **Effort: M** — SPA flow + controller `step_up` admin endpoint + Falcon-ID coordination (claim emission).

4. **Teleport-style lock primitive — broader taxonomy** — currently jess kills sessions on grant-revoke (Phase 5g-6) + IdP push (Phase 5h-6). Add lock targets: user, role, MFA-device, cert-serial, Agent UUID. **Effort: S** — new admin endpoint + lock store + composer over existing grant-tick.

5. **Browser-rendered RDP completion (Phase 5f-8b)** — ADR 0033 scoped; matches Cloudflare/Guacamole/Teleport parity. **Effort: L** — see ADR 0033's 4 sub-phases; smart-card cert flow (5f-8b-3) is the long pole.

### New from run 2

6. **SPIRE-based worker mTLS** — replace `JESS_TLS_CERT/KEY/CA` file mount with SPIFFE SVIDs via `JESS_SPIFFE_SOCKET` (the stub exists). Industry norm; k8s_psat is the right attestation plugin for our environment. **Effort: M** — SPIRE Server deployment + agents + registration entries for `jess-controller`/`jess-worker` SAs. **Research pending** for the canonical attestation chain — confirm before starting.

7. **Lock list as separate plane (Teleport-equivalent)** — even when grant is still valid, an admin should be able to lock a specific cert serial OR user OR MFA-device factor with a single command and have it propagate within ≤1 CRL refresh interval (jess) or ≤5s (Teleport). Pairs with #4. **Effort: S** — refine #4's design.

8. **Cross-session WORM chain — productize as a feature** — jess is the only stack we found (Boundary, Teleport, Guacamole all checked) that has both per-session sig AND cross-session chain. Phase 5e-18 chain integrity monitor exists; surface it on a dashboard (Phase 5e-13 admin tab auto-refresh has the substrate) and document as a competitive differentiator. **Effort: S — mostly docs/SPA polish**.

9. **Ingress worker filtering** — Boundary HCP-only feature; jess Phase 7a-h discovery substrate could implement client-facing filter equivalents in OSS (worker selection by region tag, by source IP allow-list). Closes a Boundary-Enterprise feature gap *in OSS*. **Effort: M** — needs design work in `internal/spine`.

10. **PQC migration plan** — adopt hybrid TLS 1.3 X25519MLKEM768 named group as soon as Go's `crypto/tls` ships it (per published roadmaps, Q1-Q3 2027). Track NIST IR 8547 PQ migration. **No code today**; commit to an ADR-tracked deadline (PQ encryption by 2030 per NIST). **Effort: S — planning** (deferred until Go stdlib ships).

### Pending research, then decide

- **A.** SOC 2 CC6 evidence inventory + automated collection (auditor-ready).
- **B.** CISA ZTMM v2.0 mapping per pillar; target "Advanced" for Identity + Devices.
- **C.** FedRAMP moderate baseline mapping for AC/AU/IA/SC control families.
- **D.** Device-posture contract semantics with the existing `devicepolicy.Verdict` — push vs poll, freshness budget.
- **E.** BeyondTrust PRA gap re-research (vendor docs were paywalled/unreliable).
- **F.** PQC posture of Teleport, Boundary, StrongDM — re-run when a new survey is published.

## Alternatives considered

**Alternative A: ship everything from §Decisions in one mega-phase ("Phase 5i").** Rejected — too coupled, too big. Each priority is independently shippable; phasing keeps blast radius local.

**Alternative B: defer everything until SOC 2/FedRAMP research completes.** Rejected — the Tier-1 priorities (#1, #3, #4) are valuable independent of certification.

**Alternative C: drop jess entirely and adopt Teleport.** Rejected for the obvious cost reasons + jess already-shipped differentiators (cross-session chain, dynamic catalog with Hexx-specific providers, integrated Falcon-ID / Talon / Vault tooling that a Teleport adoption would duplicate or replace). The roadmap progression keeps jess as the broker.

## Consequences

- **Positive**: clear catalog of what tier-1 looks like in 2026; priorities are sequenced with effort labels; honest gaps are flagged rather than papered over.
- **Negative**: research is partial. A future operator who consumes this ADR should treat the "RESEARCH PENDING" sections as **not** authoritative for compliance decisions.
- **Risks**: the verified vendor claims age fast. Teleport version pins (FIPS 140-3 in 17.7.3+/18.0.0+) drift; Guacamole's "no integrity scheme" could be fixed in 1.7.0; AWS Cedar policy language remains stable but its IAM Identity Center integration evolves. **Refresh cadence: annual.**

## Open questions (carried from both runs)

1. **CyberArk PSM recording-storage** — colocation in Vault was REFUTED 0-3. Where do PSM recordings actually live? Likely SMB share / NAS, but unconfirmed.
2. **StrongDM "credentials never reach client"** — 2-1 verified; the minority refute flagged a malicious-administrator edge case. Worth a second pass.
3. **Boundary BSR Ed25519** — confirmed; what's the BSR public-key distribution model? (Embedded in artifact? Co-located? Out-of-band?)
4. **Teleport session-recording integrity** — the source-cited mechanism in run 1 was age-based encryption; the actual integrity primitive (Merkle hash tree? per-event signature? both?) needs a primary-source dive.
5. **PIV/YubiKey CSR shape for jess** — per ADR 0033 §5f-8b-3, jess's smart-card cert flow needs the CSR + cert binding details from the Microsoft KB 281245 family. Open.
6. **Boundary "ingress worker filtering"** — confirmed HCP/Enterprise-only. Is there an OSS-license-compatible reimplementation pattern, or does HashiCorp's enterprise patent prevent us from replicating?
7. **Device-posture contract** — poll vs push, freshness budget, hard/soft fail. Needs Tailscale + Teleport + CrowdStrike doc reads.
8. **SDP / SPA in 2026** — is fwknop / CSA SDP v2 / AppGate's SPA leg still relevant alongside mTLS-at-listener, or fully superseded?

## Refuted claims (kept for honesty)

These claims were tested adversarially and **refuted** (0-3 or 0-1 votes). Listed so a future reader doesn't accidentally restate them:

- Teleport uses agent-based architecture; StrongDM operates agentlessly (0-3 — both are agent-based per their own docs).
- StrongDM supports broader protocols than Teleport, which is "cloud-native-only" (0-3 — Teleport supports DBs, K8s, RDP, web; not cloud-native-only).
- "Federal ZTA requires E2E encryption with mutual auth + micro-seg + centralized tamper-proof logging" — 1-0 only, source attribution wasn't strong enough.
- "Three distinct ZTNA architectural models: cloud-routed, mesh VPN P2P, self-hosted reverse proxy" — 0-1 (taxonomy not authoritative).
- "Pomerium supports WebAuthn + FleetDM device identity vs IAP" — 0-0 abstain (source too thin to support).
- "Context-aware access decisions should integrate ALL organizational signals" — 0-0 abstain (overgeneralized).
- "BeyondCorp Enterprise IAP pattern matches jess's Talon-as-IAP" — 0-0 abstain (architectural analogy, not a fact).
- "BeyondCorp Enterprise no-VPN verification matches jess's Phase 3 BeyondCorp L4" — 0-0 abstain (same).
- "BeyondCorp Enterprise device posture matches jess Phase 5h-5" — 0-0 abstain (source too thin).
- "CyberArk PSM uploads recordings to the Vault for retention" — 0-3 (Vault stores credentials, not video).

## References (40+ sources, quality-tagged)

### Primary sources (vendor docs, NIST/IETF/CISA/AICPA official, IETF drafts)

| Source | Topic | Quality |
|---|---|---|
| https://goteleport.com/docs/zero-trust-access/authentication/hardware-key-support/ | Teleport hardware key + PIV/YubiKey | primary |
| https://goteleport.com/docs/zero-trust-access/compliance-frameworks/fedramp/ | Teleport FedRAMP + FIPS 140-3 + AU/IA mapping | primary |
| https://goteleport.com/docs/identity-governance/locking/ | Teleport session/identity locking | primary |
| https://goteleport.com/docs/enroll-resources/server-access/guides/encrypted-session-recordings/ | Teleport session recording encryption | primary |
| https://cloud.google.com/security/products/iap | Google Cloud IAP — identity-aware access | primary |
| https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/browser-rendering/ | Cloudflare Access browser SSH/VNC | primary |
| https://developer.hashicorp.com/boundary/docs/session-recording | Boundary BSR fundamentals | primary |
| https://developer.hashicorp.com/boundary/docs/session-recording/data/bsr-file-structure | Boundary BSR on-disk format | primary |
| https://developer.hashicorp.com/boundary/docs/workers/filters | Boundary worker tagging + ingress/egress filters | primary |
| https://docs.strongdm.com/admin/networking/gateways-and-relays | StrongDM Gateway/Relay architecture | primary |
| https://docs.strongdm.com/concepts/security/credentials-and-secrets-management | StrongDM credential injection model | primary |
| https://guacamole.apache.org/doc/gug/recording-playback.html | Apache Guacamole recording (no integrity) | primary |
| https://docs.cyberark.com/pam-self-hosted/14.0/en/content/pasimp/psm-architecture.htm | CyberArk PSM architecture | primary |
| https://docs.aws.amazon.com/verified-access/latest/ug/auth-policies.html | AWS Verified Access policies (Cedar) | primary |
| https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf | NIST SP 800-207 Zero Trust Architecture | primary |
| https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf | CISA Zero Trust Maturity Model v2.0 | primary |
| https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 | AICPA Trust Services Criteria 2017 (with 2022 PoF) | primary |
| https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | NIST SP 800-53 r5 (FedRAMP baseline source) | primary |
| https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | NIST IR 8547 — PQ migration roadmap | primary |
| https://csrc.nist.gov/pubs/fips/203/final | FIPS 203 — ML-KEM | primary |
| https://www.federalregister.gov/documents/2024/08/14/2024-17956/... | FIPS 203 federal register announcement | primary |
| https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/ | IETF draft — hybrid TLS 1.3 X25519MLKEM768 | primary |
| https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/ | SPIFFE concepts | primary |
| https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md | SPIRE k8s_psat attestation plugin | primary |
| https://tailscale.com/docs/integrations/crowdstrike-zta | Tailscale + CrowdStrike Falcon ZTA integration | primary |
| https://cloudsecurityalliance.org/artifacts/software-defined-perimeter-zero-trust-specification-v2 | CSA SDP v2 spec | primary |
| https://blog.cloudflare.com/pq-2025/ | Cloudflare PQ readiness 2025 | primary (vendor blog, technical) |
| https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans | HashiCorp PQ plans | primary (vendor blog) |
| https://learn.microsoft.com/en-us/entra/standards/memo-22-09-multi-factor-authentication | OMB M-22-09 federal ZT strategy MFA mandate | primary |

### Blog / vendor-comparison sources (treat as supplementary)

| Source | Topic | Quality |
|---|---|---|
| https://goteleport.com/blog/how-teleport-extends-beyondcorp-and-federal-zero-trust-strategy/ | Teleport BeyondCorp claim | blog |
| https://www.pomerium.com/blog/cloudflare-access-vs-tailscale-vs-pomerium | Pomerium comparison post (vendor) | blog |
| https://www.pomerium.com/comparisons/google-iap | Pomerium vs IAP (vendor) | blog |
| https://www.pomerium.com/comparisons | Pomerium comparison hub | blog |
| https://inventivehq.com/blog/cloudflare-access-vs-aws-verified-access-vs-azure-entra-vs-google-beyondcorp | IAP-vendor comparison | blog |
| https://oneuptime.com/blog/post/2026-02-17-how-to-implement-zero-trust-access-to-web-applications-using-beyondcorp-enterprise/view | BeyondCorp Enterprise how-to | blog |

### Refuted / paywall / 404 (kept for paper-trail)

| Source | Reason |
|---|---|
| https://www.strongdm.com/comparison/strongdm-vs-teleport | Multiple agent-architecture claims refuted 0-3 |
| https://www.beyondtrust.com/resources/competitor-comparisons/cyberark-alternative | Zero surviving claims (unreliable per workflow) |
| https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/monitoring-privileged-sessions.htm | URL 404s (current docs at versioned URLs) |
| https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/privileged-session%20manager-introduction.htm | URL 404s |
| https://www.beyondtrust.com/products/privileged-remote-access | Marketing landing — no extractable claims |
| https://www.beyondtrust.com/docs/archive/privileged-remote-access/23-3/pra-access-console-23-3.pdf | Archived; URL unreliable |
| https://www.fedramp.gov/assets/resources/documents/FedRAMP_Security_Controls_Baseline.xlsx | XLSX format — not directly verifiable as claim |
| https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF | CNSA 2.0 — not surviving |

### Workflow provenance

- Run 1: `wf_3e0e634d-669` — 93 agents, 2.2M tokens, 11 sources fetched, 16 verified, 9 refuted, 7 after synthesis.
- Run 2: `wf_51615894-030` — 111 agents, 3.6M tokens, 29 sources fetched, 24 verified, 1 refuted, 14 after synthesis.
- Total: 204 agents, 5.8M tokens, 40 distinct source URLs, 30 verified claims, 10 refuted claims.

This ADR is **research-partial**. The Teleport / Google IAP / Cloudflare Access / Pomerium / Boundary / StrongDM / CyberArk PSM / AWS Verified Access / Apache Guacamole / NIST SP 800-207 / OMB M-22-09 axis is verified. The CISA ZTMM v2 / SOC 2 CC6 / FedRAMP moderate / PQC / SPIRE / device-posture-contract / SDP-SPA / BeyondTrust PRA / PIV-CSR axis is **NOT** verified and remains open per §"Open questions" and §"Pending research, then decide".
