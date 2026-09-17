# CISA Zero Trust Maturity Model v2.0 — jess Compliance Mapping

| | |
|---|---|
| **Title** | CISA ZTMM v2.0 mapping for the jess access broker |
| **Date** | 2026-06-03 |
| **Status** | DRAFT — first-pass mapping; intended for internal calibration, not external attestation |
| **Scope** | jess access broker only (controller + workers + admin port + recording stack + jessctl). Out of scope: operator workstations (jess does not enroll them), Falcon-ID (covered separately), Talon (covered separately), Vault/MinIO infrastructure beyond jess's direct integration surface. |
| **Source authority** | CISA, *Zero Trust Maturity Model Version 2.0*, April 2023 (TLP:CLEAR). Pillar function names and Initial/Advanced/Optimal stage descriptions are quoted/paraphrased from the document and from Microsoft's per-pillar gloss of the same text on learn.microsoft.com (which reproduces CISA's stage descriptions verbatim before adding Microsoft-product guidance). |
| **Authors** | jess maintainers |
| **Related** | ADR 0030 (jess phase 7 dynamic catalog), ADR 0034 (Tier-1 ZTNA/PAM enhancements catalog — research-partial), ADRs 0035–0040 (hardware-bound keys, FIPS 140-3, per-session MFA, SPIRE worker mTLS, ingress worker filtering, PQC migration) |

## 0. How to read this document

CISA ZTMM v2.0 organises Zero Trust into **5 pillars** (Identity, Devices, Networks, Applications & Workloads, Data) and **3 cross-cutting capabilities** (Visibility & Analytics, Automation & Orchestration, Governance). Each pillar contains 4–7 *functions*, and each function has 4 *maturity stages*: **Traditional → Initial → Advanced → Optimal**.

This document scores jess on each function with the following conventions:

- **Stage**: the maturity stage jess currently achieves on that function. Where jess is on a boundary, the lower of the two is recorded (no half-credit).
- **Evidence**: concrete artefacts in the jess repo, phase deliverables (per ADR 0030 inventory), or live production state. Quoted phase IDs reference the jess roadmap.
- **Gap**: what would have to ship for the next stage.

**Honesty rule**: CISA's Optimal stage requires *continuous, real-time, fully-automated* behaviour across the *whole enterprise*. jess is a single component — many Optimal-stage criteria are out of scope for the broker (e.g. enterprise-wide data classification) or require integrations jess does not yet have (e.g. SIEM-driven SOAR playbooks). Honest scoring puts jess at **Advanced on most functions where it has real ownership** and **Initial on functions where jess is mostly a passthrough** or the criterion is enterprise-scoped.

**Scope discipline**: CISA ZTMM is written for *agencies* (whole enterprises). jess is *one access broker* inside the HexxLock enterprise. Where a function asks "does the enterprise do X across all systems", the honest answer for "jess by itself" is bounded — and is recorded as such rather than inflated to Optimal.

## 1. Identity pillar

CISA's framing: "an attribute, or attribute set, which uniquely describes an agency user or entity, including nonperson entities." Functions: Authentication, Identity Stores, Risk Assessments, Access Management.

### 1.1 Function: Authentication

**CISA stage criteria** (paraphrased from ZTMM v2.0 §1.1):
- **Traditional** — passwords, no MFA, or static MFA with no entity-attribute validation.
- **Initial** — MFA with multi-attribute validation (e.g. locale, activity).
- **Advanced** — phishing-resistant MFA across all identities (FIDO2 / PIV).
- **Optimal** — phishing-resistant MFA continuously validated, not just at initial grant.

**jess evidence**:
- Operator authentication is a *cert-binding + OIDC composite*. The operator presents an mTLS client cert (RFC 8705 §2.1 `tls_client_auth`, Vault PKI `jess-ca` role `operator-cert`, max_ttl=8h) AND a Falcon-ID JWT whose subject matches the cert CN. Both must succeed at the operator port `:7101`. Phishing-resistant by construction: the private key is never sent, the cert is bound to the OIDC subject.
- Falcon-ID enforces upstream MFA at token mint (TOTP today; WebAuthn/PIV planned per ADR 0037).
- Phase 5h-6 CAEP subscriber accepts IdP-pushed session-revocation events, so identity validation is *not* one-shot at session open — when Falcon-ID emits a session-revoke CAEP event, jess's continuous grant verifier (Phase 5g-6) tears live sessions down.
- Per-session MFA step-up *at the broker* is **planned** (ADR 0037 "per-session MFA step-up"); today jess relies on Falcon-ID's MFA at token mint, not at every session open. This is the OMB M-22-09 "MFA at the application layer" gap called out in ADR 0034 §OMB M-22-09.

**Stage: Advanced.**

**Why not Optimal**: continuous *re-authentication* in CISA's sense means the user is re-challenged with phishing-resistant MFA mid-session on risk signal, not merely that the session is killed when the IdP pushes revocation. ADR 0037 closes this gap. Until then, mid-session step-up is unimplemented.

### 1.2 Function: Identity stores

**CISA stage criteria**:
- **Initial** — mix of self-managed and hosted stores with minimal integration.
- **Advanced** — consolidating onto a single identity store.
- **Optimal** — fully integrated across all partners and environments.

**jess evidence**:
- jess has **no identity store of its own**. The single source of identity is **Falcon-ID** (cluster IdP, OIDC + SCIM, Phase 5 substrate). All grant subjects in `jit_grants.subject` resolve to a Falcon-ID OIDC subject.
- Vault PKI's `jess-ca` mount issues operator certs only after Falcon-ID OIDC authentication; the CN is the verified Falcon-ID subject (`jessctl up` enforces this).
- No shadow user table in jess's Postgres schema; `jit_grants`, `jit_requests`, `jit_sessions` reference subjects by IdP string.

**Stage: Advanced.**

**Why not Optimal**: Optimal at the pillar level requires "securely integrates identity stores across all partners and environments." jess is consolidated on one IdP (Falcon-ID) which is itself the consolidation target — but cross-partner / cross-tenant identity federation isn't an explicit jess feature today. Falcon-ID handles partner federation; jess inherits it. This is borderline Optimal, scored Advanced for honesty.

### 1.3 Function: Risk assessments

**CISA stage criteria**:
- **Initial** — manual review, static rules.
- **Advanced** — some automated analysis, dynamic rules informing access decisions.
- **Optimal** — real-time, continuous analysis with dynamic rules delivering ongoing protection.

**jess evidence**:
- Phase 5h-4a shipped a rules-v1 risk evaluator (in-process, deterministic). Phase 5h-4b moved the rule set to OPA — `data.jess.risk` evaluated at session-open via the controller's OPA client. Risk score gates auto-approval vs human approval.
- Phase 5h-5 device-posture verdict (`devicepolicy.Verdict`) fires at session-open and contributes to the risk eval.
- Phase 5g-6 continuous grant verifier polls grant validity at 10s cadence and kills sessions when revoked. This is *continuous* but it's binary (valid / revoked) rather than dynamic risk-score-driven.
- Phase 5h-6 CAEP subscriber consumes IdP-pushed risk signals (e.g. `session-revoked`, `credential-change-required`).

**Stage: Advanced.**

**Why not Optimal**: jess does not feed mid-session behavioural risk back into a continuous re-scoring loop. The risk score is computed at session-open and at grant-tick boundaries, not per-keystroke or per-query. UEBA-style behavioural anomaly detection over the WORM stream (Phase 5e-15 audit JSONL) exists as a data substrate but is not wired to a feedback loop that adjusts trust mid-session. ADR 0037's per-session MFA step-up partially closes this (step-up *can* be triggered by risk-score drift); a fuller closure would need an OPA `data.jess.risk` rule evaluated against streaming session telemetry.

### 1.4 Function: Access management

**CISA stage criteria**:
- **Initial** — authorize access including privileged with expiration and automated review.
- **Advanced** — need-based, session-based access, tailored to actions/resources.
- **Optimal** — automated JIT and just-enough-access tailored to individual actions and resource needs.

**jess evidence**:
- Phase 5b JIT grants: every access grant is bounded by (target, subject, TTL, scope). The grant ledger (`jit_grants`) is the authoritative source. Default TTL is short (15min for ad-hoc, max 8h for the operator cert itself).
- Phase 5b approval workflow: `jit_requests` → admin approval (or auto-approval per OPA policy) → same-TX grant mint. Notifications via SPA Admin tab + desktop push.
- Grants are scope-narrowed (per-target, per-subject); they don't carry across to other targets (NIST SP 800-207 Tenet 3 compliance, verified per ADR 0034).
- Postgres broker uses Vault dynamic creds (`v-kubernet-jess-pg-*` ephemeral users) — each session gets a new DB user, scoped, with TTL matching the grant.
- Continuous grant verifier (Phase 5g-6) ticks every 10s and kills sessions on grant revocation.

**Stage: Advanced.**

**Why not Optimal**: Optimal calls for "just-enough access tailored to *individual actions* and *individual resource needs*." jess grants are scoped to a target+subject+TTL, not to *individual actions within a session*. A user with a Postgres grant can run arbitrary SQL within their dynamic-cred role; a user with an SSH grant gets a shell. Per-action JIT (e.g., "approve THIS query, not arbitrary queries") would require either query-rewriting (SQL firewall) or per-command shell gating. This is a real gap; the closest analog is the Phase 5h HTTP-proxy recording for browser-rendered RDP, where per-frame visibility exists but not per-frame authorization.

### Identity pillar — overall: **Advanced**

Rationale: cert + OIDC composite authentication is genuinely phishing-resistant; Falcon-ID consolidation gives single-IdP posture; OPA-backed risk eval + CAEP push gets us beyond static rules; JIT grants with TTL + Vault dynamic creds is the canonical Advanced posture. Gaps to Optimal: per-session MFA step-up at the broker (ADR 0037), per-action JIT, and continuous mid-session risk-score re-evaluation.

## 2. Devices pillar

CISA's framing: assets connecting to a network — servers, endpoints, IoT, VMs, networking equipment. Functions: Policy Enforcement & Compliance Monitoring, Asset & Supply-Chain Risk Management, Resource Access, Device Threat Detection.

### Scoping note

jess is a broker, not a device-management plane. The "devices" relevant to jess are:
1. **Operator workstations** — the device the operator uses to launch `jessctl up` or open the SPA. jess does NOT enroll, manage, or inventory these. Operator-workstation posture is the responsibility of the enterprise MDM (out of scope for jess).
2. **jess's own pods** — controller + worker pods. These are managed by GitOps (the GitOps repository + Argo) + image-updater + Reloader; jess does not self-manage them.
3. **Target hosts** — the SSH/Postgres/RDP targets jess brokers to. These are discovered via Phase 7 dynamic catalog providers (Proxmox / K8s / AWS / Azure) but jess does not enroll them as managed devices either; it brokers access *to* them.

Most Devices-pillar functions are therefore out-of-scope for jess. Where jess contributes is in **device-posture-at-session-open** (Phase 5h-5) — jess refuses to broker a session if the operator workstation's posture verdict from the IdP/MDM is non-compliant.

### 2.1 Function: Policy enforcement and compliance monitoring

**CISA stage criteria**:
- **Initial** — self-reported device characteristics, limited enforcement.
- **Advanced** — verified insights at initial access, compliance enforcement for most devices, automated patching.
- **Optimal** — continuous verification and compliance enforcement throughout device lifetime.

**jess evidence**:
- Phase 5h-5 device-posture wall: at session-open, jess calls `devicepolicy.Verdict(subject, deviceID)` against the policy backend; non-compliant = no session. Verdict source today is OPA + IdP-emitted device-posture claims.
- jess does NOT continuously monitor operator-device posture mid-session (that's the MDM's job). CAEP push from the IdP (Phase 5h-6) is the closest analog: if the IdP detects the device went non-compliant mid-session, it pushes a session-revoke event and jess tears the session down.

**Stage: Initial-leaning-Advanced.**

**Why not Advanced fully**: "verified insights" in CISA's sense includes admin-inspectable device data on each session. jess sees only the verdict, not the underlying device-posture data. Closing this requires a richer device-posture-contract design (open question per ADR 0034 §Device-posture contract semantics — RESEARCH PENDING).

**Why not Optimal**: continuous lifetime enforcement is out-of-scope for jess by design — that's the MDM's responsibility. CAEP push gives us *event-driven* lifetime enforcement, which is partial credit toward Advanced.

### 2.2 Function: Asset and supply-chain risk management

**Stage: N/A for jess as a broker.**

jess does not inventory devices, manage supply chain, or track third-party assessments. This is enterprise IT's pillar. For completeness: the *jess images themselves* are built by GitLab CI, signed (Cosign), scanned (Trivy), and stored in Harbor — that's tracked in the Applications & Workloads pillar §4.4 below.

### 2.3 Function: Resource access

**CISA stage criteria**:
- **Initial** — some devices report characteristics that gate resource access.
- **Advanced** — initial access considers verified device insights.
- **Optimal** — real-time risk analytics within devices inform access.

**jess evidence**: same as §2.1 — Phase 5h-5 device-posture wall is the device-insight gate at initial access. CAEP push gives near-real-time updates.

**Stage: Advanced.**

**Why not Optimal**: jess takes a *verdict* (compliant / non-compliant / unknown) at session-open, not real-time risk-score deltas. The device posture's freshness budget is one of the open questions in ADR 0034.

### 2.4 Function: Device threat detection

**Stage: N/A for jess.**

Threat detection on operator workstations is the MDM/EDR's job. jess consumes the EDR's verdict via the IdP's device-posture claim, but does not deploy or operate EDR itself.

### Devices pillar — overall: **Initial-leaning-Advanced**

Rationale: device-posture-at-session-open + CAEP push for IdP-driven revocation give us real Advanced-tier behaviour on the functions where jess has agency (resource access, policy enforcement). The other functions (asset inventory, supply-chain, threat detection) are explicitly enterprise-IT concerns; jess is a *consumer* of those signals, not a producer. The pillar score is bounded by the lowest function where jess has meaningful agency, which is policy-enforcement-and-compliance-monitoring (Initial-leaning-Advanced).

## 3. Networks pillar

CISA's framing: open communication medium (internal nets, wireless, internet, cellular). Functions: Network Segmentation, Network Traffic Management, Traffic Encryption, Network Resilience.

### 3.1 Function: Network segmentation

**CISA stage criteria**:
- **Initial** — isolate critical workloads, constrain connectivity, transition to service-specific interconnections.
- **Advanced** — endpoint and application profile isolation with ingress/egress micro-perimeters.
- **Optimal** — fully distributed micro-perimeters + extensive micro-segmentation + dynamic JIT/JEA connectivity.

**jess evidence**:
- jess controller + workers run in a dedicated K8s namespace; Linkerd service mesh provides per-pod mTLS-on-by-default with `opaque-ports` annotations on the jess broker ports (raw TLS workloads bypass HTTP-aware proxying but keep transport encryption).
- Talon is the sole IAP for `internal.example.com` — jess's admin port `:7103` and operator port `:7101` (when accessed via the SPA) sit behind Talon credexchange.
- Envoy Gateway is the IAP for customer-tier hostnames (post-Phase 7.4.e migration).
- Operator port `:7101` is also exposed publicly on `203.0.113.10:7101` (Phase 3 BeyondCorp L4) as a TLS-mTLS listener — no VPN required. Cert verification + Falcon-ID JWT both required.
- NetworkPolicies in the jess namespace restrict egress to: Postgres (CNPG), MinIO, Vault, Falcon-ID, OPA, Linkerd identity, telemetry. No wildcard egress.

**Stage: Advanced.**

**Why not Optimal**: Optimal calls for "dynamic just-in-time and just-enough connectivity for service-specific interconnections." jess's NetworkPolicies are static (declared in manifests, GitOps-managed). Per-session network policy (e.g., "open egress to this target host only when this session is active") is not implemented — and arguably is the wrong design for a broker that already proxies traffic through the worker pods. The actual JIT in jess happens at the *grant* layer, not the network layer.

### 3.2 Function: Network traffic management

**CISA stage criteria**:
- **Initial** — application profiles with distinct traffic management; static rules; periodic manual audits.
- **Advanced** — dynamic rules adapted on risk-aware application profile assessments.
- **Optimal** — continuously evolving rules reprioritising by mission criticality and risk.

**jess evidence**:
- jess's "traffic profile" is encoded in the worker's spine routing: per-session, the worker establishes outbound to the target via yamux + TLS, with the upstream target chosen by the grant.
- No dynamic mid-session traffic-rule adaptation today.

**Stage: Initial.**

**Why not Advanced**: jess does not dynamically re-rule traffic based on per-session risk. This isn't a high-leverage gap for a broker (where the *grant* is the gate), but it's honestly Initial against CISA's wording.

### 3.3 Function: Traffic encryption

**CISA stage criteria**:
- **Initial** — encrypt all traffic to internal apps; formalise key management.
- **Advanced** — encrypt all internal+external traffic with rotation and cryptographic agility.
- **Optimal** — encrypt all, enforce least-privilege key management, cryptographic agility enterprise-wide.

**jess evidence**:
- All jess ports terminate TLS 1.3. Operator port `:7101` and admin port `:7103` require mTLS (client cert REQUIRED; verified against `jess-ca` trust bundle + CRL).
- Worker↔controller is mTLS over TLS 1.3 + yamux (Phase 5 substrate).
- Linkerd mesh adds another mTLS layer for in-cluster pod-to-pod (defense in depth; identity rotates every 24h via Linkerd identity controller).
- WORM recording bundles in MinIO: server-side encryption (SSE-C with Vault Transit-derived keys, Phase 5e), per-bundle Ed25519 signature via Vault Transit (Phase 5e-16 cross-session chain), keys never leave Vault Transit.
- Vault PKI: `jess-ca` root TTL 1y, intermediate signs operator cert role `operator-cert` (max_ttl=8h), per-session SSH cert TTL 15min.
- Cryptographic agility: primitives are Ed25519 (sig), ECDSA P-256 (operator cert), AES-256-GCM (TLS), HKDF (key derivation). PQC migration plan tracked in ADR 0040 — deferred until Go stdlib ships hybrid X25519+ML-KEM-768 named group (per published roadmaps Q1–Q3 2027). FIPS 140-3 validated mode is ADR 0036; not shipped.

**Stage: Advanced.**

**Why not Optimal**: cryptographic agility is *partial* — the algorithm choices are sound but the build is not FIPS-validated (ADR 0036) and is not PQ-ready (ADR 0040). Least-privilege key management is real (Vault Transit + RBAC on PKI roles) but rotation cadence on the operator-cert root is 1y (long for Optimal's "enterprise-wide best practice" framing). FIPS shipping → Advanced becomes solid; PQC → starts approaching Optimal.

### 3.4 Function: Network resilience

**CISA stage criteria**:
- **Initial** — configure for availability for additional apps; expand resilience beyond mission-critical.
- **Advanced** — dynamic availability management for majority of apps.
- **Optimal** — holistic, proportionate resilience across all workloads.

**jess evidence**:
- Controller HA (replicas=2 + PDB + topology spread) is **scoped but not yet merged** (MR !798 noted as "in conflict" in ADR 0034 §"Open in roadmap"). Today the controller runs single-replica.
- Worker pods are stateless and horizontally scalable; Reloader bounces on cert/secret change.
- Postgres backend is CNPG (3-replica cluster). MinIO is single-tenant but with bucket replication off-cluster (per <gitops-bootstrap-repo> config).

**Stage: Initial.**

**Why not Advanced**: single-replica controller is a single point of failure. PDB + topology spread + leader election (the HA design from MR !798) need to ship before jess passes Advanced on this function.

### Networks pillar — overall: **Initial-leaning-Advanced**

Rationale: segmentation + traffic encryption are genuinely Advanced (Linkerd + Talon + EG layers, TLS-everywhere with mTLS at the broker, Vault PKI with short TTLs); but traffic management is Initial and network resilience is Initial (controller HA gap). Pillar score bounded by lowest meaningful function.

## 4. Applications & Workloads pillar

CISA's framing: enterprise systems, programs, services executing on-prem, on mobile, in cloud. Functions: Application Access, Application Threat Protections, Accessible Applications, Secure Application Development & Deployment Workflow, Application Security Testing.

### 4.1 Function: Application access

**CISA stage criteria**:
- **Initial** — authorize app access incorporating contextual info per request with expiration.
- **Advanced** — automated app access decisions with expanded contextual info enforcing least privilege.
- **Optimal** — continuously authorize app access using real-time risk analytics, behaviour, usage patterns.

**jess evidence**:
- jess is itself an *application* — operators access it via SPA (`jess.hexxlock.com`) or via `jessctl`. Access is gated by Talon credexchange (for SPA, ops-tier IAP) or by direct mTLS+OIDC at the operator port (for `jessctl`).
- The *resources* jess brokers (SSH/Postgres/RDP targets) get authorization via JIT grants (Phase 5b) which carry contextual info: subject, target, TTL, scope, optional ticket reference, optional approval chain.
- Per-request continuous re-auth at the IAP layer (Talon) — Talon verifies the JWT every request via Falcon-ID JWKS.
- Phase 5g-6 continuous grant verifier (10s tick) is the jess-internal continuous-authorization loop.

**Stage: Advanced.**

**Why not Optimal**: real-time risk analytics feedback into mid-session authorization isn't implemented at the application-access layer. CAEP push (Phase 5h-6) covers the IdP-driven side; in-session risk-score change doesn't yet re-evaluate the grant.

### 4.2 Function: Application threat protections

**CISA stage criteria**:
- **Initial** — threat protections in mission-critical app workflows for known threats.
- **Advanced** — threat protections in all app workflows for app-specific and targeted threats.
- **Optimal** — advanced threat protections with real-time visibility and content-aware protections.

**jess evidence**:
- Coraza WAF (OWASP CRS) sits in front of all customer-tier traffic at Envoy Gateway; sits in front of ops-tier traffic at Talon. jess SPA + admin port traffic passes Coraza on the way in (Phase 7.4.c step 5 v4 LIVE per cluster memory).
- jess's own input validation: typed JSON schemas on all controller HTTP endpoints; mTLS pins on admin port `:7103` (no auth bypass).
- No application-specific anomaly detection for jess (no UEBA over operator command patterns yet).

**Stage: Advanced.**

**Why not Optimal**: Coraza is in DetectionOnly mode in production per cluster memory (Phase 7.4.d step 2 mearax migration note). Until Coraza is in Block mode for all jess traffic AND content-aware payload inspection runs over the audit JSONL stream, this isn't Optimal.

### 4.3 Function: Accessible applications

**CISA stage criteria**:
- **Initial** — some mission-critical apps available over open public networks via brokered connections.
- **Advanced** — most mission-critical apps over public networks.
- **Optimal** — all applicable apps over public networks for authorized users + devices.

**jess evidence**:
- Phase 3 BeyondCorp L4: operator port `:7101` exposed on public IP `203.0.113.10:7101` as `jess.hexxlock.com`. Verified live 2026-05-29 from arbitrary internet (no VPN required).
- SPA reachable at `jess.hexxlock.com` (via Talon ops-tier IAP).
- Admin port `:7103` is *not* publicly exposed (intentionally — admin-tier access requires in-cluster).

**Stage: Advanced.**

**Why not Optimal**: admin port is intentionally not publicly accessible (a design choice that arguably *exceeds* CISA's framing — defense in depth). Operator-tier and SPA are publicly accessible without VPN. This is the BeyondCorp posture CISA's Optimal stage describes. Scored Advanced because not *all* jess endpoints are publicly available — admin remains in-cluster.

### 4.4 Function: Secure application development and deployment workflow

**CISA stage criteria**:
- **Initial** — formal CI/CD pipelines with least-privilege access controls.
- **Advanced** — distinct teams for dev/sec/ops; remove dev access to production deployment.
- **Optimal** — immutable workloads; remove admin access in favour of automated processes.

**jess evidence**:
- jess CI: GitLab pipelines (.gitlab-ci.yml) for build → unit test → integration test → image build → Cosign sign → Harbor push → image-updater bumps the GitOps repository → Argo reconciles → Reloader bounces pods.
- Image signing: Cosign with keyless signing via Falcon-ID OIDC token (Sigstore-style); signatures verified by image-updater + Argo image-verifier on pull.
- Image scanning: Trivy in CI pipeline + Harbor scanner on push. CVE-fail-on-HIGH gate in pipeline.
- Developer access to production: no direct kubectl apply allowed; all changes go through Atlantis (Terraform) or GitOps (Argo). Per cluster memory, atlantis-tf-runner has scoped Vault policy (Phase 5+ live).
- Immutable workloads: jess images are immutable (Cosign-signed digests); pods are immutable (no in-place patching). Helm chart deploys the same image+config every time.
- ServiceClientClaim Crossplane substrate auto-provisions jess's OIDC service client (Falcon-ID), so even the OIDC client config is declarative.

**Stage: Advanced — borderline Optimal.**

**Why not solid Optimal**: developer access to production is removed (good); admin access to deployment environments isn't fully automated away (operators can `kubectl exec` into jess pods with platform-admin Talon roles). Immutable workloads pattern is real for the image but Helm value overrides at deploy time provide a small admin-mediated surface. Closing this would require either OPA-gating all Helm overrides or moving to a pure-image-tag-bump-only deploy model.

### 4.5 Function: Application security testing

**CISA stage criteria**:
- **Initial** — SAST and DAST prior to deployment.
- **Advanced** — security testing integrated into dev pipeline with periodic DAST.
- **Optimal** — testing throughout SDLC with routine automated tests on deployed apps.

**jess evidence**:
- SAST: golangci-lint + staticcheck in CI; jess-specific lint rules (e.g., panic-on-error checks in worker code).
- DAST: no automated DAST against deployed jess today. ZAP scans against the SPA could be added.
- SBOM: per cluster memory, GitLab CI emits SPDX SBOMs (Microsoft SBOM tool).
- Dependency scanning: govulncheck in CI; renovate for module bumps.
- Integration tests run against ephemeral jess instances per PR (Phase 6 `jessctl up` substrate makes this trivial).

**Stage: Initial-leaning-Advanced.**

**Why not Advanced fully**: DAST gap. Periodic DAST against deployed jess (ZAP + a recorded auth flow) would close this. Routine automated testing on deployed apps (Optimal) requires production-traffic-replay or shadow-deploy infrastructure that's out of scope for this brokering layer.

### Applications & Workloads pillar — overall: **Advanced**

Rationale: app access + accessible apps + secure dev/deployment are all genuinely Advanced; threat protection is Advanced with Coraza-in-Detection caveat; app security testing is Initial-leaning-Advanced due to DAST gap. Pillar score Advanced (the access and deployment functions are the load-bearing ones for a broker).

## 5. Data pillar

CISA's framing: all structured and unstructured files and fragments resident in federal systems, devices, networks, apps, DBs, infra, backups, on-prem and virtual. Includes metadata. Functions: Data Inventory Management, Data Categorization, Data Availability, Data Access, Data Encryption.

### Scope note for jess

jess's "data" comprises:
- **Operational state** — Postgres tables `jit_grants`, `jit_requests`, `jit_sessions`, `jit_locks` and metadata in `jess` database.
- **Session recordings** — asciicast manifests + recording bundles in MinIO bucket `jess-recordings`. Per-session Ed25519 signature via Vault Transit (Phase 5e). Cross-session WORM hash chain (Phase 5e-16).
- **Audit event stream** — Phase 5e-15 JSONL export endpoint.
- **No PII handled by jess** — jess does not store customer data; operators are HexxLock staff; subjects are Falcon-ID IDs. Recording content can include sensitive operational data (passwords typed mid-session, query payloads), so recordings are *confidentiality-sensitive* but not PII per se.

### 5.1 Function: Data inventory management

**CISA stage criteria**:
- **Initial** — automate data inventory for both on-prem and cloud, covering most data.
- **Advanced** — automate inventory enterprise-wide, covering all applicable data, with DLP based on static attrs or labels.
- **Optimal** — continuous inventory + dynamic DLP that blocks suspected exfiltration.

**jess evidence**:
- jess has a *bounded* and *known* inventory: 4 Postgres tables + 1 MinIO bucket + audit-event JSONL stream. The schema is declared in migration files; the bucket is declared in Terraform; the JSONL export endpoint is declared in the controller.
- No DLP per se (jess doesn't classify outbound payloads).

**Stage: Initial.**

**Why not Advanced**: inventory is *known* but not *automated and continuously discovered* — it's known because the surface is small and declared. If a new data category appears, it'd be added by code change. No automated discovery scan over the MinIO bucket detects, e.g., unexpected content types. For a broker with a small fixed surface, this is arguably fine (the inventory IS small and complete); CISA's framing assumes a larger discovery problem.

### 5.2 Function: Data categorization

**CISA stage criteria**:
- **Initial** — defined labels with manual enforcement.
- **Advanced** — automated categorization in consistent, tiered, targeted manner.
- **Optimal** — automated enterprise-wide with granular formats and mechanisms for all data types.

**jess evidence**:
- Recording bundles carry implicit category: "operator session recording, confidentiality-sensitive". No formal sensitivity label is attached.
- Audit JSONL events are not labelled by sensitivity.
- Postgres tables: no row-level classification.

**Stage: Initial — bordering Traditional.**

**Why**: no formal labeling pipeline. The whole jess data corpus is treated uniformly as "broker-internal, confidentiality-sensitive". This is honest — jess's data is *all* the same category, so a labeling system would be over-engineered. But measured against CISA's framing, this is Initial.

### 5.3 Function: Data availability

**CISA stage criteria**:
- **Initial** — some data from redundant HA stores; off-site backups.
- **Advanced** — primarily from redundant HA stores; historical access.
- **Optimal** — dynamic optimization of availability per user/entity need.

**jess evidence**:
- Postgres: CNPG 3-replica cluster with WAL backup to S3 (HexxLock infra standard).
- MinIO recording bucket: replicated off-cluster (per <gitops-bootstrap-repo> config).
- Recording bundles are immutable (WORM) and historical access via the SPA's session-playback UI is unlimited (Phase 5e-2..20).
- Audit JSONL export is on-demand from the controller; history bounded by Postgres retention (currently 1y).

**Stage: Advanced.**

**Why not Optimal**: availability is HA and historical, but not *dynamically* optimized per user need. Operators can pull any historical session; there's no automatic tiering of hot/cold recordings based on access patterns. For a broker, this is appropriate-by-design.

### 5.4 Function: Data access

**CISA stage criteria**:
- **Initial** — automated access controls with elements of least privilege.
- **Advanced** — automated controls considering identity, device risk, app, data category, time-limited.
- **Optimal** — JIT/JEA enterprise-wide with continuous permission review.

**jess evidence**:
- Postgres access: Vault dynamic creds (`v-kubernet-jess-pg-*`), per-grant ephemeral user, TTL = grant TTL.
- MinIO bucket access: signed URLs via Vault for SPA recording playback; the jess controller is the only persistent IAM role with write access to `jess-recordings`.
- Admin API access (read/manage grants, sessions): Talon credexchange + admin Falcon-ID JWT + mTLS to admin port `:7103`.
- Audit JSONL endpoint: admin-tier only, mTLS + JWT.
- Continuous review: grants have TTL (auto-expire); no automated access-review cadence over the *admin role assignments* themselves (that's Falcon-ID's job via SCIM + access-review tooling, not jess).

**Stage: Advanced.**

**Why not Optimal**: JIT is real for *target access* (the resources jess brokers TO); not for jess's own data (recordings, audit). An operator with the right grant can pull any historical recording in scope — there's no "JIT recording access". For the audit pillar this is arguably right (auditors must have free read), but it's still measured Advanced against CISA's Optimal framing.

### 5.5 Function: Data encryption

**CISA stage criteria**:
- **Initial** — encrypt all data in transit; encrypt data at rest where feasible; formalise key management.
- **Advanced** — encrypt all at rest and in transit; cryptographic agility; protect keys (no hardcoded secrets, regular rotation).
- **Optimal** — encrypt data in use where appropriate; enforce least-privilege key management enterprise-wide; cryptographic agility.

**jess evidence**:
- In transit: TLS 1.3 everywhere (covered in §3.3).
- At rest:
  - Postgres: at-rest encryption via underlying storage class (LUKS); CNPG manages keys via K8s Secret.
  - MinIO recording bucket: SSE-C with Vault-Transit-derived per-object keys.
  - Vault: Transit engine for signature operations; root key sealed by auto-unseal (Transit auto-unseal against the platform-shared Vault).
- Keys not hardcoded — every secret is in Vault, fetched via ESO (External Secrets Operator) into K8s Secrets, mounted into pods. Reloader bounces pods on Secret change.
- Rotation cadence: operator-cert role TTL 8h; SSH cert TTL 15min; Vault Transit signing keys rotated quarterly per platform policy.
- Data in use: not encrypted (memory is plaintext during session brokering — this is standard).

**Stage: Advanced.**

**Why not Optimal**: data-in-use encryption (memory enclaves, e.g. SGX / SEV-SNP) is not implemented and is out-of-scope for a Go-based broker today. PQC (ADR 0040) and FIPS 140-3 (ADR 0036) are gaps blocking the cryptographic-agility-and-validated-modules box from being fully ticked.

### Data pillar — overall: **Advanced for recording integrity; Initial for classification**

Rationale: recording integrity (cross-session hash chain + per-session Ed25519 sig via Vault Transit — Phase 5e-16) is *industry-leading* (per ADR 0034 §3 Synthesis: ahead of Boundary BSR, Teleport, and Guacamole on this axis). Encryption and access controls are Advanced. Classification is Initial because there's no labeling pipeline (and arguably none needed for a bounded broker data surface). Availability is Advanced. The pillar's lowest meaningfully-applicable function is data categorization at Initial; the highest is recording integrity at borderline Optimal. Overall pillar score: **Advanced**, with explicit caveat that data categorization is Initial.

## 6. Visibility & Analytics (cross-cutter)

**CISA stage criteria**:
- **Initial** — collect activity logs; routine manual + some automated analysis; limited cross-log correlation.
- **Advanced** — automated analysis across some log types; augmented collection to address gaps.
- **Optimal** — comprehensive enterprise-wide visibility + behaviour-based analytics.

**jess evidence**:
- **Audit event export** (Phase 5e-15): JSONL endpoint emits every state-changing event with subject, target, action, timestamp, ticket-ref. Suitable for SIEM ingestion.
- **Prometheus metrics**: `jess_*` namespace — request totals, OIDC handshake outcomes, session-open SLO histogram (Phase 5g-5), session outcome counters, grant-tick rate, CRL refresh counters, CAEP event counters. Per cluster memory, the upstream pattern for these counters is wired correctly (commit 94bd0b8 fix).
- **Cross-session WORM chain** (Phase 5e-16): tamper-evident hash chain spanning all session recordings for a given controller pod. Verified via the Phase 5e-14 tamper-evidence verifier.
- **Per-session signing** (Phase 5e): Ed25519 sig via Vault Transit on every recording bundle.
- **Session-playback in browser** (Phase 5e-18 + asciinema-player): operators (admins) can replay any historical session.
- **Manifest↔session link** (per Phase 5e-20): every recording manifest references its session-id in `jit_sessions`; bidirectional traversal.

**Stage: Advanced.**

**Why not Optimal**: jess emits all the signals; consuming them into a SIEM with cross-source behaviour-based analytics is *external to jess*. Optimal would require either (a) jess shipping its own behaviour-based analytics layer (unwarranted scope creep), or (b) integration into a SIEM that runs UEBA over the JSONL stream (out of jess's hands; that's the SOC's pillar). The jess substrate is Advanced; the SIEM-side completion is what would move the whole stack to Optimal.

## 7. Automation & Orchestration (cross-cutter)

**CISA stage criteria**:
- **Initial** — some automation; resources have defined lifetimes.
- **Advanced** — automated change management (CI/CD); response and enforcement against perceived risks.
- **Optimal** — infrastructure-as-code with automated change management and lifecycle alignment.

**jess evidence**:
- **CI/CD**: GitLab pipelines for jess + automated image-updater + Argo reconcile + Reloader bounce → fully automated deploy.
- **Phase 5g-6 continuous grant verifier**: 10s tick over `jit_grants` table; kills any live session whose grant is revoked or expired.
- **Phase 5h-6 CAEP subscriber**: consumes IdP-pushed session-revoke events.
- **Phase 4 full CRL refresh**: 5min poll of `/v1/jess-ca/crl/pem`; `VerifyPeerCertificate` hook on both operator + admin ports rejects revoked certs (TLS alert 42 `bad_certificate`). Verified live 2026-06-02.
- **Crossplane**: ServiceClientClaim for jess's OIDC client; ESO for secret hydration; Kyverno auto-bump policy (per cluster memory) for ServiceClientClaim rotationGeneration.
- **No SOAR-style playbooks**: jess does not currently execute multi-step automated response (e.g., "on CAEP push from IdP, also rotate the operator cert + notify admin + open a ticket"). The response is single-action: kill the session.

**Stage: Advanced.**

**Why not Optimal**: SOAR-style automated response playbooks would close the gap. Today jess's response model is "kill session on revoke"; a richer model would chain into operator-cert revocation + ticket creation + admin escalation. Also, infrastructure-as-code is partial for jess specifically — Helm chart values are declarative but not every operational knob (e.g. log levels) is GitOps-managed.

## 8. Governance (cross-cutter)

**CISA stage criteria**:
- **Initial** — defined policies; minimal automation; manual updates.
- **Advanced** — policies enforced enterprise-wide with automation and periodic updates.
- **Optimal** — full automation with continuous enforcement and dynamic updates.

**jess evidence**:
- **ADR catalogue**: ADR 0030–0040 in `/docs/adr/`. ADRs 0030 (catalog), 0033 (RDP), 0034 (Tier-1 enhancements catalog), 0035 (HW keys), 0036 (FIPS), 0037 (MFA step-up), 0038 (SPIRE), 0039 (ingress worker filtering), 0040 (PQC).
- **Vault policy-as-code**: HCL policies for jess service account; PKI role definitions in Terraform.
- **Crossplane Composition**: serviceclient-falcon-id Composition for jess OIDC client provisioning.
- **GitOps**: every jess deployment is declarative (Helm chart values + Argo Application).
- **Kyverno**: policies covering ServiceClientClaim auto-bump (per cluster memory).
- **Approval workflow** (Phase 5b): JIT grants pass through `jit_requests` with admin approval gating; approval is auditable.
- **No formal access-review cadence** for jess-itself: who has admin Falcon-ID role over jess is reviewed at the IdP, not by a jess-internal scheduled access review.
- **No formal policy-review cadence**: ADRs are written when needed (event-driven), not on a scheduled review interval.

**Stage: Initial-leaning-Advanced.**

**Why**: policy-as-code is real (Vault HCL, K8s manifests, ADRs); enforcement is automated (Crossplane, Argo, Kyverno). Gap to Advanced: formal review cadence (quarterly ADR review? annual policy review?). Gap to Optimal: continuous dynamic policy updates driven by automated risk feedback (e.g., auto-tightening grant TTLs based on observed risk).

## 9. Summary scoring table

| # | Pillar / Cross-cutter | Stage | Confidence | Key gap to next stage |
|---|---|---|---|---|
| 1 | **Identity** | Advanced | High | Per-session MFA step-up at broker (ADR 0037); per-action JIT; mid-session risk re-eval |
| 2 | **Devices** | Initial-leaning-Advanced | Medium | Bounded by what's in-scope for a broker; device-posture-contract maturity (ADR 0034 open Q) |
| 3 | **Networks** | Initial-leaning-Advanced | Medium | Controller HA (MR !798); dynamic risk-aware traffic management |
| 4 | **Applications & Workloads** | Advanced | High | DAST automation; Coraza in Block mode for all jess traffic |
| 5 | **Data** | Advanced (recording integrity industry-leading; classification Initial) | High | Formal data labeling; data-in-use encryption (out-of-scope?) |
| 6 | **Visibility & Analytics** | Advanced | High | SIEM-side UEBA integration (external to jess) |
| 7 | **Automation & Orchestration** | Advanced | High | SOAR playbooks; richer multi-step automated response |
| 8 | **Governance** | Initial-leaning-Advanced | Medium | Formal policy-review and access-review cadence |

**Composite jess stage: Advanced** (with explicit Initial-leaning-Advanced bands on Devices, Networks, Governance, and Initial on the Data-categorization sub-function).

## 10. Gap-to-Optimal roadmap

Concrete deltas required to reach Optimal on each pillar. Effort labels: **S** = single-week, **M** = multi-week, **L** = multi-month.

### 10.1 Identity → Optimal

1. **Per-session MFA step-up at the broker** (ADR 0037). WebAuthn/PIV challenge at every session-open; mid-session step-up triggered by OPA risk-score drift. **Effort: M.**
2. **Per-action JIT** for high-sensitivity targets. E.g., for Postgres, gate per-query via a SQL-firewall middleware; for SSH, optional per-command approval mode. **Effort: L.**
3. **Continuous mid-session risk re-evaluation**. OPA `data.jess.risk` evaluated against streaming session telemetry (keystroke timing, command pattern, query rate). Feeds into step-up MFA challenge or session kill. **Effort: L.**

### 10.2 Devices → Optimal

This pillar is largely out-of-scope for jess as a broker. The Optimal-tier delta is *enterprise* — MDM + EDR + continuous device-posture telemetry. jess's contribution would be:

1. **Richer device-posture contract**. Resolve open Q from ADR 0034 §Device-posture contract semantics. Define poll-vs-push, freshness budget, hard/soft fail. **Effort: M (research + design + impl).**
2. **Device-attestation at session open**. Beyond `devicepolicy.Verdict` (an opaque verdict), consume an attestation payload (TPM quote, MDM compliance report, EDR posture) and surface it in the audit event. **Effort: M.**

### 10.3 Networks → Optimal

1. **Controller HA** (MR !798). 2-replica + PDB + topology spread + leader election. **Effort: S — already designed.**
2. **FIPS 140-3 validated build** (ADR 0036). Go `GODEBUG=fips140=on` + boringssl + Vault PKI in FIPS mode + CI matrix. **Effort: M.**
3. **PQC hybrid TLS** (ADR 0040). Adopt X25519+ML-KEM-768 named group when Go stdlib ships it (Q1–Q3 2027). **Effort: S — planning today; implementation deferred.**
4. **Dynamic mid-session network policy** — arguably wrong design for a broker; deferred unless a regulatory driver appears.

### 10.4 Applications & Workloads → Optimal

1. **Coraza WAF in Block mode** for all jess hostnames. Currently DetectionOnly per cluster memory. **Effort: S — flip after tuning the false-positive baseline.**
2. **DAST in CI** — ZAP scan with recorded auth flow against ephemeral jess instance per PR. **Effort: S.**
3. **Routine production DAST** — schedule a weekly ZAP run against staging jess. **Effort: S.**
4. **OPA-gate all Helm deploy-time overrides** — eliminate the small admin-mediated surface in production deploys. **Effort: M.**

### 10.5 Data → Optimal

1. **Formal data classification pipeline**. Define labels for jess data (e.g., `recording-confidential`, `audit-event-internal`, `grant-metadata`), attach labels at write-time, surface in audit events. **Effort: S, low-leverage** — jess's data is uniform; this is largely cosmetic.
2. **Data-in-use encryption** — would require running jess in a TEE (SGX / SEV-SNP). Not practical for a Go binary today; deferred indefinitely.
3. **JIT recording access** — gate historical recording playback behind a per-recording approval. **Effort: M.**

### 10.6 Visibility & Analytics → Optimal

1. **SIEM integration** (external to jess). Hook the audit JSONL export into the platform SIEM; build UEBA rules over operator-command patterns, session-open rate, recording-access rate. **Effort: M, mostly SIEM-side.**
2. **Tamper-evidence dashboard** in the jess SPA (Phase 5e-18 substrate exists; needs SPA polish per ADR 0034 §Decisions #8). **Effort: S.**

### 10.7 Automation & Orchestration → Optimal

1. **SOAR playbooks**. On CAEP push, chain: revoke session + rotate operator cert + notify admin + open ticket. **Effort: M.**
2. **Auto-tightening grant TTLs** driven by observed risk. **Effort: M.**
3. **Image-updater + Argo for all config knobs** — close the gap on operational knobs that are still values-overrides. **Effort: S.**

### 10.8 Governance → Optimal

1. **Quarterly ADR review cadence** — formal calendar event; outcome posted to a governance log. **Effort: S.**
2. **Annual policy review** — review Vault policies, K8s RBAC for jess SA, Falcon-ID role assignments over jess. **Effort: S, annual.**
3. **Access review automation for admin role over jess** — feeds into Falcon-ID's SCIM access-review system. **Effort: M.**

## 11. ADR cross-reference

How ADRs 0030–0040 advance each pillar:

| ADR | Pillar(s) advanced | Stage delta |
|---|---|---|
| **0030** — Phase 7 dynamic catalog | Devices (target inventory); Apps (accessible applications) | Already shipped; underpins current Advanced scores |
| **0033** — Phase 5f Rust IronRDP bridge | Apps (accessible applications); Data (recording integrity for RDP) | When 5f-8b completes, browser-RDP joins the brokered-protocol set at parity with Cloudflare/Teleport |
| **0034** — Tier-1 ZTNA/PAM catalog | All pillars (informational; spawns 0035–0040) | Source-of-truth; this ZTMM mapping is one of the §Decisions follow-ups |
| **0035** — Hardware-bound operator keys | Identity (Authentication → Optimal); Devices (resource access) | Closes Teleport-parity gap; phishing-resistance becomes hardware-rooted |
| **0036** — FIPS 140-3 mode | Networks (Traffic encryption → Optimal); Data (Encryption → Optimal) | Federal-tier compliance unlock |
| **0037** — Per-session MFA step-up | Identity (Authentication → Optimal; Access management → Optimal) | Closes OMB M-22-09 "MFA at application layer" gap |
| **0038** — SPIRE worker mTLS | Networks (Segmentation → Optimal); Apps (App access at workload-to-workload layer) | Replaces file-mount JWT with SVID; industry-norm workload identity |
| **0039** — Ingress worker filtering | Networks (Segmentation; Traffic management → Advanced) | Boundary HCP-only feature in OSS; per-source-IP / per-region worker selection |
| **0040** — PQC migration plan | Networks (Traffic encryption); Data (Encryption) | Planning ADR; no code today; tracks NIST IR 8547 deadlines (2030 PQ-encryption, 2035 PQ-signatures) |

**Pillar coverage**:
- **Identity**: ADR 0035, 0037 — Optimal in sight once both ship.
- **Devices**: minimal jess-side ADRs; broker is not the right layer.
- **Networks**: ADR 0036, 0038, 0039, 0040 — broadest ADR coverage; Optimal achievable in 12–18mo if all four ship.
- **Apps & Workloads**: ADR 0033 (RDP completion); 0035 (hardware keys at app-access layer).
- **Data**: ADR 0036, 0040 (encryption modernization); recording-integrity pillar already industry-leading per ADR 0034 §3 synthesis.
- **Visibility & Analytics**: no ADR; SIEM-side gap is enterprise SOC's pillar.
- **Automation & Orchestration**: no ADR; incremental work.
- **Governance**: this mapping document itself contributes; cadence formalisation is a process change, not an ADR.

## 12. Open questions

1. **Should jess be assessed as a *system* or as a *component within HexxLock*?** This document scores jess-as-component. A whole-HexxLock ZTMM mapping (combining jess + Falcon-ID + Talon + EG + MDM + EDR + SIEM) would score higher on Devices and Visibility & Analytics where jess-alone is bounded.
2. **Is "Optimal" the right target?** CISA's Optimal is calibrated for federal agencies. For a private-sector single-tenant broker, Advanced may be the cost-effective ceiling. ADR 0034 §Decisions priorities are the practical floor; Optimal-tier work beyond that should be cost-justified.
3. **Should ADR 0040 (PQC) be Tier-1 priority?** Today scored Advanced on cryptographic agility because Ed25519 + ECDSA + AES-GCM are sound choices. PQC is *forward-looking* protection (harvest-now-decrypt-later threats against today's recordings). Federal deadlines (CNSA 2.0, NIST IR 8547) suggest priority increase in the next 12–24 months.
4. **What's the formal review cadence for this mapping?** Recommend annual re-assessment, aligned with ADR review.

## 13. References

- CISA, *Zero Trust Maturity Model Version 2.0*, April 2023. TLP:CLEAR. (Primary source.)
- Microsoft Learn, *Configure Microsoft cloud services for the CISA Zero Trust Maturity Model* — per-pillar pages on learn.microsoft.com reproduce CISA's stage descriptions verbatim before adding Microsoft-product guidance. Used here to source stage criteria when the CISA PDF was unreachable.
- NIST SP 800-207, *Zero Trust Architecture* — referenced by CISA ZTMM; jess's NIST 800-207 mapping is in ADR 0034 §2.
- OMB M-22-09, *Moving the U.S. Government Toward Zero Trust Cybersecurity Principles* — referenced for MFA-at-application-layer requirement.
- jess ADR 0030 — Phase 7 dynamic catalog (substrate context).
- jess ADR 0034 — Tier-1 ZTNA/PAM enhancements catalog (this mapping is the §Pending-research item B follow-up).
- jess ADRs 0035–0040 — gap-closing enhancements; see §11 above.
- jess source: `/internal/spine`, `/internal/admin`, `/internal/risk`, `/internal/devicepolicy`, `/internal/recording` (relative to jess repo root).
