# SOC 2 Common Criteria CC6 — Logical & Physical Access Controls — jess Mapping

| | |
|---|---|
| **Document type** | Compliance control mapping (not an ADR) |
| **Date** | 2026-06-03 |
| **Scope** | The **jess access broker** only — `cmd/jess-controller`, `cmd/jess-worker`, `cmd/jessctl`, `cmd/jess-web`, and the supporting `internal/*` packages in this repository. **Out of scope**: the wider HexxLock platform (Falcon-ID, Talon, Vault, Harbor, Linkerd, Argo CD, etc.). Those systems carry their own SOC 2 mappings; this document only addresses controls *as they apply to jess as a single auditable subsystem* and notes the platform dependencies it relies on. |
| **Authoritative source** | AICPA Trust Services Criteria 2017, with the 2022 revision of Points of Focus. Criterion text for CC6.1–CC6.8 was verified against published AICPA criterion language; see *References* at the bottom. |
| **Status** | **DRAFT** — internal self-attestation pending an external SOC 2 Type I readiness assessment. Not a SOC 2 report; not an opinion of an independent auditor. |
| **Owner** | jess maintainers (`@platform/jess`) |
| **Review cadence** | Each ADR landing for Phases 5j-*, 5h-*, and 5g-* must update the relevant control row in the summary table at §8. |

---

## 1. How to read this document

Each section maps one CC6 criterion onto jess in four parts:

1. **Control text** — the AICPA criterion sentence, paraphrased to one or two sentences. The verbatim AICPA wording is in *References* so this document can be read on its own.
2. **jess implementation** — which jess phase(s), files, packages, and where applicable commits satisfy the control. Where coverage is partial, the partial is stated explicitly rather than glossed over.
3. **Evidence types** — what an auditor would inspect (logs, screenshots, configs, code paths) to confirm the control is operating.
4. **Status** — one of *Met / Partial / Not Met*. "Partial" means the design is in place but a named gap remains; "Not Met" means there is no implementation today. Every Partial or Not Met has a corresponding gap and remediation ADR.

Phase numbering follows the jess phase taxonomy used across the ADRs (Phase 4 = PKI / mTLS, Phase 5a–5j = the post-OIDC operator-broker lanes, Phase 7 = dynamic catalog, etc.). The phase inventory baseline this document maps against is the "shipped inventory" table in **ADR 0034 (Tier-1 ZTNA Enhancements)** at `docs/adr/0034-tier-1-ztna-enhancements.md` and the per-phase implementation ADRs 0035–0040.

Code references are repository-relative paths from the root of `services/jess` (i.e. `internal/pdp/pdp.go` resolves to `<repo>/internal/pdp/pdp.go`).

---

## 2. CC6.1 — Logical access security software, infrastructure, and architectures

**Control text.** The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. For jess, "protected information assets" are the target systems brokered by jess — production Postgres clusters, MySQL clusters, SSH endpoints, Windows RDP endpoints, kubectl cluster control planes, and the audit chain itself.

**jess implementation.**

- **Identity at the front door (Phase 5 substrate).** Every operator session begins with a Falcon-ID OIDC bearer token verified at the jess-controller operator port `:7101`. Verification logic lives in `internal/pdp/verify.go` and the controller wires the verifier in `cmd/jess-controller/main.go`. No anonymous code path exists on `:7101`; an unauthenticated request is rejected before any policy decision is made.
- **Network-layer IAP (platform dependency).** All `internal.example.com` admin hostnames sit behind Talon, the platform's identity-aware proxy. Talon enforces CVE-2021-21378-class invariants (unknown issuer ⇒ 401, never passthrough) at the Envoy data plane before traffic reaches the jess-controller. This is not jess code, but it is a *named* prerequisite — an auditor should request Talon's CC6.1 evidence separately and link it to jess sessions by issuer/subject claim correlation.
- **mTLS device binding (Phase 4 — full).** Operator-facing mTLS uses a dual-CA scheme codified in Phase 4 (commit `046c305 — Phase 4 full — CRL enforcement at mTLS layer`, with prior `7063030 — Phase 4 lite — operator-cert revoke surface`). Operator device certificates are minted from Vault PKI (`pki_int_operators`) and presented at TLS handshake against the controller's admin port; the broker rejects sessions whose presented client certificate is not chained to a known operator CA *or* whose serial appears on the refreshed CRL.
- **Worker mTLS (yamux).** Worker ↔ controller traffic rides a mutually authenticated TLS tunnel multiplexed with `hashicorp/yamux`. Worker identity is bound to a per-worker Vault-issued certificate; admission of new workers to the control plane is gated on a controller-side allowlist plus mTLS chain verification.
- **Per-target authorization (Phase 5j-1).** Beyond authentication, jess performs a per-session authorization decision in `internal/pdp/pdp.go` (`RoleAuthorizer`). Each `JessTarget` declares `spec.requiredRoles`; the operator's Falcon-ID `roles` claim is checked against the target's required role set. Phase 5j-1 adds the **lock primitive** that allows a target to be marked locked (read-only) without a deploy.
- **Catalog as inventory (Phase 7 — shipped).** The set of protected assets jess fronts is itself an asset registry. The discovery providers in `internal/catalog/providers/{kubernetes,proxmox,jesstargetcrd}` keep the live catalog reconciled with the underlying inventory; the `JessTarget` CRD (Phase 7e) is the durable record of every brokered target.

**Evidence types.**

- jess-controller structured logs of `session.open` and `session.authn` events, including verified `sub`, `iss`, `aud`, presented certificate fingerprint, and the resolved `target_id`.
- Prometheus counter `jess_authz_decisions_total{result="allow|deny"}` (defined in `internal/metrics/metrics.go`) and the histogram `jess_session_open_duration_seconds`.
- Falcon-ID audit log entries for the token mint, correlated to jess audit chain rows by `(sub, jti, target_id, requested_at)` tuple.
- Vault audit-device entries for operator-cert issuance from `pki_int_operators`.
- The JessTarget CRD inventory (`kubectl get jesstargets -A -o yaml`), demonstrating the closed-world set of brokered assets.
- A live demonstration: an auditor presents an unauthenticated request and observes a 401 with `jess_session_open_outcome_total{result="authn"}` incrementing.

**Status.** **Met.**

**Gaps + remediation.**

- **Per-session MFA step-up not yet shipped.** The `JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR` env (at `cmd/jess-controller/main.go:182`) gates *admin-direct-connect* on the token's stamped `amr` claim, but does not re-prove user presence at session-open for the general operator population. Without step-up, a token unlocked with WebAuthn at 09:00 can open a Postgres session at 16:55 with no fresh presence proof. Scoped to **ADR 0037 — Phase 5j-3 per-session MFA step-up at the broker** (`docs/adr/0037-per-session-mfa-step-up.md`); implementation deferred to a dedicated 5j-3 sprint. Status downgrade to Partial is *not* asserted because CC6.1 is about logical access *security implementation*, which jess does have today; step-up is a CC6.6-adjacent strengthening that the AICPA criterion language does not strictly require.

---

## 3. CC6.2 — Registration and authorization of new users; removal of access

**Control text.** Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity, and removes access when no longer required. This is the criterion where jess is **strongest** — multiple independent kill-paths converge on the same audit chain.

**jess implementation.**

- **JIT grant TTL (Phase 5b).** Operator access to any brokered target is gated on a Just-In-Time grant recorded in `internal/jit/{grant,session,requests,memory,postgres}.go`. SSH session certificates issued from Vault SSH-CA are scoped to **15 minutes** by default; the grant itself has a hard cap of **8 hours** regardless of operator activity. No long-lived ambient credentials exist.
- **Approval workflow (Phase 5b).** `internal/jit/requests.go` implements the request → approve flow. A request row's `decided_by` field is enforced ≠ `subject` at write time; approvers cannot approve their own requests. The grant row records `(subject, approver, target_id, scopes, expires_at, decision_reason)`.
- **Continuous grant verifier (Phase 5g-6).** A background reconciler in the controller polls live grants against the Falcon-ID grant table and against the JessTarget CRD; if a grant has been revoked, expired, or its target removed, the verifier closes any active session held under that grant. Counter: `jess_session_revocations_total{reason="grant_revoked|grant_expired|target_removed"}`.
- **CAEP subscriber for IdP-pushed revocation (Phase 5h-6).** `internal/caep/{subscriber,token_file}.go` subscribes to Falcon-ID's Continuous Access Evaluation Profile (CAEP) stream and reacts to `session-revoked`, `credential-change`, and `token-claims-change` events in near-real-time (median sub-second). Counters: `jess_caep_events_received_total`, `jess_caep_grants_revoked_total`, `jess_caep_reconnects_total`, `jess_caep_subscribe_failures_total`.
- **CRL enforcement at TLS handshake (Phase 4 — full).** Operator-cert revocation is enforced at the mTLS handshake itself. The `VerifyConnection` callback in the controller's admin TLS config refuses a chained certificate whose serial is on the current CRL pulled from Vault. CRL refresh cadence and revoked count are observable via `jess_operator_cert_crl_refreshes_total`, `jess_operator_cert_crl_last_refresh_timestamp_seconds`, and `jess_operator_cert_crl_revoked_count`.
- **Lock primitive (Phase 5j-1).** A `JessTarget` can be flipped to `spec.locked: true`, which causes session-open to deny with `jit` outcome for *all* operators regardless of grant. This is the fastest emergency kill switch for a single target — no Falcon-ID round-trip required.

**Evidence types.**

- Audit-chain entries with `action ∈ {grant_create, grant_decide, grant_revoke, session_open, session_close}` from `internal/audit/audit.go`. The audit chain is a hash-linked append-only stream stored in Postgres (`jit_chain` table) and the chain head is published as `jess_chain_intact` / `jess_chain_breaks_total` / `jess_chain_total_rows`.
- `jit_requests` rows showing `decided_by ≠ subject` for every approved request (segregation-of-duties evidence).
- Counter time-series: `jess_session_revocations_total` (per reason), `jess_caep_grants_revoked_total` (per event type), `jess_operator_cert_revocation_checks_total`.
- The Vault CRL (`vault read pki_int_operators/cert/crl`) and its revoked-serial list.
- A demonstration scenario: auditor revokes a test operator's Falcon-ID session, observes a CAEP event arriving at jess within seconds, then observes any open jess session held by that operator closing, with corresponding audit row `action=session_revoked` and counter increment.

**Status.** **Met** — multiple independent kill-paths exist (TTL expiry, continuous verifier polling, CAEP push, CRL at handshake, JessTarget lock). The defence is in depth and an auditor can sever access at any layer independently.

**Gaps + remediation.**

- None at the criterion level. **One operational note for the auditor**: the median CAEP propagation latency is monitored but does not have a hard SLO; if a SOC 2 auditor requires a maximum revocation latency commitment (e.g. "≤ N seconds"), that SLO should be added to the controller's `/metrics` SLO dashboard and tracked separately — this is not a code gap but an attestation gap.

---

## 4. CC6.3 — Role-based access, least privilege, segregation of duties

**Control text.** The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties.

**jess implementation.**

- **RBAC core (Phase 5j-1).** The Policy Decision Point is `internal/pdp/pdp.go`. `RoleAuthorizer.Decide(ctx, claims, target)` consults `target.spec.requiredRoles` against the operator's verified Falcon-ID `roles` claim. The role set is Falcon-ID-managed; canonical roles include `platform_admin`, `iam_admin`, `db_operator`, `sre_oncall`, etc.
- **Target catalog as policy substrate.** Each `JessTarget` carries its own `requiredRoles`. The catalog therefore is the policy — every target's required role set is reviewable as a Kubernetes resource (`kubectl get jesstargets -o jsonpath='{.items[*].spec.requiredRoles}'`).
- **Risk-score gate for elevated targets (Phase 5h-4a / 5h-4b).** Targets flagged "elevated" route through `internal/riskscore/{riskscore,opa}.go`, which calls an OPA-backed PDP (`data.jess.risk.allow`) with `(operator_sub, target_id, claims, device_posture)` as input. Risk score must exceed the target's `spec.riskThreshold` for the session to open. This is least-privilege enforcement at a finer grain than role membership alone.
- **Approval segregation (Phase 5b).** As noted in §3, `internal/jit/requests.go` rejects self-approval at the storage layer (`decided_by ≠ subject`). The audit chain entry for `action=grant_decide` always records both `subject` and `decided_by`, allowing an auditor to scan for any anomalies.
- **Admin vs operator port separation.** jess-controller listens on `:7101` (operator) and a separate admin port; the admin port requires the additional admin-tier role and has its own mTLS material. An operator cannot reach the admin surface via the operator port even with a valid token.

**Evidence types.**

- Falcon-ID role assignment export for the SOC 2 period (`SELECT subject, role, granted_at, granted_by FROM iam_role_grants WHERE …`).
- `JessTarget` catalog dump showing `requiredRoles` per target.
- `jit_requests` table query: `SELECT count(*) FROM jit_requests WHERE decided_by = subject` — must be zero.
- A walkthrough of the OPA policy (`data.jess.risk`) and a sample evaluation trace.
- Live demonstration: auditor logs in as a `db_operator`, attempts to open an admin-tier target, observes deny with `jess_session_open_outcome_total{result="authz"}` increment.

**Status.** **Met.**

**Gaps + remediation.**

- **Explicit segregation-of-duties policy documentation is informal.** The enforcement is correct in code, but the *human-readable policy statement* — "an operator may request grants for their own role's targets; no operator may approve their own request" — lives only in this mapping document and in the source of `internal/jit/requests.go`. For SOC 2, this should be promoted to a section of `docs/DESIGN.md` and cross-referenced from this row. Scoped to a **DESIGN.md edit** (not its own ADR; trivial documentation lift). No code change required.

---

## 5. CC6.6 — Logical access security against external threats

**Control text.** The entity implements logical access security measures to protect against threats from sources outside its system boundaries. For jess, the "system boundary" is the controller's listening ports plus the worker control-plane fabric; threats include unauthenticated probes, replayed tokens, posture-failing devices, and credential-stuffing attempts.

**jess implementation.**

- **Default-deny at every gate.** The controller's session-open path is a series of gates each of which can deny, and *every* deny emits a structured audit entry plus a metric increment. Gates in order: (1) TLS handshake (CRL + chain), (2) bearer-token verify (`internal/pdp/verify.go`), (3) device posture (`internal/devicepolicy/devicepolicy.go`), (4) risk-score (`internal/riskscore/opa.go`), (5) JIT grant existence, (6) target required-role check, (7) JessTarget lock check.
- **Device-posture wall (Phase 5h-5).** `internal/devicepolicy/devicepolicy.go` enforces a posture verdict from the platform device-attestation system. Non-compliant device ⇒ session open denied with `jess_session_device_claim_denies_total{reason="…"}` increment. Posture signals include OS version, disk-encryption status, EDR-running flag, and device-cert chain to the corporate Device CA.
- **Risk-score gate (Phase 5h-4a / 5h-4b).** OPA-backed continuous evaluation as in §4; this also covers CC6.6 because elevated risk score is itself an external-threat signal (anomalous geolocation, impossible travel, new device).
- **Full CRL enforcement at TLS (Phase 4).** Already covered in §3; the relevance to CC6.6 is that a stolen-but-revoked operator certificate cannot be replayed against the broker.
- **Rate limiting and brute-force resistance.** The Falcon-ID token verifier rejects malformed tokens cheaply (no DB lookup); replays are bounded by Falcon-ID's `jti` cache. Sustained brute-force attempts surface as `jess_session_open_outcome_total{result="authn"}` spikes.
- **Audit chain visibility of denies.** Every deny — at any gate — is an audit row, not just an in-memory log. Audit rows are hash-chained (`internal/audit/audit.go` plus the `jit_chain` table); chain integrity is exposed as `jess_chain_intact`.

**Evidence types.**

- Audit chain rows filtered by `action ∈ {session_deny, posture_deny, risk_deny, role_deny, lock_deny}`.
- Time-series of `jess_session_open_outcome_total` broken down by `result` (authn, authz, jit, posture, risk, lock).
- Time-series of `jess_session_device_claim_denies_total` by reason.
- OPA policy bundle and a sample input/output trace for an elevated target.
- Talon's own CC6.6 evidence (platform dependency) showing that traffic reaching jess has already been WAF-filtered (Coraza WAF in DetectionOnly today) and identity-checked at the Envoy edge.

**Status.** **Met.**

**Gaps + remediation.**

- **Coraza WAF in DetectionOnly mode (platform-level).** The Coraza Wasm filter on Envoy is currently in `DetectionOnly` rather than `Enforcement`. This is a platform decision tracked outside jess; it does not block CC6.6 because the AICPA criterion is satisfied by the broker's own deny gates, not by an upstream WAF. Noted for auditor visibility only.

---

## 6. CC6.7 — Restriction and protection of information in transmission, movement, and removal

**Control text.** The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal. For jess, "information" means session data flowing through the broker (interactive shell I/O, Postgres rows, MySQL rows, RDP frames, kubectl request/response bodies) and the resulting session recordings.

**jess implementation.**

- **TLS 1.3 on all jess-listening ports.** Operator port `:7101`, admin port, and worker control-plane port all require TLS 1.3 with modern cipher suites; the `tls.Config` in `cmd/jess-controller/main.go` and `cmd/jess-worker/main.go` pins `MinVersion: tls.VersionTLS13`.
- **mTLS on every leg.**
  - *Operator ↔ controller*: dual-CA mTLS per Phase 4 (full opCfg.Clone() pattern at `cmd/jess-controller/main.go`), with CRL enforcement.
  - *Worker ↔ controller*: mTLS over yamux (`internal/transport` + `internal/tunnel`).
  - *Admin clients*: separate admin CA, same dual-CA pattern.
- **In-transit protocols are wrapped, not bridged.** SSH, Postgres, MySQL, and RDP traffic is brokered through `internal/sshproxy`, `internal/dbproxy`, `internal/mysqlproxy`, and the Rust `services/ironrdp-broker` respectively. The broker terminates the operator-side TLS, applies the authorization decision, and then opens an upstream connection — operator credentials are never proxied to the upstream system in cleartext.
- **WORM session recording (Phase 5e and Phase 5e-16 chain).** Every interactive session is recorded to an asciicast bundle and signed with Ed25519 via Vault Transit. Files in `internal/recording/{recording,bundle,sign,s3store,httpndjson}.go`. The signed manifest binds the recording to the session metadata (operator, target, start/end timestamps, byte counts).
- **Object-lock for the audit archive bucket.** Recordings are streamed to MinIO with bucket-level Object Lock in **governance** mode and a multi-year retention period. Deletion before retention expiry requires a privileged role that the jess service account does not hold.
- **Audit chain confidentiality and integrity.** The `jit_chain` table is hash-linked; tampering breaks the chain and surfaces as `jess_chain_breaks_total > 0`. The chain rides Postgres TLS (CNPG cluster-internal mTLS) and is backed up via the platform's backup pipeline.

**Evidence types.**

- TLS handshake logs / `kubectl exec` curl probes showing `MinVersion=TLS1.3` negotiation.
- A recording bundle (`*.cast` + `*.sig` + `manifest.json`) with verifiable Ed25519 signature; auditor can re-verify with the public Vault Transit verification key.
- MinIO bucket policy export showing Object Lock governance + retention period for the audit-archive bucket.
- Vault Transit key configuration (`vault read transit/keys/jess-recording-signer`) showing key versions and key-rotation policy.
- A demonstration: auditor opens a test SSH session, exits, retrieves the corresponding `*.cast`, verifies the signature, replays the cast and confirms the byte-for-byte capture.

**Status.** **Met.**

**Gaps + remediation.**

- **FIPS 140-3 validation pending.** Today jess uses the Go standard library `crypto/tls`, which is not FIPS 140-3 validated in its default form. For SOC 2, FIPS validation is *not* required (FIPS is a separate FedRAMP / NIST requirement); it becomes mandatory only for federal customers. Scoped to **ADR 0036 — FIPS 140-3 mode** (`docs/adr/0036-fips-140-3-mode.md`). For the SOC 2 readiness assessment, the criterion is met without FIPS.
- **Object-lock is in `governance` mode rather than `compliance` mode.** Governance mode allows a privileged role to override the lock; compliance mode does not. For the strictest interpretation of CC6.7 (cannot remove information until retention elapses, period), compliance mode would be required. This is a platform-level MinIO configuration choice and is tracked in the platform's MinIO docs, not in jess. Noted here so an auditor can ask the right question.

---

## 7. CC6.8 — Prevention and detection of unauthorized or malicious software

**Control text.** The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity's objectives. For jess, this concerns the supply chain of jess images, the runtime image surface (what can execute inside the container), and any third-party modules pulled in at build time.

**jess implementation.**

- **Distroless base image.** The production image is built `FROM gcr.io/distroless/static-debian12:nonroot` (`Dockerfile` line 67). There is no shell, no package manager, no `curl`, no `wget`. An attacker who gained a foothold inside a running jess container could not download or `apt install` malicious tools — the OS surface to install onto does not exist.
- **Multi-stage build with isolated frontend stage.** The Vite/React SPA is compiled in a separate `node:22-bookworm` stage; only the resulting `dist/` directory is copied into the Go build context (`Dockerfile` line 20). The Node toolchain never reaches the production image. This is *defence-in-depth supply chain* — the production image never trusts an external pre-built SPA artefact and is reproducible from source alone.
- **CGO disabled in production builds.** `CGO_ENABLED=0` removes the libc surface entirely; the resulting binary is statically linked. Race-detector tests that need cgo run only in CI's `go-test` job, never in the production image.
- **Trivy image scanning in CI.** Every image build runs Trivy against the resulting image; CRITICAL findings fail the pipeline. Trivy reports are retained as CI artefacts for the SOC 2 period.
- **Cosign image signing.** Production images pushed to Harbor are signed with Cosign. The Argo CD Composition pins images by SHA256 digest, not by mutable tag — a malicious actor cannot substitute a tampered image at deploy time without also rotating the Argo manifest, which is itself a Git-tracked, reviewed change.
- **Harbor image retention.** Harbor retains signed image SHAs for the retention window; pinned SHAs in Argo manifests are protected by Kyverno mutating policy that flags unpinned image references. (This is the *upstream* control to prevent the recurrence of the 2026-05-30 incident where a Harbor retention sweep removed a pinned provisioner image.)
- **Go module supply chain.** `go.mod` and `go.sum` are committed; the build is hermetic against the Go module proxy. Renovate-managed updates land as MRs reviewed by humans before merge.
- **Linkerd mTLS mesh + opaque-ports.** All east-west pod traffic in the cluster rides Linkerd mTLS; jess opaque-ports allow Linkerd to skip TLS termination for protocols where jess does its own TLS (the broker's `:7101` and worker control-plane port). Lateral movement across pods is therefore observed and authenticated by Linkerd before reaching jess.

**Evidence types.**

- The `Dockerfile` itself (auditor can read it).
- A CI build log for a recent jess image showing Trivy scan output with zero CRITICAL findings.
- Cosign signature verification for the live image SHA: `cosign verify --certificate-identity-regexp '.*hexxlock.*' registry.example.com/jess/jess:<sha>`.
- Argo manifest excerpt showing image pinning by SHA digest.
- Kyverno policy report showing no unpinned image references in the jess namespace.
- The Linkerd mesh tap output for a sample jess session showing mTLS in use east-west.

**Status.** **Met for the image supply chain.**

**Gaps + remediation.**

- **Runtime malicious-process detection (Falco / Tetragon) is a platform-level control, not jess-specific.** Detection of malicious *behaviour* inside a running jess container (e.g. an unexpected `exec` syscall) is delegated to a cluster-wide eBPF-based runtime detector. This is outside jess scope; the platform's SOC 2 mapping must cover it. From jess's perspective, the distroless image plus the sealed Go binary mean the *baseline* runtime surface is minimal; runtime detection is hardening on top.
- **No software-bill-of-materials (SBOM) emission today.** Trivy scans the image but does not yet emit an SBOM (SPDX / CycloneDX) as a build artefact. For SOC 2 this is not strictly required, but SBOM emission would strengthen the CC6.8 attestation and is a frequent auditor ask. Scoped to a CI lift (not a jess code change) — recommend adding `cosign attach sbom` and `syft scan` to the platform build pipeline.

---

## 8. Summary table

| Criterion | Status | Primary evidence type | Outstanding gap | Remediation ADR / action |
|---|---|---|---|---|
| **CC6.1** Logical access security | Met | Controller authn logs; `jess_authz_decisions_total`; Falcon-ID audit join | Per-session MFA step-up not yet shipped | ADR 0037 — Phase 5j-3 |
| **CC6.2** Registration / removal of access | Met | Audit chain `grant_*` rows; `jess_session_revocations_total`; Vault CRL | None at criterion level; consider hard CAEP-latency SLO | Operational SLO add (no ADR) |
| **CC6.3** RBAC + segregation of duties | Met | Falcon-ID role export; `jit_requests` self-approval query; OPA traces | Explicit SoD policy statement in `DESIGN.md` | `DESIGN.md` doc lift (no ADR) |
| **CC6.6** Defence against external threats | Met | Audit deny rows; `jess_session_open_outcome_total` per result; posture deny metric | Coraza WAF is DetectionOnly (platform decision, not jess) | Platform-level Coraza promotion |
| **CC6.7** Transmission / movement / removal | Met | TLS 1.3 evidence; signed recordings; MinIO Object-Lock policy | FIPS 140-3 validation pending; Object-Lock in governance (not compliance) mode | ADR 0036; platform MinIO config |
| **CC6.8** Anti-malicious-software | Met | Distroless `Dockerfile`; Trivy CI artefacts; Cosign verification | No SBOM emission today; runtime detection is platform-level | CI lift (Syft + Cosign-SBOM) |

The auditor's quickest read: jess's CC6 posture is **defensible across all six criteria today**, with **no Not-Met rows** and **no Partial-status downgrades that block a Type I readiness opinion**. The Partial-style gaps that exist are *enhancement* opportunities (step-up MFA, FIPS, SBOM) rather than missing baseline controls.

---

## 9. Open audit-prep checklist

Items the operator should pre-collect into a shared evidence folder **before the auditor's kickoff call**. Estimated total prep time: one engineer-day if the cluster is in a clean state.

### 9.1 Identity and authentication (CC6.1, CC6.3)

- [ ] Falcon-ID OIDC issuer JWKS endpoint URL and a fresh JWKS export.
- [ ] Falcon-ID role-grant export covering the SOC 2 period, in CSV: `(subject, role, granted_at, granted_by, revoked_at)`.
- [ ] `kubectl get jesstargets -A -o yaml` snapshot (the live catalog).
- [ ] Vault PKI `pki_int_operators` configuration: issuer cert, current CRL, role definitions.
- [ ] Sample valid operator-cert chain (one Vault-issued cert, one CRL fetch).

### 9.2 Access lifecycle (CC6.2)

- [ ] 30-day extract of audit chain rows for `action ∈ {grant_create, grant_decide, grant_revoke, session_open, session_close, session_revoked}`.
- [ ] `jit_requests` table query result for `SELECT count(*) WHERE decided_by = subject` (must be 0).
- [ ] Live CAEP subscriber status from `/metrics`: `jess_caep_reconnects_total`, `jess_caep_subscribe_failures_total{result}`, last-event-received timestamp.
- [ ] Recorded screen capture of a kill-test: operator-A opens session, admin-B revokes operator-A's Falcon-ID session, operator-A's jess session terminates within seconds; capture the corresponding audit row.

### 9.3 Boundary defence (CC6.6)

- [ ] Grafana dashboard screenshots for: `jess_session_open_outcome_total` (24h, broken down by `result`), `jess_session_device_claim_denies_total` (24h), `jess_authz_decisions_total` (24h).
- [ ] OPA policy bundle (`data.jess.risk`) and a sample `opa eval` trace for an elevated target.
- [ ] Talon route definition for the `internal.example.com` family (this is the platform IAP in front of jess).

### 9.4 Data protection (CC6.7)

- [ ] TLS scan output (e.g. `testssl.sh`) against the jess-controller operator port confirming TLS 1.3 only.
- [ ] One representative session recording bundle (`*.cast` + `*.sig` + `manifest.json`) and the public Vault Transit verification key, with a short walkthrough showing the signature verifies.
- [ ] MinIO bucket policy export for the audit-archive bucket showing Object Lock + retention.
- [ ] Vault audit-device log excerpt showing recording-signer key use.

### 9.5 Supply chain (CC6.8)

- [ ] `Dockerfile` at the SHA shipped in production.
- [ ] Most recent Trivy scan report for the live image SHA, plus the CI pipeline artefact URL.
- [ ] `cosign verify` output for the live image SHA.
- [ ] Argo manifest showing image pinning by digest, not tag.
- [ ] Kyverno policy report for the jess namespace.
- [ ] `go.mod`, `go.sum`, and a copy of the upstream Go toolchain SHA used in CI.

### 9.6 Organizational / out-of-jess-but-asked

- [ ] Pointers to platform-level evidence for: Falcon-ID (own SOC 2 mapping), Talon (own SOC 2 mapping), Vault (own SOC 2 mapping), MinIO Object-Lock (platform infra), Linkerd mesh (platform infra), Coraza WAF (platform infra).
- [ ] List of named operators currently authorised to approve jess JIT requests, with their Falcon-ID role.
- [ ] Incident log for any jess-related security events in the SOC 2 period (none expected; surface anyway).

---

## 10. References

### 10.1 Verified AICPA criterion text (verbatim)

These are the criterion sentences this document maps against; verified 2026-06-03 against published AICPA TSC 2017 (revised 2022 PoF) criterion language quoted across multiple secondary sources.

- **CC6.1.** "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives."
- **CC6.2.** "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users whose access is administered by the entity. For those users whose access is administered by the entity, user system credentials are removed when user access is no longer authorized."
- **CC6.3.** "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties, to meet the entity's objectives."
- **CC6.6.** "The entity implements logical access security measures to protect against threats from sources outside its system boundaries."
- **CC6.7.** "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives."
- **CC6.8.** "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity's objectives."

(CC6.4 and CC6.5 — physical access to facilities and physical-asset disposal — are out of scope for jess; the broker is a software component, not a physical-access controller. They are covered by the platform's data-centre SOC 2 mapping.)

### 10.2 Authoritative source

- AICPA / CIMA, *2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (With Revised Points of Focus — 2022)*. The official PDF is paywalled but listed at https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022.

### 10.3 Internal cross-references

- `docs/adr/0030-phase-7-dynamic-catalog.md` — JessTarget CRD and discovery providers (catalog as inventory).
- `docs/adr/0033-phase-5f-rust-ironrdp-bridge.md` — RDP bridge transmission security.
- `docs/adr/0035-hardware-bound-operator-keys.md` — strengthening CC6.1 with hardware-bound operator keys.
- `docs/adr/0036-fips-140-3-mode.md` — closes the CC6.7 FIPS gap.
- `docs/adr/0037-per-session-mfa-step-up.md` — closes the CC6.1 step-up gap.
- `docs/adr/0038-spire-worker-mtls.md` — strengthening worker-leg mTLS identity (CC6.1 / CC6.6).
- `docs/adr/0039-ingress-worker-filtering.md` — additional CC6.6 ingress restriction.
- `docs/adr/0040-pqc-migration-plan.md` — post-quantum readiness for CC6.7.
- `docs/sessions/2026-05-29-jess-operator-e2e.md` — Phase A/B/C operator end-to-end runbook (live evidence of CC6.1 / CC6.2 / CC6.7 in operation).
- `cmd/jess-controller/main.go` — TLS configuration, port bindings, env-flag wiring.
- `internal/pdp/{pdp,verify,stub}.go` — Policy Decision Point.
- `internal/jit/{grant,session,requests,chain,memory,postgres}.go` — JIT grant and approval workflow.
- `internal/caep/{subscriber,token_file}.go` — Continuous Access Evaluation subscriber.
- `internal/devicepolicy/devicepolicy.go` — device-posture gate.
- `internal/riskscore/{riskscore,opa}.go` — risk-score evaluator.
- `internal/audit/{audit,json}.go` — hash-linked audit chain.
- `internal/recording/{recording,bundle,sign,s3store}.go` — WORM recording with Vault Transit signing.
- `internal/vaultx/{vaultx,transit_signer}.go` — Vault client + Transit signer.
- `internal/metrics/metrics.go` — Prometheus counters and histograms cited throughout.

### 10.4 Change log

| Date | Change | Author |
|---|---|---|
| 2026-06-03 | Initial DRAFT | jess maintainers |
