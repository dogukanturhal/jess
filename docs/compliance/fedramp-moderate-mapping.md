# FedRAMP Moderate Baseline — PAM-Relevant Control Mapping for jess

| | |
|---|---|
| **Document** | FedRAMP Moderate Baseline — PAM-Relevant Control Mapping |
| **System** | jess access broker (controller + worker + web + jessctl + db/RDP proxies) |
| **Date** | 2026-06-03 |
| **Status** | **DRAFT — informational mapping, NOT an ATO and NOT a SSP** |
| **Scope** | The privileged-access-management (PAM) -relevant *subset* of the FedRAMP Moderate baseline as it applies to the jess broker proper. This is **not** the full 325-control FedRAMP Moderate baseline — see [Boundary of control](#boundary-of-control) below for the controls explicitly *out* of jess's responsibility. |
| **Source authority** | NIST SP 800-53 Rev 5 (control catalog) + FedRAMP Rev 5 Moderate inclusion list (control selection). |
| **Audience** | Engineering self-assessment + customer due-diligence pre-reads + input to a future SSP. Do not present to a 3PAO as evidence of compliance. |

## How to read this document

Each control section has five fields:

1. **Control text** — 1-2 sentence plain-English summary of the SP 800-53 r5 control objective. Not a verbatim quotation. Refer to NIST SP 800-53 Rev 5 for canonical text.
2. **jess implementation** — which jess Phase(s), which files, and which ADR(s) carry the design.
3. **Evidence types** — what an auditor / customer due-diligence reviewer would inspect to verify the implementation.
4. **Status** — `Implemented` / `Partial` / `Not Implemented` / `Inherited` (control responsibility lives outside jess — e.g. with Falcon-ID or the HexxLock platform).
5. **Gaps** — pointer to the ADR (existing or planned) that closes any partial / not-implemented surface.

All file paths in *jess implementation* are repo-relative to `github.com/dogukanturhal/jess` unless noted.

---

## AC-2 — Account Management

**Control text:** The system must establish and manage information-system accounts (identification, provisioning, modification, disabling, removal), including periodic review and notification of account-lifecycle events.

**jess implementation:**

- **Account lifecycle is fully delegated to Falcon-ID** (the HexxLock OIDC IdP). Jess does not maintain its own user table — every operator identity is a Falcon-ID `sub`. Operator onboarding, disablement, role change, and offboarding are Falcon-ID operations, not jess operations. See `internal/pdp/verify.go` (token verification leg) and `internal/admin/operator_cert.go` (per-operator mTLS cert binding).
- **JIT grants are time-boxed accounts at the target.** Phase 5 (SSH via Vault `ssh-client-signer`) and Phase 5+ (Postgres via Vault dynamic credentials) mint a fresh per-session credential that expires at the end of the grant. Files: `internal/jit/grant.go`, `internal/jit/session.go`, `internal/vaultx/vaultx.go`, `internal/dbproxy/postgres.go`. Effect: every jess session at the target is an account that lives for the grant's TTL and is automatically revoked at grant expiry.
- **CRL revocation** for operator mTLS certs lives in `internal/admin/crl.go` — explicit account-disable path for the broker-side credential.

**Evidence types:**

- Falcon-ID IdP onboarding/offboarding runbook (out-of-tree at platform/iam).
- jess audit-log `grant.opened` + `grant.closed` + `grant.revoked` events showing per-session lifecycle (see `internal/audit/audit.go` Sink interface, JSONL exporter at `internal/audit/json.go`).
- Vault audit log entries for `ssh-client-signer` cert mints and Postgres dyn-cred `creds/jess-pg` leases — joinable to jess audit by `decision_id`.

**Status:** **Inherited** (Falcon-ID owns the operator account lifecycle) **+ Implemented** (JIT grants as time-boxed target-side accounts).

**Gaps:** None inside jess scope. Falcon-ID's account-management posture is mapped separately in the Falcon-ID compliance dossier.

---

## AC-4 — Information Flow Enforcement

**Control text:** The system must enforce approved authorizations for controlling the flow of information within the system and between connected systems.

**jess implementation:**

- **Talon IAP enforces per-host info flow** for every operator-facing jess hostname (`internal.example.com`, `jess-controller`, etc.). Talon's TalonRoute (jess Helm chart, Phase 5f-3) dictates `authMode`, allowed claims, and upstream binding. Cross-host traversal requires re-authentication.
- **Envoy Gateway (EG) HTTPRoute enforces per-path info flow** within the operator-tier (`/api/v1/grants`, `/api/v1/admin/*`, `/rdp/*`, `/ssh/*`). Different paths can require different role claims. See `internal/admin/admin.go` (admin router) + `internal/spine/` (controller router).
- **Egress flow restrictions** on the worker side: the worker can only reach targets in the catalog (`internal/catalog/`) — runtime egress is constrained by Kubernetes NetworkPolicy (out-of-tree, the GitOps repository).
- **Linkerd opaque-ports** (platform-tier) keeps the broker's bidirectional RDP/SSH/Postgres bridge byte-streams from being misinterpreted by the mesh as HTTP.

**Evidence types:**

- Talon route config for every jess hostname (read-back via `talonctl routes ls`).
- EG HTTPRoute YAML for the operator-tier `/api/*` and `/rdp/*` paths.
- NetworkPolicy YAML for the jess namespace (egress denied except to enumerated CIDRs).
- Linkerd `opaque-ports` annotation on the jess-controller + jess-worker Deployments.

**Status:** **Implemented.**

**Gaps:** None.

---

## AC-6 — Least Privilege

**Control text:** The system must employ the principle of least privilege, allowing only authorized accesses for users (and processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks.

**jess implementation:**

- **JIT grants enforce per-`(subject, target, TTL)` least-privilege** — an operator's grant is bound to a single target ID, a single role (or set of allowed actions), and an explicit TTL (default 30 minutes). After expiry, the grant is unusable; a new grant must be requested. See `internal/jit/grant.go` (`Grant` struct fields: `SubjectSub`, `TargetID`, `Role`, `TTL`, `ExpiresAt`).
- **pdp.RoleAuthorizer** is the policy decision point that checks the operator's Falcon-ID claim against the target's `RequiredRoles` set before opening a session. See `internal/pdp/pdp.go` + `internal/pdp/verify.go`. Default-deny — a target with no matching role for the operator returns 403 at the controller.
- **Target.RequiredRoles** is the per-target authorization surface (configured in the catalog ConfigMap, Phase 7e: future `JessTarget` CRD). Different targets can require different roles; the broker enforces the intersection.
- **Database-broker per-query rules** (Phase 5+ Postgres) — the dbproxy can enforce per-query authorization (SELECT-only role, no DDL) via the dyn-cred role definition in Vault, not jess code. See `internal/dbproxy/postgres.go` for the broker proxy.

**Evidence types:**

- Catalog entry `RequiredRoles` for each target (catalog ConfigMap or future `JessTarget` CRD).
- Audit-log `grant.requested` events with `role` + `requested_ttl` showing what was asked.
- Audit-log `grant.opened` events with `granted_role` + `granted_ttl` showing what was authorized.
- Vault dyn-cred role definitions for Postgres (per-target SQL grants).

**Status:** **Implemented.**

**Gaps:** None for the broker. Per-query SQL-level rules at the target are inherited from Vault's dyn-cred role definitions — operator must keep those tight.

---

### AC-6(2) — Non-Privileged Access for Nonsecurity Functions

**Control text:** Users with privileged accounts must use non-privileged accounts (or roles) when accessing nonsecurity functions, to limit exposure of privileged credentials.

**jess implementation:**

- **Falcon-ID operators authenticate as non-privileged by default.** The OIDC token issued by Falcon-ID for jess does not contain the `admin` role; that role is only present in tokens issued for a separate `admin`-scoped client when the operator explicitly opts into an admin session. See `internal/pdp/verify.go` (claim verification) — admin endpoints under `internal/admin/admin.go` check for the `admin` claim explicitly via `pdp.RoleAuthorizer`.
- **Admin role requires an explicit token claim** (`role=admin`) — non-privileged operators cannot call `/api/v1/admin/*` endpoints even with a valid jess token.
- **mTLS device binding** on the admin endpoints adds a second factor: even an `admin`-claim token cannot reach `/admin/*` without a device-bound client cert minted via Vault PKI `jess-ca` per `internal/admin/operator_cert.go` + `internal/admin/operator_cert_vault.go`.

**Evidence types:**

- Falcon-ID client configuration showing the `admin` client is a separate ServiceClientClaim (out-of-tree).
- Audit-log entries for `/api/v1/admin/*` calls showing `role=admin` claim + `cert_serial=...` on every request.
- pdp.RoleAuthorizer test coverage at `internal/pdp/verify.go` confirming default-deny without explicit role.

**Status:** **Implemented.**

**Gaps:** None.

---

## AC-17 — Remote Access

**Control text:** The system must establish usage restrictions, configuration/connection requirements, and implementation guidance for each type of remote access allowed, and must authorize remote access prior to allowing such connections.

**jess implementation:**

- **Phase 3 BeyondCorp L4 model** — operator port `:7101` is publicly reachable at `203.0.113.10:7101` (MetalLB IP, no VPN required). Operators connect from any internet location; authentication and authorization happen at the broker (Falcon-ID OIDC + mTLS device binding), not at a network perimeter. This is the modern ZTA replacement for traditional VPN-based remote access.
- **Per-session encryption** — TLS 1.3 on every operator-facing port (jess controller `:7101`, jess-web `:8443`, admin `:7102`).
- **Per-session re-authorization** — each session re-validates the Falcon-ID JWT against the issuer + reaffirms the mTLS cert chain. No persistent "logged-in" state at the broker.
- **Per-session WORM recording** of SSH sessions (asciicast) + RDP fastpath (Phase 5f-8b-4, see ADR 0033) to `audit-archive/jess-ssh/<session>/` and `audit-archive/jess-rdp/<session>/`.

**Evidence types:**

- Public reachability test: `curl -v https://203.0.113.10:7101/healthz` from any internet location (passes TLS handshake, fails authz without a token — expected).
- MetalLB IP allocation YAML showing the operator-tier ingress.
- TLS configuration `internal/transport/` enforcing TLS 1.3 only.
- Falcon-ID OIDC issuer config showing the jess client + signing keys.

**Status:** **Implemented** — modern ZTA model (BeyondCorp) replaces traditional VPN-based remote access. NIST SP 800-207 (Zero Trust Architecture) is the policy backstop for this posture; FedRAMP authorizing officials accept ZTA-equivalent in lieu of VPN per the Rev 5 update.

**Gaps:** None for the broker. Customer SSPs deploying jess may need to map their tenant-side remote-access posture (workstation hardening, EDR, conditional access) as inherited controls.

---

## AU-2 — Event Logging

**Control text:** The organization must determine which events are auditable (login, privilege escalation, access to sensitive data, policy changes, etc.) and document the rationale; the system must be capable of generating audit records for those events.

**jess implementation:**

- **`audit.Sink` interface** in `internal/audit/audit.go` is the broker's single emission point. Every state-changing operation in the controller goes through `audit.Sink.Emit(ctx, Event)`. Event types currently emitted: `grant.requested`, `grant.opened`, `grant.closed`, `grant.denied`, `grant.revoked`, `cert.minted`, `cert.revoked`, `session.bytes`, `query.executed` (db-broker), `admin.*` (every admin action).
- **JSONL exporter** at `internal/audit/json.go` writes the canonical export format; Phase 5e-15 added the controller HTTP endpoint `/api/v1/audit/export?since=<RFC3339>&until=<RFC3339>` for streaming JSONL out to an external SIEM.
- **Per-query audit for db-broker** — `internal/dbproxy/postgres.go` emits one `query.executed` event per SQL statement (operator, target, db, query hash, duration, rows-returned, error).
- **Chain-hash audit log** (Phase 5e-16, `internal/jit/chain.go`) — each event is hash-linked to its predecessor, producing a tamper-evident chain. Any post-hoc redaction breaks the chain and is detectable.

**Evidence types:**

- Sample export from `/api/v1/audit/export` for a 24h window.
- `internal/audit/audit.go` source confirming the event taxonomy.
- Chain-hash verification: `jessctl admin audit verify --since <T>` (Phase 5e-16) re-computes the chain.

**Status:** **Implemented.**

**Gaps:** None.

---

## AU-3 — Content of Audit Records

**Control text:** Audit records must contain information that establishes what type of event occurred, when, where, the source, the outcome, and the identity of the subject associated with the event.

**jess implementation:**

- **Every audit Event has the AU-3 required fields:**
  - `event_type` — e.g. `grant.opened`
  - `subject_sub` — Falcon-ID `sub` claim of the operator
  - `subject_email` — Falcon-ID `email` claim (denormalized for human-readable audit)
  - `target_id` — catalog entry ID
  - `target_host` — resolved hostname:port
  - `decision_id` — UUIDv7 unique per request, propagated to upstream Vault calls (joinable across audit chains)
  - `timestamp` — RFC3339 nanosecond precision
  - `outcome` — `success` | `denied` | `error`
  - `outcome_detail` — error class on failure (e.g. `pdp.role_not_granted`, `vault.lease_denied`)
  - `source_ip` — operator's source IP from `X-Forwarded-For` (Talon-injected, signed)
  - `cert_serial` — operator's mTLS cert serial when present
  - `chain_prev_hash` + `chain_self_hash` — chain-link
- See `internal/audit/audit.go` `Event` struct for the canonical field list.

**Evidence types:**

- One representative event of each type from a live audit export, sanity-checked field-by-field.
- `internal/audit/audit.go` `Event` struct definition.

**Status:** **Implemented.**

**Gaps:** None.

---

## AU-12 — Audit Record Generation

**Control text:** The system must provide audit record generation capability for the auditable events at all system components, and must allow authorized users to select which auditable events are audited by specific components.

**jess implementation:**

- **jess-controller emits to two sinks by default**: stdout (for the platform log pipeline → Vector → Loki) and the JSONL bucket sink (for long-term WORM retention in MinIO). See `internal/audit/audit.go` `MultiSink`.
- **Per-query audit emission** lives at the db-broker (`internal/dbproxy/postgres.go`) and is enabled by default — there is no "audit off" switch. Operators cannot disable audit on a per-target basis.
- **No silent failure** — sink errors are themselves audited (a `sink.error` event is emitted via the other sink), and the broker degrades to fail-closed if both sinks fail (refuses to open new grants). See `internal/audit/audit.go` `MultiSink.Emit` error path.

**Evidence types:**

- jess-controller stdout sample showing per-event lines.
- MinIO bucket listing for `audit-archive/jess-controller/<date>/`.
- `internal/audit/audit.go` `MultiSink.Emit` source confirming fail-closed behavior.

**Status:** **Implemented.**

**Gaps:** None.

---

## IA-2 — Identification and Authentication (Organizational Users)

**Control text:** The system must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

**jess implementation:**

- **Falcon-ID OIDC** is the primary identity verification: every request to the controller carries an Authorization Bearer JWT issued by Falcon-ID. `internal/pdp/verify.go` validates the JWT against the Falcon-ID JWKS, checks `iss`, `aud=jess`, `exp`, `nbf`, and signature.
- **mTLS device binding** on the operator port: every TLS connection requires a client cert minted via Vault PKI `jess-ca`. The operator cert binds the operator (Falcon-ID `sub`) to a device (hardware-attested public key when available via WebAuthn enrollment, software-attested otherwise). See `internal/admin/operator_cert.go` + `internal/admin/operator_cert_vault.go`.
- **Cert + JWT cross-check** — the controller verifies that the JWT `sub` claim matches the cert's `CN` field (or `SAN otherName` for service identities); mismatch is a 401 + audit `auth.cert_jwt_mismatch`.

**Evidence types:**

- Falcon-ID JWKS endpoint pinned in jess config.
- Vault PKI `jess-ca` role config showing per-operator cert lifetime + key-usage constraints.
- Audit-log entries showing `subject_sub` + `cert_serial` on every authenticated request.

**Status:** **Implemented.**

**Gaps:** None for the broker.

---

### IA-2(1) — Multi-Factor Authentication to Privileged Accounts

**Control text:** The system must implement multi-factor authentication for access to privileged accounts.

**jess implementation:**

- **Two factors are required for the `admin` role** — Falcon-ID OIDC token *and* the per-operator mTLS device cert. The token alone is insufficient (no `admin` claim without explicit upstream IdP-side MFA at Falcon-ID); the cert alone is insufficient (no `admin` action without a fresh `admin`-scoped token).
- **Falcon-ID upstream MFA** — Falcon-ID enforces WebAuthn (or TOTP fallback) at OIDC login for `admin`-scoped clients. The MFA happens at Falcon-ID; jess inherits the assertion via the `amr` claim in the token.
- **Per-session re-validation** of both factors on every admin endpoint call (no session-cookie shortcut).

**Evidence types:**

- Falcon-ID admin-client config showing `amr=mfa` is required.
- Audit-log `amr` field on `/api/v1/admin/*` calls.
- Vault PKI `jess-ca` role for operator certs showing per-device binding.

**Status:** **Implemented.**

**Gaps:** None for the broker. Falcon-ID inherits the MFA-at-IdP responsibility.

---

### IA-2(11) — Acceptance of PIV Credentials from Other Agencies

**Control text:** The system must accept and electronically verify Personal Identity Verification (PIV) credentials issued by other federal agencies (cross-certified) for access by federal employees and contractors.

**jess implementation:**

- **Not currently supported.** jess accepts Falcon-ID OIDC tokens and Vault-PKI-minted mTLS certs; it does not accept PIV smart cards or PIV-derived credentials from federal HSPD-12 cross-certified roots.
- The Phase 5f-8b-3 smart-card flow (ADR 0033) mints *broker-side* smart-card certs for Windows AD logon — that is the opposite direction (broker mints, Windows AD trusts) and does not enable PIV acceptance on the *operator* side.
- **PLANNED** in a future ADR (working title ADR 0035 — Tier-1 ZTNA enhancements, PIV/CAC acceptance leg). Design sketch: a separate Falcon-ID identity provider in front of jess that accepts PIV at the IdP (federal PIV root + PIVAuth EKU verification), then issues a normal Falcon-ID token downstream. Jess itself wouldn't need to change much — the PIV-verification leg is an IdP concern.

**Evidence types:**

- N/A — not implemented.

**Status:** **Not Implemented (PLANNED).**

**Gaps:** ADR 0035 (planned) — PIV/CAC acceptance at the Falcon-ID layer.

---

## IA-5 — Authenticator Management

**Control text:** The system must manage information-system authenticators (passwords, tokens, certificates, keys) including initial distribution, lost/compromised replacement, periodic refresh, and revocation.

**jess implementation:**

- **Vault PKI for operator certs** (Phase 4) — `jess-ca` mount issues per-operator client certs with a short lifetime (default 8h). Renewal is automatic on session resume; revocation propagates via CRL (see `internal/admin/crl.go`). Vault audit logs every issue/revoke.
- **Vault SSH-CA for target SSH** (Phase 5) — `ssh-client-signer` mount signs operator SSH certs per-session with TTL = grant TTL (default 30min). No long-lived SSH keys live on operator workstations or the broker. Vault audit logs every cert sign.
- **Falcon-ID for OIDC tokens** — short-lived (≤1h) access tokens; refresh requires re-authentication. Falcon-ID rotates signing keys on a schedule (out-of-tree).
- **Per-session-cert auto-rotation** — every new grant mints a fresh leaf cert; certs do not outlive their grants. No long-lived "service account" certs in the operator path.
- **Vault transit signer** (`internal/vaultx/transit_signer.go`) for the chain-hash audit log signing key — managed by Vault, rotated per Vault policy.

**Evidence types:**

- Vault PKI `jess-ca` role config (max_ttl, key_usage, allowed_domains).
- Vault SSH-CA `ssh-client-signer` role config (ttl, allowed_users, allowed_extensions).
- Vault audit log entries showing per-session cert mints joinable to jess audit by `decision_id`.
- `internal/admin/crl.go` source confirming CRL is regenerated on revoke.

**Status:** **Implemented.**

**Gaps:** None for the broker. Vault-managed-key rotation cadence is a Vault platform concern.

---

## IA-11 — Re-Authentication

**Control text:** The system must require users to re-authenticate when access conditions change (privilege elevation, role change, session timeout, etc.).

**jess implementation:**

- **Grant expiry forces re-authentication** — when a JIT grant expires, the operator must request a new grant, which re-validates the Falcon-ID token (re-checks expiry + signature + claim set) and re-evaluates pdp policy. There is no session-cookie shortcut.
- **Token expiry forces re-authentication** — Falcon-ID tokens are ≤1h; on expiry the operator's browser/SPA must obtain a fresh token before the next call.
- **No mid-session step-up MFA today.** If an operator opens a regular grant and then escalates to an admin action mid-session, jess does *not* currently force a fresh MFA prompt — it relies on the original token's `amr` claim being valid for the new action. This is a known gap.
- **Phase 5j-3 per-session MFA step-up** (planned, ADR 0037) closes the gap: jess will require a fresh Falcon-ID re-authentication (with `acr` step-up) when the operator transitions from a non-admin grant to an admin action within the same browser session.

**Evidence types:**

- Audit-log `grant.expired` + subsequent `grant.requested` events showing re-auth.
- Token-expiry behavior: a token-stale request returns 401, not a silent refresh.

**Status:** **Partial** — grant + token expiry force re-auth, but mid-session privilege escalation does not yet trigger step-up.

**Gaps:** ADR 0037 (planned) — Phase 5j-3 per-session MFA step-up.

---

## SC-7 — Boundary Protection

**Control text:** The system must monitor and control communications at the external boundary and at key internal boundaries, employing subnetworks for publicly accessible system components separated from internal networks.

**jess implementation:**

- **Talon IAP** is the application-layer perimeter for every jess hostname — denies every request that doesn't pass OIDC + claim verification.
- **EG Coraza WAF** sits in front of the operator-tier `/api/*` paths (Phase 7.4.c, currently DetectionOnly) — adds OWASP CRS coverage for L7 attack patterns. Will move to Enforce in Phase 7.4.f.
- **Linkerd opaque-ports** is the in-mesh boundary — jess's byte-stream ports (SSH bridge `:2222`, RDP bridge `:3389`, Postgres bridge `:5432`) are marked opaque so the mesh doesn't mis-parse them as HTTP.
- **MetalLB allowlist** at OPNsense — the public IP `203.0.113.10:7101` is reachable globally, but other operator-tier ports are restricted at the firewall (admin port `:7102` is internal-only).
- **Kubernetes NetworkPolicy** (out-of-tree, the GitOps repository) restricts jess-namespace egress to enumerated CIDRs (target VLANs only).

**Evidence types:**

- Talon route config dump for jess hostnames.
- EG HTTPRoute YAML.
- OPNsense firewall rules for jess-tier IPs.
- NetworkPolicy YAML in the GitOps repository `platform/jess/networkpolicy.yaml`.
- Linkerd `config.linkerd.io/opaque-ports` annotation on jess Deployments.

**Status:** **Implemented.**

**Gaps:** EG Coraza WAF moves to Enforce in Phase 7.4.f (already planned + tracked).

---

## SC-8 — Transmission Confidentiality and Integrity

**Control text:** The system must protect the confidentiality and integrity of transmitted information.

**jess implementation:**

- **TLS 1.3 on every jess port.** Operator port `:7101`, jess-web `:8443`, admin port `:7102`, controller-to-worker mTLS, controller-to-Vault mTLS. TLS 1.2 is disabled. See `internal/transport/` for TLS config.
- **SSH protocol** for target SSH bridge — confidentiality + integrity via SSH MAC. Host-key pinning via Vault SSH-CA host-key trust (Phase 5, see `internal/sshproxy/`).
- **CredSSP-in-TLS** for target RDP bridge (Phase 5f-8b-2/3, ADR 0033) — RDP fastpath bytes flow inside TLS to the broker, then inside TLS to the target.
- **Postgres TLS** for the db-broker upstream leg — `sslmode=verify-full` against the target CNPG cluster cert (Phase 5+ Postgres).

**Evidence types:**

- `nmap --script ssl-enum-ciphers -p 7101 203.0.113.10` showing TLS 1.3 only.
- `internal/transport/` source confirming TLS 1.3 minimum.
- Vault SSH-CA `host-key-signer` config for host-cert verification.

**Status:** **Implemented.**

**Gaps:** None at the protocol-selection layer. See SC-8(1) for cryptographic-validation gap.

---

### SC-8(1) — Cryptographic Protection (FIPS-Validated)

**Control text:** When cryptographic mechanisms are used to protect transmitted information, the mechanisms must be FIPS-validated or NSA-approved.

**jess implementation:**

- Jess currently uses **Go stdlib crypto** (`crypto/tls`, `crypto/x509`, `golang.org/x/crypto`) which is **not FIPS-validated** in the default Go build.
- The cryptographic primitives are correct (TLS 1.3, AES-GCM, ECDSA P-256, RSA-2048+) but the *implementation* lacks a FIPS 140-3 validation certificate.
- **PLANNED** in ADR 0036 (planned) — Phase 6 FIPS lane: switch to a FIPS-validated Go toolchain (BoringSSL-backed `goboring`, or Microsoft `microsoft/go` with FIPS mode) for FedRAMP-pursuing customer deployments. Dual-build: stock Go for community, FIPS Go for FedRAMP.

**Evidence types:**

- Currently: N/A (no FIPS validation).
- Future: NIST CMVP certificate number + module configuration evidence.

**Status:** **Partial** — correct algorithms but uncertified implementation.

**Gaps:** ADR 0036 (planned) — FIPS 140-3 validated crypto module.

---

## SC-12 — Cryptographic Key Establishment and Management

**Control text:** The system must establish and manage cryptographic keys when cryptography is employed, in accordance with NIST SP 800-57 (or equivalent).

**jess implementation:**

- **Vault PKI mounts** are the canonical key-management substrate:
  - `jess-ca` — operator mTLS leaf certs (Phase 4)
  - `ssh-client-signer` — target SSH user certs (Phase 5)
  - `ssh-host-signer` — target SSH host certs (Phase 5)
  - `transit` — chain-hash audit-log signing keys + per-tenant data-encryption keys (Phase 5e-16)
  - `jess-smartcard-ca` — Windows AD smart-card certs (Phase 5f-8b-3, ADR 0033, planned)
  - `jess-apps-pki` — apps-tier mTLS (Phase 7, hexxlock.com substrate, codified)
- **Key rotation** — every certificate has a finite TTL (8h operator certs, 30min SSH-cert per grant, ≤30min smart-card-cert per session). Root CA rotation is a documented Vault platform procedure (out-of-tree).
- **Key destruction** — leaf certs expire and are never reissued; Vault audit logs the issue + revoke pair.
- **No long-lived key material on the broker.** The broker holds only short-lived material; the long-lived root material lives in Vault HSM-or-Shamir-protected unseal config.

**Evidence types:**

- Vault PKI mount listing (`vault secrets list`) for each mount.
- Vault PKI root cert chain (downloadable, public).
- Vault audit log showing key issue/revoke per mount.
- jess source confirming the broker does not persist private-key material to disk (in-memory only via `internal/vaultx/` + `internal/admin/operator_cert_vault.go`).

**Status:** **Implemented.**

**Gaps:** None for the broker. Vault HSM unseal posture is a Vault platform concern.

---

## SC-13 — Cryptographic Protection

**Control text:** The system must implement FIPS-validated or NSA-approved cryptographic mechanisms for protecting information (confidentiality, integrity, authentication, non-repudiation).

**jess implementation:**

- **Same status as SC-8(1).** Go stdlib crypto provides the correct algorithms but lacks a FIPS 140-3 certificate.
- **Algorithm choices are FIPS-eligible** — AES-256-GCM, ECDSA P-256 / P-384, RSA-2048+, SHA-256+, X25519 (TLS 1.3 KEM). No deprecated algorithms (3DES, MD5, SHA-1) are used in production paths.
- **PLANNED** in ADR 0036 — FIPS-validated Go toolchain build lane.

**Evidence types:**

- Source review of `internal/transport/`, `internal/vaultx/`, `internal/audit/` confirming no deprecated-algorithm usage.
- Future: NIST CMVP certificate.

**Status:** **Not Implemented (PLANNED)** — algorithms are FIPS-eligible but implementation lacks the certificate.

**Gaps:** ADR 0036 (planned) — FIPS 140-3 validated crypto module. Same root cause as SC-8(1).

---

## Summary table

| Control | Title | Status | Closing ADR |
|---|---|---|---|
| AC-2 | Account Management | Inherited (Falcon-ID) + Implemented (JIT) | none |
| AC-4 | Information Flow Enforcement | Implemented | none |
| AC-6 | Least Privilege | Implemented | none |
| AC-6(2) | Non-Privileged Access | Implemented | none |
| AC-17 | Remote Access | Implemented (BeyondCorp ZTA) | none |
| AU-2 | Event Logging | Implemented | none |
| AU-3 | Content of Audit Records | Implemented | none |
| AU-12 | Audit Record Generation | Implemented | none |
| IA-2 | Identification and Authentication | Implemented | none |
| IA-2(1) | MFA to Privileged Accounts | Implemented | none |
| IA-2(11) | PIV Credential Acceptance | **Not Implemented (PLANNED)** | ADR 0035 (planned) |
| IA-5 | Authenticator Management | Implemented | none |
| IA-11 | Re-Authentication | **Partial** (no mid-session step-up) | ADR 0037 (planned) |
| SC-7 | Boundary Protection | Implemented | none |
| SC-8 | Transmission Confidentiality + Integrity | Implemented | none |
| SC-8(1) | Cryptographic Protection (FIPS) | **Partial** (no FIPS cert) | ADR 0036 (planned) |
| SC-12 | Cryptographic Key Establishment + Management | Implemented | none |
| SC-13 | Cryptographic Protection (FIPS) | **Not Implemented (PLANNED)** | ADR 0036 (planned) |

**Rollup**: 14 Implemented + 1 Inherited-and-Implemented (AC-2) + 2 Partial (IA-11, SC-8(1)) + 2 Not-Implemented-Planned (IA-2(11), SC-13). All 4 gaps trace back to 3 future ADRs (0035 PIV, 0036 FIPS, 0037 step-up MFA).

---

## Boundary of control

This mapping covers **the jess broker proper** — the controller, worker, web SPA, jessctl CLI, db-broker, and RDP-broker components.

**Out of scope for this document** (and out of jess's responsibility — these are HexxLock platform-tier controls owned elsewhere in the organization):

- **CM-* (Configuration Management)** — Argo CD, GitOps repos, change-approval flow. <gitops-bootstrap-repo> + the GitOps repository own these.
- **CP-* (Contingency Planning)** — DR runbooks, backup-restoration testing, RTO/RPO commitments. Platform-tier ops own these.
- **IR-* (Incident Response)** — SOC playbooks, escalation paths, post-incident review. Platform SecOps own these.
- **PE-* (Physical and Environmental)** — Hetzner / colo facility controls. Hetzner ships their own SOC 2 + ISO 27001 + C5 inheritance package.
- **PS-* (Personnel Security)** — background checks, separation procedures. HR / People Ops own these.
- **MA-* (Maintenance)** — scheduled-maintenance procedures, remote-maintenance authorization. Platform-tier ops own these.
- **MP-* (Media Protection)** — backup-media handling, sanitization. Platform-tier ops own these.
- **PL-* (Planning)** — system security plan authorship. CISO / GRC own this.
- **PM-* (Program Management)** — risk-management program, security architecture. CISO / GRC own this.
- **RA-* (Risk Assessment)** — periodic risk assessment, vulnerability scanning. Platform SecOps own these (Trivy in the image pipeline, Wiz for cluster scans).
- **SA-* (System and Services Acquisition)** — supply-chain controls beyond what cosign + SBOM provide for jess images. Platform supply-chain owns these.
- **SI-* (System and Information Integrity)** — most SI-* controls (flaw remediation, malicious-code protection, monitoring) are platform-tier. SI-7 (software-firmware-integrity) is partially in jess scope via cosign-signed images.

**A full FedRAMP Moderate ATO requires all 325 controls of the baseline**, not just the PAM-relevant subset mapped here. This document is a starting point for the access-control + audit + identification + cryptography slice; the rest must be filled in by platform-tier documentation.

---

## ATO-readiness checklist — top 5 items to close before pursuing FedRAMP Moderate

This list reflects the gaps surfaced by this mapping plus the priority ordering of ADR 0034 (planned — Tier-1 ZTNA enhancements). Items are ordered by ATO-blocking severity, not by engineering effort.

1. **FIPS 140-3 validated crypto module (ADR 0036, planned)** — addresses SC-8(1) + SC-13. Without a FIPS-validated crypto module, jess cannot satisfy SC-8(1) or SC-13 even though its algorithm choices are correct. This is the single biggest gating item for a federal-customer ATO. Approach: dual-build lane (stock Go for community, `microsoft/go` or BoringSSL-backed Go for FedRAMP), gated by build tag, verified via CMVP certificate number reference.
2. **Per-session MFA step-up (ADR 0037, planned)** — addresses IA-11 Partial. Closes the mid-session-escalation gap by requiring a fresh `acr=mfa` token assertion when transitioning from non-admin to admin actions in the same browser session. Mostly a Falcon-ID + frontend change; broker work is small (claim check on `amr` recency).
3. **PIV/CAC acceptance at Falcon-ID (ADR 0035, planned)** — addresses IA-2(11). Required for federal civilian agency use; not required for FedRAMP Moderate baseline itself (IA-2(11) is conditional on the agency-side identity model) but strongly expected by federal customer due-diligence. Design: PIV verification at Falcon-ID IdP layer, downstream-issued Falcon-ID token unchanged. Jess broker requires no change.
4. **External SIEM ingestion + retention proof (ADR 0034 priority #6, planned)** — supports AU-2/AU-3/AU-12 evidence. The current JSONL bucket sink + Loki path satisfies the *generation* and *content* controls, but FedRAMP also requires demonstrable 12-month online retention + offline archival to specific durability standards. Need an MR for: MinIO bucket lifecycle policy → Glacier-equivalent after 90 days, retention-lock for 12 months, periodic restoration-test runbook.
5. **3PAO-readable SSP starter (NEW — not yet ADR-tracked)** — this very document is informational; an actual ATO requires a 3PAO-readable System Security Plan in the FedRAMP-prescribed template. Recommended next step: convert this mapping into the FedRAMP SSP Moderate template (form 1.4) with platform-tier inherited-control sections drafted from the HexxLock platform compliance inventory. Estimated effort: ~2 weeks for the first draft + 1 week with a GRC reviewer.

---

## References

- NIST SP 800-53 Rev 5 — Security and Privacy Controls for Information Systems and Organizations (latest update). Control catalog source: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-53A Rev 5 — Assessment Procedures (companion document for auditor evidence expectations).
- NIST SP 800-207 — Zero Trust Architecture (policy backstop for the BeyondCorp model on AC-17).
- FedRAMP Rev 5 Baselines — control inclusion list: https://www.fedramp.gov/baselines/
- FedRAMP SSP Template (Moderate) — for converting this mapping into a 3PAO-readable document.
- jess ADR 0030 — Phase 7 Dynamic Target Catalog (catalog substrate referenced under AC-6 / AC-4).
- jess ADR 0033 — Phase 5f-8b Rust IronRDP Browser-RDP Bridge (RDP path referenced under AC-17 / SC-8 / SC-12).
- jess ADR 0034 — Tier-1 ZTNA Enhancements (planned — ATO-readiness checklist priorities).
- jess ADR 0035 — PIV/CAC acceptance at Falcon-ID (planned — IA-2(11) gap closure).
- jess ADR 0036 — FIPS 140-3 validated crypto module (planned — SC-8(1) + SC-13 gap closure).
- jess ADR 0037 — Phase 5j-3 per-session MFA step-up (planned — IA-11 gap closure).

---

## Change log

| Date | Change | Author |
|---|---|---|
| 2026-06-03 | Initial DRAFT — informational mapping of FedRAMP Moderate PAM-relevant subset against jess Phases 4 / 5 / 5e / 5f / 7. | platform/jess maintainers |
