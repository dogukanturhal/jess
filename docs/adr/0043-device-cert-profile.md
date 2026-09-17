# ADR 0043 — jess device-cert profile (ZTNA Phase 3)

**Status:** Proposed — implementation gated on Phase 0 (locked) + Phase 2 (ADR 0042 ✓)
**Date:** 2026-06-06
**Phase:** ZTNA Phase 3 — device-cert profile + attestation + Talon edge mTLS
**Owners:** jess maintainers
**Parent:** Talon ADR 0040 (master), Talon ADR 0040-A (threat model), Talon ADR 0040-B (decision register)

## Context

Talon ADR 0040 §Phase 3 commits jess to issuing hardware-rooted device
certificates (24h TTL, auto-rotated at 12h) that Talon's edge listener
requires at the TLS handshake (mTLS). The cert is bound to a key
non-extractable from the device's TPM 2.0 / Secure Enclave /
StrongBox / TEE; the binding is proven via vendor-specific
**attestation evidence** verified by jess before mint.

jess already operates Vault PKI mounts (`jess-ca` for operator-cert,
ADR 0035) and the CRLCache + VerifyPeerCertificate pattern (ADR 0035
Phase 4). Phase 3 ADDs a second mount + role + verifier:

- New Vault PKI mount `jess-device-ca`
- New Jess controller endpoint `/device-cert` (mirror of `/operator-cert`)
- New attestation verifier per platform (Windows TPM 2.0, Linux TPM 2.0, Apple App Attest, Android key attestation, macOS MDM-fallback)
- Talon edge listener gated on Vault-published `jess-device-ca/crl/pem`

## Decision

### 3.a — Vault PKI mount `jess-device-ca`

```hcl
# infrastructure-iac/datacenters/eu-west-1/vault/vault-jess-device-ca.tf
resource "vault_mount" "jess_device_ca" {
  path        = "jess-device-ca"
  type        = "pki"
  description = "Jess device-cert CA (ZTNA Phase 3, ADR 0040)"

  # Root: 5-year. Caps the leaf TTL per
  # internal engineering notes.
  default_lease_ttl_seconds = 86400      # 24h leaf default
  max_lease_ttl_seconds     = 157680000  # 5y root cap
}

resource "vault_pki_secret_backend_root_cert" "jess_device_ca_root" {
  backend  = vault_mount.jess_device_ca.path
  type     = "internal"
  common_name = "HexxLock Jess Device CA"
  ttl      = 157680000  # 5y
  key_type = "ec"
  key_bits = 384  # P-384 — tier-1 default
}

resource "vault_pki_secret_backend_config_urls" "jess_device_ca_urls" {
  backend                 = vault_mount.jess_device_ca.path
  issuing_certificates    = ["https://vault.example.com/v1/jess-device-ca/ca"]
  crl_distribution_points = ["https://vault.example.com/v1/jess-device-ca/crl"]
  ocsp_servers            = ["https://vault.example.com/v1/jess-device-ca/ocsp"]
}

resource "vault_pki_secret_backend_role" "jess_device_cert" {
  backend  = vault_mount.jess_device_ca.path
  name     = "device-cert"
  ttl      = 86400       # 24h default
  max_ttl  = 86400
  allow_subdomains = false
  allow_glob_domains = false
  allow_localhost = false
  allowed_domains = ["device.hexxlock.com"]
  enforce_hostnames = false
  client_flag = true
  server_flag = false  # client-cert only — Talon edge does NOT trust it as server
  use_csr_common_name = false
  use_csr_sans = true  # device-uuid SPIFFE SAN comes from CSR

  # No interpolation — the controller fully owns the CN + SANs after
  # attestation verification.
}
```

Atlantis MR pattern mirrors `vault-jess-ca.tf` + ADR 0035; expect 4
TF drifts on first apply (same shape as ADR 0035's bring-up).

### 3.b — Controller endpoint `/device-cert`

Wire `/device-cert` (port :7102, distinct from operator port :7101) on
the existing jess controller. Pattern mirrors `/operator-cert` per
ADR 0035 §3, but the input shape carries attestation evidence:

```jsonc
POST /device-cert
{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "platform": "tpm2-windows | tpm2-linux | apple-app-attest | android-key-attestation | macos-mdm",
  "attestation": {
    // Platform-specific blob; see §3.c verifiers below.
    // Examples:
    //   TPM 2.0 — { "ek_cert_pem": "...", "ak_pub_pem": "...", "ak_cert_pem": "...",
    //               "make_credential_blob": "...", "certify_info": "..." }
    //   Android — { "cert_chain_pem": ["..."] }  (chain incl OID 1.3.6.1.4.1.11129.2.1.17)
    //   App Attest — { "key_id": "...", "attestation_object_cbor_b64": "...", "client_data_hash": "..." }
    //   macOS MDM — { "mdm_assertion_jwt": "...", "app_attest_blob": { ... } }
    //
    // Each verifier returns:
    //   - device_uuid (canonical UUIDv4 — bound to the AK / SE key / Strongbox)
    //   - tier (TIER_CORP | TIER_BYOD per ADR 0040 D-006)
    //   - attestation_fingerprint (sha256 of the evidence — for replay protection)
  },
  "user_assertion": {
    // RFC 9449 DPoP proof that the user is authenticated AND consents to
    // the device-cert mint for THIS device. Bound to a Falcon-ID OIDC
    // ID token in cnf.jkt. Prevents an attacker who steals user creds
    // from minting a device-cert without the user's WebAuthn touch.
    "dpop_proof_jws": "...",
    "id_token": "..."
  }
}

201 Created
{
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "ca_chain_pem": ["..."],
  "expires_at": "2026-06-07T17:00:00Z",
  "device_uuid": "01HZZ...",
  "tier": "TIER_CORP"
}
```

CSR validation: `Common Name` ignored. `Subject Alternative Name` MUST
carry `spiffe://hexxlock.com/device/<device_uuid>` (D-005 SPIFFE
naming). Mismatch → 422.

### 3.c — Attestation verifiers

Per the Phase 0 research finding (Apple App Attest = app integrity not
device identity; no public SE chain), each platform has its own verifier
file. **Plan for 4 code paths** behind a `DeviceAttestation` interface
(D-001 acknowledgement).

```
internal/attestation/
├── doc.go                      // platform table + cross-refs
├── verifier.go                 // interface + dispatch
├── tpm2/
│   ├── verifier.go             // EK chain → AK → device-key Certify
│   ├── ek_roots.go             // 15-25 manufacturer roots (Intel, AMD,
│   │                           //   Infineon, STMicro, Nuvoton, MS test)
│   ├── ek_roots_test.go        // pinned-fingerprint smoke tests
│   └── shell_tpm2_tools.go     // FFI fallback to tpm2-tools (no Rust
│                               //   peer of go-attestation; Go has it)
├── android/
│   ├── verifier.go             // OID 1.3.6.1.4.1.11129.2.1.17 parser
│   ├── google_roots.go         // Google attestation CA chain (curated)
│   └── strongbox_test.go
├── appattest/
│   ├── verifier.go             // appattest-rs equivalent in Go
│   │                           // (PrismaPhonic/appattest reference)
│   └── apple_root.go           // Apple App Attest CA
├── macosmdm/
│   ├── verifier.go             // MDM JWT + App Attest layered
│   │                           // (residual risk R1 mitigation)
│   └── trusted_mdm_issuers.go  // Jamf, Kandji, Mosyle, JumpCloud
│                               //   tenant CA pinnings
```

Production rollout order (D-001 + research finding):
1. **TPM 2.0** (Linux) — easiest, full Go ecosystem via `go-attestation`
2. **Android key attestation** — port `google/android-key-attestation` Java to Go
3. **TPM 2.0** (Windows) — same code path as Linux + Microsoft PCP delegation
4. **Apple App Attest** — port `PrismaPhonic/appattest` to Go
5. **macOS MDM fallback** — last (depends on operator MDM selection: D-001 pending decision P-007)

### 3.d — Talon edge mTLS

Talon's Envoy listener gains a `clientTLS` config requiring a cert
chained to `jess-device-ca`. Pattern:

```yaml
# the GitOps repository envoy-gateway/envoy-cluster-config.yaml
spec:
  client_certificate_authentication:
    cert_authority_secret: jess-device-ca-bundle  # synced from Vault
    optional_client_certificate: false  # FAIL if no cert presented
    require_san_uri_match: "spiffe://hexxlock.com/device/.*"
```

Talon's posture verifier reads the presented cert's SAN, fingerprint
+ tier, and projects them into `RegoInputPosture.Compliance`:

- `compliance.device_cert_valid = true`
- `compliance.device_cert_fingerprint = sha256:<...>`
- `compliance.tier = TIER_CORP`  (or TIER_BYOD per cert SAN)

Posture JWT (ADR 0042 §2.3) is then optional — for TIER_CORP the
device-cert is the primary device-identity claim; the posture JWT
augments with continuous probes (disk encryption, screen lock, etc).

### 3.e — Cert lifecycle

- **Issuance**: HexxLock Access agent calls `/device-cert` on first
  install + on cert expiry warning (12h before exp).
- **Rotation**: agent watches local cert NotAfter; at 12h-remaining
  triggers re-mint. Atomic swap on success; rollback on fail.
- **Revocation**: jess admin endpoint `POST /device-cert/revoke` (mirror
  of operator-cert revoke). Triggers `vault_pki_secret_backend_cert_revoke`
  + CRLCache invalidation. Talon's edge listener pulls the CRL every
  5 min (mirror of operator-cert CRL cadence).
- **Re-enrollment** (lost device): user removes old cert via Falcon-ID
  account UI → triggers revoke. New device install triggers fresh
  mint with new device_uuid (NOT the old one — UUID is bound to the
  TPM/SE/StrongBox key).

### 3.f — Audit + observability

Per mint, emit:

- audit event `device_cert.minted` with `device_uuid`, `tier`, `attestation_fingerprint`, `user_sub`, `platform`
- audit event `device_cert.revoked` with `device_uuid`, `reason`
- Prometheus counter `jess_device_cert_minted_total{platform, tier}`
- Prometheus counter `jess_device_cert_revoked_total{reason}`
- Prometheus histogram `jess_device_cert_mint_duration_seconds{platform}`
- Per-platform attestation-verifier latency histogram

Operator Grafana dashboard `jess Device-Cert lifecycle` (Phase 8 scope).

## Consequences

### Positive

- Talon ZTNA Rego baseline (Phase 5) gates on `device_cert_valid` →
  closes BeyondCorp CBA (Certificate-Based Access) tier-1 requirement
- Reuses jess's existing Vault PKI + CRLCache + VerifyPeerCertificate
  infrastructure (ADR 0035) — no new operational primitive
- Per-platform verifier files keep the code paths independent —
  Apple's complexity doesn't pollute the TPM path
- Cert SAN = SPIFFE ID → future multi-cluster federation open (D-005)

### Negative

- Net-new attestation verification surface — 4 code paths × ~3-5 weeks each = 12-20 weeks if sequential
- macOS desktop trust ceiling remains BYOD without MDM (R1)
- TPM EK trust list curation is manual ongoing operational toil
  (Intel/AMD/Infineon/STMicro/Nuvoton release new roots periodically)
- Android key attestation requires Java reference port (no Rust crate)
  — pick Go via Java's BouncyCastle equivalent or port directly

### Open questions

| # | Question | Lock by |
|---|----------|---------|
| Q1 | Per-platform verifier rollout order? | This ADR §3.c locks: Linux TPM → Android → Win TPM → App Attest → macOS MDM |
| Q2 | TPM EK trust list source-of-truth? | Curate in `internal/attestation/tpm2/ek_roots.go`; refresh quarterly; document refresh runbook in Phase 9 |
| Q3 | MDM selection (Jamf, Kandji, Mosyle, JumpCloud)? | Operator decision — defer to D-001 pending P-007 |
| Q4 | Device-cert SAN canonical form? | `spiffe://hexxlock.com/device/<uuid>` (D-005); device_uuid is UUIDv4 |
| Q5 | Falcon-ID device registry? | New table `iam_devices(device_uuid, user_sub, tier, fingerprint, registered_at, last_seen_at)` — Phase 4 scope sibling MR |
| Q6 | Phase 3.d enforcement mode at edge — fail-closed from day 1? | NO — ship in shadow mode for 2 weeks per Phase 5.b rollout doctrine, then flip to enforcing |

## Implementation phases

| Sub-phase | What | Effort |
|-----------|------|--------|
| 3.a | Vault PKI mount + role TF + Atlantis MR | 2-3d |
| 3.b | Controller `/device-cert` endpoint + CSR validation | 3-4d |
| 3.c.1 | Linux TPM 2.0 verifier (Go via go-attestation) | 2 weeks |
| 3.c.2 | Android key attestation verifier | 2-3 weeks |
| 3.c.3 | Windows TPM 2.0 (delegates to 3.c.1 + PCP) | 1 week |
| 3.c.4 | Apple App Attest verifier | 2-3 weeks |
| 3.c.5 | macOS MDM fallback verifier | 1-2 weeks (after MDM selection P-007) |
| 3.d | Talon edge mTLS gate + posture projection | 1 week |
| 3.e | Cert lifecycle hooks (rotation + revocation) | 1 week |
| 3.f | Audit + observability | 3d |

**Total**: 5-7 weeks elapsed (with parallel attestation work) per Phase 0 D-007. Critical path: 3.a → 3.b → 3.c.1 → 3.d → 3.e.

## References

- Talon ADR 0040 — ZTNA Platform (Phase 3 = this ADR's scope)
- Talon ADR 0040-A — Threat Model (TD1..TD8 device-identity threats, R2 TPM revocation residual)
- jess ADR 0035 — hardware-bound operator-keys (sibling pattern)
- jess ADR 0042 — Talon integration (posture JWT contract)
- TCG EK Credential Profile v2.5 (Mar 2022)
- TCG EK-Based Key Attestation with TPM Firmware v1 RC1 (May 2025)
- AOSP Key + ID Attestation
- google/go-attestation (Go reference)
- google/android-key-attestation (Java reference; port target)
- Apple App Attest server SDK landscape (PrismaPhonic + TheDhejavu Rust references)
- Approov + Guardsquare research on Apple SE attestation gap (residual R1)
