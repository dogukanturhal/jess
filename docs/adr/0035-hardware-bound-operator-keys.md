# ADR 0035 Phase 5j-1 — Hardware-bound operator keys (PIV / YubiKey)

| | |
|---|---|
| **Status** | Proposed — design committed 2026-06-03; implementation deferred to a dedicated sprint |
| **Phase** | 5j-1 (substrate) — spawns 5j-1a..5j-1d sub-phases; further smart-card lifecycle work tracked as 5j-2+ |
| **Owners** | Platform / jess maintainers |
| **Supersedes** | none (extends Phase 5 operator-cert substrate; closes ADR 0034 §Decisions priority #1) |
| **Required by** | ADR 0034 §Decisions #1 ("Hardware-bound operator keys"); tier-1 PAM parity with Teleport `hardware_key_touch_and_pin` |

## Problem

Today every jess operator runs `jessctl up`, which generates an EC P-256 keypair **in-process** and writes the private key to `~/.config/jess/operator.key` at mode 0600. The corresponding cert is minted by the controller via Vault PKI mount `jess-ca` role `operator-cert` (max_ttl=8h, 1y root) and stored alongside as `operator.crt`. The cert+key pair drives mTLS to the operator port (`:7101`) per RFC 8705 §2.1 (`tls_client_auth`), with CN bound to the verified Falcon-ID subject.

This is the canonical **software-resident key** posture. It has three structural weaknesses:

1. **Exfiltration is a single-file read.** Anything that can read the operator's home directory (malware, backup theft, a misconfigured sync agent, a compromised IDE plugin, a snapshot-restore on a shared workstation) walks away with a key that mints valid mTLS sessions until the cert expires — up to 8h of unattended impersonation. Phase 4 CRL revocation (ADR 0034 §"jess current state") closes the window after-the-fact but not while the cert is live.
2. **No proof-of-presence per cert use.** A stolen key on a hijacked workstation can drive sessions unattended. There is no "the operator physically touched the device" signal anywhere in the stack.
3. **No proof-of-origin for the key.** The controller cannot tell whether the public key in the CSR was generated on a hardware boundary or on an exfiltrated software file. The cert chain has no attestation extension; Vault PKI signs anything the operator presents.

ADR 0034 §"Hardware-key enforcement" verified this as **the largest single-axis gap vs Teleport Enterprise**. Teleport's `hardware_key_touch_and_pin` mode (verified 5x 3-0 in the deep-research run) requires both touch AND PIN for every cert use; hardware-resident keys are non-exportable; attestation is validated at session-open. ADR 0034 §Decisions ranked this priority #1 with effort label M.

ADR 0034 §Decisions language, retained verbatim for the implementation owner:

> **Hardware-bound operator keys** — PIV/YubiKey 5+ enrollment; non-exportable private keys; cert binding via attestation. Match Teleport Device Trust. **Effort: M** — needs PIV CSR shape research + Vault PKI `attestation_validation` + `jessctl up --hardware` flag + ADR. Touches the lifetime of every operator cert.

This ADR is the design commitment for that work.

## Industry survey (2026-06)

Surveyed 6 vendors + 3 platform-native HSM substrates for operator-key hardware binding. Four dominant shapes:

| Pattern | Vendor / substrate | Key boundary | Attestation | Per-use enforcement |
|---|---|---|---|---|
| **PIV X.509 over USB-CCID** | Teleport Enterprise (PIV slot 9d default); HashiCorp Boundary (claim unverified per ADR 0034); CyberArk PSM (PIV-style); AWS Verified Access (via trust provider) | YubiKey 5 NEO/Nano/Bio/FIPS, generic PIV smart cards (NIST SP 800-73-4), iPhone Secure Enclave via PIV bridge tools (e.g., Yubico Authenticator on iOS, third-party PIV apps) | Per-vendor attestation cert chain (Yubico f9 + intermediate → Yubico Attestation Root 1 for firmware 5.7.4+; older devices use Yubico PIV CA roots or U2F root) | Touch policy (`never`/`cached`-15s/`always`) + PIN policy (`never`/`once`/`always`) configured at key-generation time, enforced by the device firmware on every private-key operation |
| **Apple Secure Enclave + macOS Keychain** | macOS-native (CryptoTokenKit, SecureEnclave); 1Password SSH agent; Krypton (deprecated); Tailscale tlskey | Secure Enclave (T2 / Apple Silicon); private key never leaves SoC; non-exportable by design | DCAppAttest / SEP attestation (proprietary, validated via Apple's attestation servers) | Touch ID / Face ID gate per use (`kSecAccessControlBiometryCurrentSet`) |
| **Windows Hello for Business + TPM 2.0** | Windows-native; Microsoft Entra; Microsoft Authenticator | TPM 2.0 (Pluton on newer SKUs); key sealed to platform PCRs | TPM attestation key (AIK / DevID per TCG spec) validated against Microsoft / OEM CA chains | Gesture (PIN / fingerprint / face) gate per use; PIN cached per logon session |
| **FIDO2 device certs (X.509)** | Cloudflare Access (FIDO2/PIV per ADR 0034); Pomerium; less common for traditional X.509 client-cert mTLS — most FIDO2 use is WebAuthn over CTAP2, NOT X.509 PIV | YubiKey 5 (FIDO2 applet), Solo Keys, Token2, NitroKey | FIDO MDS attestation (Metadata Service) | UV (user-verification) gesture per `authenticatorMakeCredential` / `authenticatorGetAssertion` |

Findings worth carrying:

1. **PIV is the only X.509-native substrate that runs cross-platform on commodity hardware.** Apple Secure Enclave and Windows TPM are platform-locked; FIDO2 is WebAuthn-native, not X.509-mTLS-native. PIV runs on Linux, macOS, Windows over USB-CCID (PCSC) with mature tooling (`go-piv`, OpenSC, `ykman`). Teleport's adoption is the strongest single signal — they explicitly chose PIV over TPM/SEP/FIDO2 for exactly this portability reason.
2. **YubiKey attestation is the reference chain.** Slot `f9` holds a pre-loaded YubiKey-specific attestation key signed by a Yubico PIV CA intermediate, which chains to Yubico's published root (firmware 5.7.4+ uses **Yubico Attestation Root 1**; older devices use the legacy Yubico PIV CA / U2F roots). The attestation cert for a key generated in slot `9a`/`9c`/`9d`/`9e` is signed by the f9 key and carries custom extensions encoding firmware version (OID `1.3.6.1.4.1.41482.3.3`), PIN policy (OID `1.3.6.1.4.1.41482.3.8` low byte), touch policy (same OID high byte), and form factor (OID `1.3.6.1.4.1.41482.3.9`). The very existence of an attestation cert from this chain proves on-device key generation.
3. **`go-piv/piv-go` v2 is the right Go library.** Current release v2.6.0 (April 2026), v2 import path `github.com/go-piv/piv-go/v2/piv`. macOS and Windows are zero-prereq (built-in PCSC); Linux needs `libpcsclite-dev` (Debian) / `pcsc-lite-devel` (Fedora/CentOS/FreeBSD). The Windows path is flagged "best effort due to lack of test hardware" in the upstream README — a real risk for our build matrix. PKCS#11 is the alternative but adds a per-OS shim (`opensc-pkcs11.so` / Windows minidriver / `libykcs11.dylib`) for marginal benefit; **recommend `go-piv` for portability + auditability**.
4. **Teleport's slot choice is 9d (key-management), NOT 9a (authentication).** Per Teleport docs, `hardware_key_touch_and_pin` uses slot 9d by default with `--piv-slot` / `TELEPORT_PIV_SLOT` overrides. The rationale isn't documented in primary sources, but slot 9d's PIN-policy default is `once`/`always` (vs slot 9a's typical `never`/`once`) which aligns with the "PIN every cert use" posture. **jess will use slot 9a** to keep the mental model simple (slot 9a is the canonical "authentication" slot per NIST SP 800-73-4 §3.3.2) and configure PIN policy explicitly at key-generation time. Open question #2 below — revisit if Windows minidriver behavior forces a slot change.
5. **The CredSSP smart-card flow from ADR 0033 §5f-8b-3 is a sibling, not the same thing.** ADR 0033 mints a short-lived smart-card cert via Vault PKI for the BROKER to present to Windows AD as the operator's logon credential (no operator-side hardware). This ADR (0035) puts the OPERATOR's own private key into hardware on their workstation. Both can ship independently; they share zero code.

## Decision

**Adopt PIV (X.509 over USB-CCID) as the primary HSM substrate for operator keys.** Devices: YubiKey 5 series (NEO, Nano, Bio, FIPS variants) as the reference target; generic PIV-compliant smart cards (NIST SP 800-73-4) supported by extension; iPhone Secure Enclave via third-party PIV bridge apps as a non-reference fallback. TPM 2.0 (Windows + Linux) tracked as a **secondary** substrate behind a separate Phase 5j-2 ADR.

**Reasons for PIV over alternatives**:

- **Cross-platform** — Linux / macOS / Windows via PCSC; no platform lock-in.
- **X.509-native** — produces a CSR + cert directly consumable by Vault PKI; no WebAuthn↔X.509 bridge code.
- **Attestation is mature** — Yubico's chain is well-documented, public roots, in-the-wild deployments (Teleport, AWS IAM Roles Anywhere, Smallstep, FreeIPA).
- **Tier-1 vendor consensus** — Teleport's choice is the same; CyberArk PSM's PIV-style flow is the same; Boundary's hardware-key-claim is unverified but documented PIV-shaped.

To minimise risk and time-to-shipped-cert, split into four sub-phases that each ship independently:

```
5j-1a (~1 week)   — jessctl up --hardware flag + on-device key gen + CSR
                     with attestation chain. Soft-attested: controller logs
                     the chain but does NOT yet reject software-key CSRs.
                     Operator end-to-end gets a hardware-bound cert; no
                     enforcement.

5j-1b (~1.5 weeks) — Controller-side attestation validation. Signer interface
                     gets ValidateAttestation(csr). Vault PKI role
                     `operator-cert-hardware` requires the Yubico chain to
                     verify against pinned Yubico CA roots. Issued cert
                     tagged with hardware_key_attested=true in OU SAN or
                     X.509 extended-key-usage. CRL field carries the
                     attestation hash so revocation propagates.

5j-1c (~1 week)   — Touch + PIN enforcement. Operator client re-prompts PIN
                     per cert use (sliding window cache configurable 0 /
                     15min / 8h). Touch indication per Teleport's pattern:
                     touch policy cached (15s) / always / never. SPA badge
                     surfaces "hardware-attested" on the session bar.

5j-1d (~1.5 weeks) — Target-side enforcement. Controller rejects software-
                     key certs for catalog targets tagged
                     `high_criticality=true`. Soft-mode warning for the
                     transition window (env flag JESS_HARDWARE_REQUIRED=
                     warn|enforce). After transition window expires,
                     enforce is the default.
```

**Default posture after 5j-1d ships** = all operator certs that touch a `high_criticality` target MUST chain to a Yubico attestation root and MUST carry the `hardware_key_attested=true` tag. Non-attested certs remain valid for non-critical targets (admin SPA login, catalog browse) so operators without hardware tokens can still do read-only ops while procurement rolls out.

**Hardware procurement assumption** — every active jess operator has at minimum a YubiKey 5 NFC (USB-A or USB-C) or YubiKey 5 Bio. Spare devices stored in the platform safe. Replacement / loss workflow is OUT of this ADR (see §"Out of scope"); a separate Phase 5j-2 ADR will scope it.

## Implementation slices

### 5j-1a — `jessctl up --hardware` flag + on-device key gen + CSR with attestation chain

**Files:** `cmd/jessctl/up.go` (extend), `cmd/jessctl/internal/piv/piv.go` (new), `cmd/jessctl/internal/piv/attestation.go` (new), `internal/admin/operator_cert.go` (CSR validation entrypoint already exists — extend to accept attestation chain in CSR extensions), `go.mod` (add `github.com/go-piv/piv-go/v2 v2.6.0`).

**Sequence:**

1. Operator runs `jessctl up --hardware` (or `--hardware-slot=9a` to override). Default slot is 9a.
2. `jessctl` opens the first PIV-compliant card via `piv.Cards()` + `piv.Open(name)`. Error if none found, with a printed list of detected smart-card readers for debug.
3. Prompt for management key (default `010203040506070801020304050607080102030405060708` — operator can override via `--management-key=hex` or `JESSCTL_PIV_MGMT_KEY`). Prompt for PIN (default `123456` — operator MUST change before production use; `jessctl` prints a warning).
4. Generate EC P-256 key in slot 9a: `yk.GenerateKey(managementKey, piv.SlotAuthentication, piv.Key{Algorithm: piv.AlgorithmEC256, PINPolicy: piv.PINPolicyAlways, TouchPolicy: piv.TouchPolicyAlways})`. PIN+touch policy MUST be `Always` for the operator-cert use case; the controller will reject CSRs whose attestation cert encodes weaker policies (enforced in 5j-1b).
5. Retrieve the slot attestation cert: `slotAttCert := yk.Attest(piv.SlotAuthentication)`. This cert is signed by the YubiKey's slot-f9 attestation key.
6. Retrieve the intermediate attestation cert (f9): `interAttCert := yk.AttestationCertificate()`. This cert is signed by a Yubico CA root.
7. Build CSR using `crypto/x509.CreateCertificateRequest` with the slot-9a key as signer (via `piv.Auth{PIN: pin}` PIN-prompted `crypto.Signer`). CSR subject CN = verified Falcon-ID subject (resolved during the existing `jessctl up` OIDC dance). Embed the two attestation certs as a custom CSR extension `1.3.6.1.4.1.99999.1.1.1` (placeholder — pick a real HexxLock PEN once allocated) carrying a DER-encoded `SEQUENCE { slotAttCert, interAttCert }`.
8. POST CSR to controller `/v1/operator-cert/sign` (existing endpoint). Controller signs via Vault PKI as today; in 5j-1a it does NOT validate the attestation extension (soft mode). Controller LOGS the attestation chain (with operator sub + cert serial) at INFO level so we have a corpus for 5j-1b regression tests.
9. Controller returns the signed cert; `jessctl` writes it to `~/.config/jess/operator.crt` as today. The PRIVATE KEY IS NOT WRITTEN to disk — `operator.key` is absent when `--hardware` is used. mTLS at runtime uses `tls.Config.GetClientCertificate` with a `crypto.Signer` backed by the PIV slot (PIN-prompted per use).

**Acceptance:**
- Lab YubiKey 5 NFC + a fresh `jessctl up --hardware` produces a cert without writing `operator.key`. Controller logs the attestation chain at INFO. Operator opens an existing SSH grant against `node-app-01` — session works; PIV prompts for PIN+touch on the first connect.
- `jess_operator_cert_hardware_total{result="ok",substrate="piv-yubikey"}` increments.
- Linux (Debian/Ubuntu) verified manually; macOS verified manually. **Windows verified manually** — Windows is the long pole (see §"Cross-cutting" build matrix); this acceptance gate is the early canary.

**Risk:** PCSC contention on Linux when `pcscd` is already holding the reader for `gpg-agent` or a Yubico-Authenticator-style desktop app. Mitigation: `jessctl up --hardware` detects the conflict and prints "Close other smart-card applications and retry" with a one-line `lsof /var/run/pcscd/pcscd.comm` debug hint. Open question #1 below — should `jessctl` attempt to evict the holder?

### 5j-1b — Controller-side attestation validation

**Files:** `internal/admin/operator_cert.go` (`Signer` interface gains `ValidateAttestation(csr *x509.CertificateRequest) (*AttestationResult, error)`), `internal/admin/attestation/yubico.go` (new — pinned Yubico CA roots + intermediate-cache + verify), `internal/admin/attestation/policy.go` (new — `PINPolicyAlways` + `TouchPolicyAlways` enforcement), `infrastructure-iac/datacenters/eu-west-1/vault/vault-jess-pki.tf` (extend — add Vault PKI role `operator-cert-hardware`).

**Sequence:**

1. CSR arrives at `/v1/operator-cert/sign` carrying the attestation extension from 5j-1a.
2. `ValidateAttestation` extracts the two certs from the extension. Verifies:
   - **Chain validity** — intermediate signed by a pinned Yubico CA root (we embed all currently-published Yubico CA roots in `internal/admin/attestation/yubico_roots.go`; this list is updated via PR when Yubico publishes a new root, with a CI test asserting the embedded set matches the upstream Yubico CA repository).
   - **Slot cert validity** — slot cert signed by the intermediate. EC P-256 signature verify.
   - **Policy claims** — parse the custom extensions: firmware version OID `1.3.6.1.4.1.41482.3.3`, PIN policy + touch policy OID `1.3.6.1.4.1.41482.3.8`, form factor OID `1.3.6.1.4.1.41482.3.9`. Require firmware ≥ 5.4.3 (PIN policy `always` available); require PIN policy = `always` (0x03); require touch policy = `always` (0x02) OR `cached` (0x03) — `never` (0x01) is rejected.
   - **Subject binding** — CSR public key MUST equal slot-attestation-cert public key (this is the structural binding that makes the attestation MEAN anything; without it an attacker could attach any attestation chain to any CSR).
3. On success, mark the issuance request for Vault PKI role `operator-cert-hardware` (separate role from existing `operator-cert`). Vault config: `allowed_other_sans = "hardware_key_attested=true"` enforced via Vault PKI policy template. Issued cert carries `OU=hardware_key_attested:true` in subject for SPA/CLI visibility, and a custom extension `1.3.6.1.4.1.99999.1.1.2` carrying a SHA-256 hash of the slot-attestation-cert so CRL revocation can target a specific device.
4. On failure, controller returns HTTP 400 with the specific validation error (chain failed / policy mismatch / public-key mismatch). `jess_operator_cert_attested_total{result="<reason>"}` increments.

**Acceptance:**
- Same lab YubiKey from 5j-1a now produces a cert with `OU=hardware_key_attested:true`. SPA session bar surfaces a "Hardware-attested" badge.
- Tampered CSR (attestation cert replaced with an unrelated valid Yubico chain) is rejected with `result="csr_pubkey_mismatch"`.
- Software-key CSR (no attestation extension) is rejected with `result="no_attestation"` on the `-hardware` endpoint; still accepted on the legacy `/v1/operator-cert/sign` endpoint until 5j-1d makes it the default.
- Vault audit log shows the role split (`operator-cert` vs `operator-cert-hardware`).

**Risk:** Yubico publishes new CA roots periodically (the 5.7.4 firmware shift to "Yubico Attestation Root 1" caught the ecosystem off-guard in 2024). CI test must fetch the upstream list and fail if a new root appears without an embedded match — surfaces the gap loudly rather than silently failing attestation for new devices.

### 5j-1c — Touch + PIN enforcement (per-use + sliding window cache)

**Files:** `cmd/jessctl/internal/piv/signer.go` (PIN cache + touch wrapping `crypto.Signer`), `cmd/jessctl/up.go` (CLI flags `--pin-cache-ttl=0|15m|8h`, default 15m), `cmd/jess-web/web/src/components/SessionBar.tsx` (badge + touch-pending toast).

**Sequence:**

1. Operator opens a session; `jessctl` (or the worker, if the operator went through the SPA flow) calls `crypto.Signer.Sign` on the PIV-backed key.
2. The signer wrapper checks the PIN cache:
   - Cache miss / expired → prompt for PIN via OS dialog (`pinentry` on Linux, native dialog on macOS, Win32 dialog on Windows). On success, cache the PIN for the configured TTL (default 15 minutes; `0` = always-prompt; `8h` = cert lifetime).
   - Cache hit → reuse PIN.
3. Send the PIN to the PIV applet via `yk.PrivateKey(slot, pubKey, piv.KeyAuth{PIN: pin})` then `.Sign(...)`. With `TouchPolicyAlways`, the YubiKey LED flashes; user has 15s to touch. With `TouchPolicyCached`, only the first sign within a 15s window requires touch.
4. SPA emits a `session.touch_pending` event; SessionBar shows "Touch your YubiKey now" toast for 15s. Auto-clears on signature complete or timeout.
5. Telemetry: `jess_operator_pin_prompts_total{result=ok|cancelled|timeout}`, `jess_operator_touch_prompts_total{result=ok|timeout|cancelled}`.

**Acceptance:**
- `jessctl ssh node-app-01` with `--pin-cache-ttl=15m` prompts PIN once, prompts touch on every TCP-stream open within the 15-minute window. After 15 minutes, prompts both again.
- SPA badge correctly reflects cache state (hardware-attested green; PIN-cached blue; PIN-expired yellow).
- PIN failure 3 times locks the YubiKey PIV applet (device behavior, not jess); `jessctl` prints the recovery instruction (`ykman piv access unblock-pin`).

**Risk:** PIN cache stored in the operator's process memory; if `jessctl` is a long-lived daemon (which `jessctl up` *is* once we move past one-shot), the cache becomes a small attack surface. Mitigation: `zeroize` the byte slice on TTL expiry and on `jessctl` exit; do NOT page-lock (mlock has too many cross-platform footguns for marginal benefit at this threat tier).

### 5j-1d — Controller rejects software-key certs for high-criticality targets

**Files:** `internal/admin/grant.go` (extend grant-eligibility check), `internal/catalog/target.go` (add `HighCriticality bool` field — already exists as `risk_score` in Phase 5h-4a; reuse and threshold at score ≥ 80), `cmd/jessctl/admin/grant.go` (surface rejection reason), helm `values.yaml` (env `JESS_HARDWARE_REQUIRED=warn|enforce`, default `warn` for soft-launch window).

**Sequence:**

1. Operator requests a grant against a target with `risk_score ≥ 80`. Existing 5b JIT flow.
2. Approve-side check: read the operator's most-recent cert from `jit_sessions` table (we already store cert serial there). Look up `cert_extensions` to determine if `hardware_key_attested=true` is present.
3. If `JESS_HARDWARE_REQUIRED=enforce` and cert is not attested → reject grant with `reason="hardware_key_required"`. SPA shows a help link: "This target requires a hardware-bound key. Run `jessctl up --hardware` to enroll."
4. If `JESS_HARDWARE_REQUIRED=warn` → grant succeeds, audit-event records `hardware_key_warning=true`, SPA shows a yellow banner.
5. Default stays at `warn` for the 30-day transition window after 5j-1c ships. Operator-comms email goes out at warn-day-0; flip to `enforce` at warn-day-30.

**Acceptance:**
- Operator with software-key cert can request a low-criticality grant (works), high-criticality grant in `warn` mode (works with banner), high-criticality grant in `enforce` mode (rejected with clear reason).
- Operator with hardware-key cert always works.
- `jess_operator_cert_hardware_required_target_total{result=allowed|warned|denied}` tracks the cohort over the transition window.

**Risk:** Mis-tagged catalog target (something marked high-criticality that operators rely on for daily work) creates a hard block. Mitigation: 5j-1d's enforce flip is gated behind the 30-day warn period AND requires a manual `kubectl set env` flip — no automatic clock-driven escalation.

## Cross-cutting concerns

### Go dependency notes

- **`github.com/go-piv/piv-go/v2 v2.6.0`** — exact pin, not `^` semver. piv-go's v2 release reset import paths and any future v3 will need an audit.
- **`github.com/hashicorp/vault/api`** already in go.mod for existing PKI calls; no new Vault dependency.
- **`crypto/x509` + `encoding/asn1`** for CSR extension construction — stdlib.

### Rust dependency notes (jess-ironrdp-broker)

The Rust broker does NOT participate in operator-key hardware binding (operator mTLS terminates at the controller, not the broker). The broker's own service cert is unaffected. ADR 0033 §5f-8b-3's broker-minted smart-card cert is a separate flow (broker as PRESENTER, not operator-key boundary).

### PCSC system dependencies per OS

| OS | Dependency | Install command | Notes |
|---|---|---|---|
| Debian/Ubuntu Linux | `libpcsclite1` runtime + `libpcsclite-dev` build | `apt install libpcsclite1 pcscd` | `pcscd` daemon must be running |
| RHEL/Fedora/CentOS | `pcsc-lite` runtime + `pcsc-lite-devel` build | `dnf install pcsc-lite pcsc-lite-devel` | `pcscd` daemon must be running |
| macOS | Built-in CryptoTokenKit + PCSC framework | none | Zero-prereq per go-piv README |
| Windows | Built-in Microsoft smart-card minidriver | none | Yubico Smart Card Minidriver optional; go-piv README flags Windows as "best effort due to lack of test hardware" — **expect debug time** |
| FreeBSD | `pcsc-lite` package | `pkg install pcsc-lite` | `jessctl` build supported but not gated in CI |

### Build matrix changes

CI lane changes for `jessctl`:

| Target | OS | Arch | New step |
|---|---|---|---|
| `jessctl-linux-amd64` | Linux | amd64 | Install `libpcsclite-dev` in builder image; build with `CGO_ENABLED=1` (piv-go uses cgo for PCSC) |
| `jessctl-linux-arm64` | Linux | arm64 | Same as above, ARM64 cross-build |
| `jessctl-darwin-amd64` | macOS | amd64 | No dep; cgo enabled on macOS runner |
| `jessctl-darwin-arm64` | macOS | arm64 | Same |
| `jessctl-windows-amd64.exe` | Windows | amd64 | No dep; cgo with MinGW or MSVC toolchain — **NEW lane, today's CI doesn't build Windows** |

The Windows lane is **new work**, not a tweak. Today `jessctl` is built for Linux + macOS only (no Windows operators in current cohort). Adding the Windows lane is a prerequisite for 5j-1a's Windows acceptance gate. Estimate +2 days of CI plumbing.

### Telemetry

| Metric | Type | Labels | Phase |
|---|---|---|---|
| `jess_operator_cert_hardware_total` | counter | result (ok\|piv_unavailable\|gen_failed\|csr_failed), substrate (piv-yubikey\|piv-generic) | 5j-1a |
| `jess_operator_cert_attested_total` | counter | result (ok\|chain_invalid\|policy_weak\|csr_pubkey_mismatch\|no_attestation\|unknown_root) | 5j-1b |
| `jess_operator_pin_prompts_total` | counter | result (ok\|cancelled\|timeout\|piv_locked) | 5j-1c |
| `jess_operator_touch_prompts_total` | counter | result (ok\|timeout\|cancelled) | 5j-1c |
| `jess_operator_cert_hardware_required_target_total` | counter | result (allowed\|warned\|denied), target_id | 5j-1d |
| `jess_operator_cert_attestation_validation_duration_seconds` | histogram | result | 5j-1b |

### Audit events

- `operator.cert.attested` — operator cert signed via hardware path; payload includes serial + Yubico attestation cert hash + policy values + firmware version.
- `operator.pin.entered` — PIN entered (NOT the PIN value); payload includes operator sub + cache TTL setting + cache-hit-or-miss.
- `operator.touch.completed` — physical touch confirmed; payload includes operator sub + slot + signature target (cert use, e.g., session-open).
- `grant.hardware_required.denied` — grant denied because target requires hardware key.

## Failure modes worth alerting

- **Operator cert reuses unattested key on hardware-required target** — `jess_operator_cert_hardware_required_target_total{result=denied}` rate > 5/h sustained 1h. Likely cause: an operator dropped/lost a token mid-shift; surface to the on-call so a replacement can be expedited.
- **Attestation chain doesn't validate** — `jess_operator_cert_attested_total{result=chain_invalid}` non-zero. Likely cause: new Yubico root not yet embedded; could also be a counterfeit device or device tampering. CRITICAL-tier; page the platform on-call.
- **Touch timeout exceeded** — `jess_operator_touch_prompts_total{result=timeout}` rate sustained suggests operator UX problem (LED not visible, dongle unreachable, RDP-through-RDP scenario where the touch can't propagate). Surface to ops for runbook tuning.
- **PIN unlock failures** — `jess_operator_pin_prompts_total{result=piv_locked}` non-zero means an operator's YubiKey is bricked at the PIV applet level (3 wrong PINs locks; 3 wrong PUKs blocks). Replacement workflow required (Phase 5j-2 scope).
- **Yubico root drift** — CI test that fetches upstream Yubico CA list and diffs against embedded fails. Treated as a build failure, blocks merges to main until the new root is embedded.

## Out of scope

- **Operator smart-card replacement / loss workflow** — when an operator loses their YubiKey, how does the org issue a new one with continuity? Includes PUK escrow, attestation-rebinding, CRL flooding considerations. Tracked as **Phase 5j-2**.
- **FIDO2 attestation as an alternate substrate** — WebAuthn-native; would need a separate cert-binding flow (FIDO2 doesn't natively produce X.509 CSRs). Tracked as Phase 5j-3 if demand materializes.
- **MDM-managed PIV provisioning** — auto-enrolling YubiKeys via an MDM (Jamf, Intune) instead of `jessctl up --hardware`. Useful for fleet rollouts but introduces an MDM dependency that we don't have today. Phase 5j-4.
- **TPM 2.0 as primary substrate (Windows / Linux)** — secondary substrate for environments where PIV tokens aren't feasible. Phase 5j-5; separate ADR for the substrate-specific attestation flow (Microsoft / OEM CA chains vs Yubico).
- **Apple Secure Enclave native binding** — would require a macOS-native code path (CryptoTokenKit + SEP); platform-locked. Phase 5j-6 if demand materializes; the PIV-bridge fallback is the recommended interim.
- **Hardware-bound BROKER service certs** — broker svc-cert is a workload cred, not an operator cred; covered by ADR 0034 §Decisions #6 (SPIRE-based worker mTLS), not here.
- **Hardware-bound CONTROLLER signing key** — controller's Vault PKI sign-leg is already protected by Vault's own root key + Transit; hardware-binding the controller's Vault token is a Vault-tier decision, not jess-tier.

## Timeline summary

| Sub-phase | Estimate | Blockers |
|---|---|---|
| 5j-1a | ~1 week | Windows CI lane (+2 days plumbing if no Windows builder exists today) |
| 5j-1b | ~1.5 weeks | Vault PKI role `operator-cert-hardware` via infrastructure-iac MR (1-day TF + apply) |
| 5j-1c | ~1 week | Cross-OS PIN-prompt UX (`pinentry` on Linux, native dialogs on macOS / Windows) |
| 5j-1d | ~1.5 weeks | 30-day soft-mode warn window must elapse before enforce flip — extends real wall-clock past the engineering estimate |

**Realistic total wall-clock:** 4-6 weeks engineering for a single engineer (5j-1a..d), then a further 30-day soft-mode period before `enforce` is the default. Smart-card replacement workflow (Phase 5j-2) is the natural follow-on.

**Risk concentration:** PIV PKCS#11 cross-platform debug, **especially the Windows minidriver path**, is the long pole. go-piv's "best effort" Windows posture means we should expect 1-2 weeks of pure debugging on Windows-specific quirks (smart-card cache eviction, minidriver vs vendor-driver conflicts, RDP-session PIV pass-through, multi-reader enumeration ordering). Mitigation: identify a Windows-primary operator early and pair-debug; budget the 1-2 weeks explicitly rather than hoping it converges.

## Open questions

1. **Should `jessctl up --hardware` attempt to evict competing PCSC clients (gpg-agent, Yubico Authenticator) when reader contention is detected?** Eviction is intrusive (kills the other app's session) but avoids a confusing failure mode. **Recommend: print + abort in 5j-1a; revisit eviction in 5j-1c if support load warrants it.**
2. **PIV slot — 9a (authentication) vs 9d (key-management).** Teleport defaults to 9d; jess plan defaults to 9a. The choice affects PIN-policy defaults and which existing operator workflows we collide with (e.g., operators who already use 9a for SSH via `ykman piv key import`). **Recommend: default 9a, allow `--hardware-slot=9d` override, revisit if Windows minidriver behavior or operator-collision incidents materialize.**
3. **Attestation extension OID — placeholder `1.3.6.1.4.1.99999.1.1.1` until HexxLock has a real Private Enterprise Number (PEN) allocated from IANA.** Should we apply for a PEN now (~2 weeks IANA processing) or ship with the placeholder and rename later? **Recommend: apply for the PEN in parallel with 5j-1a; if not allocated by 5j-1b merge, ship with placeholder and rename in a follow-up (custom OIDs in X.509 extensions are renameable without crypto rebinding because the verify path looks them up by OID).**
4. **Soft-mode warn window length — 30 days vs 60 days vs 90 days.** Trade-off: shorter = pressure to enroll; longer = less risk of locking a real operator out. **Recommend: 30 days for the first 5 operators (early-adopter cohort), 60 days for the broader rollout, configurable via `JESS_HARDWARE_REQUIRED_WARN_DAYS` env. Decide cohort size at 5j-1d merge time based on procurement pace.**

## References

### Primary sources (vendor docs, NIST official, IETF, library docs)

| Source | Topic | Quality |
|---|---|---|
| https://goteleport.com/docs/zero-trust-access/authentication/hardware-key-support/ | Teleport `hardware_key_touch_and_pin` — slot 9d default, touch/PIN policy options, PIN cache TTL (≤1h), Teleport Connect as Hardware Key Agent | primary |
| https://developers.yubico.com/PIV/Introduction/PIV_attestation.html | YubiKey PIV attestation — slot f9, intermediate cert, Yubico Attestation Root 1 (firmware 5.7.4+), custom extension OIDs (1.3.6.1.4.1.41482.3.3/.8/.9) | primary |
| https://github.com/go-piv/piv-go | go-piv v2.6.0 — import path `github.com/go-piv/piv-go/v2/piv`, OS support matrix (Linux/macOS/Windows), PCSC dependencies | primary |
| https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration | Microsoft smart-card logon — EKU `szOID_KP_SMARTCARD_LOGON`, SAN otherName msUPN (OID `1.3.6.1.4.1.311.20.2.3`), `AT_KEYEXCHANGE` key type, KDC validation flow | primary |
| https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf | NIST SP 800-73-4 — PIV card application data model, slot 9a (authentication) / 9c (signature) / 9d (key-management) / 9e (card-auth) definitions | primary |
| https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-5.pdf | NIST SP 800-78-5 — PIV cryptographic algorithms (EC P-256, RSA 2048+) | primary |
| https://github.com/OpenSC/OpenSC | OpenSC — open-source PIV/PKCS#11 alternative if `go-piv` proves insufficient for non-YubiKey PIV cards | primary |
| https://datatracker.ietf.org/doc/html/rfc8705 | RFC 8705 §2.1 `tls_client_auth` — jess's existing mTLS posture (unchanged by this ADR) | primary |
| https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enabling-smart-card-logon-third-party-certification-authorities | Microsoft KB on enabling smart-card logon with 3rd-party CA — referenced for AD CA cross-trust setup (relevant to ADR 0033 §5f-8b-3, NOT this ADR's operator-key flow; included for completeness) | primary (note: original KB 281245 URL 404s in 2026; canonical now lives at the smart-card-certificate-requirements URL above) |

### Cross-references within jess docs

- ADR 0030 — Phase 5 substrate (operator-cert mTLS substrate this ADR modifies)
- ADR 0033 — Rust IronRDP bridge §5f-8b-3 (broker-minted smart-card cert flow — sibling, not the same)
- ADR 0034 — Tier-1 ZTNA enhancements §Decisions #1 (the priority this ADR closes); §"Hardware-key enforcement" verified-finding (the gap this ADR closes)

### Workflow provenance

This ADR was drafted from:
- The two reference ADRs (0033 + 0034) for structure + style + verified industry-survey citations.
- WebFetch confirmation of: Yubico PIV attestation flow (developers.yubico.com), go-piv current version + OS matrix (github.com/go-piv/piv-go), Teleport `hardware_key_touch_and_pin` enforcement details (goteleport.com), Microsoft smart-card certificate requirements (learn.microsoft.com).
- No new deep-research workflow run — this ADR's industry survey reuses the verified claims from ADR 0034's two runs (wf_3e0e634d-669 + wf_51615894-030, 204 agents, 30 verified claims).

This ADR is **design-only**. Implementation is deferred until the platform owner allocates the sprint; in the meantime, any operator who wants to experiment with `jessctl up --hardware` against a personal YubiKey can do so against a feature-branch build, but the controller-side validation (5j-1b) and target-side enforcement (5j-1d) are pre-conditions for production posture.
