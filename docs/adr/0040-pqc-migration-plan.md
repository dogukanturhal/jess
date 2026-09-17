# ADR 0040 — Post-quantum cryptography migration plan

| | |
|---|---|
| **Status** | Proposed — **planning only** (no code today; tracking ADR with quarterly review cadence) |
| **Phase** | 5k (deferred, planning) |
| **Owners** | Platform / jess maintainers |
| **Required by** | ADR 0034 §Decisions priority #10 — "PQC migration plan" |
| **Date** | 2026-06-03 |

## Problem

Sufficiently large fault-tolerant quantum computers (when they arrive) break the asymmetric primitives jess relies on today: X25519 (TLS 1.3 key exchange), ECDSA P-256 (operator-cert + Vault PKI signatures), and Ed25519 (WORM recording signatures via Vault Transit). The threat is not theoretical for **data-in-flight today** — adversaries already harvest TLS traffic for future decryption ("harvest-now-decrypt-later" / HNDL). Recording manifests signed today with ECDSA P-256 will lose their non-repudiation property the moment a CRQC (cryptographically relevant quantum computer) exists.

NIST finalised the first three post-quantum standards in 2024 — FIPS 203 (ML-KEM, key encapsulation), FIPS 204 (ML-DSA, signatures), FIPS 205 (SLH-DSA, hash-based signatures). NIST IR 8547 (draft Aug 2024) sets the federal migration roadmap: **hybrid PQ key establishment by 2030, PQ signatures by 2035**. NSA's CNSA 2.0 sets tighter National Security System deadlines. IETF `draft-ietf-tls-ecdhe-mlkem` defines hybrid TLS 1.3 named groups (X25519MLKEM768 = code point 0x11EC / 4588) and is in IESG Last Call ending 2026-06-09.

jess today (2026-06) ships **zero PQC**:
- All TLS listeners (operator port `:7101`, admin port `:7103`, worker mTLS) negotiate classical X25519 only.
- All signatures (operator cert, recording manifest, audit chain) use classical ECDSA P-256 + Ed25519.

This ADR commits jess to a **planning posture, not a code change**. Go's `crypto/tls` does not yet expose `X25519MLKEM768` to applications, Vault Transit does not yet expose ML-DSA / ML-KEM, and the IETF draft hasn't reached RFC. Shipping PQC code today would be premature and would re-implement primitives Go is about to ship for us in 2027. What we **can** commit to today is: a milestone schedule, day-from-now telemetry that lets us measure rollout when it happens, and a clear set of no-go gates.

## Industry survey (2026-06)

Verified live during ADR drafting (deep-research output cited where relevant):

### Cloudflare — operational leader

Per `blog.cloudflare.com/pq-2025/` (verified 2026-06-03): Cloudflare enabled X25519MLKEM768 server-side **for basically all customers in 2022**; as of late October 2025 **>50% of human-initiated traffic to Cloudflare uses post-quantum key agreement** and rising. Major TLS libraries (OpenSSL 3.5+, Go 1.24+, Chrome 124+, Apple TLS) ship X25519MLKEM768 enabled by default. Cloudflare explicitly frames PQ key-agreement as **"the new security baseline for the Web."** PQ **signatures and certificates** are **not yet deployed** (large cert sizes block TLS handshake performance — same blocker we face).

### Google / Chrome

PQ-Hybrid (X25519Kyber768Draft00, later X25519MLKEM768) enabled by default for TLS connections to Google services since Chrome 116 (Aug 2023, draft); rolled forward to the IETF standard codepoint in Chrome 124+ (2024). Chrome enterprise policies allow PQ-Hybrid to be disabled but it is **on by default**.

### Microsoft

Windows 11 and Windows Server 2025 added SymCrypt PQ algorithm support in 2024-2025. TLS PQ in `schannel` is staged — present in test builds, default-off as of 2026-06.

### AWS

KMS supports PQ-Hybrid for the KMS API endpoint (TLS layer); AWS Verified Access and ACM PQ posture is **roadmap, not GA** as of 2026-06 (last verified AWS re:Invent 2025 keynote).

### HashiCorp Vault

Per `hashicorp.com/blog/nist-s-post-quantum-cryptography-standards-our-plans` (verified 2026-06-03): **staged rollout starting with Vault Transit secrets engine** for the three NIST-standardised algorithms (ML-KEM, ML-DSA, SLH-DSA). Hybrid schemes for in-transit and other secrets engines tracked separately. PKI engine PQ support is **gated on Go stdlib readiness** ("when the Go programming language and the standards bodies arrive at consensus in terms of maturity for hybrid schemes"). **No firm dates published.**

### Go stdlib

Per `github.com/golang/go/issues/64537` (verified 2026-06-03): X25519MLKEM768 KEM landed in Go 1.24 (Feb 2025) **gated behind a GODEBUG option**, transparent to applications. The Go team's stated philosophy is conservative — internal-first, GODEBUG-controlled, no public API for application-level configuration until the IETF draft is published as an RFC. ML-DSA signatures are tracked in a separate proposal and have **not landed** as of 2026-06.

### IETF status

`draft-ietf-tls-ecdhe-mlkem` is in IESG Last Call **ending 2026-06-09** (six days from this ADR). Code point 0x11EC (4588) is IANA-allocated. Once published as RFC, Go's GODEBUG default flips and `crypto/tls` exposes the named group as a public constant.

### Tier-1 PAM vendors (PQC posture)

ADR 0034 §Decisions #10 + §Pending-research item F notes that PQC posture of Teleport, Boundary, and StrongDM was **not verified** in the prior research run. Per public docs spot-checked 2026-06-03:
- Teleport: no published PQC plan.
- HashiCorp Boundary: inherits Vault's PQ posture (staged via Transit).
- StrongDM: no published PQC plan.

**Synthesis**: PQ key agreement is the new web baseline (Cloudflare, Chrome, OpenSSL, Go). PQ signatures and certificates are not yet deployed anywhere at scale. The dominant tier-1 vendor posture is "track and wait for stdlib + standards body consensus." **jess matches this posture by adopting the same wait-and-track plan**, with explicit milestones so the wait is bounded.

## Decision

**No PQC code is shipped today.** Track 5 milestones over 4 years, gated on external dependencies (Go stdlib, Vault Transit, IETF RFC publication). Each milestone has a no-go gate: if the upstream isn't ready, the milestone slips, not the code quality. Telemetry (M1) lands first so we can measure when industry adoption crosses the M3 threshold.

### Milestones

| Milestone | Target | Scope | Gate (no-go if not met) |
|---|---|---|---|
| **M1 — Tracking** | **2026 Q4** | `jess_tls_pqc_negotiated_total{group, listener}` counter on operator port `:7101`, admin port `:7103`, worker mTLS. Label `group ∈ {x25519, x25519mlkem768, other}`. No behaviour change. | None — pure observability. Go 1.24+ already exposes `ConnectionState.CurveID` which is enough to read what the handshake negotiated. |
| **M2 — Opt-in** | **2027 Q2** | `JESS_TLS_PQC=hybrid` env on controller (operator + admin ports) and worker. When set, `tls.Config.CurvePreferences = [X25519MLKEM768, X25519]`. Default remains classical-only. | Go stdlib exposes `tls.X25519MLKEM768` as a public `CurveID` constant (currently GODEBUG-gated). IETF draft must be published as RFC. |
| **M3 — Default flip** | **2028 Q4** | Default mode flips to `hybrid` if Cloudflare + Chrome + Microsoft adoption all exceed 80% (measured via Cloudflare radar + Chrome telemetry blog posts). Opt-out via `JESS_TLS_PQC=classical`. | Industry adoption threshold met. M1 metrics show our own operator-side clients (jessctl, jess-web SPA browsers) successfully negotiating X25519MLKEM768 in >95% of handshakes on a staging canary. |
| **M4 — Hybrid mandate** | **2029 Q4** | Operator port `:7101` rejects classical-only handshakes (TLS alert `handshake_failure` if the client does not offer X25519MLKEM768). Admin port `:7103` likewise. Vault PKI operator-cert signing migrated to **FIPS 204 (ML-DSA-65)** or hybrid Ed25519+ML-DSA. | Vault Transit + Vault PKI ship ML-DSA support GA. Operator-side `jessctl` versions older than M2 are end-of-lifed (else they cannot connect). |
| **M5 — Full PQ** | **2030 Q4** | Drop classical X25519 from the hybrid group; negotiate ML-KEM-768 alone. Recording manifest signatures migrate from Ed25519 → ML-DSA-65 (or SLH-DSA-128 for high-assurance auditees). Aligned with **NIST IR 8547 hybrid-PQ deadline (2030)**. | Universal industry adoption of ML-KEM-768 (TLS classical curves end-of-lifed by major browsers). |

## Design — algorithms in use today and their PQ replacement

| Today | Used for | PQ replacement | Quantum-resistant today? |
|---|---|---|---|
| **X25519** (TLS 1.3 key exchange) | Operator port `:7101`, admin port `:7103`, worker mTLS, Vault HTTPS, MinIO HTTPS | **X25519MLKEM768** (hybrid, ML-KEM-768 per FIPS 203 + draft-ietf-tls-ecdhe-mlkem; code point 0x11EC) | No — first migration target |
| **ECDSA P-256** (TLS 1.3 sig + operator-cert sig + JWT alg `ES256`) | Operator cert (Vault PKI `jess-ca/operator-cert`), TLS cert chain | **ML-DSA-65** (FIPS 204) — pure; or hybrid ECDSA+ML-DSA via stapled signatures | No — second migration target |
| **Ed25519** (Vault Transit recording signature + audit-chain sig) | Phase 5e WORM recording manifest signature, Phase 5e-16 cross-session hash chain signature | **ML-DSA-65** (FIPS 204) — pure; or **SLH-DSA-128** (FIPS 205, hash-based, conservative for high-assurance) for the audit chain root signature | No — third migration target |
| **RSA-2048+** (Vault PKI root, optional intermediates) | Vault PKI root for the AD CA cross-sign in ADR 0033 §5f-8b-3 | **ML-DSA-87** (FIPS 204) for root, **ML-DSA-65** for intermediates | No — couples to AD CA migration timeline |
| **SHA-256** (chain hashing, HMAC for session integrity) | Phase 5e manifest hash, cross-session chain hash, HMAC for cookie integrity | **No replacement needed** — Grover's algorithm only halves effective security; SHA-256 retains 128-bit post-quantum security, sufficient for the use case | **Yes — keep as-is** |
| **AES-256-GCM** (symmetric TLS cipher, MinIO at-rest, recording bytes) | TLS bulk cipher, MinIO SSE-C, recording payload | **No replacement needed** — Grover halves effective security; AES-256 retains 128-bit post-quantum security | **Yes — keep as-is** |

**Symmetric-primitive note**: this is critical for plan sizing — only **asymmetric** primitives need migration. SHA-256 + AES-256 stay. This means the recording payload itself (AES-256-GCM encrypted) is already post-quantum secure for its lifetime; only the **manifest signature** and **chain HMAC root** need PQ migration. This is favourable for jess because the bulk of the audit-archive data is symmetric.

## Implementation milestones (detail)

### M1 — Tracking (2026 Q4)

**Files to touch:**
- `internal/metrics/tls.go` — register `jess_tls_pqc_negotiated_total{group, listener}` counter.
- `internal/controller/server.go` — wrap `tls.Config.GetConfigForClient` or use `tls.Conn.ConnectionState().CurveID` post-handshake to increment the counter.
- `internal/worker/server.go` — same on the worker mTLS listener.
- `internal/admin/server.go` — same on admin port `:7103`.

**Acceptance:**
- All three listeners increment `jess_tls_pqc_negotiated_total{group="x25519", listener="operator"}` on every handshake today (since no client offers PQ yet).
- A `grafana/jess-pqc-rollout.json` dashboard shows the ratio over time. Initial value is 100% `x25519`; the dashboard's job is to show that number falling as the industry adopts.

**Dependencies:** None — purely observational. Go 1.24's `ConnectionState.CurveID` API is already public.

**No-go gate:** None.

### M2 — Opt-in via env (2027 Q2)

**Files to touch:**
- `internal/config/tls.go` (new) — read `JESS_TLS_PQC` env, set `tls.Config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}` when `=hybrid`.
- All three TLS server constructors call into the shared helper.
- `cmd/jessctl/main.go` — client side; same env, same helper.
- `cmd/jess-web/web/src/*` — no change (browser TLS controlled by browser, not the SPA).

**Acceptance:**
- `JESS_TLS_PQC=hybrid jess controller` + `JESS_TLS_PQC=hybrid jessctl login` — handshake completes; `jess_tls_pqc_negotiated_total{group="x25519mlkem768"}` increments.
- Without the env, behaviour is unchanged.
- CI matrix gains a `pq-hybrid` lane that runs the full integration suite with the env set.

**Dependencies:** Go stdlib promotes `tls.X25519MLKEM768` to a public constant (out of GODEBUG). IETF `draft-ietf-tls-ecdhe-mlkem` published as RFC.

**No-go gate:** If Go stdlib has not promoted the constant by 2027 Q2, slip M2 to 2027 Q4 and re-evaluate. **Do not** vendor a third-party PQ TLS library (Cloudflare's CIRCL or Open Quantum Safe `liboqs`) as a substitute — the maintenance burden of a divergent TLS stack outweighs the wait.

### M3 — Default flip (2028 Q4)

**Files to touch:**
- `internal/config/tls.go` — invert default; `JESS_TLS_PQC=classical` becomes the opt-out.
- Documentation in `docs/runbooks/tls-pqc.md` (new) — operator runbook for the rollout, with the opt-out escape hatch.

**Acceptance:**
- Without env, jess controller offers X25519MLKEM768 as the **first** preference, falls back to X25519.
- `jess_tls_pqc_negotiated_total` ratio in production shows >95% PQ-hybrid within 30 days of M3 deploy.

**Dependencies:** Industry adoption gate met (Cloudflare + Chrome + Microsoft > 80%). M1 telemetry on our staging canary shows >95% hybrid for >7 days.

**No-go gate:** If the staging canary shows <90% hybrid (i.e., a meaningful fraction of clients lack PQ TLS), hold M3. Re-evaluate quarterly.

### M4 — Hybrid mandate + PQ signatures (2029 Q4)

**Files to touch:**
- `internal/controller/server.go` — operator + admin ports reject classical-only via `VerifyConnection` hook that inspects `ConnectionState.CurveID` and returns `tls.AlertHandshakeFailure` if not in the hybrid set.
- `infrastructure-iac/datacenters/eu-west-1/vault/vault-jess-ca.tf` — migrate `jess-ca` PKI mount to issue ML-DSA-65 certs (or hybrid via stapled signature extension if the IETF cert hybridisation draft has stabilised).
- `cmd/jessctl/admin/operator-cert.go` — adjust signer parsing.
- `internal/recording/sign.go` — Vault Transit signing key migrates from Ed25519 to ML-DSA-65; helper supports both during the rotation window.

**Acceptance:**
- Operator port refuses TLS handshakes that don't advertise the PQ-hybrid group; reject is observable as a `jess_tls_handshake_rejected_total{reason="no_pqc"}` counter.
- Newly-minted operator certs sign with ML-DSA-65; old ECDSA-signed certs are honoured until natural expiry (max 8h TTL means full rotation in <1 day).
- New WORM recordings carry an ML-DSA-65 manifest signature; the chain integrity verifier handles both old (Ed25519) and new (ML-DSA) signatures via the manifest's `sig_alg` field.

**Dependencies:** Vault Transit ships ML-DSA-65 as a key type GA. Vault PKI ships ML-DSA as a signing algorithm GA. Both gated on HashiCorp's published roadmap; **this is the highest-risk dependency in the plan**.

**No-go gate:** If Vault Transit + Vault PKI have not shipped ML-DSA support by 2029 Q4, slip M4 to 2030 Q2 and re-evaluate. Mitigating posture: keep the TLS-layer hybrid mandate (which only needs Go stdlib) and **slip only the signature migration**. The two parts of M4 can ship independently.

### M5 — Full PQ (2030 Q4)

**Files to touch:**
- `internal/config/tls.go` — `tls.Config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768Pure}` (or whatever the post-RFC pure name is).
- `internal/recording/sign.go` — drop Ed25519 verification path; ML-DSA-only.

**Acceptance:**
- jess no longer negotiates X25519 classical. Pure ML-KEM-768 only.
- Recording signatures pure ML-DSA-65.
- NIST IR 8547's 2030 deadline met.

**Dependencies:** Industry universal adoption (classical curves at end-of-life in major browsers — likely matches Chrome's planned X25519 deprecation timeline).

**No-go gate:** If a meaningful fraction of operator clients still depend on classical X25519 in 2030 Q4, retain hybrid mode (the cost of doing so is low — extra 1.2 KB per handshake — and the operational risk of locking out clients is high).

## Cross-cutting concerns

### Telemetry from day one

M1's `jess_tls_pqc_negotiated_total` counter ships in 2026 Q4 — **three years before any PQ code change**. The metric's job is to give us the data we need to call the M3 gate confidently. Without it we'd be guessing. The dashboard at `grafana/jess-pqc-rollout.json` should chart the PQ-hybrid ratio per listener over the full multi-year horizon.

### Monitoring + alerting

- **M1+**: information only — no alerts.
- **M3+**: alert `JessPQClassicalShareHigh` if `classical / total > 20%` for 7d on the operator port. This is the signal that the M3 gate is wobbly and we may need to reconsider.
- **M4+**: alert `JessAdminPortClassicalHandshake` — **page** on any classical-only handshake on the admin port. Admin-port operators are internal and we control their tooling; a classical handshake means a mis-configured client or an attempted downgrade attack.
- **M5+**: alert any handshake offering X25519 as a fallback — purely diagnostic, should never fire.

### CI matrix

- **M2+**: add a `pq-hybrid` lane to the integration test matrix. The lane runs the full Phase 5/5b/5e suite with `JESS_TLS_PQC=hybrid` set on both sides.
- **M4+**: add a `pq-mandate` lane that runs with classical-only TLS configured on the client side and asserts the controller rejects.

### Documentation

- `docs/runbooks/tls-pqc.md` (write at M2) — operator runbook for opt-in.
- `docs/runbooks/operator-cert-pqc-rotation.md` (write at M4) — runbook for the ML-DSA cert cutover.
- Quarterly milestone review note in `docs/sessions/YYYY-QN-pqc-review.md` — short paragraph per quarter on industry status, Go stdlib status, Vault status. Skip the quarter if nothing material has changed.

## Failure modes

1. **Vault Transit / Vault PKI ML-DSA slips past 2029 Q4.** Highest-risk dependency. Mitigating: M4 splits cleanly into a TLS-layer half (Go stdlib only) and a signature half (Vault dependency). Ship the TLS half on schedule and slip only the signature half. Worst case: write our own ML-DSA Transit-compatible signer wrapper around a Go ML-DSA library (e.g., `crypto/mldsa` if it lands in stdlib by then; otherwise `cloudflare/circl`) and store keys in Vault KV. Estimated 1-2 weeks of work if forced.

2. **Some operator clients have no PQ TLS at M4 mandate.** Hybrid mode in M3 gives a long runway (1 year) for clients to upgrade. M1 telemetry tells us who the laggards are by `User-Agent`. Pre-M4 communication: 90 days, 60 days, 30 days, 7 days notices to operator tenants. If a hard-blocker tenant exists, slip M4 by a quarter rather than break their access — the harvest-now risk is already bounded by the M3 hybrid posture.

3. **ironrdp / IronRDP Rust workspace lags on PQ TLS.** RDP fastpath traffic between broker and Windows targets is **out of scope** for jess's PQC commitment — Microsoft owns the Windows RDP protocol's PQC story. The jess-broker ↔ Windows leg uses standard TLS via `tokio-rustls`; PQC there waits for `rustls` to ship X25519MLKEM768 + Microsoft to enable it server-side in Windows Server. Track separately; do not block M4 on it.

4. **NIST IR 8547 final ships with different deadlines.** Current 2024 draft is the basis for this plan. If the final ships with looser deadlines (>2030 for hybrid), we keep our schedule — the harvest-now threat doesn't get less urgent because NIST relaxes the deadline. If the final ships with tighter deadlines (<2030), we accelerate M5 by one cycle.

5. **A pre-2030 cryptanalysis result breaks ML-KEM-768.** Low-probability, high-impact. Mitigating: the **hybrid** design (X25519MLKEM768, not ML-KEM-768 alone) is exactly this insurance. An adversary needs to break **both** X25519 and ML-KEM-768 to compromise the session key. Until M5 we always have classical as a fallback. M5 itself should be deferred if any meaningful ML-KEM cryptanalysis result lands.

6. **Operator-cert size growth breaks the SPA login flow.** ML-DSA-65 signatures are ~3.3 KB vs ECDSA P-256's 64 bytes. Operator certs themselves grow accordingly. The SPA's session cookie and the operator-cert payload size need re-checking in M4 (browser cookie limits are typically 4 KB per cookie, 12 KB per domain). Mitigation: store the operator cert in a Web Storage Bucket (Service Worker) rather than a cookie if it overflows.

## Out of scope

- **Q-Day attack drills** (red-team exercise assuming CRQC exists). Separate exercise, separate ADR.
- **CNSA 2.0 federal compliance**. CNSA 2.0 mandates stricter algorithms (e.g., ML-KEM-1024, ML-DSA-87) for National Security Systems on a tighter timeline. jess is not currently NSS-classified; the FedRAMP track (ADR 0034 §Pending-C) is the right place to address this if it becomes a requirement.
- **Customer-side key rotation tooling**. Operators rotate their own operator-cert keys via `jessctl up`; tenants' Falcon-ID keys are Falcon-ID's concern, not jess's.
- **Harvest-now-decrypt-later threat model**. Implicit in the M1-M5 schedule; documented in NIST IR 8547. No separate jess threat-model doc.
- **Stateful hash-based signatures (LMS, XMSS)**. Niche; SLH-DSA covers our high-assurance signature need without the state-management hazard.
- **RDP protocol PQC**. Microsoft's problem (see failure mode 3).
- **PQ-only legacy mode for paranoid tenants**. If demand surfaces we can add `JESS_TLS_PQC=pure_pq` at M4. Not a 2026 concern.

## Timeline summary

```
2026 Q4 ── M1: Tracking metric ships. No behaviour change.
2027 Q2 ── M2: JESS_TLS_PQC=hybrid opt-in. Default still classical.
2028 Q4 ── M3: Default flips to hybrid. Opt-out via env.
2029 Q4 ── M4: Hybrid mandate on operator + admin. PQ signatures begin (Vault-gated).
2030 Q4 ── M5: Full PQ (no classical fallback). Recording sigs pure ML-DSA. NIST 2030 alignment.
```

**Total horizon: 4 years.** Each milestone has a quarterly review checkpoint; missing one milestone slips the next by one quarter, not the whole plan.

## Open questions

1. **Go stdlib PQ TLS public-API timeline.** Per current roadmap, the GODEBUG-gated X25519MLKEM768 in Go 1.24 (Feb 2025) was expected to graduate to a public `tls.X25519MLKEM768` constant in Go 1.25 or 1.26. Has it? **Re-verify each quarter** until M2.
2. **Vault Transit PQ algorithm timeline.** HashiCorp's blog committed to staged rollout starting with Transit but published **no firm dates**. **Re-check the HashiCorp blog quarterly**; if no PQ Transit support is GA by 2028 Q4, raise M4 dependency risk to the team.
3. **NIST IR 8547 r1 publication.** Current published version is initial public draft Aug 2024. When does the final ship? Final-version deadlines may differ from draft.
4. **CNSA 2.0 vs FIPS PQ alignment.** CNSA 2.0 is stricter than FIPS for NSS systems. If jess takes on a customer with NSS scope, M4-M5 algorithms may need to switch to ML-KEM-1024 / ML-DSA-87 / SLH-DSA-256. **No commitment today**; flag for the FedRAMP review (ADR 0034 §Pending-C).
5. **FedRAMP PQ guidance.** Does FedRAMP require PQ by 2030 (parity with NIST IR 8547) or later? Open per ADR 0034 §Pending-C.
6. **Recording-manifest signature key rotation.** Migrating Ed25519 → ML-DSA-65 at M4 needs a Vault Transit key rotation procedure that preserves the **cross-session hash chain** (Phase 5e-16). The chain hash is SHA-256 (PQ-safe) but each link's signature is Ed25519 today. A migration manifest field (`sig_alg: ed25519 | ml-dsa-65`) lets the verifier handle both — design needed at M4 planning time.
7. **AD CA cross-sign and PQ.** ADR 0033 §5f-8b-3 plans an AD CA cross-sign of Vault PKI `jess-smartcard-ca`. Microsoft's AD CS PQ posture is unknown today; the cross-sign relationship may need an ML-DSA-aware variant once AD CS ships PQ.
8. **Browser support for PQ in TLS_CLIENT_AUTH.** Operator certs are presented via `tls_client_auth` (mTLS) from the SPA / `jessctl`. The browser side (for SPA) needs ML-DSA TLS-client-cert support — when does Chromium / Firefox ship it? Track separately.

## References

### Primary sources (verified 2026-06-03)

| Source | Topic |
|---|---|
| https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | NIST IR 8547 — Transition to Post-Quantum Cryptography Standards (initial public draft) |
| https://csrc.nist.gov/pubs/fips/203/final | FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) |
| https://csrc.nist.gov/pubs/fips/204/final | FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA) |
| https://csrc.nist.gov/pubs/fips/205/final | FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA) |
| https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/ | IETF draft — Hybrid TLS 1.3 X25519MLKEM768 (Last Call ends 2026-06-09; code point 0x11EC / 4588) |
| https://blog.cloudflare.com/pq-2025/ | Cloudflare PQ adoption 2025 — >50% human traffic hybrid PQ, X25519MLKEM768 default |
| https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans | HashiCorp staged PQ rollout — Vault Transit first |
| https://github.com/golang/go/issues/64537 | Go stdlib PQ TLS — X25519MLKEM768 landed Go 1.24 GODEBUG-gated |
| https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF | NSA CNSA 2.0 algorithm suite (federal NSS) |

### Cross-reference

- ADR 0030 — jess Phase 7 dynamic catalog (TLS substrate context).
- ADR 0033 — Phase 5f-8b Rust IronRDP browser-RDP bridge (RDP-leg PQC scope boundary; AD CA cross-sign timeline).
- ADR 0034 — Tier-1 ZTNA/PAM Enhancements Catalog §Decisions priority #10 (this ADR's parent).
