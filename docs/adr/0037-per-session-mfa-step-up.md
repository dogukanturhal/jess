# ADR 0037 Phase 5j-3 — WebAuthn / PIV per-session MFA step-up at the broker

| | |
|---|---|
| **Status** | Proposed — design committed 2026-06-03; implementation deferred to a dedicated Phase 5j-3 sprint |
| **Phase** | 5j-3 (priority #3 in ADR 0034 §Decisions) |
| **Owners** | Platform / jess maintainers + Falcon-ID maintainers (5j-3a cross-team) |
| **Supersedes** | none (extends the `JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR` substrate from `cmd/jess-controller/main.go:182`) |
| **Required by** | OMB M-22-09 application-layer MFA mandate; ADR 0034 priority #3; tier-1 PAM parity with Teleport `require_session_mfa` |

## Problem

jess today gates session-open on four signals:

- (a) verified Falcon-ID OIDC JWT (Phase 5 substrate);
- (b) JIT grant existence and freshness (Phase 5b);
- (c) device-posture verdict via `devicepolicy.Verdict` (Phase 5h-5);
- (d) risk-score evaluator (`data.jess.risk`, Phase 5h-4a/4b).

What jess does **not** do today: re-verify a fresh MFA assertion at the moment of session-open. Falcon-ID's MFA happens once, at OIDC token mint. A token's `amr` claim (e.g. `["pwd","webauthn"]`) is stamped when the token is issued and stays static for the token's lifetime (up to 8h on operator carts). An operator who unlocked a Falcon-ID session with WebAuthn at 09:00 can open a jess Postgres session at 16:55 with no fresh user-presence proof — the laptop could have been compromised, stolen, or the operator pulled away from their desk three hours ago.

**OMB M-22-09** (Federal Zero Trust Strategy, 2022) is explicit on this: *MFA must be enforced at the application layer*, not just at network ingress or at the identity provider. The "application layer" for a brokered Postgres or SSH session is **the broker**, not Falcon-ID. Cited verbatim in ADR 0034 §"OMB M-22-09 (verified — run 1)" and reiterated as priority #3 in §Decisions.

**Existing substrate**: `cmd/jess-controller/main.go:182` already wires `JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR` — a comma-separated env var that requires the token's `amr` claim contain at least one of the listed factors (e.g. `mfa,webauthn,hwk`). When set in combination with `JESS_ADMIN_DIRECT_CONNECT_ROLE`, admin-direct-connect auto-grants are gated on the token having proven MFA. That gate is the correct *shape* (claim-driven, env-configurable), but it has two limits worth closing:

1. It applies **only to admin-direct-connect**, not to the general operator session-open path. Every regular grant skips the AMR check entirely.
2. It checks the token's `amr` as stamped at *mint time*, which can be 8 hours old. Fresh user presence is not proven at session-open.

This ADR generalizes the existing AMR substrate into a per-session **step-up** flow with bounded freshness (≤5min step-up token TTL, ≤1h step-up cache TTL by default, both target-configurable).

## Industry survey (2026-06)

| Vendor / spec | Mechanism | Trigger | Factor freshness | Notes |
|---|---|---|---|---|
| **Teleport Enterprise** | `role.options.require_session_mfa: true` (also `hardware_key_touch`, `hardware_key_touch_and_pin`) | Per session-open against any resource matching the role | WebAuthn tap or YubiKey touch+PIN required immediately before session-open; no cache by default | Recorded in `tsh ssh` flow; broker prompts via tsh subprocess. Hardware-key mode forces touch on *every* cert use (key non-exportable). |
| **Microsoft Entra Conditional Access** | Sign-in frequency control: "Periodic reauthentication" hours/days or "Every time"; "Require authentication strength" with MFA strength | Per-app sign-in, optionally per-risk-evaluated request | 5-minute clock-skew tolerance; configurable from "every time" to many hours | RFC 9470 not directly cited but pattern matches: AS issues a fresh acr claim, RS (the app) checks `auth_time`. |
| **AWS IAM Identity Center** | "Require MFA" toggle per permission set, also FIDO2 enforcement at the portal | Per role assumption (STS AssumeRole) | Token TTL bounds (typically 1-8h); FIDO2 touch required at portal sign-in | No per-resource step-up beyond the portal session; coarser than Teleport. |
| **GitHub SSO step-up** | `sudo_mode` cookie for sensitive operations (delete repo, manage SSH keys); requires fresh WebAuthn/password | Per sensitive operation (UI or API X-GitHub-OTP) | `sudo_mode` cookie short-lived (≈hours, capped per session) | Limited to admin-style operations; not per "session open". |
| **Tailscale** | "Re-authentication" enforced by tailnet policy (`autoApprovers` + key expiry); WebAuthn at IdP login | Per node-key rotation, not per-connection | Key expiry typically 30-180d; doesn't gate per-session connections | Coarser than what M-22-09 wants for a broker. |
| **RFC 9470** (OAuth Step-Up Authentication Challenge Protocol) | RS returns `401 WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age=N`. Client redirects user to AS with `acr_values=...&max_age=N`, gets fresh token, retries. | Per-resource-call, RS-driven | `max_age` is the freshness floor in seconds | The canonical IETF wire protocol for application-layer step-up. JWT access tokens carry `auth_time` + `acr` claims (RFC 9068). |

**Synthesis.** The IETF wire shape is RFC 9470: RS-driven 401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, client bounces to the AS with `acr_values` + `max_age`, AS prompts for the additional factor, returns a fresh token, client retries. Every tier-1 vendor either implements this shape directly (modern Entra, Okta, Auth0) or implements a *functionally equivalent* shape over a vendor-specific wire (Teleport's `tsh mfa` subprocess prompt, GitHub's `X-GitHub-OTP` header, AWS IAM IC's portal redirect). **jess should pick RFC 9470 over a Falcon-ID-bespoke protocol** — even when both ends are HexxLock-internal — so the same broker code shape works when (someday) jess fronts an external-IdP-authenticated operator.

Teleport's `require_session_mfa` is the closest 1:1 functional match: a per-role config flag → per-session-open WebAuthn tap, with no carry across sessions by default. That's the UX target for jess.

## Decision

Adopt the RFC 9470 step-up shape, with Falcon-ID as the AS and jess-controller as the RS:

1. **Catalog metadata.** Each catalog target gains a `require_session_mfa` field on its `JessTarget.spec` (admission webhook validates one of `none|standard|elevated`):
   - `none` (default) — preserves current behavior; no step-up required.
   - `standard` — fresh step-up assertion with `amr` ∈ {`mfa`,`otp`,`totp`,`hwk`,`webauthn`} within `step_up_ttl` (default 1h).
   - `elevated` — fresh step-up assertion with `amr` ∈ {`hwk`,`webauthn`} (no TOTP) within a tighter `step_up_ttl` (default 5min). Used for prod DB targets, root-shell SSH, infra control planes.
2. **Session-open enforcement.** `internal/spine.SessionOpen` consults the target's `require_session_mfa` field. If the operator's claims do not carry a fresh `session_mfa_verified` claim that satisfies the target's policy, the broker returns the RFC 9470 401 with `error="insufficient_user_authentication"`, `acr_values` populated from the target policy, `max_age` populated from the target's `step_up_ttl`, and an extra `challenge_url` parameter pointing at Falcon-ID's `/oauth/step-up?challenge=<id>` endpoint.
3. **Falcon-ID side.** A new endpoint `POST /oauth/step-up/challenge` (issued by jess-controller, redeemed by the SPA / jessctl) mints a short-lived (≤5min) step-up challenge bound to a `(operator_sub, target_id, grant_id, nonce)` tuple, signed by Vault Transit. The operator's SPA / browser hits `/oauth/step-up?challenge=<id>`, completes WebAuthn / PIV / TOTP through the Falcon-ID UI, and Falcon-ID issues a fresh token with `amr`, `auth_time`, and a `step_up` claim binding back to the original challenge nonce.
4. **Verification.** jess-controller verifies the returned step-up token against three invariants: (a) `auth_time` is within `max_age` of now, (b) `amr` ∈ the target's required factor set, (c) the embedded challenge nonce matches the controller-side cache entry for `(operator_sub, target_id, grant_id)`. Single-use: cache entry is invalidated on first consume.
5. **Step-up cache.** Successful step-ups are cached per `(operator_sub, target_id)` for `step_up_ttl` (per-target). Within that TTL the operator can open additional sessions to the *same* target without re-prompting. Cache is in-memory only (not persisted across controller restarts — fresh restart = fresh step-up, intentional). Cache eviction at TTL is hard; no sliding window.
6. **Per-target override.** `JessTarget.spec.stepUpTTL` overrides the default per category. Examples: a customer prod DB might pin `step_up_ttl: 300s` (re-tap every 5min); a low-risk catalog browser might pin `step_up_ttl: 8h` for ergonomics.

The choice **builds on, rather than replaces**, the existing `JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR` flag. That flag becomes one of two enforcement points: it stays on the admin-direct-connect fast-path (covers ops needing a synchronous root-shell with no JIT request), while the per-target `require_session_mfa` covers the general operator population.

## Design

### Falcon-ID side (5j-3a — Falcon-ID maintainer collab)

New endpoints:

- `POST /oauth/step-up/challenge` — accepts `{operator_sub, target_id, grant_id, acr_values, max_age}`, returns `{challenge_id, challenge_url, expires_at}`. Challenge stored Vault-Transit-signed in falcon-id's DB.
- `GET /oauth/step-up?challenge=<id>` — UI endpoint; renders the WebAuthn / PIV / TOTP picker that the operator's existing factor set supports; on success issues a fresh JWT carrying:
  - `amr` — factors used in this step-up (array)
  - `auth_time` — RFC 9068, set to the moment the step-up factor was verified
  - `acr` — RFC 9068, set to the highest acr value the factor proves
  - `step_up` — object `{challenge_id, target_id, grant_id, nonce}` binding the token to the challenge that requested it
- `POST /oauth/step-up/complete` — postMessage relay for the SPA popup flow; SPA polls (or websocket-receives) and is notified when the step-up token is ready.

Step-up token TTL is ≤5min; it is a *one-shot* token consumed by exactly one jess `SessionOpen` call. The operator's main Falcon-ID OIDC session token is unchanged.

### jess-controller side (5j-3b)

**New file** `internal/admin/step_up.go`:

```go
// AdminStepUpChallenge mints a challenge bound to a (sub, target, grant) and proxies
// to Falcon-ID's POST /oauth/step-up/challenge. Returns the challenge_url for SPA/CLI to open.
func (s *AdminStepUp) AdminStepUpChallenge(ctx context.Context, req ChallengeReq) (ChallengeResp, error)

// AdminStepUpVerify validates a presented step-up token against the cached challenge.
// Returns the operator's verified factor set + auth_time, or an error.
func (s *AdminStepUp) AdminStepUpVerify(ctx context.Context, token string) (*StepUpResult, error)
```

**Extended** `internal/jit/grants.go`: `Grant` struct gains `RequiresSessionMFA StepUpPolicy` (string enum `none|standard|elevated`), denormalised from the target's catalog entry at grant time. Snapshotted into the grant so the policy that applied at grant-creation is the policy that gates session-open, even if the catalog is mutated between request and session-open.

**Extended** `internal/spine/session_open.go`: at the top of `SessionOpen`, after grant lookup + device-posture verdict + risk-score eval (current order preserved), insert step-up check:

```go
if g.RequiresSessionMFA != stepup.None && !s.stepUpCache.HasFresh(claims.Sub, g.TargetID, g.RequiresSessionMFA) {
    return nil, &StepUpRequiredError{
        ChallengeURL: s.stepUp.NewChallenge(ctx, claims.Sub, g.TargetID, g.ID, g.RequiresSessionMFA),
        AcrValues:    g.RequiresSessionMFA.AcrValues(),
        MaxAge:       g.RequiresSessionMFA.MaxAge(),
    }
}
```

Wire-shape on the response: HTTP 401 with `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="urn:falcon-id:hwk urn:falcon-id:webauthn", max_age=300, challenge_url="https://internal.example.com/oauth/step-up?challenge=..."`. The challenge_url parameter is a jess extension to RFC 9470 (the RFC leaves AS-URL discovery to client metadata).

**Step-up cache** lives in `internal/admin/stepup_cache.go`. Backed by an in-process `sync.Map[string, *StepUpEntry]` keyed by `sha256(operator_sub|target_id|policy)`. Entries hold the `auth_time`, the factor set, the entry's hard expiry, and the challenge nonce that minted them. Eviction is by a goroutine ticking every 30s.

### SPA side (5j-3c — operator UX)

**Modified file** `cmd/jess-web/web/src/components/ConnectForm.tsx`: when `SessionOpen` returns 401 with `error=insufficient_user_authentication`, parse the `challenge_url` and open a popup (1024×768) pointing at `challenge_url`. Listen for a `window.message` of shape `{type: "jess-step-up-complete", challenge_id, token}` from the popup. Retry `SessionOpen` with `Authorization: Bearer <step_up_token>` as a header in addition to the operator's main session bearer.

The Falcon-ID `/oauth/step-up` page on success calls `window.opener.postMessage({type: "jess-step-up-complete", challenge_id, token}, "https://internal.example.com")` then closes itself. **Origin-pinned postMessage** — never use `*` for the target origin or any operator-attacker-controlled page on the same browser could intercept the step-up token (CVE-shape risk).

Failure paths surface as toast notifications: "Step-up cancelled by operator", "Step-up timed out (5min)", "WebAuthn factor unavailable — contact admin to enroll".

### jessctl side (5j-3c continued)

**Modified file** `internal/jessctl/connect.go`: same wire-shape handling. On 401 + `insufficient_user_authentication`, jessctl:

1. Opens the operator's default browser at `challenge_url` (`xdg-open` / `open` / `start`).
2. Starts a local HTTP listener on `127.0.0.1:0` (ephemeral port).
3. Passes a `redirect_uri=http://127.0.0.1:<port>/jess-step-up-callback` query parameter on the challenge URL.
4. Falcon-ID redirects the operator's browser back to the loopback with `?token=<step_up_token>` after success.
5. jessctl receives the token, closes the listener, retries `connect` with the new bearer.

If `--no-browser` is set (CI / headless), jessctl prints the challenge URL + instructs the operator to complete step-up on another device, then poll Falcon-ID's `/oauth/step-up/status?challenge=<id>` until ready.

### Catalog metadata + target classifier (5j-3d)

`api/v1alpha1/jesstarget_types.go` extends `JessTargetSpec`:

```go
type StepUpPolicy string
const (
    StepUpNone     StepUpPolicy = "none"
    StepUpStandard StepUpPolicy = "standard"
    StepUpElevated StepUpPolicy = "elevated"
)
type JessTargetSpec struct {
    ...
    RequireSessionMFA StepUpPolicy   `json:"requireSessionMFA,omitempty"` // default none
    StepUpTTL         *metav1.Duration `json:"stepUpTTL,omitempty"`        // default per-policy
}
```

Admission webhook validates the enum + a sane TTL bound (≥30s, ≤8h). Discovery providers (Phase 7a-h) populate a sensible default per source: AWS RDS prod targets → `elevated`; Proxmox lab VMs → `none`; K8s cluster admin contexts → `elevated`; everything else → `standard`. Operators can override per-target via `kubectl edit jesstarget` or via the SPA Targets panel.

### Step-up cache + replay prevention (5j-3e)

Replay-prevention layers (defense in depth):

1. **Vault Transit-signed challenge nonce.** Each challenge embeds a fresh 256-bit random nonce + the `(operator_sub, target_id, grant_id)` tuple, signed by Vault Transit (`transit/jess-step-up/sign`). Tampering invalidates the signature.
2. **One-use nonce.** Cache entries are deleted from the controller-side challenge store on first redeem; replay returns "challenge already redeemed".
3. **Bound to grant.** `grant_id` in the challenge tuple ensures a step-up token minted for grant G1 cannot be replayed against grant G2 even for the same operator+target.
4. **Bound to controller clock.** `auth_time` from the step-up token is compared against the controller's wall clock with ±2min skew tolerance (matches the existing JWT validation skew in `internal/falconid/verify.go`).
5. **Cache is in-memory.** Controller restart drops all step-up state; a hostile cache snapshot cannot resurrect a stale entry.

## Sub-phases

| Sub-phase | Scope | Estimate | Owner | Blockers |
|---|---|---|---|---|
| **5j-3a** | Falcon-ID `/oauth/step-up/challenge` + `/oauth/step-up` UI + token shape (amr/auth_time/acr/step_up claims) + `/oauth/step-up/complete` postMessage relay | ~1-2 weeks | Falcon-ID maintainers | UX design for the WebAuthn / PIV / TOTP picker; existing factor enrollment must surface to step-up UI |
| **5j-3b** | jess-controller `internal/admin/step_up.go` + `internal/admin/stepup_cache.go` + spine session-open enforcement + admin API `/admin/step-up/challenge` & `/admin/step-up/verify` | ~1 week | jess maintainers | 5j-3a Falcon-ID endpoints; needs the step-up token shape stabilized first |
| **5j-3c** | SPA `ConnectForm.tsx` popup + postMessage origin pin; jessctl `connect.go` loopback callback handler | ~1 week | jess maintainers | 5j-3b |
| **5j-3d** | `JessTarget` CRD extension + admission webhook validation; discovery-provider default classifier | ~3-5 days | jess maintainers | 5j-3b (consumer of the field) |
| **5j-3e** | Vault Transit signing for challenge nonce; one-use cache invalidation; replay tests | ~3-5 days | jess maintainers | 5j-3b |

**Realistic wall-clock:** 2-3 weeks for jess-side 5j-3b/c/d/e once 5j-3a is delivered; Falcon-ID side ~1-2 weeks. **Critical path is 5j-3a → 5j-3b → 5j-3c**, with 5j-3d/e parallelisable against 5j-3c.

## Cross-cutting concerns

### Telemetry

| Metric | Type | Labels |
|---|---|---|
| `jess_session_step_up_required_total` | counter | target, policy (standard\|elevated), result (cached_fresh\|prompted\|cancelled\|expired\|failed) |
| `jess_session_step_up_duration_seconds` | histogram | policy, factor (webauthn\|hwk\|totp), result |
| `jess_session_step_up_cache_hits_total` | counter | target, policy |
| `jess_session_step_up_cache_evictions_total` | counter | reason (ttl\|restart\|invalidate) |
| `jess_session_step_up_replay_detected_total` | counter | challenge_id_prefix (first 8 hex chars only — full id is sensitive) |

**Alerting:** `jess_session_step_up_replay_detected_total > 0` over any 5min window is an immediate SecOps page — replay attempt indicates either a hostile actor or a broken client implementation. `jess_session_step_up_required_total{result="failed"} / required_total > 5%` over 10min suggests Falcon-ID outage or operator-side factor revocation cascade.

### Audit (Sink.Event)

Every step-up lifecycle event lands in the WORM audit chain (Phase 5e + 5e-16):

- `step_up.challenge_minted` — `{operator_sub, target_id, grant_id, policy, challenge_id_hash, expires_at}`
- `step_up.completed` — `{operator_sub, target_id, grant_id, challenge_id_hash, amr, auth_time, factor}`
- `step_up.cache_hit` — `{operator_sub, target_id, policy, cache_entry_age_seconds}`
- `step_up.failed` — `{operator_sub, target_id, grant_id, reason, challenge_id_hash}`
- `step_up.replay_detected` — `{operator_sub, target_id, challenge_id_hash, ip}` (security event, higher severity)

Audit events carry `step_up.challenge_id_hash` (sha256 of the challenge_id) rather than the raw id, so an audit log leak doesn't enable challenge replay attempts.

### Falcon-ID coordination

5j-3a is a *separate* MR series in the falcon-id repo. jess maintainers should pair-program the token shape with Falcon-ID maintainers to lock the JWT field names + claim semantics *before* either side ships. Recommended: a joint design review meeting + a frozen JSON schema artefact in `docs/contracts/falcon-id-step-up-v1.json` (jess-side reference copy; falcon-id repo holds the canonical).

## Failure modes

1. **Falcon-ID `/oauth/step-up` endpoint down.** Operator gets a 503 on the popup load; the SPA / jessctl surfaces "Step-up service unavailable — try again". jess-controller MUST NOT degrade-open: an unreachable step-up endpoint means session-open is denied. There is no break-glass except via `jessctl admin operator-cert-revoke`-equivalent admin override (a new ADR-level escape hatch is out of scope here — see Open Questions).
2. **WebAuthn factor revoked mid-step-up.** Operator sees the WebAuthn picker, taps the key, Falcon-ID rejects (factor revoked). `step_up.failed` audit event fires with `reason=factor_revoked`. SPA surfaces "Your WebAuthn key is no longer enrolled — contact admin".
3. **Step-up token replay.** Detection is automatic via the one-use cache + Vault Transit signature check; replay returns 401 + `step_up_already_consumed` and fires `step_up.replay_detected`. No false-positive expected (legitimate clients consume exactly once).
4. **Clock skew between Falcon-ID and jess-controller.** Both run NTP; the ±2min skew tolerance on `auth_time` matches the existing JWT validation. If the controller's clock is grossly wrong (>2min skew), `step_up.failed` with `reason=auth_time_out_of_range`. Alert via the existing NTP-skew dashboard. Worked example: operator completes WebAuthn at Falcon-ID wall-clock T; token carries `auth_time=T`. jess-controller receives at wall-clock T+30s but its clock reads T-180s due to NTP drift; the validator sees `auth_time` ahead of its own "now" by 150s and refuses. This is an availability bug, not a security bug — fail-closed is correct. Operationally, the NTP-skew dashboard already monitors all in-cluster Pods; the Falcon-ID Pods join the same monitoring.
5. **Falcon-ID emits an `amr` value the jess policy doesn't recognise.** Forward-compat: a future Falcon-ID release adds `passkey` to the factor list, but jess `elevated` policy is statically `{hwk,webauthn}`. The unrecognised value is silently dropped at jess-side intersect — operator sees `step_up.failed` with `reason=no_acceptable_factor`. Fix path: extend the `StepUpPolicy.AcrValues()` enum in jess and re-roll. Mitigation: jess emits `jess_session_step_up_unknown_amr_total{value}` so the gap surfaces in metrics before operators hit it in volume.
6. **Operator opens N parallel sessions to the same target.** First session-open mints challenge + completes step-up + populates cache. Sessions 2..N within `step_up_ttl` hit `cache_hit`. Sessions opened concurrently before the first cache-write race land on N independent challenges → N step-up prompts; UX is poor but security is preserved. Future optimisation: a single in-flight gate per `(sub, target, policy)` so a second concurrent session-open waits for the first's challenge to land.
7. **jessctl `--no-browser` headless flow stalls.** If the operator forgets to open the URL on another device, jessctl hangs at the listener forever. Mitigation: hard timeout of 5min (matches challenge TTL); print a fresh challenge URL with `jessctl connect --retry-step-up`.
8. **SPA popup blocked by browser.** Some browsers block popups not directly tied to a user gesture. The SPA must trigger the popup synchronously from the `onClick` of the Connect button; if blocked, fall back to a full-page redirect (preserving `window.opener` is not strictly necessary if a polling channel is used).

## Out of scope

- **Falcon-ID step-up UI implementation** — Falcon-ID team owns the picker + factor enrollment flow.
- **Recovery codes** — Falcon-ID concern; if WebAuthn fails, recovery code prompt lives on the Falcon-ID side.
- **Per-action step-up inside an open SSH session** (e.g. `sudo` semantics).  Long-running shells don't get re-prompted mid-session for individual commands. This is a separate concern; some PAM vendors handle it via PAM modules on the target host. Out of jess broker scope.
- **Step-up for the device-posture verdict refresh** — Phase 5h-5 device posture is independent of step-up; both are session-open gates that compose.
- **Hardware-key enrollment / management UX** — ADR 0034 priority #1 covers hardware-bound operator keys; this ADR consumes WebAuthn/PIV as factors but does not own enrollment.
- **WebAuthn attestation chain verification** at the broker — Falcon-ID does the attestation; the broker trusts Falcon-ID's `amr` claim. Future hardening (broker independently verifies the attestation) would be a separate ADR.

## Timeline

- **5j-3a (Falcon-ID):** 1-2 weeks.
- **5j-3b–e (jess):** 2-3 weeks single engineer once 5j-3a is ready.
- **Total wall-clock:** ~4-5 weeks if fully sequenced; ~3 weeks if jess-side 5j-3b is scaffolded against a stub Falcon-ID endpoint while 5j-3a is in flight.

## Open questions

1. **Does Falcon-ID's `/oauth/step-up` endpoint exist today?** Almost certainly not — Falcon-ID is HexxLock-internal and ADR 0034 lists "per-session step-up at the broker" as N/planned (priority #3). Pre-5j-3b kickoff: confirm with Falcon-ID maintainers and pin a 5j-3a delivery target.
2. **What's the canonical postMessage protocol for SPA popup completion?** Proposed: `{type: "jess-step-up-complete", challenge_id, token, expires_at}` with `targetOrigin = "https://internal.example.com"`. Should also define an error shape: `{type: "jess-step-up-error", challenge_id, error: "cancelled|expired|failed", message?}`.
3. **Should the step-up token bind to (target, grant) or just (operator, time)?** This ADR proposes the tighter binding (target + grant + nonce). Looser binding is simpler but allows a step-up minted for low-risk target A to authorise high-risk target B if both have the same policy class. **Recommend the tighter binding.** Counterargument: per-target binding kills the cache — a single operator opening sessions to 5 targets requires 5 step-ups within `step_up_ttl`. Mitigation: cache key is `(operator_sub, target_id, policy)` so per-target caching still works; just no cross-target reuse.
4. **What's the operator UX if the WebAuthn factor is unavailable on the operator's current device?** (e.g. operator left YubiKey at home.) Falcon-ID UI should fall back to TOTP if the operator has it enrolled. For `elevated` targets, no TOTP fallback — the operator either has the hardware factor or cannot open the session. Recovery codes (Falcon-ID concern) are the only break-glass.
5. **Step-up TTL defaults.** Proposed: `standard` = 1h, `elevated` = 5min. Open for tuning after live rollout. SecOps team should review before 5j-3d ships.
6. **What is the wire-shape for `acr_values` between jess and Falcon-ID?** Proposed: `urn:falcon-id:hwk` and `urn:falcon-id:webauthn` and `urn:falcon-id:totp`. RFC 9470 leaves the URN scheme to the parties. Lock these in the joint design contract.
7. **Admin break-glass.** Is there a path for SecOps to bypass step-up when Falcon-ID is down hard (extended outage)? Two options: (a) no bypass — accept that operator access is gated on Falcon-ID liveness (matches OIDC dependence today); (b) emergency operator cert with a special `JESS_STEP_UP_BYPASS_OPERATOR_CERT_FINGERPRINT` env. **Recommend (a)** for ADR 0037; revisit if Falcon-ID SLO incidents demonstrate the need.

## References

- **OMB M-22-09**, *Moving the U.S. Government Toward Zero Trust Cybersecurity Principles*, Executive Office of the President / OMB, Jan 2022. https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf — application-layer MFA mandate (§C "Devices and Users").
- **RFC 9470**, *OAuth 2.0 Step Up Authentication Challenge Protocol*, IETF, Sep 2023. https://datatracker.ietf.org/doc/html/rfc9470 — `insufficient_user_authentication` error code, `acr_values` + `max_age` challenge parameters, six-step flow between RS and AS.
- **RFC 9068**, *JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens*, IETF, Oct 2021. https://datatracker.ietf.org/doc/html/rfc9068 — `auth_time` and `acr` claim semantics on JWT access tokens.
- **W3C WebAuthn Level 3** Recommendation. https://www.w3.org/TR/webauthn-3/ — the user-presence + user-verification primitives Falcon-ID UI prompts.
- **FIDO2 / CTAP2** spec, FIDO Alliance. https://fidoalliance.org/specifications/ — hardware key + PIV transport.
- **Teleport per-session MFA docs**, `goteleport.com/docs/admin-guides/access-controls/guides/per-session-mfa/` — closest functional analog; `role.options.require_session_mfa` flag + tsh-prompted WebAuthn tap per session-open.
- **Microsoft Entra Conditional Access — Sign-in frequency** docs, learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime — periodic reauthentication, 5-min clock-skew tolerance, authentication strength + MFA enforcement.
- **AWS IAM Identity Center MFA enforcement** docs, docs.aws.amazon.com/singlesignon/latest/userguide/mfa-enable-how-to.html — portal-level MFA + FIDO2 enforcement.
- **ADR 0034** — Tier-1 ZTNA/PAM Enhancements Catalog (priority #3 = this ADR's scope).
- **ADR 0030** — Phase 7 dynamic catalog (provides the `JessTarget` CRD this ADR extends).
- **jess-controller** `cmd/jess-controller/main.go:177-194` — existing `JESS_ADMIN_DIRECT_CONNECT_REQUIRE_AMR` substrate this ADR generalises.
