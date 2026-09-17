# ADR 0039 Phase 5j-5 — Ingress worker filtering (Boundary HCP parity in OSS)

| | |
|---|---|
| **Status** | Proposed |
| **Phase** | 5j-5 (continues Phase 5j-1..4 — multi-worker spine substrate) |
| **Owners** | Platform / jess maintainers |
| **Supersedes** | none (extends ADR 0034 §Decisions #9 "Ingress worker filtering — Boundary HCP-only feature; jess could implement client-facing filter equivalents in OSS") |
| **Required by** | Regional worker placement (eu-west-1 vs eu-de-1a vs us-east-1); operator-isolation between dev / prod fleets; load distribution across worker replicas |
| **Date** | 2026-06-03 |

## Problem

jess today runs **a single worker** (`jess-worker-*` pod in `jess` ns; see `internal/spine/worker.go` registration handshake at `Register{ID, Endpoint, PublicKey}`). Every session-open the controller picks the only registered worker; routing is trivial.

As jess scales beyond a single cluster, three independent placement axes appear:

1. **Regional affinity** — the eu-west-1 worker can reach Proxmox/AWS targets in that region cheaply; routing an operator session for a `region: eu-west-1` target through a us-east-1 worker pays cross-region egress + latency. We need the controller to prefer workers in the target's region.
2. **Operator isolation** — Hexx-ops and customer-tenant operators should not share workers (blast-radius separation; a worker compromise must not yield cross-tenant access). Today this is implicit (one worker, one tenant); multi-tenant jess needs explicit ingress filtering.
3. **Load distribution** — when N workers exist for the same (region, target_class), pick one by round-robin or least-loaded so a single worker doesn't become a hot-spot.

**Boundary HCP closes (1)+(3) with "worker filters"** — boolean expressions over worker tag predicates evaluated at session-open. Boundary OSS gives **egress** worker filters (which workers can reach a given target) for free; **ingress** filters (which workers accept a given client) are HCP/Enterprise-only per `developer.hashicorp.com/boundary/docs/workers/filters`. jess wants the full pair in OSS — egress for (1), ingress for (2) — and that's the OSS feature gap this ADR closes.

The substrate is mostly there: Phase 5j-1..4 generalised `internal/spine` to talk to N workers; this ADR adds the *selection* layer on top.

## Industry survey (2026-06)

| Vendor | Filter syntax | Ingress | Egress | OSS? |
|---|---|---|---|---|
| **HashiCorp Boundary** | Tag-predicate DSL: `"us-east-1" in "/tags/region" and "/name" matches "web-prod-us-east-[12]"` — operators `in`, `==`, `matches` (regex), `and`/`or` grouping. Tags set via worker config HCL `tags { region = ["us-east-1"]; type = ["web"] }`. | **HCP/Enterprise only** | OSS (target-side `egress_worker_filter`) | partial |
| **Teleport** | `agent_routing_strategy` = `most-recent` or `unambiguous-match`; labels-based agent selection via `labels {region = "us-east-1"}` on the agent; targets reference by label selector. No boolean expression DSL — label match only. | Y (label-based) | Y (label-based) | OSS |
| **StrongDM** | Relay tags as opaque metadata; routing happens at the resource-config layer (relay binding per resource). No published filter expression language; routing is operator-configured per-resource. | Y (per-resource binding) | Y | proprietary |
| **CyberArk PSM** | PSM connector routes by hard-coded target → connector mapping; no expression DSL. | Y | Y | commercial |

**Findings worth carrying:**

1. **Boundary's filter syntax is the most expressive of the surveyed vendors** and the most adopted (Vault co-deployments, HCP Boundary GA since 2022). Adopting Boundary-style syntax means future migrations either direction are mechanical and operators familiar with one know the other.
2. **The ingress-vs-egress split is real and the OSS feature gap is real.** Boundary's docs are explicit: egress filters are OSS; ingress filters require HCP/Enterprise. jess shipping both in OSS closes a paywalled-feature gap directly. Same posture as ADR 0034's session-recording OSS lead vs Boundary's HCP-only BSR.
3. **Teleport's label-only match is simpler but less expressive.** No regex on names; no boolean composition; works fine for small fleets but doesn't scale to "this target is reachable by workers in region X OR region Y but NOT the dev-fleet workers". Worth knowing as a fallback if Boundary syntax proves too complex to embed.
4. **Operator-identity / source-IP filtering is uniquely jess's concern**, not directly modeled by any surveyed vendor at the *worker selection* layer (vendors push it to upstream auth policy). We model it as a separate `client_filter` axis on the controller side so the worker selection stays pure-tag while operator/IP rejection happens before any worker is considered.

## Decision

**Adopt Boundary-style filter expression syntax** (boolean over tag predicates) for both worker selection (egress equivalent) and client gating (ingress equivalent — the OSS gap). Implementation:

- **Workers** register with a `Tags map[string][]string` (multi-value per key, matching Boundary's `/tags/key` array semantics).
- **`TargetSpec` extends** with two new fields:
  - `WorkerFilter string` — expression evaluated against worker tags at session-open; only matching workers are candidates.
  - `ClientFilter string` — expression evaluated against the operator's identity + source IP + Falcon-ID claims at session-open; reject if no match.
- **DSL** uses `expr-lang/expr` (the mature Go expression library used by Argo, Crossplane, n8n). Boundary-shape syntax is *target syntax* — we render Boundary HCL filters into expr-lang at catalog load time so operators can copy-paste Boundary configs. Native expr-lang syntax also accepted.
- **Filter evaluator** lives in a new pkg `internal/spine/workerfilter` — parser, AST cache (parse once at catalog-update), evaluator (≤10ms hard cap), telemetry.
- **Controller selection** at `Controller.Open(ctx, *Session)`: filter registered workers by `WorkerFilter`, reject if `ClientFilter` fails, pick remaining by round-robin (or pluggable strategy).
- **Audit** every selection decision: which workers were considered, which passed each filter, which was picked, with the filter expression hash for replay.

**Why expr-lang over CEL**: expr-lang is pure Go (CEL pulls in protobuf reflection), has Boundary-overlapping operator set (`in`, `matches`, `and`/`or`, regex), is already used in our Crossplane substrate (familiarity), and has a sandboxing story (`AllowUndefinedVariables` off, `Timeout` per-eval). CEL is more rigorously specified but heavier; the ADR leaves it open if a future federal compliance need (CEL is Google-blessed) overrides.

**Why ingress + egress in OSS**: the ingress feature is the genuine Boundary paywall; shipping it in jess OSS continues the ADR 0034 pattern of putting tier-1 PAM features in OSS where Boundary keeps them HCP. The client_filter axis specifically (operator identity / source IP) is *narrower* than Boundary HCP's ingress filter (which can also filter by client cert claims) — we ship the 80% case and leave cert-claim expressions for a future iteration.

## Design

### Worker registration (5j-5a)

`internal/spine/worker.go`'s `Register` message extends:

```go
type Register struct {
    ID        string              // worker identity (existing)
    Endpoint  string              // dial address (existing)
    PublicKey []byte              // worker public key (existing)
    Tags      map[string][]string // NEW: tag namespace; e.g. {"region":["eu-west-1"], "target_class":["linux","windows"]}
    Version   string              // worker build version (existing)
}
```

Workers source tags from env at start-up:

```
JESS_WORKER_TAGS=region:eu-west-1,target_class:linux,target_class:windows,env:prod
```

Parser (in `internal/spine/worker.go` `parseTags(s string)`): split on `,`, split each kv on `:`, accumulate by key. Empty `JESS_WORKER_TAGS` → empty tag map (always-match for filters that don't predicate on tags).

Controller's `WorkerRegistry` (existing) stores `Tags` alongside the rest of the registration record. A new admin endpoint `GET /admin/workers` returns the full registry as JSON for `jessctl admin workers list`.

### Filter DSL (5j-5b)

New pkg `internal/spine/workerfilter`:

```
internal/spine/workerfilter/
  ├── parser.go      // expr-lang program compilation + cache (program hash → *vm.Program)
  ├── boundary.go    // Boundary-syntax → expr-lang rewriter (regex over the input)
  ├── env.go         // evaluation env builder (WorkerEnv, ClientEnv)
  ├── eval.go        // Evaluate(prog, env) with 10ms timeout + panic recovery
  ├── parser_test.go // parser unit tests
  └── eval_test.go   // evaluator + fixture-based golden tests
```

**Worker env** (passed to `WorkerFilter` evaluation):

```go
type WorkerEnv struct {
    Tags    map[string][]string  // worker's registered tags
    Name    string               // worker ID
    Version string               // worker build version
}
```

DSL helpers exposed:

- `tag(k)` → first value (string) or empty
- `tags(k)` → []string (all values)
- `has_tag(k, v)` → bool (v ∈ tags[k])

Example expressions (all equivalent shapes for the same intent):

```
# native expr-lang
has_tag("region", "eu-west-1") && has_tag("target_class", "linux")

# Boundary-compatible (rewritten internally)
"eu-west-1" in "/tags/region" and "linux" in "/tags/target_class"
```

**Client env** (passed to `ClientFilter` evaluation):

```go
type ClientEnv struct {
    Sub       string               // Falcon-ID subject (operator)
    Email     string               // operator email
    Groups    []string             // Falcon-ID group claim
    SourceIP  string               // observed source IP (X-Forwarded-For via Talon, see Open questions)
    Claims    map[string]any       // raw Falcon-ID claims (for advanced policy)
    TargetID  string               // requested target
}
```

DSL helpers:

- `cidr_contains(cidr, ip)` → bool
- `in_group(g)` → bool (g ∈ Groups)
- `claim(k)` → any (raw claim access)

Example:

```
in_group("hexx-prod-operators") && cidr_contains("10.0.0.0/16", SourceIP)
```

**Parser caching**: every distinct filter expression is parsed once at catalog-load (Aggregator hot-reload point); cache key = SHA-256 of expression string. Catalog-update path validates *every* filter expression before commit — syntax errors fail catalog update, not session-open (see Failure modes).

### Controller selection (5j-5c)

`Controller.Open(ctx, *Session)` flow:

```
1. Resolve target from catalog → TargetSpec{WorkerFilter, ClientFilter, ...}
2. Build ClientEnv from session context (operator sub, source IP, Falcon-ID claims)
3. If ClientFilter != "": evaluate; on false → return ErrIngressDenied (audit: deny reason + filter hash)
4. List registered workers from WorkerRegistry
5. For each worker: build WorkerEnv; evaluate WorkerFilter (or skip if "")
6. Eligible set = workers where WorkerFilter is true (or empty)
7. If len(eligible) == 0 → return ErrNoEligibleWorker (audit: filter hash + workers considered)
8. Picker.Pick(eligible) → chosen worker (default: round-robin via atomic counter; pluggable interface)
9. Audit: selection decision with full context (worker IDs considered, picked, filters used)
10. Continue existing session-open path against chosen.Endpoint
```

**Picker interface** in `internal/spine/picker.go`:

```go
type Picker interface {
    Pick(eligible []*Worker, session *Session) *Worker
}
```

Ships with `RoundRobinPicker`; `LeastLoadedPicker` deferred to 5j-5g (needs worker-side load reporting).

### Ingress filter (the OSS gap) (5j-5d)

The same `internal/spine/workerfilter` engine evaluates `ClientFilter` with `ClientEnv` (separate env shape; same evaluator). This is the Boundary HCP feature in jess OSS.

Catalog manifest example:

```json
{
  "id": "prod-pg-01",
  "kind": "postgres",
  "endpoint": "prod-pg-01.internal:5432",
  "worker_filter": "has_tag(\"region\", \"eu-west-1\") && has_tag(\"env\", \"prod\")",
  "client_filter": "in_group(\"hexx-prod-dba\") && cidr_contains(\"10.0.0.0/16\", SourceIP)"
}
```

Same shape in the JessTarget CRD (5j-5e):

```yaml
apiVersion: jess.hexxlock.com/v1
kind: JessTarget
spec:
  workerFilter: 'has_tag("region","eu-west-1") && has_tag("env","prod")'
  clientFilter: 'in_group("hexx-prod-dba") && cidr_contains("10.0.0.0/16", SourceIP)'
```

CRD schema (5j-5e): two new `string` fields under `spec`. OpenAPI validation: maxLength 4096 each; runtime validation by jess admin-API webhook (rejects expressions that don't compile).

### Catalog metadata + admin (5j-5e + 5j-5f)

`jessctl admin workers list` — table of (ID, Endpoint, Version, Tags, LastHeartbeat). JSON output via `--json`.

`jessctl admin workers tag <id> --add region=eu-west-1` — administrative tag override (writes a controller-side overlay; persists in BoltDB). Useful when a worker is misconfigured and you don't want to bounce the pod to change tags. `--remove region=eu-west-1` reverses; `--clear-overrides` purges all overlays for that worker.

Admin REST:

- `GET /admin/workers` → list
- `POST /admin/workers/{id}/tags` body `{"add":{"region":["eu-west-1"]}, "remove":{"env":["dev"]}}`
- `DELETE /admin/workers/{id}/tags` clear overrides

All admin routes require an `admin` operator cert (same gate as Phase 4 operator-cert-revoke).

## Cross-cutting concerns

### Telemetry

| Metric | Type | Labels |
|---|---|---|
| `jess_worker_selection_total` | counter | `result` (picked\|no_eligible\|ingress_denied\|filter_error), `target_id` |
| `jess_worker_filter_eval_duration_seconds` | histogram | `filter_kind` (worker\|client) |
| `jess_workers_registered` | gauge | (no labels — total count) |
| `jess_worker_tag_overrides_total` | gauge | (count of admin tag-override entries) |

### Audit

Every selection decision emits a JSONL audit event into the existing audit chain (5e-15 substrate):

```json
{
  "ts": "2026-06-03T08:42:00Z",
  "kind": "worker_selection",
  "session_id": "...",
  "target_id": "prod-pg-01",
  "operator_sub": "...",
  "source_ip": "10.0.50.12",
  "worker_filter": "has_tag(...)",
  "worker_filter_hash": "sha256:...",
  "client_filter_hash": "sha256:...",
  "workers_considered": ["w-eu-1a-1", "w-eu-1a-2", "w-us-east-1"],
  "workers_eligible": ["w-eu-1a-1", "w-eu-1a-2"],
  "worker_picked": "w-eu-1a-2",
  "decision": "picked",
  "eval_duration_ms": 1.4
}
```

`ingress_denied` decisions are first-class — auditor needs to see denied attempts as much as approved ones.

### Performance budget

Filter eval is on the session-open hot path. Budget:

- Parsed-AST cache lookup: O(1), expected < 10µs.
- expr-lang program execution: per-worker eval typically 50-200µs for the example expressions; **hard cap 10ms** with `context.WithTimeout` → returns `filter_error`, audit-logged, session-open fails closed.
- Total selection budget (N workers): O(N × per-eval) — at N=100 workers, worst-case 20ms total. Acceptable.

Histogram should alert if p99 selection time > 100ms.

## Failure modes

| Mode | Detection | Handling |
|---|---|---|
| **Filter syntax error at catalog update** | Catalog-update path validates every expression with `expr.Compile`; reject on error before persisting. | Catalog update returns 400 with the compile error pointing at the offending field. Operator fixes before retry. |
| **Filter syntax error at session-open** (shouldn't happen post-validation, but: cache invalidation race, manual DB edit) | `expr.Compile` returns error at eval time. | Audit `filter_error`, fail session-open closed (`ErrFilterCompile`), increment `jess_worker_selection_total{result="filter_error"}`. |
| **No worker matches `WorkerFilter`** | Eligible set empty after filtering. | Return `ErrNoEligibleWorker` to client with structured detail: `{filter_hash, workers_considered_count}`. SPA shows "no worker in region eu-west-1 can reach this target; contact admin." |
| **`ClientFilter` rejects the operator** | Evaluator returns false. | Return `ErrIngressDenied`. Audit logged. SPA shows "your session was not authorised for this target from this source." 403 status. |
| **expr-lang eval exceeds 10ms** | Timeout context. | `filter_error`; the offending expression is logged with its hash for operator triage. Suggest a simpler expression in error detail. |
| **Worker registered with malformed tags** | `parseTags` returns error; controller refuses registration. | Worker stays in `awaiting_registration` state; operator sees mis-tagged worker in `jessctl admin workers list` with an error note. |
| **All workers fail filter eval** (cache miss + recompile panic) | Panic recovery in evaluator → return `filter_error`. | Same as syntax error at session-open: fail closed, audit. |
| **Tag override DB corruption** | Boltdb read fails. | Fall back to worker-reported tags; log a warning; admin sees stale-override flag in `jessctl admin workers list`. |

## Out of scope

- **Auto-scaling workers per region** — operator concern; HPA / KEDA / Karpenter solves it cluster-side. jess just needs to surface registered workers; placement is upstream.
- **Worker-side load reporting** for least-loaded picker — Phase 5j-5g future. Round-robin is the 5j-5 default and is good enough for the initial multi-worker fleets.
- **Cert-claim-driven ingress filters** (Boundary HCP also filters by client cert SAN / spiffe-id) — defer; the operator-identity / source-IP axis covers the 80% case. Add when Phase 5h-7 SPIRE-SVID landings give us per-session SPIFFE IDs to filter on.
- **Worker session-affinity / stickiness across reconnects** — see Open questions; if needed, ships as 5j-5h.
- **Filter expression-language UI builder in the SPA** — operators edit raw expressions via the admin tab in 5j-5; a visual builder is a 5j+ polish item.

## Timeline

| Sub-phase | Estimate | Blockers |
|---|---|---|
| 5j-5a — worker tag registration + protocol extension | ~3 days | none — extends existing Register message |
| 5j-5b — filter DSL + parser + evaluator + tests | ~4 days | expr-lang dependency vendor + Boundary-syntax rewriter |
| 5j-5c — controller worker selection updated to use filter | ~2 days | follows 5j-5b |
| 5j-5d — ingress filter (`client_filter`) on the controller side | ~2 days | parallel to 5j-5c (same evaluator, different env) |
| 5j-5e — catalog manifest + CRD schema updates | ~2 days | follows 5j-5d (Aggregator catalog path + JessTarget CRD bump) |
| 5j-5f — `jessctl admin workers list / tag` | ~2 days | follows 5j-5e |

**Total wall-clock**: 2-3 weeks single engineer end-to-end (some parallelism between 5j-5c/d).

## Open questions

1. **DSL language choice — CEL vs expr-lang vs cuelang.** Recommend **expr-lang** for the reasons listed in §Decision. CEL is the federally-blessed alternative if FedRAMP eligibility ever requires it (ADR 0034 §Decisions #2 FIPS path). Cuelang is overkill (full schema language, not just predicate eval). Decision reversible — the AST cache pattern isolates the choice.
2. **Boundary BSL/syntax compatibility — can we exactly mirror Boundary's filter syntax to ease migration?** Recommend yes, **as a parsed-input translation**: jess accepts Boundary syntax at catalog-load, rewrites to expr-lang internally. Two-line operator migration. Open: BSL (Business Source License) — Boundary's filter docs are part of the BSL-licensed product; the syntax is a *language*, not implementation; we should be safe documenting compatibility, but legal should confirm before marketing it.
3. **Sourcing source IP correctly behind cloudflared** — jess is fronted by Talon → cloudflared → public internet (Phase 3 BeyondCorp L4). `X-Forwarded-For` is set by cloudflared but the chain includes Talon and the K8s service mesh too. **Need a trust-chain config**: `JESS_TRUSTED_PROXIES=10.0.0.0/16,<cloudflared-cidr>` so the controller strips trusted hops and picks the first untrusted IP as the operator's real source. Wrong here = ingress filter trivially spoofed via injected `X-Forwarded-For`. Resolve before 5j-5d ships to prod.
4. **Worker churn during a live session — do we need worker-affinity stickiness?** Boundary handles this via session-recording-affinity (session bound to its worker for the session's lifetime). jess Phase 5j-1..4 already does this implicitly (`Session.WorkerID` is set at open and not re-evaluated). Confirm: 5j-5 selection runs **once at session-open**; worker reconnects to controller don't trigger re-selection. If a worker dies mid-session, the session dies — operator opens a new one. This is the simple correct posture; sticky failover is a 5j-5h follow-up only if real demand surfaces.
5. **Multi-cluster catalog federation** — when jess runs in eu-west-1 *and* us-east-1 as separate controller deployments, do they share a unified worker catalog? Out of scope for 5j-5 (each controller sees its own workers); flag as a Phase 5j-6+ design question.
6. **Hot-reload semantics for filter changes** — when an operator updates a target's `worker_filter`, do *in-flight sessions* re-evaluate? Recommend **no**: filter is open-time only (matches Boundary). Catalog hot-reload updates the AST cache; next session-open picks up the change. Continuous re-evaluation conflicts with the Phase 5g-6 grant-tick model (grant verification is the continuous axis; worker selection is one-shot).

## References

- **Boundary worker filters** — https://developer.hashicorp.com/boundary/docs/workers/filters (filter syntax, ingress vs egress, HCP/Enterprise paywall on ingress)
- **Boundary worker tags** — https://developer.hashicorp.com/boundary/docs/configuration/worker/worker-configuration#tags (HCL tag format)
- **Teleport agent labels and routing** — https://goteleport.com/docs/admin-guides/management/admin/labels/ + `agent_routing_strategy` in Teleport config reference
- **StrongDM relays** — https://docs.strongdm.com/admin/networking/gateways-and-relays (per-resource binding; no published filter DSL)
- **expr-lang documentation** — https://expr-lang.org/docs/language-definition (operators, types, function-call shape) + https://github.com/expr-lang/expr (Go embedding, AST cache, timeout context)
- **CEL (alternative)** — https://github.com/google/cel-spec (compared in §Decision; rejected for jess substrate reasons)
- **ADR 0034 §Decisions #9** — `docs/adr/0034-tier-1-ztna-enhancements.md` (origin of this priority; "Boundary HCP-only feature; jess could implement client-facing filter equivalents in OSS")
- **ADR 0033** — `docs/adr/0033-phase-5f-rust-ironrdp-bridge.md` (style template + Phase-5f context this ADR extends)
