# ADR 0046 — JessPendingTarget lifecycle + Rego auto-promote (Phase E)

**Status:** Accepted — 2026-06-06
**Phase:** 7-c (auto-discovery program) — Pattern 5 (promotion half).
Phase D (Aggregator retirement TTL — ADR 0046 sibling, lifecycle
retirement half) ships in parallel.

## Context

Discovery providers (Phase B `k8s-services`, Phase C `ldap`, plus the
existing `proxmox`, `k8s-nodes`, `admin-api`, `jess-target-crd`,
`static`) surface targets at scale. The 5-target estate where each
addition gets MR review is a leftover from the manual-curation era;
once AD + k8s Services start emitting hundreds of candidates per
discovery cycle, the operator drowns or — worse — auto-onboarding
runs unchecked.

The deep-research synthesis (workflow `wf_eeb3aa50-3b5`, 2026-06-06,
24 sources, 21/25 claims confirmed) found that **no surveyed tier-1
PAM vendor ships a full discovered→pending→onboarded→retired state
machine**:

- HashiCorp Boundary documents NO lifecycle terminology.
- StrongDM ships two states (Unmanaged/Managed) and docs verbatim:
  *"there is no way to automatically delete a resource in StrongDM
  when the linked discovered resource is decommissioned."*
- CyberArk has Pending Accounts but no TTL retirement; DNA is a
  report, not a pipeline.

This ADR closes the **promotion half** of the gap.

## Decision

Introduce two layers:

1. **`JessPendingTarget` CRD** (`jess.hexxlock.com/v1alpha1`).
   Cluster-scoped, mirrors `JessTarget.spec` with three additional
   provenance fields (`source`, `source_ref`, `discovered_at`) and a
   `status` block tracking promotion phase.

2. **`internal/lifecycle/pending` reconciler**. Watches PendingTarget
   CRs; evaluates a Rego policy mounted at `JESS_PENDING_REGO_FILE`
   against each candidate's spec; on `allow=true` creates the
   corresponding `JessTarget` CR (the existing `jesstargetcrd` provider
   picks it up on the next informer tick) and deletes the
   PendingTarget; on `allow=false` writes `status.policy_reason` for
   operator review.

Default Rego policy ships at `docs/policy/jess/discovery.rego`:
- **Default deny** + clear reason
- **Rule 1** — k8s-services + non-critical → promote
- **Rule 2** — ldap + non-critical + recorded → promote
  (LDAP CriticalityByOU already stamps DCs as critical → Rule 2
  excludes them → DCs land in Pending awaiting human review)
- **Rule 3** — proxmox + jess-managed tag → promote
- **Rule 4** — explicit `jess:auto-promote` tag → bypass everything

Operators tune the Rego file (mounted as a ConfigMap into the
controller pod). Reconciler code never changes for new rules.

### Why CRD-as-queue instead of an in-memory queue?

- Multi-controller HA: PendingTargets persist in etcd → any controller
  replica can promote/reject.
- Operator visibility: `kubectl get jpt -o wide` shows the queue
  directly (Phase, Source, Address, Reason, Discovered columns).
- Audit shape: every `kubectl edit jpt …` is already in the k8s audit
  log; combined with the controller's `discovery.promoted` /
  `discovery.rejected` audit rows the SOC2 trail is complete.

### Why Rego instead of a hardcoded policy DSL?

- Talon already uses Rego (the ZTNA baseline in
  `docs/policy/ztna/ztna_baseline.rego`).
- The `riskscore` evaluator (Phase 5h-4) is also Rego — same OPA Go
  SDK already in `go.mod`.
- Operators tune one policy DSL across the platform.

### Why not require all discovery providers to write Pending?

Phase E ships the LIFECYCLE PRIMITIVE. Existing providers continue
writing directly to the Aggregator — no change to their contract.
Future providers (or refactors of existing ones) opt into the Pending
queue when policy review is required. The split keeps each MR small
and lets operators land Phase E without forcing every provider to
rewire.

## Consequences

### Positive

- Operator-visible queue: discovered candidates wait in `kubectl get
  jpt` instead of being silently auto-onboarded.
- One Rego file controls every source's promotion rules.
- Audit shape clean: `discovery.promoted` / `discovery.rejected` rows
  per (provider, target) — adds the SOC2 evidence the existing
  catalog-diff trail couldn't provide for "why was this onboarded?"
- Multi-controller HA via etcd-backed queue.

### Negative

- Adds a CRD + controller-runtime-like reconciler. Operational
  surface +1 (the reconciler can be a bottleneck if the Rego policy
  takes 100ms × 100 candidates × 5min cadence — measure before
  worrying).
- Rego compile errors fail the controller at startup. Mitigated by
  shipping `docs/policy/jess/discovery.rego` as the validated
  baseline + a CI gate that re-evaluates the policy on edit.

### Neutral

- Existing providers unaffected. Phase F (future) will convert one
  provider at a time to write Pending instead of direct.

## Implementation surface

- `deploy/crd/jesspendingtargets.jess.hexxlock.com.yaml` — new CRD.
- `internal/lifecycle/pending/reconciler.go` — new package.
  - `New(ctx, Config) (*Reconciler, error)` — compiles Rego at
    construction; malformed policy fails fast.
  - `Run(ctx) error` — starts informer + reconcile loop.
  - `evaluate(ctx, spec) Decision` — Rego eval against
    `data.jess.discovery`.
  - `promote()` — creates JessTarget, deletes Pending.
  - `reject()` — updates status.phase=Rejected + policy_reason.
  - `LoadRegoModule(path)` — convenience for `LoadFile`-style controller
    startup.
- `internal/lifecycle/pending/reconciler_test.go` — 7 cases:
  - Allow k8s-services non-critical
  - Deny k8s-services critical (default-deny)
  - Allow explicit `jess:auto-promote` tag override
  - Default-deny on unknown source
  - New() rejects malformed Rego
  - New() rejects empty Rego
  - `stripPendingFields` removes provenance only
- `docs/policy/jess/discovery.rego` — default policy (4 allow rules +
  default-deny).
- `cmd/jess-controller/pending_wiring.go` — `JESS_PENDING_RECONCILER_
  ENABLED=true` + `JESS_PENDING_REGO_FILE=/path` env gates.
- `cmd/jess-controller/main.go` — wires the reconciler alongside the
  catalog Aggregator. Audit emitter bridges to existing audit.Sink
  with `Action="discovery.<phase>"`.

## Rollout

1. **Land CRD + reconciler + policy** (this MR). Reconciler is OFF
   by default. No discovery provider writes Pending yet.
2. **Land manifests overlay** (separate MR — the GitOps repository):
   - Apply the CRD
   - Mount `docs/policy/jess/discovery.rego` as a ConfigMap
   - Set `JESS_PENDING_RECONCILER_ENABLED=true` +
     `JESS_PENDING_REGO_FILE=/etc/jess/policy/discovery.rego` on the
     controller deployment
3. **Phase F (follow-on)**: convert LDAP provider to write
   PendingTargets instead of direct catalog entries. Operator
   gates promotion via policy.
4. **Phase F-2**: convert k8s-services + proxmox the same way.

## References

- [Deep-research workflow `wf_eeb3aa50-3b5`, 2026-06-06] — market-gap
  identification, vendor capability matrix.
- ADR 0030 — original Phase 7 dynamic catalog (Aggregator substrate).
- ADR 0041 — gap-audit roadmap; this ADR closes gap #14 ("no
  promotion review queue").
- HashiCorp Boundary host-discovery docs — for the "no lifecycle"
  comparison.
- StrongDM discovery docs — for the "no auto-retire" verbatim quote.
- CyberArk Pending Accounts (PVWA) — closest comparator pattern.

## Open follow-ups

- **Provider rewiring** — Phase F.
- **Status filtering on List()** — admin UI may want to query the
  Pending CRD directly; provide a thin server-side filter so
  `/admin/pending?phase=Pending` doesn't pull every Rejected row.
- **Rego hot-reload** — currently the operator restarts the
  controller to pick up policy edits. ConfigMap-mounted file +
  fsnotify watch is the natural follow-on.
- **Bulk operator override** — `kubectl annotate jpt foo
  jess.hexxlock.com/force-promote=true` to bypass Rego for one-off
  exceptions.
