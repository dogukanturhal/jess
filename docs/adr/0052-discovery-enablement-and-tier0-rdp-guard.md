# ADR 0052 — Catalog autodiscovery enablement (audit-only / manual-approve) + Tier-0 RDP hard-guard

**Status:** Accepted — 2026-06-22. **Phase 1 (Tier-0 RDP hard-guard) implemented
in this MR**; provider rewiring (Phase F), admin queue, and enablement are gated
follow-ons. Operator chose **option (b) — "everything manual" on first rollout**
(`discovery-strict.rego`), graduating to `discovery.rego` once the queue is trusted.
**Phase:** 7-F (auto-discovery program — provider rewiring + enablement)
**Builds on:** ADR 0030 (dynamic catalog Aggregator), ADR 0046 (JessPendingTarget
lifecycle + Rego auto-promote), ADR 0049 (multi-protocol brokering).

## Context

The live broker catalog today is a **static, hand-authored `targets.json`**
(`JESS_TARGETS=/etc/jess/config/targets.json`, ConfigMap `jess-targets`). No
discovery provider is enabled in the deployment, so every catalog row shows
`Source: unknown` and a new target only appears when a human edits the ConfigMap.

This is the "snapshot ages → liability" failure mode that industry guidance warns
against. The agreed direction (operator, 2026-06-22) is **best-practice dynamic
(continuous) discovery, defaulting to audit-only / manual-approve enrollment** —
never silent auto-onboarding.

Crucially, the substrate for this **already exists in the codebase** and is ahead
of tier-1 PAM vendors (ADR 0046 deep-research: no surveyed vendor ships a full
discovered→pending→onboarded→retired state machine):

| Piece | State |
| --- | --- |
| Aggregator (event-driven `IngestSnapshot` + interval refresh + diff→audit) | **Built** (ADR 0030) |
| Discovery providers: `ldap`, `proxmox`, `kubernetes`, `kubernetesservices`, `jesstargetcrd`, `adminapi` | **Built**, all OFF |
| `JessPendingTarget` CRD + `internal/lifecycle/pending` Rego reconciler | **Built** (ADR 0046) |
| Default promotion policy `docs/policy/jess/discovery.rego` (default-deny) | **Built** |
| Target classification fields (`Criticality`, `Tags`, `Source`, `RequireDeviceClaims`) | **Built** |
| Aggregator retirement TTL (decommission half) | **Built** (ADR 0046 sibling) |

So this ADR is **not a new architecture** — it is the *completion + enablement*
design (Phase F) plus one security hardening the current default policy is missing.

### The gap (why discovery is not just "flip the flag")

1. **Providers write DIRECT to the Aggregator, not through the Pending queue.**
   ADR 0046 deliberately shipped the lifecycle *primitive* without rewiring
   providers (Phase F was left as a follow-on). If we enabled `ldap` today, its
   targets would land in the live catalog **bypassing the manual-approve gate** —
   exactly the "unreviewed labels silently enter RBAC scope" anti-pattern.

2. **Tier-0 RDP is only *softly* protected.** The LDAP provider, with
   `EnableRDP=true`, emits an `<dNSHostName>:3389` RDP candidate for **every**
   Windows computer — including Domain Controllers. The default Rego keeps DCs out
   of *auto*-promotion (DC OU → `criticality=critical` → no allow rule matches →
   manual review). But:
   - the DC's RDP candidate still *exists* in the queue and could be **manually**
     promoted, and
   - **Rule 4 (`jess:auto-promote` tag) bypasses everything** — a DC computer
     object tagged `jess:auto-promote` would auto-promote its RDP target.

   ADR 0051-adjacent decision (and web-verified Microsoft Enterprise Access / AD
   tiering best practice): **RDP to a Tier-0 Domain Controller must never be
   brokered through a lower-tier jump host.** A soft, tag-overridable policy is not
   a sufficient guarantee for a Tier-0 boundary.

3. **No operator review surface beyond `kubectl get jpt`.** Manual-approve needs a
   first-class console queue for non-kubectl operators + auditors.

4. **Nothing is wired in the deployment** — CRD not applied, Rego ConfigMap not
   mounted, reconciler + providers OFF.

## Decision

Complete the discovery program as **audit-only / manual-approve by default**, on
the existing 0030/0046 substrate, with a **hard Tier-0 RDP guard** that no policy
tag can override.

### 1. Phase F — providers write Pending, not direct (audit-only default)

Rewire each dynamic provider to emit `JessPendingTarget` CRs instead of pushing
straight into the Aggregator. The Rego reconciler is the *only* path from
discovered → brokerable. Default policy stays **default-deny**, so a freshly
discovered asset is inert until either (a) a default allow rule matches
(non-critical workers/services/lab) or (b) an operator approves it.

- Provider contract gains a `Sink` mode: `Direct` (legacy, for `static` +
  `admin-api` break-glass) vs `Pending` (all network/cloud discovery).
- `static` (ConfigMap) and `admin-api` (break-glass) keep `Direct` — they are
  human-authored intent, already reviewed.
- `ldap`, `proxmox`, `kubernetes*` switch to `Pending`.

### 2. Tier-0 RDP hard-guard (defense in depth — three layers)

a. **Provider:** the LDAP provider must NOT emit an RDP candidate for a host whose
   resolved criticality is `critical` (DC OU). SSH-only for Tier-0. (New
   `SuppressRDPForCriticality []string`, default `["critical"]`.)

b. **Policy (un-overridable):** add a hard-deny to `discovery.rego` that precedes
   and cannot be bypassed by Rule 4:
   ```rego
   # Tier-0 RDP is never brokered, even with jess:auto-promote.
   hard_deny if { input.candidate.protocol == "rdp"; input.candidate.criticality == "critical" }
   allow := false if hard_deny
   ```
   (Reconciler evaluates `hard_deny` first; `allow` is forced false when set.)

c. **Broker (existing):** the ephemeral RDP credential group `CN=JessRDPAccess`
   is GPO-nested into Tier-1 member servers ONLY — even a mis-promoted DC RDP
   target cannot authenticate (`jess-web-rdp.hcl`). Unchanged; documented here as
   the backstop.

Net: a Domain Controller can never gain a brokered RDP path via discovery,
through misconfiguration, a stray tag, or a single bad policy edit.

### 3. Admin review queue (manual-approve UX)

Add `/admin/pending` (controller) + a "Pending" view in jess-web:
- list candidates with Source, Address, Protocol, Criticality, policy reason,
  discovered-at;
- **Approve** (creates the `JessTarget`, audit `discovery.promoted`) / **Reject**
  (audit `discovery.rejected`, optional suppress);
- server-side filter `?phase=Pending` (ADR 0046 open follow-up) so Rejected rows
  don't bloat the list.

### 4. Continuous / dynamic (not periodic-static)

- Event-driven where the source supports it (k8s informer watch; LDAP
  `IngestSnapshot` on change), interval refresh otherwise.
- **Retirement TTL** (ADR 0046 sibling): a candidate/target whose source stops
  reporting it for `JESS_DISCOVERY_RETIRE_TTL` is auto-retired (audit
  `discovery.retired`) — closes the StrongDM "no auto-delete" gap.

## Consequences

**Positive:** continuous self-updating inventory (best practice); zero silent
onboarding (default-deny + manual approve); Tier-0 RDP provably impossible via
discovery; full SOC2 trail (`discovery.{promoted,rejected,retired}` + catalog
diff); operator-visible queue.

**Negative:** Phase F touches every dynamic provider (one MR each, kept small);
admin UI is net-new surface; Rego hard-deny must be CI-tested so an edit can't
regress the Tier-0 guard.

**Neutral:** `static` + `admin-api` paths unchanged; existing `targets.json`
remains the authoritative pinned baseline during rollout.

## Rollout (governance-first)

1. **This ADR + Tier-0 hard-guard** (Rego hard-deny + LDAP RDP suppression + CI
   test) — **DONE in this MR. Enables nothing.** Implemented:
   - `docs/policy/jess/discovery.rego` — un-overridable `tier0_rdp_block` (every
     allow rule, incl. the `jess:auto-promote` tag, requires `not tier0_rdp_block`).
   - `docs/policy/jess/discovery-strict.rego` — NEW "everything-manual" policy for
     the option-(b) first rollout (default-deny, no promotion, same hard-guard).
   - `internal/catalog/providers/ldap` — `SuppressRDPForCriticality` (default
     `["critical"]`): a DC never even emits an RDP candidate.
   - Tests load the REAL policy files and assert Tier-0 RDP is denied even with the
     auto-promote tag (guards against a future edit deleting the block).
2. **Admin pending queue** (controller endpoint + jess-web view).
3. **Phase F-1: LDAP → Pending, audit-only.** Enable `JESS_LDAP_DISCOVERY` +
   reconciler; mount Rego ConfigMap; apply CRD. **Soak**: candidates appear in the
   queue, nothing auto-brokers except non-critical+recorded workers. Verify the DC
   appears SSH-only and never with RDP.
3.b **Manifests** (the GitOps repository): CRD, Rego ConfigMap, env flags, retire TTL.
4. **Phase F-2: Proxmox + k8s-services → Pending.** Same pattern.
5. **Graduate**: once the queue + policy are proven, leave default-deny in place;
   tune Rego per source. Keep `targets.json` only for pins/overrides.

## References

- ADR 0030 (dynamic catalog Aggregator), ADR 0046 (PendingTarget lifecycle),
  ADR 0049 (multi-protocol brokering), `jess-web-rdp.hcl` (Tier-1-only RDP creds).
- Microsoft Enterprise Access / AD tiering — DC = Tier-0; RDP only from a clean
  Tier-0 source (PAW), never a lower-tier jump box.
- Teleport / IDSA / PAM guidance — auto-discovery is best practice **only with
  governance on labeling**; unreviewed labels silently enter RBAC scope.
- internal engineering notes (operator memory).
