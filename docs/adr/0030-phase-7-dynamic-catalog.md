# ADR 0030 Phase 7 — Dynamic Target Catalog

| | |
|---|---|
| **Status** | Proposed — design committed 2026-06-01; implementation in flight |
| **Phase** | 7 (follows 5h-6 CAEP receiver, jess !24 merged 2026-06-01) |
| **Owners** | Platform / jess maintainers |
| **Supersedes (partially)** | `configmap-targets.yaml` becomes break-glass after 7e lands |

## Problem

Today the brokered-target catalog is a static JSON ConfigMap mounted into
jess-controller (`platform/jess/configmap-targets.yaml`). Every fleet
change requires:

1. Hand-edit the ConfigMap
2. Open a the GitOps repository MR
3. Wait for review + Argo sync (~1–3 min)

At HexxLock's current ~6 targets the cost is bearable. But:

- A customer deploying jess at any scale (auto-scaling node pools, EC2
  spot fleets, ephemeral VMs, cluster-api Machines) cannot keep up.
  Even 100 nodes with a 5% daily churn is 5 manifest MRs/day.
- The static catalog has no notion of "this target was seen at
  T, hasn't been seen since T+30min" — a deleted VM stays in the
  catalog until someone notices.
- No audit trail of catalog change separate from the operator who
  opened the manifest MR (provenance vs intent are conflated).

## Industry survey (2026-06)

Surveyed 8 vendors. Three dominant patterns:

| Pattern | Adopted by |
|---|---|
| **Periodic cloud-API pull, tag-filtered, dynamic write-back** (poll ~5min) | Teleport `discovery_service`, HashiCorp Boundary plugin host catalogs, StrongDM connector crawl |
| **Agent-push with cryptographic attestation** (IAM/IID join, no shared secrets) | AWS SSM, Teleport IAM-join, Consul agent register |
| **Directory / CMDB scan with predicate auto-enrollment** | CyberArk PAM (AD/CSV), BeyondTrust Password Safe (Smart Rules) |

Pomerium Zero is the *only* surveyed product with no cloud-discovery
primitive — its Route store is REST-defined, same model as jess today.
Validates that the gap exists; jess is below the modern bar.

Two non-obvious findings worth carrying into the design:

1. **Teleport's `discovery_group`** field exists *specifically* to prevent
   two discovery services from deleting each other's resources. The
   deletion path is the highest-risk operation on a dynamic catalog —
   any design must explicitly gate it.
2. **AWS SSM skips discovery entirely** by binding access policies to
   cloud tags, treating the cloud's tag index as the catalog. Inspires
   the *aggregator* shape: jess's catalog is whatever set of providers
   currently agree on, with tag-based filtering as the policy surface.

## Decision

Adopt **Pattern 1** (periodic cloud-API pull) as the primary discovery
model, with **Pattern 2** (host attestation) layered on top as a Phase
7g hardening step. Implementation is fully additive to the existing
`catalog.Catalog` Go interface — zero call-site changes.

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                catalog.Aggregator                            │
│  (implements catalog.Catalog — what spine.Controller sees)   │
│                                                              │
│   merge(static, k8s, proxmox, aws, azure, admin-api)         │
│   precedence: admin-api > static > cloud providers           │
│   fail-closed cache: last-known-good per provider            │
│   diff-then-audit: every refresh emits add/remove/change     │
└────────────┬────────────┬──────────────┬──────────────┬──────┘
             │            │              │              │
       ┌─────▼────┐  ┌────▼────┐  ┌──────▼─────┐  ┌────▼─────┐
       │ static   │  │  k8s    │  │  proxmox   │  │  aws     │ ...
       │ provider │  │ Node    │  │  cluster   │  │  EC2     │
       │ (JSON CM)│  │ watch   │  │  resources │  │ Describe │
       └──────────┘  └─────────┘  └────────────┘  └──────────┘
```

### Core abstractions

```go
type DiscoveryProvider interface {
    Name() string                                 // audit label
    Discover(ctx context.Context) ([]Target, error)
}

type Aggregator struct {
    providers []DiscoveryProvider
    // last-known-good cache, keyed by provider name
    // diff-then-audit on every refresh
}

func (a *Aggregator) Lookup(ctx context.Context, id string) (*Target, error) { ... }
func (a *Aggregator) List(ctx context.Context, region string) ([]*Target, error) { ... }
```

`Target` gains two fields (additive — existing call sites continue to
compile):

```go
type Target struct {
    ...                        // existing fields
    Source   string    `json:"source,omitempty"`    // provider name; "static" for ConfigMap
    LastSeen time.Time `json:"last_seen,omitempty"` // wall-clock of last successful discovery
}
```

### Invariants

1. **Fail-closed on transient provider errors.** If `Discover()` returns
   non-nil error, the aggregator keeps the provider's *last successful
   snapshot* and increments `jess_catalog_provider_error_total{provider}`.
   Targets only disappear when the provider returns a successful empty/
   partial result that explicitly excludes them.
2. **WORM audit on every diff.** Compute set-diff between previous and
   new snapshot per provider. Emit one audit Event per add/remove/change
   into the existing 5e-16 chain-hashed audit log. Audit fields:
   `target_id`, `source`, `change_type`, `before_hash`, `after_hash`,
   `discovered_at`.
3. **Precedence**: `admin-api` > `static` > cloud providers (later
   sources). Conflicting IDs are logged + audited as a discovery anomaly
   but the higher-precedence source wins.
4. **Refresh cadence**: default 5min per provider (matches Teleport's
   `poll_interval` default — validated industry baseline). Per-provider
   override via ConfigMap. K8s Node watch is event-driven (no poll).
5. **Trust separation**: discovery says *what to access*. SSH-CA + Vault
   dynamic creds (Phase Pick-3, already shipped) say *who you are*.
   No agent on targets in v1 — matches Boundary/StrongDM stance.

## Phases

| Phase | Title | Effort | MRs | Deps |
|---|---|---|---|---|
| **7a** | DiscoveryProvider substrate + Aggregator + fail-closed cache + diff-audit | ~3d | 1 jess | — |
| **7b** | Proxmox provider (HexxLock's fleet) | ~2d | 1 jess + 1 iac | 7a |
| **7c** | Kubernetes Node watch provider | ~2d | 1 jess + 1 the GitOps repository | 7a |
| **7d** | AWS EC2 + Azure VM providers | ~2d | 2 jess | 7a |
| **7e** | `JessTarget` CRD + controller (GitOps-native) | ~4d | 1 jess + 1 the GitOps repository | 7a |
| **7f** | Admin API + `jessctl admin target …` | ~1d | 1 jess | 7a |
| **7g** | Host attestation join (Teleport IAM-join pattern) | ~4d | 1 jess + 1 jess-attest | 7a, 7b/7c/7d |
| **7h** | jess-web SPA panel + per-target source badge | ~2d | 1 jess | partial through 7a–7f |

**Total**: ~20 working days · ~10 MRs across jess + the GitOps repository + iac.

### Recommended rollout order

1. 7a — substrate (everything depends on it)
2. 7c — Kubernetes (highest immediate value; 3 k8s targets stop being hand-curated; proves the watch path)
3. 7b — Proxmox (HexxLock's actual VM fleet; novel coverage vs commercial leaders)
4. 7f — Admin API (cheap, unblocks ad-hoc additions)
5. 7e — CRD + controller (the GitOps target)
6. 7d — AWS + Azure (only once HexxLock actually consumes those clouds)
7. 7h — SPA wiring (closure)
8. 7g — Host attestation (security hardening on top of working catalog)

## Migration

- ConfigMap stays the source of truth through Phase 7e.
- After 7e: ConfigMap → CRD via `jessctl admin migrate-configmap-to-crd`
  (idempotent). ConfigMap demoted to break-glass.
- No big-bang cutover. Each provider runs alongside the static one
  until operator confirms parity.

## Non-goals (Phase 7 explicitly does NOT cover)

- **Self-service operator onboarding** (operator-managed targets without
  platform-admin role). Authz still 100% on platform_admin.
- **Multi-tenancy** at the catalog level. All discovered targets are
  visible to every platform_admin; tenant isolation is a Phase 8+ topic.
- **Cross-cluster federation**. Each jess-controller is its own
  aggregator. A multi-cluster jess deployment would aggregate the
  aggregators — out of scope here.

## Open questions

- **CRD scope** (7e): cluster-scoped or namespaced? Cluster-scoped is
  simpler; namespaced lets ns-bound operators manage their own targets.
  Lean cluster-scoped initially (matches current ConfigMap shape).
- **Provider plugin model**: keep providers in-tree as Go packages
  (compile-time) or load via gRPC like Boundary's plugin host catalogs?
  Lean in-tree for v1 — Go's compile speeds make rebuild-per-provider
  the simpler answer; we can move to gRPC plugins if a customer needs
  to ship one without forking jess.
- **Eviction grace period**: when a provider stops listing a target,
  how long does it stay in the catalog before eviction? Default proposal:
  immediately (next refresh tick) for cloud providers (cloud API is
  authoritative); 24h for static/admin-api (operator intent shouldn't
  be evicted by a 5-min outage). Make per-provider configurable.

## References

- Teleport — Auto-Discovery Service: https://goteleport.com/docs/enroll-resources/auto-discovery/
- Teleport — `discovery_service` config: https://goteleport.com/docs/reference/deployment/config/
- HashiCorp Boundary — Host Discovery: https://developer.hashicorp.com/boundary/docs/concepts/host-discovery
- HashiCorp Boundary 0.19 (Azure + GCP plugins): https://www.hashicorp.com/en/blog/boundary-0-19-extends-dynamic-host-discovery-to-google-cloud
- StrongDM — Resource Discovery: https://docs.strongdm.com/admin/resources/discovery
- AWS SSM Session Manager — instance permissions: https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html
- CyberArk PAM — Account Discovery: https://docs.cyberark.com/pam-self-hosted/latest/en/content/pasimp/managing-discovery-processes-modernui.htm
- BeyondTrust Password Safe — Smart Rules: https://docs.beyondtrust.com/bips/docs/ps-smart-rules
- AWS Controllers for Kubernetes — how-it-works: https://aws-controllers-k8s.github.io/community/docs/community/how-it-works/
- Cluster API Machine model: https://cluster-api.sigs.k8s.io/
