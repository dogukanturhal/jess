# ADR 0038 Phase 5j-4 — SPIRE-based worker mTLS

| | |
|---|---|
| **Status** | Proposed — design committed 2026-06-03; implementation deferred to a dedicated sprint |
| **Phase** | 5j-4 (closes priority #6 in ADR 0034 §Decisions) |
| **Owners** | Platform / jess maintainers |
| **Supersedes** | none (extends Phase 5 controller↔worker mTLS substrate) |
| **Required by** | ADR 0034 §Decisions #6; tier-1 SOC 2 CC6 / FedRAMP IA-5 evidence; long-term Linkerd-coexistence story for the jess namespace |

## Problem

Today's worker→controller mTLS uses file-mounted PEM material:

- `JESS_TLS_CERT`, `JESS_TLS_KEY`, `JESS_TLS_CA` env vars point at files mounted from a Kubernetes `Secret` populated by an `ExternalSecret` against Vault PKI mount `jess-ca`.
- ESO refresh interval is **1 hour**; the issued cert lifetime is **24 hours** (matches the existing Vault PKI `jess-worker` role).
- The pod must restart (or the running process must re-read the file) for a rotated cert to take effect. Today's controller + worker process **does not** watch the file — rotation only lands on next pod restart.

Three independent problems flow from this shape:

1. **Long rotation cadence, asymmetric.** ESO refresh (1h) and pod restart cadence (days–weeks) are decoupled. In the worst case a worker runs with a cert minted >1 day before its restart. Long-lived material expands the blast radius of a compromised pod filesystem.
2. **No cryptographic attestation chain to workload identity.** The `Secret` carrying the PEM is whoever the SA `jess` can mount. There's no proof at TLS-handshake time that the peer is *actually* a `jess-worker` pod scheduled on a Hexx node — only that the peer has a cert signed by `jess-ca` with a CN matching the expected pattern. Any pod with the right SA mount gets the cred.
3. **Stale-cert risk on Vault outage.** If Vault is unreachable for >1h, ESO's last-known cert is what every worker keeps using until restart. There's no SPIFFE-style "fail closed when SVID can't refresh" semantics — workers happily handshake with a cert that may already be revoked.

A SPIFFE-shaped solution closes all three. SPIFFE SVIDs are short-lived (default 1h, rotation triggered at 50% lifetime), cryptographically attested to a workload identity via the k8s_psat node-attestor selectors (namespace + SA + pod labels — *all* of which the k8s API server enforces), and delivered over a Workload API unix socket the workload re-reads in-process via the `go-spiffe` library (no pod restart needed). This is the industry consensus for k8s workload-to-workload mTLS in 2026.

A stub already exists in jess: `cmd/jess-controller/main.go` checks `JESS_SPIFFE_SOCKET` and, when set, swaps `transport.LoadServerConfig` for `transport.SPIFFEServerConfig` plus a `peerSPIFFEIDFn` (in place of `peerCNFn`). The wiring is there. **SPIRE itself is not deployed.** Phase 5j-4 deploys SPIRE Server + Agent + registration entries and flips the env to activate the existing code path.

## Industry survey (2026-06)

Five reference points fetched live (3 of 5 returned substantive content; 2 are flagged here as research-thin):

| Vendor / project | Workload identity model | SPIRE? | Relevance to jess |
|---|---|---|---|
| **Istio (with SPIRE integration)** | Replaces Istio's built-in CA with SPIRE; envoy proxies fetch SVIDs over SDS from the SPIRE Agent unix socket mounted by the SPIFFE CSI driver. Trust domain must match between SPIRE + Istio; workloads pre-registered via `ClusterSPIFFEID` (SPIRE Controller Manager) or `spire-server entry create`. | **Yes — first-class** | The canonical SPIRE-on-k8s deployment pattern. Even though jess doesn't use Envoy, the registration shape (`spiffe://<td>/ns/<ns>/sa/<sa>`) is identical. |
| **SPIRE k8s_psat plugin** (primary source) | Validates k8s Projected SA Tokens via the Kubernetes TokenReview API. Emits SPIFFE IDs of the form `spiffe://<td>/spire/agent/k8s_psat/<cluster>/<node_UID>`. Selectors include `k8s_psat:cluster:*`, `k8s_psat:agent_ns:*`, `k8s_psat:agent_sa:*`, `k8s_psat:agent_pod_name:*`, plus configurable label/annotation allow-lists. | n/a (this *is* SPIRE) | Definitive attestor for our environment. PSAT is mandatory over the deprecated SAT plugin — uses Projected SA Tokens with audience binding. |
| **Linkerd** | Runs its own built-in CA called `identity`. Workload certs are bound to k8s ServiceAccount via the SA token. Default trust anchor expires after 365 days and requires manual rotation. SPIRE integration is **not first-class** — cert-manager substitutes for auto-rotation; SPIRE is community-pattern, not documented. | **No (own CA)** | Coexistence matters: jess pods run on a cluster that *also* runs Linkerd for service mesh. Linkerd identity and SPIRE identity sit at different layers — Linkerd handles mesh-to-mesh proxy TLS; SPIRE handles application-to-application TLS. They don't conflict (different unix sockets, different cert chains, different consumers). Confirmed indirectly by Istio's separate SDS+SPIRE wiring. |
| **HashiCorp Boundary worker identity** | Source fetch returned HTTP 404 (URL drift between Boundary doc versions). Cross-checked against ADR 0034's vendor matrix and Boundary worker registration docs surveyed in run 2: Boundary uses **its own PKI** for worker↔controller mTLS, with worker registration via a join token + auto-rotation. SPIRE not used. | **No (own PKI + join token)** | Confirms the pattern: PAM brokers either roll their own PKI (Boundary, Teleport) or adopt SPIRE (the mesh-native path). jess sits closer to the mesh-native path because it already runs inside k8s and consumes go-spiffe in-process. |
| **Teleport Machine ID** | Source fetch returned empty content. Per ADR 0034 §Decisions #6 + the run-2 surface: Teleport Machine ID is a **proprietary alternative to SPIRE** — it issues short-lived Teleport-format certs to a "bot" identity via a bot-token enrolment flow. The cert format is Teleport's own (not X.509-SVID), the rotation is driven by the `tbot` daemon, and federation is Teleport-trust-domain-only. | **No (proprietary alternative)** | Confirms SPIRE is the open-standard route; proprietary stacks build their own equivalents. jess's already-shipped Falcon-ID-OIDC + Vault-PKI substrate does not need a `tbot`-equivalent; SPIRE slots in cleanly behind the existing go-spiffe stub. |

Three findings worth carrying:

1. **k8s_psat is the only attestor that matches our threat model.** The deprecated `k8s_sat` (Service Account Token, non-projected) attestor was vulnerable to token theft and replay; PSAT binds to a specific audience and TTL via the Kubernetes ProjectedServiceAccountToken volume. The SPIRE project deprecated SAT in v1.0. **k8s_psat is mandatory.**
2. **Trust domain choice is sticky once chosen.** Istio's docs flag trust-domain alignment as the #1 source of integration bugs. Once SPIRE Server is bootstrapped with `trust_domain: hexxlock.com`, changing it later requires bundle re-issuance for every workload + every federated peer. **Pick a trust domain that maps to the long-lived business identity, not the cluster name.**
3. **Linkerd + SPIRE coexist.** No documented conflict; the two systems operate on different unix sockets, mint different cert chains, and serve different consumers (Linkerd: mesh proxies; SPIRE: application workloads). The Istio + SPIRE pattern proves the model: a service mesh's *own* identity can coexist with SPIRE-issued workload identities. This is critical because jess pods are mesh-injected today.

## Decision

**Adopt SPIRE Server (HA, Postgres-backed) + SPIRE Agent (DaemonSet, k8s_psat node-attestor) for jess worker↔controller mTLS.** Trust domain = `hexxlock.com` (matches the long-lived business root; not cluster-local). X.509-SVIDs only for Phase 5j-4 (JWT-SVID deferred — workers don't currently call HTTP APIs that need it). Rotation cadence = SPIRE default (1h SVID validity, refreshed at 50%).

Activation = flip `JESS_SPIFFE_SOCKET=/run/spire/agent.sock` on both `jess-controller` and `jess-worker` Deployments. The existing code path in `cmd/jess-controller/main.go` (and the symmetric one in the worker) handles the rest: `transport.SPIFFEServerConfig` + `peerSPIFFEIDFn` replace `transport.LoadServerConfig` + `peerCNFn` with zero code change required.

File-mount removal (`JESS_TLS_CERT/KEY/CA` + ExternalSecret `jess-controller-mtls` + `jess-worker-mtls` + Vault PKI role `jess-worker`) deferred to sub-phase 5j-4e after a soak period to prove the SPIFFE path is stable.

## Design

### SPIRE Server deployment

- **Namespace**: new `spire` (or `spire-server`) namespace, cluster-wide infrastructure tier.
- **Workload**: StatefulSet, 3 replicas (HA — quorum-tolerant 2/3 + leader election via the Postgres datastore).
- **Datastore**: existing CNPG cluster `spire-pg` (new database `spire_server`); credentials minted via Crossplane `CNPGDatabaseClaim` like every other jess-tier service.
- **Trust domain**: `hexxlock.com`. Bundle endpoint exposed via the Talon-fronted hostname `internal.example.com` (Talon IAP) for any future federated peers — for the single-cluster MVP, this is internal-only.
- **Plugins**:
  - `DataStore: sql` (Postgres).
  - `NodeAttestor: k8s_psat` with `clusters = { hxk1 = { audience = ["spire-server"], service_account_allow_list = ["spire/spire-agent"] } }`.
  - `KeyManager: disk` (encrypted at rest via Vault Transit pre-seal — same pattern as Vault unseal).
  - `Notifier: k8sbundle` (publishes the trust bundle to a `ConfigMap` for in-cluster consumers).
- **Upstream authority**: Vault PKI mount `spire-ca` (new), so SPIRE's signing key chains up to the existing Vault root — same root of trust as `jess-ca`. This lets us reason about *both* file-mount and SPIFFE certs as descendants of the same root during the cutover window.

### SPIRE Agent deployment

- **Workload**: DaemonSet on every worker node (the same nodes that run jess workers — currently every general worker node since no taints exclude jess).
- **Unix socket**: `/run/spire/agent.sock` on the host (hostPath mount), 0660 root:root.
- **Plugins**:
  - `NodeAttestor: k8s_psat` (agent side — sends the projected SA token to the server).
  - `WorkloadAttestor: k8s` (matches workload pods via `k8s:ns:*`, `k8s:sa:*`, `k8s:pod-label:*`).
  - `WorkloadAttestor: unix` (UID/GID fallback for non-k8s workloads on the same node — not used by jess but kept for cluster-wide future use).
- **Socket sharing**: hostPath `/run/spire` mounted into every consumer pod (read-only on the consumer side, read-write on the agent side). Alternative — the SPIFFE CSI driver — is the long-term right answer; Phase 5j-4 uses hostPath as the simpler MVP and tracks CSI as a follow-up (see §Open questions).

### Registration entries

Per-SA entries for the jess workloads, registered via the SPIRE Controller Manager `ClusterSPIFFEID` CRD (declarative + GitOps-managed) — NOT via raw `spire-server entry create` (imperative + drifts).

```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: jess-controller
spec:
  spiffeIDTemplate: "spiffe://hexxlock.com/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
  podSelector:
    matchLabels:
      app.kubernetes.io/name: jess-controller
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: jess
---
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: jess-worker
spec:
  spiffeIDTemplate: "spiffe://hexxlock.com/ns/jess/sa/jess"
  podSelector:
    matchLabels:
      app.kubernetes.io/name: jess-worker
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: jess
---
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: jess-web
spec:
  spiffeIDTemplate: "spiffe://hexxlock.com/ns/jess/sa/jess"
  podSelector:
    matchLabels:
      app.kubernetes.io/name: jess-web
  namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: jess
```

All three jess pods today run as SA `jess` in namespace `jess` — the SPIFFE ID `spiffe://hexxlock.com/ns/jess/sa/jess` is intentionally shared across controller / worker / web. The `peerSPIFFEIDFn` enforces SPIFFE ID membership (allow-list), not pod-distinction; this matches the Istio sidecar pattern (every sidecar in `ns/sa` gets the same SPIFFE ID, mesh-level auth distinguishes nothing finer).

If finer distinction is needed later (e.g. limit `jess-web` from calling `jess-worker` admin port), introduce per-component SAs (`jess-controller`, `jess-worker`, `jess-web`) and register each with a distinct SPIFFE ID. Out of scope for Phase 5j-4.

### jess-controller + jess-worker wiring

The code path already exists:

```go
// cmd/jess-controller/main.go — current shape (paraphrased)
if sock := os.Getenv("JESS_SPIFFE_SOCKET"); sock != "" {
    cfg = transport.SPIFFEServerConfig(ctx, sock, allowedSPIFFEIDs)
    verifyPeerFn = peerSPIFFEIDFn(allowedSPIFFEIDs)
} else {
    cfg = transport.LoadServerConfig(certFile, keyFile, caFile)
    verifyPeerFn = peerCNFn(allowedCNs)
}
```

Phase 5j-4d sets `JESS_SPIFFE_SOCKET=/run/spire/agent.sock` and `JESS_SPIFFE_ALLOWED_IDS=spiffe://hexxlock.com/ns/jess/sa/jess` on both Deployments via the the GitOps repository Helm values. The `go-spiffe` library handles socket reconnect, SVID refresh, and trust-bundle updates in-process — no pod restart on rotation, fail-closed on socket unavailable (the next handshake errors out cleanly, surfaced via the existing `talon_request_total{result="tls_error"}` analog on the jess side).

### Mount pattern

Both controller + worker Deployments add:

```yaml
volumes:
  - name: spire-agent-socket
    hostPath:
      path: /run/spire
      type: DirectoryOrCreate
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire
    readOnly: true
```

NOTE: hostPath requires the pod's SecurityContext to permit it. The existing `jess` PSP (PodSecurityAdmission baseline) allows hostPath for the `/run/spire` path via an explicit exception — captured in the Phase 5j-4a substrate MR. The CSI-driver alternative removes the hostPath requirement entirely and is the preferred follow-up (§Open questions).

### Trust bundle propagation

SPIRE Server's `Notifier: k8sbundle` plugin publishes the trust bundle to ConfigMap `spire/spire-bundle` on every bundle change. Consumer pods don't need to mount this ConfigMap directly — the `go-spiffe` Workload API client receives bundle updates live over the agent unix socket. **No explicit trust bundle wiring required on the jess side**; the SPIFFE library handles it.

The ConfigMap is published anyway as the off-cluster federation hook for future use (cross-trust-domain peers fetch it via the Talon-fronted `internal.example.com/.well-known/spiffe-bundle` endpoint).

## Implementation slices

### 5j-4a — SPIRE Server StatefulSet + Postgres + ESO

**Files** (the GitOps repository or new `infrastructure-iac` chart):
- `the GitOps repository/apps/spire-server/Chart.yaml` + `values.yaml` + templates.
- `infrastructure-iac/datacenters/eu-west-1/vault/vault-spire-pki.tf` — Vault PKI mount `spire-ca` + role `spire-server-upstream` (extends `gitlab-infra-iac-vault-admin` policy per the standing pattern — cross-ref MEMORY.md feedback on policy coverage).
- `the GitOps repository/apps/spire-server/templates/cnpg-cluster.yaml` — CNPG `Cluster` `spire-pg` (3-instance, NVMe storage, 7-day PITR — same shape as `example-app-pg`).
- ESO `ExternalSecret` for `spire-server` to mount the Vault PKI upstream signing key + DB creds.
- ArgoCD `Application` declared in `<gitops-bootstrap-repo>/argocd/apps/spire-server.yaml` (no syncWindow — infrastructure tier matches the falcon-id pattern).

**Acceptance**:
- 3/3 SPIRE Server pods `Ready` in namespace `spire`.
- Postgres-backed leader election visible in logs (`I leader: <pod>` rotation on pod kill).
- `kubectl exec spire-server-0 -- spire-server bundle show` returns a non-empty trust bundle rooted at the Vault PKI `spire-ca` upstream.
- Bundle ConfigMap `spire/spire-bundle` populated.

**Risk**: Postgres bootstrap timing — SPIRE Server retries data-store connect on startup; the CNPG bootstrap is async. Mitigate via the standard initContainer that waits for CNPG `READY` before SPIRE Server starts.

### 5j-4b — SPIRE Agent DaemonSet + k8s_psat node attestor

**Files**:
- `the GitOps repository/apps/spire-agent/Chart.yaml` + templates.
- ClusterRole + ClusterRoleBinding granting `tokenreviews/create` on the SPIRE Server SA (server-side requirement for PSAT validation).
- Agent SA `spire/spire-agent` with the projected SA token volume (audience = `spire-server`).

**Acceptance**:
- One `spire-agent` pod per node, all `Ready`.
- Each agent successfully attests to the server (`spire-server agent list` shows N attested agents).
- Sample workload (a throwaway debug pod with the right `app.kubernetes.io/name` label) successfully receives an X.509-SVID via `spiffe-helper` or `getx509svid` test binary.

**Risk**: SAT (deprecated) vs PSAT (current) mismatch — the older `k8s_sat` examples on Google still surface. Phase 5j-4b uses **k8s_psat** exclusively; the agent config explicitly mounts a projected SA token volume.

### 5j-4c — Registration entries for jess workloads

**Files**:
- `the GitOps repository/apps/spire-server/templates/clusterspiffeids.yaml` — three `ClusterSPIFFEID` resources (controller, worker, web — all resolving to `spiffe://hexxlock.com/ns/jess/sa/jess`).
- SPIRE Controller Manager already-deployed in 5j-4a (sub-chart of SPIRE Server chart).

**Acceptance**:
- `spire-server entry show` lists the 3 entries.
- An exec into a `jess-worker` pod and a `getx509svid` test call against `/run/spire/agent.sock` returns an SVID with the expected SPIFFE ID.
- The SVID rotates within 35min (50% of default 1h validity) — verifiable via repeated `getx509svid` calls + cert serial comparison.

**Risk**: Pod label drift — if a future Helm chart change drops `app.kubernetes.io/name: jess-worker`, the selector misses and the workload silently can't get an SVID. Add a unit test in the chart values that asserts the labels are present + matches the ClusterSPIFFEID `podSelector`.

### 5j-4d — Flip jess-controller + jess-worker to SPIFFE

**Files**:
- `the GitOps repository/apps/jess/values.yaml` — add `JESS_SPIFFE_SOCKET=/run/spire/agent.sock` + `JESS_SPIFFE_ALLOWED_IDS=spiffe://hexxlock.com/ns/jess/sa/jess` env on both Deployments.
- Add the hostPath volume + mount.
- KEEP `JESS_TLS_CERT/KEY/CA` env vars for now — the code path is `if SPIFFE_SOCKET set, prefer SPIFFE; else fall back to file mount`. Belt-and-braces during cutover.

**Acceptance**:
- Both Deployments roll cleanly (PDB respected — see §Failure modes).
- `jess_session_open_total{result="ok"}` continues to increment (worker successfully dials controller post-flip).
- `kubectl logs jess-controller -- | grep SPIFFE` shows `using SPIFFE workload identity` at startup.
- Cert rotation observed: `openssl s_client -connect controller:7102` shows a different cert serial after ~35min, with no pod restart.

**Risk**: Trust-domain typo silently breaks `peerSPIFFEIDFn` — the worker handshake succeeds at the TLS layer (cert is signed by the right SPIRE CA) but the SPIFFE-ID allow-list rejects. **Mitigate** with a pre-flip dry-run: a debug pod runs `peerSPIFFEIDFn(["spiffe://hexxlock.com/ns/jess/sa/jess"])` against a manually-issued SVID and asserts accept-path works.

### 5j-4e — Remove file-mount substrate (post-soak)

**Files (after 7-day soak)**:
- `the GitOps repository/apps/jess/values.yaml` — drop `JESS_TLS_CERT/KEY/CA` env + Secret mount.
- ESO `ExternalSecret` `jess-controller-mtls` + `jess-worker-mtls` removed.
- Vault PKI role `jess-ca/jess-worker` left in-place initially (rollback hatch); removed in a follow-up MR after 30 days.

**Acceptance**:
- `kubectl get secrets -n jess | grep mtls` returns nothing.
- jess workloads still handshake successfully (SPIFFE path only — confirmed by killing the SPIRE Agent on one node and watching that node's jess-worker pod fail to mint new sessions within 1h of cert expiry, then recover when SPIRE Agent comes back).

**Risk**: Some operator tooling (e.g. `jessctl admin operator-cert-list`) may have a stale reference to the file paths. Grep the entire codebase for `JESS_TLS_CERT` before merging the removal MR.

### 5j-4f — Documentation: registration-entry runbook

**Files**:
- `jess/docs/runbooks/spire-add-workload.md` — step-by-step for adding a new jess-tier workload to SPIRE. Covers: pick a SPIFFE ID, add the `ClusterSPIFFEID` to the GitOps repository, verify with `spire-server entry show`, verify with a debug pod's `getx509svid` call.
- `jess/docs/runbooks/spire-rotation-debug.md` — debug recipes for "my SVID isn't rotating" (check agent connectivity, check entry TTL, check workload re-fetch interval).
- Update `jess/docs/sessions/2026-05-29-jess-operator-e2e.md` post-cutover with a "controller mTLS now SPIRE-backed" note.

## Cross-cutting concerns

### Telemetry to add

| Metric | Type | Labels |
|---|---|---|
| `spire_agent_svid_rotations_total` | counter | namespace, sa |
| `spire_agent_svid_fetch_failures_total` | counter | namespace, sa, reason |
| `spire_server_registration_entries_total` | gauge | trust_domain |
| `spire_server_attestation_total` | counter | attestor (k8s_psat), result |
| `jess_spiffe_peer_id_rejected_total` | counter | reason (unknown_id, expired, no_chain) |

SPIRE Server + Agent ship Prometheus metrics natively (port 8080 + 8088). jess controller adds the `jess_spiffe_peer_id_rejected_total` counter inside `peerSPIFFEIDFn` — currently the function returns an error but doesn't increment anything.

Alerts (PrometheusRule, added in 5j-4a):
- `SPIRESVIDRotationStalled` — `rate(spire_agent_svid_rotations_total[1h]) == 0` for any (namespace, sa) for >2h.
- `SPIREServerLeaderFlapping` — leader change > 3 times in 10min.
- `JessSPIFFEPeerRejectSpike` — `jess_spiffe_peer_id_rejected_total` increases more than 10 events in 5min (catches trust-domain typos + replay attempts).

### Audit logging

Every SVID issued + rotated is logged by SPIRE Server at INFO level. These logs are routed through the existing Loki collector and tagged `app=spire-server`. The audit trail joins to the jess WORM session log via the SPIRE-issued cert serial (logged on both sides — SPIRE Server logs the mint, jess controller logs the peer-cert serial on handshake).

This satisfies SOC 2 CC6.1 (logical access — workload identity establishment) and FedRAMP IA-5 (authenticator management — cryptographic credential issuance traceable).

### Linkerd compatibility

jess pods are mesh-injected by Linkerd. Linkerd's `linkerd-proxy` sidecar talks to the `linkerd-identity` CA over a different unix socket (`/var/run/linkerd/identity/end-entity`) and obtains a *separate* cert chain rooted at the `linkerd-identity-issuer` cert. SPIRE's `/run/spire/agent.sock` is a parallel concern: jess application code (not the Linkerd proxy) consumes SPIRE SVIDs for the worker↔controller TLS layer.

Concretely: a jess-worker pod has THREE cert chains live at once after Phase 5j-4d:
1. Linkerd proxy cert (mesh proxy-to-proxy TLS, rotated by `linkerd-identity`, 24h validity).
2. SPIRE SVID (application-layer mTLS for worker↔controller yamux, rotated by `spire-agent`, 1h validity).
3. (Soak window only — 5j-4d to 5j-4e) The legacy file-mounted Vault PKI cert (unused after the flip but still mounted).

No conflict — different sockets, different consumers, different chains. Verified pattern from the Istio + SPIRE integration; will hold for Linkerd + SPIRE too.

### CSI driver vs hostPath

The SPIFFE CSI driver mounts the agent socket via a CSI volume rather than hostPath. Advantages: no PSP hostPath exception needed, per-pod permission control. Disadvantage: another DaemonSet to operate. **Phase 5j-4 uses hostPath** as the MVP; **Phase 5j-5 (follow-up)** migrates to the CSI driver once SPIRE itself is proven stable.

## Failure modes

| Failure | Blast radius | Mitigation |
|---|---|---|
| **SPIRE Server down (all 3 replicas)** | Agents serve cached SVIDs until expiry (1h); after 1h, new SVIDs can't mint; existing TLS connections keep working (cached SVIDs survive in-process) but new connections fail. | HA 3-replica StatefulSet + PDB `minAvailable: 2`. Postgres CNPG with 3-instance quorum prevents single-DB failure from taking out the SPIRE control plane. Soak alert on `spire_server_up == 0` at the <gitops-bootstrap-repo> monitoring tier. |
| **SPIRE Agent down on a node** | Pods on that node can't get fresh SVIDs; existing TLS connections keep working until cert expiry (1h); after 1h, the worker can't handshake new sessions and the pod's session-open success rate drops. | DaemonSet has tight readiness probe; `node-problem-detector` surfaces socket-down. Application-side `jess_spiffe_peer_id_rejected_total` will tick on the controller side. Operator alert + rolling restart of the agent DaemonSet recovers within seconds. |
| **Registration entry typo (wrong selector)** | Affected workload pod can't get an SVID at all; pod logs `failed to fetch x509 svid: no identity issued`; the jess process panics at startup (current behaviour for missing TLS material). | Pre-merge: chart values unit test asserts label↔selector alignment. Post-merge: same `SPIRESVIDRotationStalled` alert catches a workload that never mints an SVID. |
| **Trust-domain mismatch (server says `hexxlock.com`, allow-list says `hexxlock.local`)** | Peer cert is valid X.509 but SPIFFE-ID allow-list rejects; handshakes 100% fail. | Pre-flip dry-run in 5j-4d (debug pod confirms allow-list works). Single config source-of-truth in Helm values (`global.spiffe.trustDomain`) shared between SPIRE Server config + jess env. |
| **Postgres datastore corruption / data loss** | SPIRE Server can't bootstrap; all entries lost; every workload re-attests from scratch on next agent reconnect. | CNPG nightly base backup + WAL streaming to MinIO (same pattern as every other CNPG cluster). Recovery RTO ~30min. Bundle re-issuance is automatic on Postgres restore (entries are declarative via ClusterSPIFFEID — re-applied by SPIRE Controller Manager). |
| **Linkerd identity rotation collides with SPIRE rotation** | None — different sockets, different chains. Not actually a failure mode; listed for completeness. | n/a |

## Out of scope

- **Federation across trust domains** — single-cluster MVP. SPIFFE federation (multiple SPIRE Servers in different trust domains exchanging bundles via the `.well-known/spiffe-bundle` endpoint) is a Phase 5j-5+ concern when we add a second datacenter or cross-tenant boundary.
- **JWT-SVID adoption** — workers currently call gRPC/yamux only; no HTTP API consumers in the worker→controller path. JWT-SVID becomes relevant when (e.g.) jess-controller starts calling an external HTTP webhook with a workload-identity bearer.
- **SPIRE SQL backend migration from in-memory** — irrelevant; Phase 5j-4a starts with Postgres from day one (the in-memory `sql` backend default is dev-only and would lose entries on every server restart, breaking HA quorum).
- **SPIFFE CSI driver** — defer to Phase 5j-5.
- **Per-component SAs** (`jess-controller-sa`, `jess-worker-sa`, `jess-web-sa`) — defer until policy requires SPIFFE-ID-level distinction. Today all three share SA `jess`.
- **HCP Vault PKI vs SPIRE PKI overlap** — Phase 5j-4 keeps Vault PKI as the upstream signing authority for SPIRE (`spire-ca` mount). Full Vault-replaces-SPIRE-CA-entirely is a separate architectural choice (see §Open questions).
- **ESO + Vault workload identity** — ESO uses the cluster SA + Vault k8s auth method, not SPIFFE. Migrating ESO to SPIFFE is out of scope (different consumer surface; ESO doesn't natively speak SPIFFE).
- **CRL distribution for SPIRE-issued SVIDs** — SPIRE SVIDs are short-lived (1h) and not CRL-backed; revocation = waiting up to 1h for expiry. For faster revocation, delete the `ClusterSPIFFEID` (SPIRE Controller Manager reconciles within seconds, new SVIDs not issued). Pair with the Phase 4 operator-cert lock pattern for emergency cuts.

## Timeline summary

| Sub-phase | Estimate | Blockers |
|---|---|---|
| 5j-4a — SPIRE Server + Postgres + Vault PKI upstream | ~1 week | CNPG cluster bootstrap, Vault PKI mount, Helm chart auth |
| 5j-4b — SPIRE Agent DaemonSet + PSAT attestor | ~3 days | follows 5j-4a |
| 5j-4c — Registration entries | ~2 days | follows 5j-4b |
| 5j-4d — Flip jess-controller + jess-worker to SPIFFE | ~3 days | follows 5j-4c + dry-run validation |
| 5j-4e — Remove file-mount substrate (post-soak) | ~2 days after 7-day soak | follows 5j-4d + 7 days soak |
| 5j-4f — Documentation runbook | ~1 day | parallel to 5j-4e |

**Realistic total wall-clock: 3-4 weeks for a single engineer.** SPIRE Server HA + Postgres bootstrap + trust-bundle reconciliation is the long pole at 5j-4a. The actual jess code change (5j-4d) is trivial — the stub does the work.

## Open questions

1. **Linkerd integration — replace or coexist?** Phase 5j-4 assumes coexist (Linkerd handles mesh-proxy TLS via its own CA, SPIRE handles application TLS for jess). The alternative is to replace `linkerd-identity` with SPIRE — Linkerd has community patterns for this but it's not first-class. **Recommend coexist for now**; revisit if Linkerd's manual trust-anchor rotation becomes operationally painful.
2. **Trust domain choice — `hexxlock.com` vs `hexxlock.local` vs cluster-name?** Phase 5j-4 picks `hexxlock.com` (matches the long-lived business identity). Counterargument: if we ever federate across customer-tenant boundaries, a cluster-scoped name might be cleaner. **Recommend `hexxlock.com`** — federation comes later and federation specifically supports cross-trust-domain.
3. **HCP Vault PKI vs SPIRE PKI — overlap or federation?** Phase 5j-4 has SPIRE chain up to Vault PKI `spire-ca` (Vault stays root). The alternative is SPIRE as its own root with no Vault dependency. **Recommend keep Vault as upstream root** — single source of truth for the org's PKI, matches how `jess-ca` + `falcon-id-ca` already chain.
4. **What about ESO + Vault that ALSO needs workload identity?** ESO currently uses the Kubernetes auth method (SA token → Vault role binding). Migrating ESO to consume SPIFFE SVIDs against Vault's `cert` auth method is technically possible but cross-cuts the entire secret-fetch substrate. **Defer to a separate ADR**; Phase 5j-4 is jess-scoped.
5. **Trust bundle distribution outside the cluster** — when a future federated peer needs the bundle, do we publish via Talon-fronted `.well-known/spiffe-bundle` or via a dedicated unauth endpoint? **Talon-fronted is more consistent** with how every other IdP-tier metadata is exposed; deferred until federation actually surfaces.
6. **SPIFFE CSI driver migration timeline** — Phase 5j-5 or roll it into 5j-4 from the start? **Roll-into-5j-4 is cleaner** but adds a week of CSI debugging. Recommend 5j-5 follow-up to keep 5j-4 lean.
7. **JWT-SVID for jess admin HTTP endpoints** — `jessctl admin` calls (`/grants`, `/operator-cert/revoke`, etc.) currently use operator-cert mTLS. Could move to JWT-SVID if the operator workstation runs a SPIRE Agent. **Out of scope** — operators don't run SPIRE Agents on their workstations and shouldn't have to.

## References

| Source | Topic |
|---|---|
| https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/ | SPIFFE concepts (trust domain, SPIFFE ID, SVID) |
| https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_psat.md | SPIRE k8s_psat node attestor (primary source — fetched live 2026-06-03) |
| https://istio.io/latest/docs/ops/integrations/spire/ | Istio + SPIRE integration (primary — fetched live; ClusterSPIFFEID pattern + SDS wiring) |
| https://linkerd.io/2/features/automatic-mtls/ | Linkerd automatic mTLS (primary — fetched live; confirms own-CA model, no SPIRE first-class) |
| https://github.com/spiffe/spire-controller-manager | SPIRE Controller Manager — ClusterSPIFFEID CRD reconciler |
| https://github.com/spiffe/spiffe-csi | SPIFFE CSI driver (deferred to Phase 5j-5) |
| https://github.com/spiffe/go-spiffe | go-spiffe library — used by existing `transport.SPIFFEServerConfig` stub |
| https://csrc.nist.gov/pubs/sp/800/204/a/final | NIST SP 800-204A — Service Mesh Proxy Models (informs SPIRE-vs-mesh-CA architectural reasoning) |
| https://developer.hashicorp.com/boundary/docs/concepts/security/workers | HashiCorp Boundary worker identity (fetched live — 404; substituted from ADR 0034 run-2 surface) |
| https://goteleport.com/docs/enroll-resources/machine-id/introduction/ | Teleport Machine ID (fetched live — empty content; substituted from ADR 0034 §Decisions #6 prior research) |
| jess/docs/adr/0033-phase-5f-rust-ironrdp-bridge.md | Style template (this ADR mirrors its slice-per-sub-phase structure) |
| jess/docs/adr/0034-tier-1-ztna-enhancements.md | Source for priority #6 (SPIRE-based worker mTLS) |
| jess/cmd/jess-controller/main.go | Existing `JESS_SPIFFE_SOCKET` stub + `transport.SPIFFEServerConfig` + `peerSPIFFEIDFn` |
