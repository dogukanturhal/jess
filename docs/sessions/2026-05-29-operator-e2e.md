# Jess operator E2E runbook — 2026-05-29

Purpose: walk the deployed Jess broker through a real operator session,
end-to-end, from Falcon-ID OIDC + MFA through to a shell on a target node,
with evidence captured. Converts deployed-but-undemonstrated into proven
product. ADR 0030 Phase 5 capstone.

Operator: dogukanturhal (Falcon-ID sub `04ad2960-3202-4718-833e-2d58c948b09d`,
roles `platform_admin` + `iam_admin`, tenant `example-tenant`
`00000000-0000-0000-0000-000000000002`).

Target: `node-app-01` (SSH, `required_roles=[platform_admin]`, `recorded=true`,
host_key pinned).

---

## Pre-flight state (verified 2026-05-28T21:44Z)

- `jess` ArgoCD app: Synced / Healthy
- `jess-controller` 2/2 Running, uptime 24h, 0 restarts
- `jess-worker` 2/2 Running, uptime 24h, 0 restarts, **mTLS-connected**
  (`jess_workers_connected=1` via `/metrics`)
- `jess-pg` CNPG cluster healthy, primary = `jess-pg-1`
- 7/7 ExternalSecrets SecretSynced
- `jess-operator` LB `10.0.60.202:7101` TLS-reachable (cert subject
  `CN=jess-operator, O=HexxLock`, SAN `DNS:internal.example.com` +
  `IP:10.0.60.202`)
- `jess-controller` `/readyz` → `ready`
- Targets configmap loaded (node-app-01 SSH + jess-pg-db Postgres)
- jess-ca extracted to `~/.config/jess/jess-ca.crt`
- JIT grant **`grant-demo-20260528T214633Z`** in jess-pg (subject =
  dogukanturhal sub, target = node-app-01, expires 2026-05-28T22:16:33Z)
- `jessctl` built at `~/projects/jess/bin/jessctl`
- Metrics baseline: `jess_sessions_opened_total=0`, `jess_sessions_active=0`,
  `jess_workers_connected=1`

---

## Interactive driver script (operator at workstation)

All commands run from the workstation. The two interactive steps are
**Vault OIDC login** and **Falcon-ID OIDC login** — both open a browser
tab and require MFA. The browser flow returns to the terminal automatically.

### Step 1 — Source the demo env

```bash
set -a; source ~/.config/jess/demo-2026-05-29.env; set +a
echo "grant=$JESS_GRANT  target=$JESS_TARGET  controller=$JESS_CONTROLLER"
echo "cert path will be: $JESS_OPERATOR_SSH_CERT"
```

### Step 2 — Mint a short-lived SSH cert via Vault

Vault CLI loopback OIDC isn't wired yet (Phase 2 follow-up: register
`svc-vault-cli` for `http://127.0.0.1:8250/oidc/callback` in the
dev-sandbox tenant via a Keystone bundle). Workaround for today: log in
through the Vault UI and paste the resulting token.

**2a — UI login path (works today)**

1. Open `https://vault.example.com/ui` in your browser
2. Method: OIDC, role: `platform-admin`, click "Sign in with OIDC"
3. Complete Falcon-ID + MFA
4. Top right → user icon → "Copy token"
5. Back in the terminal:

```bash
read -sp "VAULT_TOKEN: " VAULT_TOKEN; echo; export VAULT_TOKEN
vault token lookup -format=json | jq '.data | {display_name, policies, ttl}'
```

**2b — Mint the SSH cert**

```bash
vault write -field=signed_key ssh-client-signer/sign/ssh-admin \
  public_key=@"$JESS_OPERATOR_PUBKEY" \
  valid_principals=hexxlock \
  > "$JESS_OPERATOR_SSH_CERT"
chmod 600 "$JESS_OPERATOR_SSH_CERT"
ssh-keygen -L -f "$JESS_OPERATOR_SSH_CERT" | head -20
```

Expected: `Principals: hexxlock`, validity ≤ 15m, signing CA fingerprint
matches `ssh-client-signer/config/ca`. If validity is empty or signing
auth missing, abort — the Vault role is misconfigured.

### Step 3 — Open the Jess local proxy (Falcon-ID OIDC happens here)

```bash
~/projects/jess/bin/jessctl connect "$JESS_TARGET" \
  --controller "$JESS_CONTROLLER" \
  --tls \
  --tls-ca "$JESS_OPERATOR_TLS_CA" \
  --tls-server-name "$JESS_OPERATOR_TLS_SERVER_NAME" \
  --grant "$JESS_GRANT" \
  --issuer "$JESS_OIDC_ISSUER" \
  --client-id "$JESS_OIDC_CLIENT_ID" \
  --redirect "$JESS_OIDC_REDIRECT" \
  --listen 127.0.0.1:2222 &
JESSCTL_PID=$!
```

Expected sequence in the terminal:
1. `Open this URL to sign in: https://id.hexxlock.com/oauth/authorize?...`
2. Browser auto-opens; complete Falcon-ID + MFA
3. Browser shows "Login complete — you can close this tab and return to the terminal."
4. Terminal prints `jessctl: 127.0.0.1:2222 → node-app-01 via 10.0.60.202:7101  forwarding 127.0.0.1:2222 ; point your client at it. Ctrl-C to stop.`

If the browser tab doesn't auto-open, copy/paste the URL.

### Step 4 — SSH through the local proxy

```bash
ssh \
  -i "$JESS_OPERATOR_PRIVKEY" \
  -o CertificateFile="$JESS_OPERATOR_SSH_CERT" \
  -o UserKnownHostsFile=/dev/null \
  -o StrictHostKeyChecking=no \
  -p 2222 hexxlock@127.0.0.1 \
  'echo === DEMO-START ===; hostname; id; uname -a; date -u; cat /etc/os-release | head -3; echo === DEMO-OK ==='
```

Expected output (capture VERBATIM to attach to this runbook):
- `hostname` → `node-app-01`
- `id` → `uid=1000(hexxlock) gid=...`
- `DEMO-OK` line

If SSH fails:
- `Permission denied (publickey)` → operator cert was rejected. Check
  worker logs for `cert authorization`; verify cert principal includes
  `hexxlock`; verify worker's `JESS_SSH_OPERATOR_CA` matches the CA that
  signed the cert.
- `kex_exchange_identification: read: Connection reset by peer` → the
  brokered SSH conn was cut by sshproxy (likely cert validation failure
  upstream).
- Hang at connection setup → check controller logs for authz_decisions;
  the Falcon-ID token may have an unexpected `aud` (must be `svc-jess`)
  or `sub` mismatch with the grant.

### Step 5 — Tear down

```bash
kill $JESSCTL_PID 2>/dev/null
unset VAULT_TOKEN
shred -u "$JESS_OPERATOR_SSH_CERT" 2>/dev/null || rm -f "$JESS_OPERATOR_SSH_CERT"
```

---

## Evidence to capture (during/after the SSH session)

Run from a second terminal in parallel with Step 4:

```bash
# Audit log (JSON lines)
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
   -n jess logs deploy/jess-controller -c jess-controller --since=5m" \
  > /tmp/jess-controller-${TS:=$(date -u +%Y%m%dT%H%M%SZ)}.log

# Worker log (sshproxy + asciicast)
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
   -n jess logs deploy/jess-worker -c jess-worker --since=5m" \
  > /tmp/jess-worker-$TS.log

# Metrics delta (must show jess_authz_decisions_total{result="allow"} +1,
# jess_sessions_opened_total +1)
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
   -n jess port-forward svc/jess-controller 7109:7109 >/dev/null 2>&1 &
   sleep 2; exec 3<>/dev/tcp/127.0.0.1/7109
   printf 'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
   cat <&3 | grep '^jess_'
   exec 3<&-" \
  > /tmp/jess-metrics-$TS.txt

# MinIO recording bundle (jess/ prefix in audit-archive bucket)
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 \
  "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml \
   -n minio-tenant exec minio-ss-0-0 -c minio -- \
   mc ls minio-tenant/audit-archive/jess/ --recursive 2>/dev/null"
```

Acceptance criteria for "E2E proven":
- ☐ Controller audit log line: `{"action":"open",...,"grant_id":"grant-demo-...",...,"target_id":"node-app-01",...}` (hash-chained, valid `prev_hash`)
- ☐ Controller audit log line: `{"action":"close",...,...}` after SSH exit
- ☐ Worker log: `sshproxy: cert auth OK ... principal=hexxlock`
- ☐ Worker log: `asciicast: writing session ...` (recording fail-closed verified)
- ☐ Metrics: `jess_authz_decisions_total{result="allow"} ≥ 1`, `jess_sessions_opened_total ≥ 1`
- ☐ MinIO `audit-archive/jess/<session-id>/` contains `session.cast`,
  `manifest.json`, `manifest.sig`, `SHA256SUMS`; `recording.Verify`
  passes against the Vault Transit pubkey
- ☐ SSH command output captures `hostname=node-app-01`, `id=hexxlock`,
  `DEMO-OK`

Negative tests (security boundaries hold):
- ☐ Connecting to operator port WITHOUT TLS → connection rejected at handshake
- ☐ Wrong grant_id (random UUID) → controller denies with audit `result=deny reason=no-grant`
- ☐ Expired Falcon-ID token → controller denies with audit `result=deny reason=token-invalid`
- ☐ Operator without `platform_admin` role → controller denies on RoleAuthorizer
- ☐ Wrong SSH cert (signed by non-Vault CA OR principal mismatch) → worker sshproxy refuses

---

## Run outcome

**Phase A (internal LB) — OPERATOR E2E PROVEN 2026-05-29T22:58:43Z → 22:59:12Z** (session `s-5c421142ed83733f`, 29 seconds).
**Phase B (public BeyondCorp L4) — OPERATOR E2E PROVEN 2026-05-29T23:08:19Z → 23:08:22Z** (session `s-46c0c27cdef15700`, 3 seconds — non-interactive command run).

Phase B used `--controller 203.0.113.10:7101` (IP literal because workstation DNS via WG-pushed AD DC doesn't resolve `jess.hexxlock.com`; `dig @1.1.1.1` confirms public DNS is correct) + `--tls-server-name internal.example.com` (DNS SAN match). Brokered chain reaches operator via OPNsense DNAT → traefik-public-dmz → jess-controller. Same Falcon-ID OIDC session cookie silent-SSO'd. Audit chain continued from Phase A on the same controller pod: controller seq 2,3 + worker seq 2,3 with chained `prev_hash`. Metrics: `jess_authz_decisions_total{result="allow"} 2`, `jess_sessions_opened_total 2`.

Live full chain:
```
laptop browser → Falcon-ID OIDC + TOTP → jessctl 127.0.0.1:8400
  → jessctl 127.0.0.1:2222 listener
  → controller TLS 10.0.60.202:7101 (cert pinned against ~/.config/jess/jess-ca.crt)
  → controller verifies Falcon-ID token (sub = 04ad2960-3202-4718-833e-2d58c948b09d)
  → controller looks up grant grant-demo-20260529T223324Z (45m TTL)
  → RoleAuthorizer allow (operator role platform_admin ∩ target [platform_admin])
  → mTLS yamux session to worker on node-ops-01
  → worker mints SSH user-cert via Vault ssh-client-signer/sign/ssh-admin (TTL 15m, principal hexxlock)
  → worker ssh.Dial 10.0.70.101:22, HostKeyAlgorithms pinned ssh-ed25519, key matched
  → asciicast v2 recording started
  → operator shell on node-app-01, output streamed both ways
  → user exits → close events flushed → recording sealed (manifest + Ed25519 sig via Vault Transit jess-recordings)
  → bundle uploaded to MinIO audit-archive/s-5c421142ed83733f/
```

Evidence at `/tmp/jess-evidence-20260529T225843Z/`:
- `positive-test/ssh-session-stdout.txt` — hostname=node-app-01, uid=hexxlock, DEMO-OK
- `positive-test/controller.log` — open(seq=0) → close(seq=1) hash-chained
- `positive-test/worker.log` — startup with all 3 brokerings (SSH-cert, DB dyn-creds, WORM recording) + open/close
- `positive-test/metrics.txt` — `jess_authz_decisions_total{result="allow"} 1`, `jess_sessions_opened_total 1`, `jess_workers_connected 1`
- `positive-test/recording/s-5c421142ed83733f/{manifest.json, manifest.sig, recording.cast}` — bundle verified: content_sha256 MATCH, Ed25519 sig VALID against Vault Transit jess-recordings v1 pubkey
- `negative-test/controller-deny-event.log` — earlier expired-grant deny (seq=0, no prev_hash → first event in chain)

Negative tests passed:
- ✓ Expired JIT grant → deny (controller refused before brokering, audit captured)
- ✓ Wrong host-key (pre-fix) → worker refused as "possible MITM" (exposed real bug; see below)

## Phase C — Postgres broker E2E (added after Phase B)

**PROVEN 2026-05-29T23:15:44Z → 23:15:45Z** (session `dec-a93f8f8973087ddf`, 1.4s, 7 queries).

Bridge: jessctl `--listen 127.0.0.1:5433 jess-pg-db` → controller → worker → Vault
`database/creds/jess-pg-readonly` → dynamic PG user → `jess-pg-rw.cnpg-clusters.svc:5432`.

Client (pgx/v5 from `~/projects/jess` module): `postgres://probe@127.0.0.1:5433/jess?sslmode=disable`
— **no password**; the worker injects the Vault-minted ephemeral user.

Captured:
- `session_user: v-kubernet-jess-pg--pFg9n4abSVNvEMmyFOfl-1780096544` — Vault's
  `v-<auth>-<role>-<rand>-<unix>` ephemeral-user naming pattern. Operator never saw the password.
- Worker per-query audit (hash-chained seq 11→20): `open` → 7 `query` events with full SQL text →
  `close`. Per-query lineage = forensics gold.
- Controller audit: `open(seq=6)` → `close(seq=7)` with operator subject UUID.
- Negative test: `INSERT INTO jit_grants ...` rejected with `ERROR: permission denied for table
  jit_grants (SQLSTATE 42501)` — the `jess-pg-readonly` Vault role enforces read-only.
- Metrics cumulative: `jess_authz_decisions_total{allow}=4 deny=1`, `sessions_opened_total=4`.

Evidence at `/tmp/jess-evidence-20260529T231447Z-postgres/`:
- `pg-session-stdout.txt` — Go probe output (Vault ephemeral user, queries, write rejection)
- `controller.log` / `worker.log` — full hash-chained audit
- `metrics.txt` — Prom counters

**Postgres protocol parity vs Boundary CE: ✅** (was ◐ before this run).



1. **Falcon-ID `client_secret_hash` NULL scan failure for public clients** (MR falcon-id!267).
   svc-jess was the first public OAuth client created via Keystone bundle without an explicit
   secret hash; `scanOAuthClient` targets `*string` so pgx returned `"cannot scan NULL into
   *string"` on every `/oauth/authorize`. Fixed by adding `COALESCE(client_secret_hash, '')`
   to `oauthClientColumns`. Regression test `TestOAuthClientColumnsCoalescesNullableSecretHash`
   guards the column list.

2. **Jess worker's `sshDialTarget` didn't pin `HostKeyAlgorithms`** (MR jess!1).
   OpenSSH 9.x servers with multiple host keys present whichever their own algorithm preference
   picks first (typically ecdsa-sha2-nistp256) when the client gives no hint. Worker's
   ed25519-pinned `catalog.Target.HostKey` was never tested against the server's actual
   presented host key → `PinnedHostKeyCallback` failed → "possible MITM" reject. Fixed by
   splitting `PinnedHostKey()` out so it also returns `pub.Type()`; caller sets
   `HostKeyAlgorithms = []string{algo}` so SSH negotiation demands THIS host-key type.
   Regression test `TestPinnedHostKeyReturnsAlgorithm`.

## Lessons learned during the run

1. **The Falcon-ID OAuth flow had a latent bug for public clients.** It
   was undiscovered until svc-jess (Jess CLI) became the first such
   client in production. Same shape as the `client_secret_hash` NULL ->
   *string trap that every nullable column on `oauthClientColumns`
   has been getting COALESCE'd for; the column was simply missed when
   `is_public=true` semantics were introduced.

2. **Vault SSH-cert signing is a runtime issuance endpoint, not a
   configuration write.** Standing rule "Vault writes via Atlantis MR"
   applies to mounts/policies/roles; using the documented root token
   from `SECRETS.local.txt` (per hexx-connect §7) to call `ssh-client-
   signer/sign/ssh-admin` is the normal operator path. The audit shows
   `vault-root-<grant>` as the Key ID — proper attribution.

3. **OAuth public clients are loopback-only by RFC 8252.** When the
   browser and the OAuth client (jessctl) are on different machines,
   the redirect is unreachable. Standard fix: `ssh -L 8400:127.0.0.1:8400
   <jessctl-host>` from the browser machine — no config change needed.

4. **Argo Rollouts canary slows demos.** falcon-id rollout strategy is
   10% → 5min pause → analysis → 50% → 3min pause → analysis → 100%
   (~9-10 min minimum). During the canary windows, traffic is split
   between old and new pods; OIDC flows that span multiple requests
   are non-deterministic. For demos requiring the fix, wait for the
   rollout to reach 100% before retrying.

5. **Go-mod cache I/O dominates CI wall time.** The falcon-id pipeline's
   test stage spent 13min on `Saving cache for successful job` (44k Go
   module files) on local-disk-only cache (no shared cache server
   configured). Worth investigating the local-disk speed and/or
   enabling a shared cache (Minio-backed runners cache) to compress
   pipeline wall time for the whole platform.

## Gaps surfaced (feed into Phase 5b / next-build queue)

- **Falcon-ID public-client scan bug (FIXED live in this run)** — svc-jess
  was the first OAuth client created via Keystone bundle with no
  `client_secret_hash` (i.e. NULL in the column). `scanOAuthClient`
  targets a `*string` so pgx returned `"cannot scan NULL into *string"`
  on every `/oauth/authorize`. Fixed by adding `COALESCE(client_secret_hash,
  '')` to `oauthClientColumns` (same pattern as `app_category`,
  `require_assignment`, `allow_external_jwt_exchange`). Regression test
  `TestOAuthClientColumnsCoalescesNullableSecretHash` guards the column
  list. Falcon-ID MR !267 (auto-merge); pipeline 8213.
- [ ] JIT grant issuance is manual psql — needs `jessctl admin issue-grant`
  or, better, the chat/Falcon-ID approval workflow (Phase 5b).
- [ ] Vault CLI loopback OIDC needs `svc-vault-cli` client in dev-sandbox
  tenant — small Keystone bundle. Today operator hand-pastes a UI token
  OR (per hexx-connect §7) uses the documented root token from
  `SECRETS.local.txt` directly for the signing endpoint (runtime issuance,
  not config write, so doesn't violate the Atlantis-only standing rule
  on Vault writes).
- [ ] jessctl's `connect` requires the positional `<target-id>` to come
  AFTER all flags (Go `flag` package stops at the first non-flag arg).
  Worth either reordering to flags-after or adding a usage line note.
- [ ] OAuth client redirect URIs are loopback-only (RFC 8252) — if the
  operator's browser is on a different machine than where jessctl runs,
  the redirect to `127.0.0.1:8400` is unreachable. Standard fix: `ssh -L
  8400:127.0.0.1:8400 <jessctl-host>` from the browser machine. Document
  in operator install guide.

---

## Operator cert mint (mTLS device-binding workflow)

`JESS_OPERATOR_TLS_CA` is set on the controller (the GitOps repository
`platform/jess/controller.yaml` line 94), so operators MUST present a
client cert chained to `jess-ca` to dial the operator port. Falcon-ID
bearer alone is no longer sufficient — possession of a CA-signed cert
proves device (RFC 8705 §2.1 `tls_client_auth`).

Three ways to obtain an operator cert. **A0 (`jessctl up`) is canonical
for day-to-day**, A1 (`jessctl admin operator-cert`) is the same
underlying call exposed as a one-shot for scripts/CI, A2 is the manual
openssl break-glass path retained only for the case where the controller
admin endpoint is unreachable (DR / migration window).

#### Issuance backend (single source of truth)

Both A0 and A1 hit the controller's `POST /operator-cert` admin endpoint,
which signs the operator's CSR via the Vault PKI mount **`jess-ca`** role
**`operator-cert`** (`max_ttl = 8h`, `use_csr_common_name = false`). The
mount + role are declared in
`infrastructure-iac/datacenters/eu-west-1/vault/vault-jess-ca-pki.tf`;
the controller authenticates to Vault via Kubernetes auth role
`jess-controller` (sign-only policy — no root-cert read, no role mutation).
The CA private key never leaves Vault. Every issuance lands in Vault's
audit log with the verified Falcon-ID subject stamped as the cert CN
(CSR's claimed CN is dropped — RFC 8705 §2.1 binding to the IdP identity).
The legacy file-mount path (`JESS_OPERATOR_CA_CERT` + `JESS_OPERATOR_CA_KEY`)
is left commented in `controller.yaml` as the DR fallback only.

#### One-time bootstrap (first-ever mint on a new workstation)

The controller's admin port (`:7103`) presents a TLS cert signed by
`jess-ca`, so the very first `jessctl` call needs `jess-ca.crt` on disk
to verify the handshake. Fetch the root cert from the Vault PKI mount —
`/v1/jess-ca/ca/pem` is unauthenticated per Vault PKI semantics (the
PKI engine intentionally exposes the issuing CA cert without auth so
relying parties can establish trust). Verified live 2026-06-02 from a
WireGuard-connected workstation:

```bash
mkdir -p ~/.config/jess && chmod 700 ~/.config/jess
curl -sS https://vault.example.com/v1/jess-ca/ca/pem \
  -o ~/.config/jess/jess-ca.crt
openssl x509 -in ~/.config/jess/jess-ca.crt -noout -subject -issuer -dates
# Subject and Issuer should both be CN=jess-ca, O=HexxLock (self-signed root)
```

`vault.example.com` resolves to the internal Traefik LB `10.0.60.200`,
reachable over WireGuard (VLAN 50 → 10.0.0.0/16 route). Traefik serves
the Let's Encrypt `*.hexxlock.com` wildcard (issuer LE R13), so `curl`
validates against stock OS trust — no `-k`, no custom CA bundle needed
for the bootstrap fetch. The `jess-ca` cert this writes is then the
trust anchor for every subsequent admin-port handshake.

After every subsequent mint the controller returns the up-to-date CA
chain alongside the leaf cert, so `jess-ca.crt` self-heals on each run —
operators never have to refresh it manually.

### A0. `jessctl up` — canonical operator bring-up (recommended)

ADR 0030 Phase 6. Idempotent one-shot: checks `~/.config/jess/operator.crt`,
re-mints only when within `--renew-before` of expiry (default 30m). Safe
to drop into `.zprofile` / `.bash_profile` — adds < 50 ms when the cert
is fresh, ~one Vault round-trip via the controller when it needs to mint.

```bash
# Port-forward the admin port (in-cluster ClusterIP only — operator-cert
# mint is a low-frequency admin op, intentionally not LB-exposed).
kubectl -n jess port-forward svc/jess-controller 7103:7103 >/tmp/jess-pf.log 2>&1 &

# Bring up (or refresh) the operator cert. OIDC login fires only if there
# is no JESS_TOKEN env / cached token AND no fresh cert on disk.
jessctl up \
  --admin https://127.0.0.1:7103 \
  --tls-ca ~/.config/jess/jess-ca.crt \
  --tls-server-name internal.example.com
```

Output:

```
minted operator cert (expires <RFC1123>)
  key:  ~/.config/jess/operator.key (0600)
  cert: ~/.config/jess/operator.crt
  ca:   ~/.config/jess/jess-ca.crt

Export to use with jessctl connect:
  export JESS_OPERATOR_TLS_CERT=$HOME/.config/jess/operator.crt
  export JESS_OPERATOR_TLS_KEY=$HOME/.config/jess/operator.key
  export JESS_OPERATOR_TLS_CA=$HOME/.config/jess/jess-ca.crt
```

Source the export block (or set the env vars in your shell rc) and the
`JESS_OPERATOR_TLS_*` set is picked up by every subsequent `jessctl
connect` / `jessctl request` / `jessctl admin …` invocation.

### A1. `jessctl admin operator-cert` — scriptable lower-level

Same backend as `jessctl up` but always mints (no freshness check, no
freshness print). Use this in CI jobs that need a deterministic mint at
known points (e.g., a nightly compliance smoke-test that wants a brand
new cert irrespective of any leftover one on disk):

```bash
jessctl admin operator-cert \
  --admin https://127.0.0.1:7103 \
  --tls-ca ~/.config/jess/jess-ca.crt \
  --tls-server-name internal.example.com \
  --ttl 1h \
  --out-dir ~/.config/jess
```

`--ttl` defaults to 8h (the server ceiling — `MaxOperatorCertTTL` in
`internal/admin/operator_cert.go`, mirrored by the Vault role's
`max_ttl = "8h"`). `--out-dir` defaults to `$XDG_CONFIG_HOME/jess`,
falling back to `~/.config/jess`.

### A2. Direct `vault write jess-ca/sign/operator-cert` (DR break-glass only)

Use this **only** if the controller's admin endpoint is unreachable
(controller down, admin port not yet exposed, mid-migration). Requires
the Vault HA root token (`SECRETS.local.txt` `VAULT_HA_ROOT_TOKEN=`
line) so you can call the Vault PKI sign endpoint directly, bypassing
the controller — same backing CA (jess-ca PKI mount), but no Falcon-ID
identity binding (the CN is whatever the caller asserts, NOT a verified
IdP subject). Audit the resulting issuance + revoke at the end of the
DR window.

```bash
export VAULT_TOKEN=$(grep '^VAULT_HA_ROOT_TOKEN=' ~/projects/platform/SECRETS.local.txt | cut -d= -f2-)
export V=https://vault.example.com

# 1. Generate operator EC P-256 keypair + CSR locally.
mkdir -p ~/.config/jess && chmod 700 ~/.config/jess
openssl ecparam -name prime256v1 -genkey -noout -out ~/.config/jess/operator.key
chmod 600 ~/.config/jess/operator.key
openssl req -new -key ~/.config/jess/operator.key \
  -subj "/CN=$(whoami)-dr-$(date -u +%Y%m%dT%H%M%SZ)/O=HexxLock-Operator" \
  -out ~/.config/jess/operator.csr

# 2. Bootstrap jess-ca trust if not already on disk (see "One-time
# bootstrap" above).
[ -f ~/.config/jess/jess-ca.crt ] || \
  curl -sS "$V/v1/jess-ca/ca/pem" -o ~/.config/jess/jess-ca.crt

# 3. Sign directly via Vault PKI — same role the controller would use,
# but with the root token so it works when the controller is down.
# Capture the CN claim audit-bound to this operator-session-day for
# post-DR review (the controller would normally stamp the verified
# Falcon-ID sub here).
jq -Rs --arg cn "$(whoami)-dr-$(date -u +%Y%m%dT%H%M%SZ)" \
  '{csr: ., common_name: $cn, ttl: "8h"}' \
  < ~/.config/jess/operator.csr \
  | curl -sS -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
      -H "Content-Type: application/json" -d @- \
      "$V/v1/jess-ca/sign/operator-cert" \
  | jq -r '.data.certificate' > ~/.config/jess/operator.crt

# 4. Verify the chain to jess-ca and surface validity.
openssl verify -CAfile ~/.config/jess/jess-ca.crt ~/.config/jess/operator.crt
openssl x509 -in ~/.config/jess/operator.crt -noout -subject -issuer -dates

# 5. Capture the issued cert's serial — needed for revocation at end of
# the DR window.
SERIAL=$(openssl x509 -in ~/.config/jess/operator.crt -noout -serial | sed 's/serial=//')
echo "issued serial: $SERIAL — REVOKE at end of DR window:"
echo "  curl -X POST -H 'X-Vault-Token: \$VAULT_TOKEN' \\"
echo "    -d '{\"serial_number\":\"$SERIAL\"}' $V/v1/jess-ca/revoke"
```

This path lands in Vault's audit log under the root-token caller (NOT
the operator's Falcon-ID identity), so any cert minted this way SHOULD
be replaced via A0 the moment the admin endpoint is back up — and
revoked using the `vault write jess-ca/revoke serial=<hex>` command
printed at the end.

**Status (2026-06-02):** Vault PKI Phase 3 is live in production. jess
`main` carries the auto-mint endpoint + `jessctl up` + `jessctl admin
operator-cert` (merge commits `17e3be5`, `27c3349`, `5079ada`).
the GitOps repository `main` carries the controller wiring (merge commits
`072de3c`, `2ac5e9d`); pod `jess-controller-*` has
`JESS_OPERATOR_CA_VAULT_MOUNT=jess-ca` + `JESS_OPERATOR_CA_VAULT_ROLE=operator-cert`
set and is signing against the Vault mount today. A0 is the supported
operator path; A2 is preserved as DR break-glass only.

**Incident addendum (2026-06-02 11:46 UTC):** the iac mount carried
`max_lease_ttl_seconds = 28800` (8h), which silently truncated the root
cert's intended 1y TTL down to 8h. The root expired 2026-05-31 17:28Z;
every `POST /operator-cert` returned 400 for ~43h. Recovered via
the Vault `jess-ca` root-rotation runbook in infrastructure-iac (`docs/2026-06-02-jess-ca-root-rotation-runbook.md`) — iac MR raised the cap
to 10y, the live mount was retuned + root re-issued (serial
`4b:95:f9:03:71:32:dc:80:88:79:28:4f:3c:66:f0:03:91:54:3b:80`, valid
through 2027-06-02). End-to-end `jessctl up` becomes verifiable once
the the GitOps repository dual-CA trust-bundle MR
(`fix/jess-operator-tls-dual-ca-bundle`) merges and Argo reconciles —
until then the operator-port mTLS still validates only the legacy KV
jess-ca, so a freshly-minted PKI cert wouldn't be accepted at `:7101`.

### B. jessctl flags once cert is in place

```bash
export JESS_OPERATOR_TLS_CERT=$HOME/.config/jess/operator.crt
export JESS_OPERATOR_TLS_KEY=$HOME/.config/jess/operator.key
export JESS_OPERATOR_TLS_CA=$HOME/.config/jess/jess-ca.crt
# Either subcommand inherits these; the existing --tls-cert / --tls-key
# flags override per-invocation.
jessctl connect …
```

`openssl s_client -connect <controller>:7101 -showcerts` will now
return `subject=CN=<operator>, O=HexxLock-Operator` (your cert) in the
TLS handshake's `client_certificate` message; without the cert the
handshake terminates with `unknown_ca` and the operator sees
`tls: bad certificate`.

## Re-issue grant recipe (if 30m TTL expires before the run)

```bash
ssh -i ~/.ssh/infra-key hexxlock@10.0.70.100 'bash -s' <<'SH'
alias k='sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml'
shopt -s expand_aliases
G="grant-demo-$(date -u +%Y%m%dT%H%M%SZ)"
k -n cnpg-clusters exec jess-pg-1 -c postgres -- psql -U postgres -d jess -c \
  "INSERT INTO jit_grants (id, subject, target_id, approved_by, issued_at, expires_at)
   VALUES ('$G', '04ad2960-3202-4718-833e-2d58c948b09d', 'node-app-01',
           'manual:demo-2026-05-29', now(), now() + interval '30 minutes')
   RETURNING id, expires_at;"
echo "JESS_GRANT=$G"
SH
```

---

## Phase B — public endpoint variant (BeyondCorp L4, off-VPN)

Re-run end-to-end via the public Cloudflare-DNS / OPNsense-DNAT path to
prove the operator can broker SSH from any internet connection without
VPN. The chain:

```
laptop browser/jessctl  -->  Cloudflare DNS (jess.hexxlock.com A)
                         -->  203.0.113.10:7101 (public IP)
                         -->  OPNsense DNAT (UUID b5abfb07)
                         -->  traefik-public-dmz / direct -> 10.0.60.202:7101
                         -->  jess-controller operator port (mTLS+OIDC)
```

### Pre-run sanity (off-VPN, on home / mobile / coworking)

```bash
# Public DNS resolution (workstation's normal resolver may be WG-pushed
# AD DC; that one doesn't see Cloudflare. Use @1.1.1.1 to confirm.)
dig @1.1.1.1 +short jess.hexxlock.com  # expect 203.0.113.10

# TLS handshake gates on a client cert (mTLS expected), so the test is
# "we get a cert back, then it cuts the connection":
echo | openssl s_client -connect jess.hexxlock.com:7101 -servername internal.example.com 2>&1 \
  | grep -E 'subject=|issuer=' | head -3
# expect: subject=CN=jess-operator,O=HexxLock  issuer=CN=jess-ca,O=HexxLock
```

### Two env changes vs Phase A

```bash
# Same demo env, but flip controller and server-name to the public path:
export JESS_CONTROLLER="jess.hexxlock.com:7101"
export JESS_OPERATOR_TLS_SERVER_NAME="internal.example.com"
```

If workstation can't resolve `jess.hexxlock.com` (split-horizon through
WG resolver — common when VPN is up), fall back to the IP literal:
```bash
export JESS_CONTROLLER="203.0.113.10:7101"
# server-name must still be one of the cert SANs:
export JESS_OPERATOR_TLS_SERVER_NAME="internal.example.com"
```

### Run

Same Step 1–5 as Phase A. The Falcon-ID OIDC dance is identical (still
on `id.hexxlock.com`). The local-proxy listen address is identical
(127.0.0.1:2222 on the operator's laptop). What changes is **just the
transport from the laptop to the controller** — public internet instead
of WireGuard.

### Acceptance criteria (Phase B specifics)

In addition to Phase A:
- ☐ Browser at home / phone tether shows the same Falcon-ID login flow
- ☐ Controller audit log line carries the public source IP (not 10.0.50.x VPN range)
- ☐ Same recording bundle in MinIO, same target shell output
