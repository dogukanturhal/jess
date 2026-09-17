# ADR 0050 — Clientless-Operator Credentials (Talon-vouched brokered sessions)

Status: Proposed (design only — gates the clientless-SSH activation)
Date: 2026-06-20
Related: ADR 0049 (multi-protocol brokering), ADR 0044 (SSH CA host/user
certs), ADR 0030 (session recording / WORM), ADR 0042 (Talon integration),
ADR 0046 (pending-target lifecycle), talon ADR 0044 (clientless browser
access)

## Context

talon ADR 0044 Phase 2 ships a clientless **access-broker**: a browser opens
an authenticated WebSocket (Talon IAP gate, `channel=clientless`) and gets an
in-browser xterm.js SSH terminal. The relay + recording-tee + WebSocket codec
are built and tested; the one stub is the access-broker → jess dial
(`accessbroker.jessSSHBackend.Dial` → `ErrBackendNotWired`).

Tracing the real jess brokering path, a brokered SSH session needs the caller
to perform the full **operator ceremony**:

1. A **wire request** to the controller operator port —
   `wire.OperatorRequest{Token, TargetID, GrantID}` over the operator mTLS
   listener (`internal/client.Dial`).
2. The controller bridges the connection to jess's **SSH MitM record-proxy**
   (`internal/sshproxy`), which authenticates the operator with
   `ServerConfig.PublicKeyCallback: checkOperatorCert` — i.e. an **SSH
   certificate signed by jess's operator CA**.
3. A live **JIT grant** for `(subject, target)` (`internal/jit`).

A human operator gets all of this via `jessctl` + their Falcon-ID login + their
operator SSH cert. **A clientless browser user has none of it** — no SSH key,
no device cert, no operator cert (they are agentless by definition). So the
access-broker must obtain these credentials **on behalf of** the Talon-
authenticated user. Minting credentials on another component's say-so is the
security core of the product; this ADR fixes the trust model before any code.

The recording + audit MUST bind to the **real Falcon-ID subject**, never to the
access-broker's identity — otherwise the WORM trail is useless for the
clientless tier.

## Decision

Add a **clientless-operator session issuance** flow to jess: the access-broker
authenticates to jess over Linkerd mTLS, presents a **Talon-signed assertion**
of the authenticated user, and jess (after verifying the assertion, applying
JIT policy, and the sensitivity cap) mints a **short-lived, grant-scoped
operator SSH certificate** for a **per-session ephemeral key the access-broker
generates**. The access-broker then runs the normal operator ceremony with
those credentials. No standing credentials; everything is per-session and
bound to the real subject.

### Trust chain (two layers, both required)

1. **Transport: Linkerd mTLS, access-broker SA allow-list.** The access-broker
   reaches jess only over the mesh; jess's authz allows exactly the
   access-broker ServiceAccount identity. This authenticates *the component*,
   not the user. (Same pattern as the existing Envoy/Talon allowedCallers.)

2. **Identity: a Talon-signed clientless-access assertion (JWT).** Talon (the
   IAP that authenticated the user) mints a short-lived JWT and jess verifies
   it against Talon's IAP identity-signer JWKS
   (`https://internal.example.com/.well-known/jwks.json` — already published;
   jess already fetches JWKS for CAEP). The assertion is tightly scoped:

   ```
   iss = https://internal.example.com         # Talon IAP signer
   aud = https://jess.<...>/clientless          # jess only — not a general token
   sub = <Falcon-ID iam_users.id>               # the REAL user (recording binds here)
   sid = <Talon session UUID>                   # joins jess recording ↔ Talon audit
   chan = "clientless"                          # marks the agentless tier
   tgt = <target id>                            # bound to ONE target (anti-confused-deputy)
   exp = now + ~60s                             # single-use window; replay-bounded
   ```

   jess trusts Talon to assert the user because Talon **is** the authentication
   authority for `*.ops` (it already gates every admin session). The mTLS layer
   ensures only Talon's access-broker can present assertions; the per-target,
   ~60s, jess-only-audience scoping bounds replay + confused-deputy.

### Issuance flow

```
access-broker (per browser SSH session):
  1. generate an EPHEMERAL ed25519 keypair (priv never leaves the broker; dies with the session)
  2. obtain the Talon clientless-access assertion for (user, sid, target)
  3. POST jess /v1/clientless/operator-session  (Linkerd mTLS)
       { assertion, target_id, ssh_pubkey }
jess:
  4. verify mTLS caller == access-broker SA            (component auth)
  5. verify assertion sig vs Talon JWKS + aud/exp/chan (identity auth)
  6. JIT decision for (sub, target) by route sensitivity (see matrix below)
  7. mint operator SSH cert: CA-signed over ssh_pubkey,
       principals = target's allowed login(s), validity = grant TTL,
       key_id = "clientless:<sub>:<sid>:<grant>",  (audit), minimal extensions
  8. return { operator_cert, grant_id, session_token, controller_addr }
access-broker:
  9. client.Dial(controller_addr, mTLS, OperatorRequest{session_token, target, grant_id})
  10. ssh client over the brokered conn, PublicKeys auth = {ephemeral priv + operator_cert}
  11. PTY shell → relay ⇄ WebSocket   (jess MitM records the session to WORM, bound to sub)
```

### JIT / sensitivity matrix (clientless tier)

Clientless has **no device cert**, so it is capped exactly like the talon-side
rego + access-zone fail-closed cap (ADR 0044):

| Route sensitivity | Clientless grant |
|---|---|
| low / medium | **auto-grant**, short TTL (e.g. ≤15m) |
| high | **approval required** — reuse `internal/jit` request + the Path-B witness/approver ceremony |
| critical | **deny** (no clientless to critical; matches talon `allowClientless=false` fail-closed) |

jess is the authority for this decision (defense in depth: even if talon mis-
routes, jess re-applies the cap).

## Security considerations

- **The access-broker is a trusted minting intermediary** — its compromise
  would let an attacker request brokered sessions. Mitigations: (a) mTLS-pinned
  SA (only it can call the issuance API); (b) jess binds the cert + recording
  to the **assertion's `sub`**, not the broker, so audit always names the real
  user; (c) per-target, ~60s, single-audience assertions bound replay/confused-
  deputy; (d) per-session ephemeral keys + short grant-scoped cert TTL =
  no standing credentials; (e) JIT + sensitivity cap (no clientless→critical);
  (f) full WORM recording; (g) CAEP `session-revoked` tears down live sessions.
- **No private key crosses a boundary**: the access-broker generates the key,
  jess signs only the public key (SSH CA model, identical to `jessctl`).
- **Honest degraded posture** (per talon ADR 0044): clientless asserts no
  device posture it cannot prove; it is capped (talon: AAL2+/WebAuthn; jess:
  sensitivity), recorded, and JIT-gated — never granted critical access.
- **Assertion signer separation**: jess verifies Talon's IAP signer JWKS
  specifically for `aud=jess/clientless`; a leaked general Talon IAP token must
  NOT be accepted (audience pin enforces this).

## Consequences

- New jess surface: the `/v1/clientless/operator-session` issuance endpoint
  (mTLS-gated) + assertion verification (Talon JWKS) + operator-cert minting
  over a caller-supplied pubkey. **Reuses unchanged:** the operator CA (ADR
  0044), `internal/jit` (grant + approval), the SSH MitM + WORM recording
  (sshproxy + ADR 0030), and the JWKS-fetch the CAEP receiver already does.
- talon side: a clientless-access assertion **signer** (reuse the IAP
  identity-token signer) + the access-broker ceremony (replaces the
  `ErrBackendNotWired` stub).
- Generalises to DB / k8s clientless (talon ADR 0044 P4): same ceremony, the
  per-protocol broker cred (ephemeral Vault DB role / k8s impersonation token)
  swaps in at step 7 instead of an SSH cert.
- New trusted path to threat-model + pen-test before enabling in prod.

## Phased plan

- **P1 — this ADR** (trust model). ← you are here.
- **P2 — jess issuance flow:** `/v1/clientless/operator-session` (mTLS authz +
  Talon-assertion verify + JIT/sensitivity + operator-cert mint) + tests.
- **P3 — talon un-stub:** clientless-access assertion signer + access-broker
  ceremony (ephemeral key → assertion → jess → `client.Dial` + SSH-cert auth +
  PTY relay), replacing `jessSSHBackend.Dial`'s stub.
- **P4 — deploy + live-test:** access-broker Deployment + `access.` zone
  (IngressRoute/TalonRoute `allowClientless`) + DNS + Linkerd authz
  (access-broker → jess controller + issuance API) + e2e via a real browser,
  audit-only first.
- **P5 — generalise** to DB / k8s clientless (same ceremony, per-protocol cred).

Each phase is independently reviewable; P2 is the next concrete build and the
prerequisite for un-stubbing the talon access-broker.
