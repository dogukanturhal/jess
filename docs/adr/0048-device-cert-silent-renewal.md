# ADR 0048 — Device-cert silent renewal (daemon-driven mTLS rotation)

Status: Proposed (2026-06-17)
Relates: ADR 0040 D-003 (device-cert 24h TTL, client auto-rotate at 12h),
ADR 0043 (device attest), internal engineering notes

## Problem

The device cert (24h TTL, minted by `jess-device-ca`) is only ever
(re)minted by the **interactive enrollment wizard** (`/device-cert/attest`,
Talon-fronted, needs a Falcon-ID OIDC Bearer + a WebAuthn operator
witness). The `posture-agent` (a headless systemd **system** daemon) only
heartbeats; it does NOT rotate the cert. The "Refresh cert" button is a
disabled Phase-F scaffold ("agent IPC pending").

Consequence: ~24h after enrollment the device cert expires → Envoy's
device-cert mTLS rejects it → heartbeat fails → the operator must
**manually re-enroll daily**. ADR 0040 D-003 specifies auto-rotation at
50% TTL; it was never built. This blocks unattended/fleet operation.

## Decision

Implement **daemon-driven silent renewal**, authenticated by the *current
valid device cert* (the SPIFFE/SPIRE SVID-rotation pattern; WARP/Tailscale
rotate their device identity the same way — no re-login). No OIDC, no
witness, no GUI dependency.

### Renewal endpoint — `POST /device-cert/renew` (jess-controller)

- Reached over **Envoy device-cert mTLS** (NOT the Talon-fronted attest
  admin port). Reuses the posture topology: agent → `posture.hexxlock.com`
  (Traefik TLS-passthrough) → Envoy `posture-mtls` listener (clientValidation
  vs `jess-device-ca` + XFCC SanitizeSet, `Cert` included) → jess-controller.
  A path rule `/device-cert/renew` on the existing HTTPRoute routes to a NEW
  jess-controller HTTP port (plain HTTP behind Envoy; Linkerd mTLS secures
  the hop). jess-controller is meshed → its Server CR must authorize the EG
  data-plane SA `envoy-envoy-gateway-system-eg-canary-<hash>` (same Linkerd
  fix as posture-signer — see the posture memory; remember the stale-snapshot
  rollout-restart caveat).
- Auth = the presented cert (XFCC): validate chain→`jess-device-ca`, not
  expired, `id-kp-clientAuth` EKU, extract `device_uuid` from the SPIFFE
  SAN (`spiffe://hexxlock.com/device/<uuid>`) and `user_sub` from CN.
- Authz = device still enrolled + not revoked in `iam_devices`
  (falcon-id `/internal/v1/iam-devices/`), and the device cert not on the
  jess-device-ca CRL.
- Body = a fresh PKCS#10 CSR (proof-of-possession of the device key;
  same key reused, or rotated). Server ignores CSR subject/SANs.
- Mint = `SignPKICert(jess-device-ca, device-cert, {CSR, CN=user_sub,
  URISans=[spiffe://…/device/<uuid>], TTL=24h})` — identical to
  `mintDeviceCert`. Returns `{device_cert_pem, expires_at, serial}`.
- Refuse renewal once the presented cert is **past expiry** (force full
  re-enroll) — renewal is a *liveness* extension of a still-valid identity,
  not a resurrection.

Why a valid cert is sufficient auth: it was issued only after full
attestation (EK/TPM + operator witness). Continuously presenting an
unexpired, unrevoked, CA-chained cert is the standard renewal proof; the
50%-TTL cadence guarantees a healthy device re-proves liveness twice per
lifetime and revocation/CRL cuts a compromised device at the next attempt.

### Agent rotation (posture-agent)

- Each tick (and on a dedicated timer), compute the cert lifetime from its
  `notBefore`/`notAfter`; if `now >= notBefore + 0.5*(notAfter-notBefore)`,
  POST a fresh CSR to the renew endpoint over the current-cert mTLS client.
- On success: write `device-cert.pem` (+ key if rotated) **atomically**
  (temp + `rename`), rebuild the mTLS `HeartbeatClient`, continue. The agent
  runs as the system user that owns `/var/lib/hexxlock-access`, so no pkexec.
- On renew failure while the cert is still valid: log + retry next tick
  (non-fatal). Only emit the re-enroll signal once the cert is actually
  expired AND renewal has failed (genuine loss of identity).
- Gated by `HEXXLOCK_DEVICE_RENEW_ENDPOINT` (default
  `https://posture.hexxlock.com/device-cert/renew`); empty disables
  rotation (current behavior) for safe rollout.

### "Refresh cert" button / manual trigger

- The shell signals the agent to rotate now via a minimal control channel:
  `SIGUSR1` to the system unit (cheapest), or a root-helper
  `enroll-helper rotate-now` invoked via the existing polkit action. The
  agent traps the signal → runs one rotation immediately. Wire the
  status-panel button + tray item to it; drop the "agent IPC pending" gate.

## Rollout (mirror the posture fix, which is already live)

1. jess: `device_renew_handler.go` + new HTTP listener + chart port/Service.
2. infra: confirm `jess-device-ca` role unchanged (it already allows the
   uri_sans + clientAuth); jess-controller mounts the device-CA trust
   bundle (trust-manager bundle, same as posture-signer) to validate the
   presented cert.
3. the GitOps repository: HTTPRoute path `/device-cert/renew` → jess-controller
   + ReferenceGrant (jess ns) + jess-controller `linkerd.inbound.allowedCallers`
   = the EG data-plane SA.
4. hexxlock-access: agent rotation module + Refresh-cert IPC; version bump.
5. Verify by forcing a short TTL (or `SIGUSR1`) and watching a clean
   rotation + uninterrupted heartbeats across the boundary.

## Alternatives rejected

- **Shell-driven OIDC re-attest at 50% TTL** — reuses `/device-cert/attest`,
  no new endpoint, but requires the GUI running + a live OIDC session; fails
  when the user closes the app. Daemon rotation must not depend on the GUI.
- **Agent holds a long-lived OIDC refresh token** — extra long-lived secret
  to store/revoke; the device key + cert already are the credential.
