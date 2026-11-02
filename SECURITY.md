# Security policy

Jess sits between operators and production infrastructure and mints
short-lived credentials for it. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**
(<https://github.com/dogukanturhal/jess/security/advisories/new>).

If you cannot use GitHub, email **dogukanturhal@hexxlock.com**. Do not post
details in a public issue, discussion or chat.

Please include:

- What the issue is and which version, image tag or commit is affected.
- A way to reproduce it: configuration, target type, what you saw and what
  you expected.
- Who can trigger it and what they gain (for example: an operator without a
  grant opening a session, a session that is not recorded, a forged audit
  entry).
- Whether you want to be credited.

We acknowledge reports within two business days.

## Disclosure

We follow a 90-day coordinated disclosure window from acknowledgement.

| Day | What happens |
|---|---|
| 0 | Report acknowledged, triage starts. |
| 0-7 | Severity assessed (CVSS v3.1); a CVE is requested if it applies. |
| 7-60 | Fix developed and reviewed privately. |
| ~90 | Patched release and advisory published together. |

A simple fix ships sooner. If a fix needs a breaking change we may agree a
longer window with you, never without telling you. If the issue is being
exploited we release immediately. Reporters are credited unless they ask not
to be. There is no bug bounty.

## Supported versions

Jess is pre-1.0. Only the latest release (or, before the first release, the
`main` branch) receives security fixes.

## Scope

In scope: `jess-controller`, `jess-worker`, `jess-web`, `jessctl`, the Rust
RDP broker in `services/ironrdp-broker`, the console in `cmd/jess-web/web`,
the container image built from the root `Dockerfile`, and release artifacts
(checksums, SBOM, signatures).

Out of scope: vulnerabilities in Vault, MinIO, OpenSSH, Postgres, Windows or
other dependencies and targets (report those upstream; tell us if Jess's use
of them makes it worse), the demo in `demo/` (it uses fixed development
credentials on purpose and is not meant to be exposed), and denial of service
by someone who already holds the controller's admin role.

## Verifying releases

Release archives are listed in a `checksums.txt` signed with cosign keyless
signing, and each archive has an SPDX SBOM. A build provenance attestation
covers the checksummed artifacts:

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/dogukanturhal/jess/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Dependencies are watched by Dependabot and CodeQL, and `govulncheck` runs on
every pull request.
