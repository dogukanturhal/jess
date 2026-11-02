# Changelog

All notable changes to Jess are documented here. The project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- Sync from the development repository, the first since the initial public
  snapshot. Documentation and examples were cleaned for public use:
  placeholder hostnames and registries replaced, internal planning and
  operations material withheld.
- The README now describes what the code does: SSH, Postgres and MySQL
  brokering through the worker, RDP through the web console and the Rust
  broker, and the limits that still apply (see "Status and limitations").
- The root `Dockerfile` has separate `demo` and `release` targets and no
  longer references private build infrastructure.

### Known issues

- The `unused` linter is disabled in CI: five unused helpers remain
  (`helpfulWebSocketError`, `attestedData`, `sessionID` and two test helpers).
- The govulncheck CI job ignores one advisory in a dependency that has no
  fixed release (see `.github/workflows/ci.yml`) and fails on any other
  reachable finding.

### Added

- Brokering for MySQL (`internal/mysqlproxy`) next to Postgres
  (`internal/dbproxy`), both with Vault dynamic database credentials.
- Browser RDP through `jess-web` and the Rust broker in
  `services/ironrdp-broker`, with CredSSP, RDP host-certificate trust checks
  and session recording and replay.
- Per-session MFA step-up, device posture claims and attestation (TPM 2.0,
  Apple, AWS, Azure), a risk-score policy evaluated with OPA, and a CAEP
  subscriber that ends grants when the identity provider revokes a session.
- Target catalog providers: JSON file, Kubernetes custom resources, Proxmox,
  LDAP and an admin API, plus a pending-target approval lifecycle.
- Offline pre-positioned session credentials for links that are down.
- A cross-session hash chain over session rows, with a verifier endpoint and
  metrics.
- GitHub Actions for CI (Go, TypeScript, Rust), CodeQL, OpenSSF Scorecard and
  tagged releases; Dependabot for Go, Cargo, npm, Docker and Actions; issue
  templates; governance files.
- A docker compose demo (`demo/`) that brokers an SSH session to a throwaway
  OpenSSH server and records it.
