# Contributing to Jess

Thanks for helping. Jess is an AGPL-3.0-or-later access broker written in Go,
with a Rust RDP worker (`services/ironrdp-broker`) and a TypeScript console
(`cmd/jess-web/web`).

## Before you start

- Skim [docs/DESIGN.md](docs/DESIGN.md) and the notes in [docs/adr](docs/adr).
  They explain choices that are not obvious from the code (the controller and
  worker split, outbound-only workers, why RDP decoding lives in a separate
  Rust process).
- For a new protocol, a change to the grant or audit model, or anything that
  touches how credentials are minted, open an issue first and describe the
  design. Small fixes, tests and docs can go straight to a pull request.
- Security issues do not belong in issues: see [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line, which certifies the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "sshproxy: reject unknown channel requests"
```

To fix a missing sign-off: `git commit --amend -s` or
`git rebase --signoff main`.

## Development setup

You need the Go version in `go.mod`. For the console you need Node 22 and
pnpm; for the RDP broker, the Rust toolchain pinned in
`services/ironrdp-broker/rust-toolchain.toml`.

```sh
go build ./...
go vet ./...
go test -race ./...

# Console
cd cmd/jess-web/web && pnpm install --frozen-lockfile && pnpm typecheck && pnpm build

# RDP broker
cd services/ironrdp-broker && cargo test --locked --workspace
```

Several tests that talk to Vault, MinIO or a real SSH server only run when the
matching environment variables are set. They skip otherwise.

To try a change end to end, use the compose setup in [demo/](demo/README.md).

## Pull requests

- Branch from `main`; keep the change focused.
- Commit messages: short imperative subject (`area: what changed`), body
  explains why.
- Add or update tests. A fix should come with a test that fails without it.
- Update `CHANGELOG.md` under `[Unreleased]` for anything user-visible.
- Describe what you ran, including target OS and protocol versions for
  anything that touches SSH, Postgres, MySQL or RDP behaviour.

## Licensing of contributions

Contributions are licensed under AGPL-3.0-or-later, the licence of the
repository. New source files carry an `SPDX-License-Identifier` header. Code
under `services/ironrdp-broker/vendor/` keeps its upstream licence.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
