# Jess demo

A docker compose setup that brokers one SSH session to a throwaway OpenSSH
server, records it, and lets you replay the recording. It also brokers a
Postgres session with a database password the operator never sees.

This is a development demo. It uses fixed secrets, a Vault dev server, a
plaintext operator port and a mock OIDC server. Do not expose the ports and
do not use it as a deployment template.

## What runs

| Service | Image | Role |
|---|---|---|
| `vault` | `hashicorp/vault` (dev mode) | SSH CA, transit signing key, dynamic database users |
| `minio`, `minio-init` | `minio/minio`, `minio/mc` | recording store, bucket created with Object Lock |
| `postgres` | `postgres:16-alpine` | Jess's own state: grants, sessions, audit chain |
| `oidc` | `ghcr.io/navikt/mock-oauth2-server` | issues a token for one fixed operator with the role `demo-operator` |
| `target-ssh` | built from `target-ssh/` | OpenSSH that only trusts certificates from the Vault CA |
| `target-postgres` | `postgres:16` (TLS on) | the brokered database |
| `setup` | the demo image | configures Vault, makes certificates and keys, writes the target list |
| `controller`, `worker` | the demo image (`jess-controller`, `jess-worker`) | the broker |
| `operator` | the demo image | your side: token, SSH certificate, `jessctl`, `ssh` or `psql` |

Two networks: the `operator` container can reach the controller, the OIDC
mock and Vault, but not the targets. Only the worker can.

## Run it

You need Docker with the compose plugin. The first build compiles the Go
binaries and takes a few minutes.

```sh
cd demo
docker compose up -d --build
docker compose logs -f controller worker      # wait for the worker to connect
```

The worker is up when its log shows it dialing the controller and the
controller log shows a registered worker. Both restart on failure while
they wait for `setup` and the OIDC server, so a couple of restarts in the
first minute are normal.

Give the demo operator a grant. Jess refuses to open a session without an
unexpired grant that belongs to the token's subject. The demo inserts it
straight into the database; in a real deployment it comes from the request
and approval flow.

```sh
docker compose run --rm grant
```

### Brokered SSH

```sh
docker compose run --rm operator
```

This gets a token from the mock OIDC server, an SSH certificate from Vault,
and runs `ssh` through `jessctl connect --stdio`. You land in a shell on
`target-ssh` as `demo`. Type a few commands, then `exit`. You can also pass a
command: `docker compose run --rm operator uname -a`.

What happened: your token was verified by the controller, the role on it was
checked against the target, the grant was checked, and the controller opened
a stream into the worker. The worker checked your SSH certificate against the
Vault CA, asked Vault for a new five-minute certificate of its own, and used
that to log in to the target. Your key never touched the target.

### The recording

When the session closes, the worker writes the recording, a manifest and a
signature to the `audit-archive` bucket.

```sh
docker compose run --rm mc ls --recursive local/audit-archive
```

You will see `<session-id>/recording.cast`, `manifest.json` and
`manifest.sig`. Replay it (asciicast v2 format):

```sh
ID=<session-id>
docker compose run --rm -T mc cat local/audit-archive/$ID/recording.cast > session.cast
asciinema play session.cast
```

Without asciinema, print the terminal output as text:

```sh
jq -rj 'select(type=="array" and .[1]=="o") | .[2]' session.cast
```

Check the content hash against the manifest, and the signature against the
Vault transit key (the demo publishes Vault on `127.0.0.1:8200` for this):

```sh
docker compose run --rm -T mc cat local/audit-archive/$ID/manifest.json > manifest.json
docker compose run --rm -T mc cat local/audit-archive/$ID/manifest.sig  > manifest.sig

jq -r .content_sha256 manifest.json
sha256sum session.cast

curl -s -H 'X-Vault-Token: root' \
  -d "{\"input\":\"$(base64 -w0 manifest.json)\",\"signature\":\"vault:v1:$(base64 -w0 manifest.sig)\"}" \
  http://127.0.0.1:8200/v1/transit/verify/jess-recordings
```

The hashes should match and the last command should return `"valid":true`.
The same check is available through the controller's admin API
(`jessctl admin bundle-verify`), which the demo does not configure.

### Brokered Postgres

```sh
docker compose run --rm -e JESS_TARGET=demo-postgres operator -c 'select * from widgets'
```

`psql` connects to a local listener that `jessctl` opens. The worker asks
Vault for a short-lived database role (read-only on the demo tables) and
connects to `target-postgres` with it. The query text goes to the audit log:
`docker compose logs worker`. This target has `recorded: false`, so there is
no replay for it.

## Things to try

- End a grant while a session is open. The controller re-checks it about
  every ten seconds and closes the session:
  `docker compose exec postgres psql -U jess -c "UPDATE jit_grants SET expires_at = now() WHERE id = 'demo-grant'"`
- Run the operator with a different target id: `JESS_TARGET=nope`. It is
  denied, and the controller logs why.
- Stop `minio` and open a session. The worker is meant to keep the recording
  on local disk and upload it when MinIO is back (the store-and-forward
  spool). Check the worker log to see which happened.

## Clean up

```sh
docker compose down -v
```

## Things this demo does not show

- The worker's SSH host key is generated at start, so the operator skips host
  key checking for that one hop. In a deployment, set `JESS_SSH_HOST_KEY`.
- The operator port is plaintext. Set `JESS_OPERATOR_TLS_CERT` and
  `JESS_OPERATOR_TLS_KEY` on the controller to wrap it in TLS.
- The admin API, the web console (`jess-web`) and RDP are not started. RDP
  needs a Windows target; see the main README.
- The operator container holds a Vault token that can only sign operator
  certificates. In a deployment the controller's admin API issues those.
