#!/usr/bin/env bash
# The operator's side of the demo. Runs in the `operator` container, which can
# reach the controller, the OIDC mock and Vault, but not the targets.
#
#   1. Get a token for the demo operator from the mock OIDC server.
#   2. Get an SSH certificate from Vault's SSH CA (the worker only accepts
#      certificates signed by that CA).
#   3. ssh to the target through `jessctl connect --stdio`.
#
# With arguments, they are passed to ssh as the remote command; without, you
# get a shell. JESS_TARGET=demo-postgres uses psql instead of ssh.
set -euo pipefail

ISSUER=http://oidc:8080/demo
export JESS_CONTROLLER=${JESS_CONTROLLER:-controller:7101}
TARGET=${JESS_TARGET:-demo-ssh}
case "$TARGET" in
  demo-postgres) export JESS_GRANT=${JESS_GRANT:-demo-grant-db} ;;
  *)             export JESS_GRANT=${JESS_GRANT:-demo-grant} ;;
esac

# shellcheck disable=SC1091
. /shared/operator.env

echo ">> requesting a token from $ISSUER" >&2
JESS_TOKEN=$(curl -fsS -X POST "$ISSUER/token" \
  -d grant_type=client_credentials \
  -d client_id=jess-demo \
  -d client_secret=demo-secret \
  -d scope=openid | jq -r .access_token)
export JESS_TOKEN

# Postgres: open a local listener through the broker and point psql at it.
# The operator never sees the database password; the worker gets a short-lived
# one from Vault for each session.
if [ "$TARGET" = demo-postgres ]; then
  echo ">> connecting to $TARGET through the broker (grant $JESS_GRANT)" >&2
  jessctl connect --listen 127.0.0.1:15432 "$TARGET" >/dev/null &
  until (echo > /dev/tcp/127.0.0.1/15432) 2>/dev/null; do sleep 0.3; done
  exec psql "host=127.0.0.1 port=15432 user=demo dbname=demo sslmode=disable" "$@"
fi

KEY=$HOME/.ssh/jess-demo
mkdir -p "$HOME/.ssh"
rm -f "$KEY" "$KEY.pub" "$KEY-cert.pub"
ssh-keygen -q -t ed25519 -N '' -f "$KEY"

echo ">> requesting an SSH certificate from Vault" >&2
curl -fsS -X POST -H "X-Vault-Token: $VAULT_OPERATOR_TOKEN" \
  -d "$(jq -n --arg k "$(cat "$KEY.pub")" '{public_key:$k, valid_principals:"demo", cert_type:"user"}')" \
  http://vault:8200/v1/ssh-client-signer/sign/operator | jq -r .data.signed_key > "$KEY-cert.pub"

echo ">> connecting to $TARGET through the broker (grant $JESS_GRANT)" >&2
# The worker's SSH host key changes on every restart in the demo (it is
# generated at start), so host key checking is off for this hop only. Do not
# do this outside the demo; set JESS_SSH_HOST_KEY on the worker instead.
exec ssh -i "$KEY" -o IdentitiesOnly=yes -o "CertificateFile=$KEY-cert.pub" \
  -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR \
  -o "ProxyCommand=jessctl connect --stdio $TARGET" \
  "demo@$TARGET" "$@"
