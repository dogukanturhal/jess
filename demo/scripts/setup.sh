#!/usr/bin/env bash
# One-shot demo setup. Runs in the `setup` container on the backend network.
#
#   1. Vault: SSH CA, a transit key for signing recordings, the database
#      secrets engine, two policies and two scoped tokens.
#   2. TLS certificates for the worker <-> controller mTLS link.
#   3. SSH host key for the target, and the target catalog (targets.json).
#   4. /shared/worker.env and /shared/operator.env with the values only known
#      now (Vault tokens, the SSH CA public key).
#
# Safe to re-run: existing mounts and keys are reused.
set -euo pipefail

: "${VAULT_ADDR:?}" "${VAULT_TOKEN:?}"
SHARED=/shared
TLS=$SHARED/tls
mkdir -p "$TLS"

vault_api() { # METHOD PATH [JSON]
  local method=$1 path=$2 body=${3-}
  if [ -n "$body" ]; then
    curl -fsS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" \
      -H 'Content-Type: application/json' -d "$body" "$VAULT_ADDR/v1/$path"
  else
    curl -fsS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/$path"
  fi
}

mount_if_absent() { # PATH TYPE
  if ! vault_api GET sys/mounts | jq -e --arg p "$1/" 'has($p)' >/dev/null; then
    vault_api POST "sys/mounts/$1" "{\"type\":\"$2\"}" >/dev/null
  fi
}

echo "[1/4] Vault"
mount_if_absent ssh-client-signer ssh
mount_if_absent transit transit
mount_if_absent database database

# SSH CA. The same CA signs the operator's certificate (checked by the worker)
# and the worker's per-session certificate (checked by the target sshd).
if ! ca_pub=$(curl -fsS "$VAULT_ADDR/v1/ssh-client-signer/public_key" 2>/dev/null) || [ -z "$ca_pub" ]; then
  ca_pub=$(vault_api POST ssh-client-signer/config/ca \
    '{"generate_signing_key":true,"key_type":"ssh-ed25519"}' | jq -r .data.public_key)
fi
ca_pub=$(printf '%s' "$ca_pub" | head -n1)

role_body='{
  "key_type": "ca",
  "allow_user_certificates": true,
  "allowed_users": "demo",
  "default_user": "demo",
  "default_extensions": {"permit-pty": ""},
  "ttl": "5m",
  "max_ttl": "1h"
}'
vault_api POST ssh-client-signer/roles/ssh-admin "$role_body" >/dev/null   # worker -> target
vault_api POST ssh-client-signer/roles/operator  "$role_body" >/dev/null    # operator -> worker

# Recording signatures: ed25519 key that never leaves Vault.
vault_api POST transit/keys/jess-recordings '{"type":"ed25519"}' >/dev/null

# Dynamic Postgres users for the target database.
vault_api POST database/config/target-postgres "$(jq -n '{
  plugin_name: "postgresql-database-plugin",
  allowed_roles: "demo-postgres",
  connection_url: "postgresql://{{username}}:{{password}}@target-postgres:5432/demo?sslmode=disable",
  username: "postgres",
  password: "target-admin-demo"
}')" >/dev/null
vault_api POST database/roles/demo-postgres "$(jq -n '{
  db_name: "target-postgres",
  creation_statements: "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '\''{{password}}'\'' VALID UNTIL '\''{{expiration}}'\''; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  default_ttl: "5m",
  max_ttl: "15m"
}')" >/dev/null

# Policies: the worker gets exactly the paths it uses; the operator can only
# ask for an SSH certificate.
worker_policy='
path "ssh-client-signer/sign/ssh-admin"   { capabilities = ["create", "update"] }
path "database/creds/demo-postgres"       { capabilities = ["read"] }
path "transit/sign/jess-recordings"       { capabilities = ["create", "update"] }
path "transit/keys/jess-recordings"       { capabilities = ["read"] }
'
operator_policy='
path "ssh-client-signer/sign/operator" { capabilities = ["create", "update"] }
'
vault_api PUT sys/policies/acl/jess-worker   "$(jq -n --arg p "$worker_policy"   '{policy:$p}')" >/dev/null
vault_api PUT sys/policies/acl/demo-operator "$(jq -n --arg p "$operator_policy" '{policy:$p}')" >/dev/null

worker_token=$(vault_api POST auth/token/create \
  '{"policies":["jess-worker"],"ttl":"720h","no_parent":true}' | jq -r .auth.client_token)
operator_token=$(vault_api POST auth/token/create \
  '{"policies":["demo-operator"],"ttl":"720h","no_parent":true}' | jq -r .auth.client_token)

echo "[2/4] TLS (worker <-> controller mTLS)"
if [ ! -f "$TLS/ca.crt" ]; then
  cd "$TLS"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=jess-demo-ca" -keyout ca.key -out ca.crt 2>/dev/null
  issue() { # NAME CN SAN EKU
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -subj "/CN=$2" -keyout "$1.key" -out "$1.csr" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 30 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  }
  issue controller controller DNS:controller serverAuth
  issue worker worker-1 DNS:worker-1 clientAuth
  rm -f ./*.csr ./*.ext ca.srl
  cd - >/dev/null
fi
chmod 644 "$TLS"/*.crt
chmod 600 "$TLS"/*.key

echo "[3/4] SSH host key and target catalog"
if [ ! -f "$SHARED/ssh_host_ed25519_key" ]; then
  ssh-keygen -q -t ed25519 -N '' -C jess-demo-target -f "$SHARED/ssh_host_ed25519_key"
fi
host_pub=$(cut -d' ' -f1,2 "$SHARED/ssh_host_ed25519_key.pub")

# The worker pins the target's SSH host key; an empty host_key is refused.
jq -n --arg hk "$host_pub" '[
  {
    id: "demo-ssh", name: "Demo SSH target", protocol: "ssh",
    address: "target-ssh:22", required_roles: ["demo-operator"],
    recorded: true, host_key: $hk, ssh_login_user: "demo"
  },
  {
    id: "demo-postgres", name: "Demo Postgres target", protocol: "postgres",
    address: "target-postgres:5432", database: "demo",
    required_roles: ["demo-operator"], recorded: false
  }
]' > "$SHARED/targets.json.tmp"
mv "$SHARED/targets.json.tmp" "$SHARED/targets.json"

echo "[4/4] environment files"
umask 077
{
  printf 'export JESS_VAULT_TOKEN=%q\n' "$worker_token"
  printf 'export JESS_SSH_OPERATOR_CA=%q\n' "$ca_pub"
} > "$SHARED/worker.env.tmp"
{
  printf 'export VAULT_OPERATOR_TOKEN=%q\n' "$operator_token"
} > "$SHARED/operator.env.tmp"
chmod 644 "$SHARED/worker.env.tmp" "$SHARED/operator.env.tmp"
mv "$SHARED/worker.env.tmp" "$SHARED/worker.env"
mv "$SHARED/operator.env.tmp" "$SHARED/operator.env"

# The target's sshd waits for this file, so write it last.
printf '%s\n' "$ca_pub" > "$SHARED/ssh_user_ca.pub.tmp"
chmod 644 "$SHARED/ssh_user_ca.pub.tmp"
mv "$SHARED/ssh_user_ca.pub.tmp" "$SHARED/ssh_user_ca.pub"

echo "setup done"
