#!/bin/sh
set -eu
# `setup` writes the CA public key last, so once it exists the host key does too.
until [ -s /shared/ssh_user_ca.pub ] && [ -f /shared/ssh_host_ed25519_key ]; do
  sleep 1
done
install -m 600 /shared/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
install -m 644 /shared/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
exec /usr/sbin/sshd -D -e
