FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash -p '*' demo

# Debian's sshd_config includes sshd_config.d first, and sshd keeps the first
# value it sees for each keyword, so this file wins.
COPY 10-demo.conf /etc/ssh/sshd_config.d/10-demo.conf
COPY entrypoint.sh /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
