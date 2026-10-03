# OPTIONAL self-hosted storage server for WezCrypt Vault (the desktop app does NOT need Docker).
# Hardened, SFTP-only OpenSSH. Stores encrypted .wezenc containers; it has no master key and
# no decryption capability. Public-key authentication only by default.
FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-sftp-server tini \
 && addgroup -S storage \
 && adduser -S -D -H -G storage -h /data -s /sbin/nologin storage \
 && sed -i 's/^storage:!/storage:*/' /etc/shadow \
 && mkdir -p /etc/ssh/keys /etc/ssh/authorized_keys /data \
 && rm -f /etc/ssh/ssh_host_*

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0644 /etc/ssh/sshd_config && chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 22
VOLUME ["/data", "/etc/ssh/keys"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 22 || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
