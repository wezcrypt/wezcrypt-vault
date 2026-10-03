#!/bin/sh
# Prepares host keys (persisted in a volume so the fingerprint never changes between restarts),
# the authorized key of the storage user, and the chroot layout. Contains no credentials.
set -eu

KEYS=/etc/ssh/keys
[ -f "$KEYS/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEYS/ssh_host_ed25519_key"
[ -f "$KEYS/ssh_host_rsa_key" ] || ssh-keygen -q -t rsa -b 4096 -N "" -f "$KEYS/ssh_host_rsa_key"
chmod 600 "$KEYS"/ssh_host_*_key

if [ -z "${STORAGE_AUTHORIZED_KEY:-}" ] && [ ! -s /etc/ssh/authorized_keys/storage ]; then
  echo "ERROR: set STORAGE_AUTHORIZED_KEY to the PUBLIC key (ssh-ed25519 AAAA...) of the WezCrypt Vault user." >&2
  exit 1
fi
if [ -n "${STORAGE_AUTHORIZED_KEY:-}" ]; then
  case "$STORAGE_AUTHORIZED_KEY" in
    ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
    *) echo "ERROR: STORAGE_AUTHORIZED_KEY must be an OpenSSH public key line." >&2; exit 1 ;;
  esac
  printf '%s\n' "$STORAGE_AUTHORIZED_KEY" > /etc/ssh/authorized_keys/storage
fi
chown root:root /etc/ssh/authorized_keys /etc/ssh/authorized_keys/storage
chmod 755 /etc/ssh/authorized_keys
chmod 644 /etc/ssh/authorized_keys/storage

# Chroot root must be owned by root and not writable by others; data lives below it.
chown root:root /data
chmod 755 /data
mkdir -p /data/storage
chown storage:storage /data/storage
chmod 700 /data/storage

echo "WezCrypt Vault storage server host key fingerprints (verify these in the app's Setup Wizard):"
for k in "$KEYS"/ssh_host_*_key.pub; do ssh-keygen -lf "$k"; done

/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
