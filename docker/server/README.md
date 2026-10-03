# Optional SFTP storage server (Docker)

**The WezCrypt Vault desktop app does not need Docker.** This folder is only for people who
want to self-host the storage side on a Linux server.

The container runs a hardened, SFTP-only OpenSSH:

* dedicated non-root `storage` user, chrooted, `ForceCommand internal-sftp`
* root login disabled, password authentication disabled, public-key only
* no TTY, no port/agent/X11 forwarding, modern key exchange and ciphers only
* persistent volumes for data and for the host keys (the SSH fingerprint stays stable)
* read-only root filesystem, dropped capabilities, `no-new-privileges`, healthcheck, restart policy

It only ever stores encrypted `.wezenc` containers. It never receives the master key and has no
ability to decrypt anything.

## Run

```bash
ssh-keygen -t ed25519 -f ~/.ssh/wezcrypt_storage      # on your PC; keep the private key there
cp .env.example .env                                 # paste the .pub line into STORAGE_AUTHORIZED_KEY
docker compose up -d --build
docker compose logs wezcrypt-sftp | grep SHA256      # host key fingerprints to compare in the app
```

## Connect from WezCrypt Vault (Setup Wizard)

| Field | Value |
|---|---|
| Server Host / IP | your server's address |
| SSH Port | `SFTP_PORT` from `.env` (default 2222) |
| Username | `storage` |
| Remote Storage Path | `/storage/` |
| Authentication | SSH Private Key → `~/.ssh/wezcrypt_storage` |

Trust the server only if the fingerprint shown by the wizard matches the one printed in the
container logs.

## Backups

Back up the `wezcrypt-data` volume (ciphertext only) and the `wezcrypt-hostkeys` volume. Restoring
the host keys keeps the fingerprint unchanged; new host keys will be (correctly) blocked by the app
until you deliberately re-verify them.
