# WezCrypt Vault

**Secure Client-Side Encrypted File Storage** — version 1.1.0

## About

WezCrypt Vault is a Windows desktop application that encrypts any file on your computer with
**AES-256-GCM** before it leaves the machine, then stores only the encrypted container on your own
server (SFTP, or an HTTPS API you operate). The server never receives your master key, your
plaintext, or your original filenames.

> ⚠ **Your unified master key protects all files encrypted with it.**
> ⚠ **If this key is lost, encrypted files may become permanently unrecoverable.**
> ⚠ **Anyone who obtains this key may be able to decrypt all files protected by it.**

## Features

* Client-side AES-256-GCM, chunked streaming encryption (any file type and size)
* One 256-bit unified master key, with recovery-key backup, print, offline backup and verification
* Unique nonce per chunk, enforced by a persistent nonce-reservation database
* Encrypted metadata: the server sees only random `<file-id>.wezenc` names
* SFTP with strict SSH host-key verification (no auto-accept, changed keys are blocked)
* Server profiles (e.g. *Personal VPS*, *Backup Server*, *Office Storage*)
* First-run Setup Wizard with connection test and a real end-to-end encrypted round-trip test
* Resumable, verified uploads; tamper-evident downloads; crash recovery
* Secrets kept in Windows Credential Manager, never in plain-text files
* Privacy-safe structured logs, dark-mode Qt interface, drag and drop

## Security Model

Encryption and decryption happen only on your computer. Each file is split into chunks; every chunk
is authenticated together with the file ID, chunk index, chunk count and header, so any change,
truncation, reordering or substitution is detected and nothing is written. Full details, the threat
model and the limitations are in [SECURITY.md](SECURITY.md).

## Installation

### Windows

Download:

`WezCryptVault-Setup-1.1.0.exe`

Run it, click **Install**, then launch WezCrypt Vault from the Start Menu.

No Python, pip, Docker, or Git required — everything the app needs is bundled.

* Installs to `C:\Program Files\WezCrypt Vault\` (or a per-user location if you choose so).
* Your data lives in `%LOCALAPPDATA%\WezCryptVault\` (`data`, `config`, `logs`, `cache`, `temp`).
* Upgrades keep your database, settings, server profiles, trusted fingerprints and Credential
  Manager entries. Data from version 1.0 (`%APPDATA%\WezCryptVault`) is migrated automatically.
* Uninstalling removes the program only; you are asked separately (default **No**) whether to
  also remove local data. Credential Manager entries are never removed automatically.
* Verify the download against `SHA256SUMS.txt` from the release page:
  `Get-FileHash .\WezCryptVault-Setup-1.1.0.exe -Algorithm SHA256`

If Windows SmartScreen warns about an unknown publisher (unsigned build), choose
*More info → Run anyway* only if the SHA-256 matches the published checksum.

## First Run

The Setup Wizard opens automatically:

1. **Welcome** — what the app does.
2. **Master Key** — generate a new key or import an existing one; back it up; acknowledge that
   losing it loses your files. Uploads stay disabled until you acknowledge.
3. **Storage Type** — SFTP Server (recommended) or HTTPS API.
4. **Server Details** — host, port, username, remote path.
5. **Authentication** — SSH private key (recommended) or password.
6. **Server Identity** — the server's SSH fingerprint; trust it only if it matches the server.
7. **Test Connection** — reachability, SSH, authentication, remote folder (offered for creation
   if missing), write and read access, using a temporary probe that is deleted.
8. **End-to-End Test** — encrypts a random file, uploads only ciphertext, downloads, decrypts,
   compares byte for byte, then deletes all test data.
9. **Done** — start using the app or open Settings.

## Master Key

* Generated from the operating system's secure random generator; exactly 256 bits.
* Shown only when you click **Show / Hide**. **Copy** clears the clipboard automatically.
* **Save Backup / Create Offline Backup / Print** produce `wezcrypt-recovery-key.txt`
  (version, key ID, key — never server credentials). Keep at least one copy offline.
* **Verify Backup** confirms a backup matches the loaded key.
* Storage mode: *Manual* (enter it at each start) or *Windows Credential Manager*.
* The app never replaces or regenerates your key on its own.

## Server Setup

| Setting | Meaning |
|---|---|
| Host | DNS name or IP of your server (`example.com`) |
| Port | SSH port, usually `22` |
| Username | dedicated storage account (`storageuser`) |
| Remote path | folder for encrypted containers (`/storage/encrypted/`) |
| SSH key / password | key recommended; secrets go to Credential Manager |
| Fingerprint | compare with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server |

Changing host or port forgets the old trust and requires fingerprint verification again; changing
authentication requires a new connection test before transfers. If a server key ever changes
unexpectedly the connection is blocked — there is no "continue anyway".

Optional self-hosted, hardened SFTP container: [docker/server/README.md](docker/server/README.md).
Docker is never required by the desktop app.

## Build From Source

Build machine only (Windows 10/11 x64, 64-bit Python 3.12+, Inno Setup 6):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
```

The script validates the environment, creates `.venv-build`, installs dependencies, runs the full
test suite (stops on failure), runs the secret scan, builds `dist\WezCryptVault.exe` from
`packaging\WezCryptVault.spec`, runs the packaged-app self-test (`WezCryptVault.exe --self-test`),
builds `dist\WezCryptVault-Setup-<version>.exe` from `packaging\WezCryptVault.iss`, and writes
`dist\SHA256SUMS.txt`.

Code signing is optional and configured only through environment variables / CI secrets
(`WEZCRYPT_SIGN_THUMBPRINT`, or `WEZCRYPT_SIGN_PFX` + `WEZCRYPT_SIGN_PFX_PASSWORD`, and
`WEZCRYPT_SIGN_TIMESTAMP`). Without them the build is unsigned and reports
`CODE SIGNING: NOT CONFIGURED`.

Tagging `v1.1.0` runs `.github/workflows/release.yml`, which performs the same build on
`windows-latest` and publishes `WezCryptVault.exe`, `WezCryptVault-Setup-1.1.0.exe`,
`SHA256SUMS.txt` and a source archive. The version lives only in `wezcrypt_vault/version.py`.

Run from source for development:

```bash
python -m venv .venv && .venv\Scripts\activate      # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Testing

```bash
pip install -r requirements.txt pytest
python -m pytest -v
python scripts/secret_scan.py
```

The suite covers cryptography (round trips, tampering, truncation, chunk reordering/duplication,
counter overflow, 1,000,000-nonce uniqueness, concurrency), path safety, storage resume and
interruption, strict host-key checking and the connection/end-to-end tests against a live
in-process SFTP server, the complete Setup Wizard flow, server profiles, 1.0 → 1.1 data migration,
the About page, and release consistency. On Windows, the symlink test is skipped when the account
lacks the symlink privilege; skips are reported.

## Security Limitations

* One key protects everything: no forward secrecy and no per-file key isolation.
* Python cannot guarantee that secrets are wiped from memory.
* Deleting files on SSDs is not a secure erase.
* The local database contains original filenames (needed for *My Files*); protect your Windows
  account and consider BitLocker.
* Malware on your computer can read what you can read.

See [SECURITY.md](SECURITY.md) for the complete list.

## Developer

Developer:
wezcrypt

Website:
https://wezcrypt.com

GitHub:
https://github.com/wezcrypt

Repository:
https://github.com/wezcrypt/wezcrypt-vault
