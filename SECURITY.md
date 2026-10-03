# WezCrypt Vault — Security Design & Threat Model

## Summary

| Property | Value |
|---|---|
| Cipher | AES-256-GCM (`cryptography` / OpenSSL; no hand-written AES) |
| Key | ONE unified 256-bit master key from `os.urandom(32)`, used for every file |
| Nonce | 96 bits = 64-bit random per-file prefix ‖ 32-bit chunk counter |
| Nonce reuse protection | Persistent SQLite reservation under `BEGIN IMMEDIATE` lock + one-time reservation tokens + counter limit |
| Integrity | GCM tag per chunk; header, File ID, version, algorithm, chunk index, chunk count and metadata hash bound as AAD |
| Metadata privacy | Filename, extension, MIME type, size and plaintext SHA-256 are encrypted |
| Server sees | `<random 256-bit File ID>.wezenc` and ciphertext only |

## The central tradeoff: one unified master key

**Because one unified master AES key protects every file, compromise of that
master key compromises every file encrypted with it — past and future.**

* There is **no forward secrecy**: a key stolen today decrypts every file uploaded before.
* There is **no per-file key isolation**: you cannot share or revoke access to a single file.
* Losing the key makes **all** files permanently unrecoverable. There is no backdoor and no recovery service.
* Rotating the key requires decrypting and re-encrypting every file (not automated; the app never changes the key on its own).

This was an explicit requirement. If you need isolation, use per-file data keys wrapped by a master key instead.

## AES-GCM nonce safety (why it matters and how it is enforced)

Reusing a (key, nonce) pair in GCM is catastrophic: it reveals `P1 XOR P2` and
lets an attacker recover the GHASH subkey and forge ciphertexts. With a single
key for everything, nonce uniqueness is the most important invariant in the system.

1. **Per-file prefix** — 64 bits from `os.urandom`, never derived from filename, time or counters.
2. **Durable reservation before encryption** — `crypto/nonce_manager.py` checks
   `SHA-256(domain ‖ prefix)` against `used_nonces` and inserts it inside a
   `BEGIN IMMEDIATE` transaction. SQLite's write lock serialises threads,
   processes and multiple app windows sharing the vault database. A collision
   discards the candidate and draws again; 16 consecutive collisions (a broken
   RNG) stop encryption. Reservations are never deleted, including after failed
   encryptions, so prefixes cannot be handed out twice, even after restarts.
3. **One-time reservation tokens** — the encryptor refuses to run without a
   reservation object from the manager, refuses one issued for a different File
   ID, and refuses to use the same reservation twice.
4. **Per-chunk nonces** — chunk *i* uses `prefix ‖ i`. Counter `0xFFFFFFFF` is
   reserved for the metadata block. Files needing more than 2³²−1 chunks are refused.
5. Containers decrypted on this machine (e.g. from another device) have their
   prefixes recorded so they are never reissued locally.

**Residual risk:** two installations using the same key keep separate nonce
databases. Between them, uniqueness rests on 64 random bits per file: the
collision probability for *n* files in total is about n²/2⁶⁵ (≈ 3×10⁻⁸ for
one million files). Prefer encrypting from a single installation or a shared database.

Tests: 1,000,000 generated nonces with zero duplicates; forced collisions via
an injected random source; a manually inserted nonce hash is rejected; 8
threads and 4 processes reserving concurrently never share a prefix.

## Container format (`.wezenc`, version 1)

Fixed 80-byte header (`magic, version, cipher, flags, file id, nonce prefix,
chunk size, total chunks, key fingerprint, metadata length`) → encrypted
metadata → chunks. The header is the AAD of the metadata block, and its hash
is in every chunk's AAD together with the chunk index, chunk count, File ID,
version, algorithm and the hash of the encrypted metadata. Consequences:

* Modification of any ciphertext byte, tag, nonce, header field, File ID or metadata → authentication failure.
* Chunk reordering, duplication, insertion, deletion, cross-file splicing and truncation → rejected.
* Parsing is strict and bounded: unsupported versions, unknown algorithms,
  non-zero flags, invalid chunk sizes (4 KiB–64 MiB), zero/oversized chunk
  counts, oversized metadata (>16 KiB) and any size that does not exactly match
  the authenticated metadata are rejected **before** large reads or allocations.
* Decryption writes to a random `0600` `.part` file; it is published (no-clobber
  hard-link/rename) only after every chunk authenticated and the plaintext
  SHA-256 and size match. On any failure the `.part` is deleted — no partial or corrupted output.

The key fingerprint (`SHA-256("wezcrypt-key-fingerprint-v1" ‖ key)[:16]`) is
stored in the clear header so a wrong key is reported as *"This file appears to
use a different master key."* before decryption. It reveals only that files
share a key (they all do by design). A forged fingerprint still fails GCM authentication.

## Threats addressed

**Storage server compromise.** The server holds only ciphertext under random
File-ID names. It never receives the master key, plaintext, filenames,
extensions, local paths, usernames or hostnames. Plaintext hashes are never
uploaded. It can delete or withhold data (availability is not protected) but
cannot read or undetectably modify it.

**Network interception.** SFTP runs over SSH with mandatory strict host-key
checking: the fingerprint is shown on first connection and must be explicitly
trusted; a changed key blocks the connection *before any credentials are sent*
("Server host key changed. Connection blocked for security."). There is no
automatic bypass. HTTPS always uses certificate and hostname verification
(TLS ≥ 1.2); there is no code path that disables verification. Even without transport security
the payload is already encrypted and authenticated.

**Encrypted-file theft.** Stolen containers are useless without the master key (256-bit security).

**File modification.** Detected by AES-GCM authentication on every chunk and
the metadata block, by the registered encrypted SHA-256 on download, and by
remote read-back verification on upload. Failures abort with *"Authentication
failed. The file may be corrupted, modified, or the key is incorrect."*

**Local database theft.** `vault.db` contains File IDs, **original filenames**,
sizes, encrypted hashes, upload dates, server paths, key fingerprints, trusted
SSH host fingerprints and nonce-prefix hashes. It never contains the master
key, passwords, passphrases or tokens. A thief learns what you stored (names
and sizes) but cannot decrypt anything. Protect the user profile with OS disk
encryption (BitLocker / FileVault / LUKS) if filenames are sensitive.

**Hostile containers.** Filenames from metadata are reduced to a sanitized
basename: directory components stripped (`../../Windows/System32/file.exe` →
`file.exe`), control/bidi/format characters and `<>:"/\|?*` replaced, Windows
reserved names (`CON`, `NUL`, `COM1`, …) prefixed, malformed Unicode replaced,
length capped at 200 UTF-8 bytes. Output files are created with `O_EXCL`
(and `O_NOFOLLOW` where available) and never overwrite or follow existing files/symlinks.

## Secrets handling

* The master key is never hardcoded and never written to config, SQLite, logs or source. The user generates or imports it after installation.
* Optional storage only in the OS credential store via `keyring`; insecure fallback backends (plaintext/"alt" keyrings) are refused.
* SSH passwords, key passphrases and HTTPS tokens are stored only in the OS credential store; `config.toml` rejects secret-looking keys.
* Logs are JSON lines with an allow-list of fields (timestamp, operation, File ID, encrypted size, server, status, error category); a redaction filter removes anything shaped like a recovery key, PEM key, bearer token or `password=`. Filenames are excluded unless privacy logging is turned off.
* Clipboard copies of the key are cleared after a configurable timeout, only if the clipboard still holds the exact copied value.

## Known limitations (honest list)

* **Memory:** Python cannot guarantee secrets are wiped. "Lock Master Key"
  zeroes the app's `bytearray` copy and drops references, but immutable `bytes`
  copies passed to `cryptography`, Qt widget text, and clipboard contents may
  remain in process memory until reused. Swap/hibernation files may hold them.
  Quit the application to release process memory.
* **Secure deletion:** removing temp files deletes names only. SSD wear
  levelling, TRIM, journaling and copy-on-write filesystems may retain data.
  Plaintext temp files are never created during encryption; decryption output
  is plaintext by definition.
* **Compromised endpoint:** malware on your computer can read the key and plaintext. No client-side design prevents that.
* **Traffic analysis:** the server learns ciphertext sizes (≈ plaintext size + 16 bytes/chunk + header) and upload times.
* **Availability/rollback:** a malicious server can delete objects or serve an
  older container of the *same* File ID only if it previously stored it; File
  IDs are never reused, and the registered encrypted hash detects substitution.
* **HTTPS uploads** restart from zero after interruption (SFTP and local backends resume with verification).
* **Two-device nonce coordination** — see residual risk above.

## Internal security review checklist (performed)

| Item | Result |
|---|---|
| AES key length | Enforced 32 bytes everywhere (`AES256GCM`, `MasterKey`, recovery decode) |
| AES-GCM nonce reuse | Prefix reservation + counter + one-time tokens; tested |
| Chunk nonce construction | `prefix(8) ‖ BE32(index)`, metadata uses reserved counter |
| Random generator | `os.urandom` only; repo test bans `random.*` in source |
| Secret leakage | Tests scan vault directory, DB and logs for the key/recovery string |
| Logs | Allow-listed fields + redaction |
| SQLite contents | No keys/credentials; nonce *hashes* only |
| Config files | Secret keys rejected on load |
| Temp files | Random names, `0600`, `O_EXCL`, private app dir (`0700`) |
| Host-key checking | Strict, verified before authentication; tested against a live in-process SFTP server |
| TLS validation | `create_default_context`, `CERT_REQUIRED`, hostname check; no disable option |
| Path traversal | Basename-only sanitization + resolved-parent check |
| Race conditions / TOCTOU | Nonce reservation in an exclusive transaction; no-clobber publish via `link`; `O_EXCL` creation |
| Symlinks | `O_NOFOLLOW` on create; existing symlinks treated as occupied names |
| Unsafe permissions | App dir `0700`, files `0600` (POSIX); per-user `%APPDATA%` ACL on Windows |
| Malformed containers | Strict parser, exact size cross-check, fuzz-style tamper tests |
| Repository secret scan | Automated test (`test_repository_contains_no_secrets`) |

## Version 1.1.0 additions

**Server profiles.** Profiles store only non-secret settings (host, port, username, remote path,
authentication method, key path) in `vault.db`. SSH passwords, key passphrases and API tokens are
stored per profile in Windows Credential Manager. If no secure credential store exists, secrets are
kept in memory for the current session only and the user is told so — there is no plaintext
fallback. Changing host or port forgets the previously trusted host key (unless another profile
uses that endpoint); changing any connection or authentication field requires a new successful
connection test before transfers.

**Host keys.** Unknown keys are never auto-accepted: the wizard shows algorithm and SHA-256
fingerprint and the user must click *Trust This Server*. Credentials are only sent after the key
is verified. A changed key blocks the connection with no bypass; only the explicit *Forget Trusted
Host Key* action (with confirmation) removes a trusted key.

**Remote directory.** The configured folder is never created implicitly; the user confirms
*Create Remote Directory* first.

**Connection and end-to-end tests.** The connection test writes a random 64-byte probe with a
random name and deletes it immediately. The end-to-end test uses the real nonce reservation and
container format with the real master key on random data, uploads only ciphertext, verifies the
round trip byte for byte and deletes all remote and local test data. Each stage reports PASS only
after it actually succeeded; cleanup failures are reported as FAIL.

**First upload gate.** Uploads are refused until the user acknowledges responsibility for the
master-key backup.

**User data location.** `%LOCALAPPDATA%\WezCryptVault\{data,config,logs,cache,temp}`; nothing
mutable is written under Program Files. Version 1.0 data is copied (never overwritten) into the new
layout on first start; nonce reservations are carried over so no prefix can be reused after an
upgrade.

**Installer and release artifacts.** The installer contains only the application binary, README and
SECURITY documents — no keys, credentials, databases or configuration. Upgrades keep user data;
uninstall asks separately (default *No*) before removing local data and never touches Credential
Manager. The release pipeline runs the test suite, a project-only secret scan (virtual environments
and installed dependencies are excluded) and an in-binary self-test before packaging. Signing
certificates are supplied only through environment variables or CI secrets.

**URLs** on the About page are opened with `QDesktopServices.openUrl`; no shell is invoked.

## Reporting

Report vulnerabilities privately to the repository owner. Do not open public issues containing key material.
