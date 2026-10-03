"""OS credential store integration via ``keyring``.

Backends: Windows Credential Manager, macOS Keychain, Linux Secret Service.
Insecure fallback backends (plaintext files, "null"/"fail" keyrings) are
refused so secrets never silently land on disk unprotected.
"""

from __future__ import annotations

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from crypto.key_manager import decode_recovery_key, encode_recovery_key
from utils.errors import MasterKeyError

SERVICE = "WezCryptVault"
MASTER_KEY_ENTRY = "master-key"
_INSECURE_BACKEND_MARKERS = ("PlaintextKeyring", "fail.Keyring", "null.Keyring", "EncryptedKeyring")


class CredentialStoreError(MasterKeyError):
    error_category = "credential_store"


def backend_name() -> str:
    kr = keyring.get_keyring()
    return f"{type(kr).__module__}.{type(kr).__name__}"


def _require_secure_backend() -> None:
    name = backend_name()
    if any(marker in name for marker in _INSECURE_BACKEND_MARKERS) or "keyrings.alt" in name:
        raise CredentialStoreError(
            "No secure OS credential store is available. Use manual key entry instead."
        )


def is_available() -> bool:
    try:
        _require_secure_backend()
        return True
    except CredentialStoreError:
        return False


def store_master_key(key: bytes) -> None:
    _require_secure_backend()
    try:
        existing = keyring.get_password(SERVICE, MASTER_KEY_ENTRY)
        if existing is not None and decode_recovery_key(existing) != key:
            raise CredentialStoreError(
                "A different master key is already stored. Remove it explicitly before storing another."
            )
        keyring.set_password(SERVICE, MASTER_KEY_ENTRY, encode_recovery_key(key))
    except KeyringError as exc:
        raise CredentialStoreError("Could not write to the OS credential store.") from exc


def load_master_key() -> bytes | None:
    _require_secure_backend()
    try:
        value = keyring.get_password(SERVICE, MASTER_KEY_ENTRY)
    except KeyringError as exc:
        raise CredentialStoreError("Could not read the OS credential store.") from exc
    return decode_recovery_key(value) if value else None


def delete_master_key() -> None:
    _require_secure_backend()
    try:
        keyring.delete_password(SERVICE, MASTER_KEY_ENTRY)
    except PasswordDeleteError:
        return
    except KeyringError as exc:
        raise CredentialStoreError("Could not delete from the OS credential store.") from exc


def _entry(kind: str, ident: str) -> str:
    if kind not in ("ssh-password", "ssh-key-passphrase", "https-token"):
        raise CredentialStoreError("Unknown credential kind.")
    return f"{kind}:{ident}"


def set_secret(kind: str, ident: str, value: str) -> None:
    _require_secure_backend()
    try:
        if value:
            keyring.set_password(SERVICE, _entry(kind, ident), value)
        else:
            try:
                keyring.delete_password(SERVICE, _entry(kind, ident))
            except PasswordDeleteError:
                pass
    except KeyringError as exc:
        raise CredentialStoreError("Could not write to the OS credential store.") from exc


def get_secret(kind: str, ident: str) -> str | None:
    if not is_available():
        return None
    try:
        return keyring.get_password(SERVICE, _entry(kind, ident))
    except KeyringError:
        return None
