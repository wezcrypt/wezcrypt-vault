"""Unified AES-256 master key handling.

One master key protects every file. It is generated from the operating
system CSPRNG (``os.urandom``), is exactly 32 bytes, and is never written to
config files, SQLite, logs or source code.

Recovery key format (version 1)::

    wezcrypt-v1-<43 chars base64url(key), no padding>-<8 hex chars checksum>

The prefix and checksum are framing only; all 256 bits of entropy live in the
base64url body and are decoded byte-for-byte without transformation. The
checksum detects typos; it is NOT a security mechanism.

Memory limitation: Python cannot guarantee that secrets are wiped from RAM.
The key is held in a ``bytearray`` that is overwritten on ``lock()``, but
immutable ``bytes`` copies required by the ``cryptography`` API, the
clipboard and Qt widgets may persist until the garbage collector and the OS
reuse that memory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from utils.errors import InvalidRecoveryKeyError, KeyNotLoadedError

KEY_SIZE_BYTES = 32
RECOVERY_PREFIX = "wezcrypt-v1-"
RECOVERY_FORMAT_VERSION = 1
_FINGERPRINT_DOMAIN = b"wezcrypt-key-fingerprint-v1\x00"
_CHECKSUM_DOMAIN = b"wezcrypt-recovery-checksum-v1\x00"
_RECOVERY_RE = re.compile(r"^wezcrypt-v1-([A-Za-z0-9_-]{43})(?:-([0-9a-fA-F]{8}))?$")
FINGERPRINT_BYTES = 16


def generate_master_key() -> bytes:
    """Return 32 bytes from the OS CSPRNG."""
    key = os.urandom(KEY_SIZE_BYTES)
    if len(key) != KEY_SIZE_BYTES:
        raise InvalidRecoveryKeyError("CSPRNG returned an unexpected key length.")
    return key


def key_fingerprint(key: bytes) -> bytes:
    """Non-secret 128-bit identifier of a key. Never used as key material."""
    _check_len(key)
    return hashlib.sha256(_FINGERPRINT_DOMAIN + key).digest()[:FINGERPRINT_BYTES]


def format_fingerprint(fp: bytes) -> str:
    """Short display form, e.g. ``AB42-F731-0EF2-91CD`` (first 64 bits)."""
    h = fp[:8].hex().upper()
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


def _checksum(key: bytes) -> str:
    return hashlib.sha256(_CHECKSUM_DOMAIN + key).hexdigest()[:8]


def _check_len(key: bytes | bytearray) -> None:
    if len(key) != KEY_SIZE_BYTES:
        raise InvalidRecoveryKeyError("Master key must be exactly 32 bytes (256 bits).")


def encode_recovery_key(key: bytes) -> str:
    _check_len(key)
    body = base64.urlsafe_b64encode(bytes(key)).decode("ascii").rstrip("=")
    return f"{RECOVERY_PREFIX}{body}-{_checksum(bytes(key))}"


def decode_recovery_key(text: str) -> bytes:
    """Validate format, length and checksum; return the exact 32 key bytes."""
    if not isinstance(text, str):
        raise InvalidRecoveryKeyError("Recovery key must be text.")
    cleaned = "".join(text.split())
    if len(cleaned) > 128:
        raise InvalidRecoveryKeyError("Recovery key is too long.")
    m = _RECOVERY_RE.fullmatch(cleaned)
    if not m:
        raise InvalidRecoveryKeyError(
            "Invalid recovery key format. Expected wezcrypt-v1-<43 characters>-<8 hex checksum>."
        )
    body, checksum = m.group(1), m.group(2)
    try:
        key = base64.urlsafe_b64decode(body + "=")
    except (binascii.Error, ValueError) as exc:
        raise InvalidRecoveryKeyError("Recovery key body is not valid base64url.") from exc
    if len(key) != KEY_SIZE_BYTES:
        raise InvalidRecoveryKeyError("Decoded key is not exactly 32 bytes.")
    # Reject non-canonical encodings (trailing bits set) so one key == one string.
    if base64.urlsafe_b64encode(key).decode("ascii").rstrip("=") != body:
        raise InvalidRecoveryKeyError("Recovery key body is not canonical base64url.")
    if checksum is not None and not hmac.compare_digest(checksum.lower(), _checksum(key)):
        raise InvalidRecoveryKeyError("Recovery key checksum mismatch. Check for typos.")
    return key


def recovery_file_text(key: bytes) -> str:
    """Contents of ``wezcrypt-recovery-key.txt``. Contains no server credentials."""
    fp = format_fingerprint(key_fingerprint(key))
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        "WEZCRYPT VAULT - MASTER RECOVERY KEY\n"
        "====================================\n"
        f"Version: {RECOVERY_FORMAT_VERSION}\n"
        f"Key ID: {fp}\n"
        f"Created: {created}\n"
        "Cipher: AES-256-GCM\n"
        "\n"
        f"Master AES key: {encode_recovery_key(key)}\n"
        "\n"
        "WARNING: Anyone who has this key can decrypt all files protected by this application.\n"
        "WARNING: If this key is lost, encrypted files may become permanently unrecoverable.\n"
        "Store this file offline (paper, encrypted USB, safe). Never upload it to the storage server.\n"
    )


def extract_key_from_backup_text(text: str) -> bytes:
    """Accept either a bare recovery key or the contents of a recovery file."""
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("master aes key:"):
            return decode_recovery_key(line.split(":", 1)[1])
    return decode_recovery_key(text)


@dataclass(frozen=True)
class KeyInfo:
    fingerprint: bytes
    display_fingerprint: str


class MasterKey:
    """Thread-safe holder for the loaded master key.

    Never silently regenerates or replaces a key: ``load`` refuses to replace
    a different loaded key unless ``replace=True`` is passed explicitly.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._key: bytearray | None = None
        self._fp: bytes | None = None

    @property
    def is_loaded(self) -> bool:
        with self._lock:
            return self._key is not None

    def load(self, key: bytes, *, replace: bool = False) -> KeyInfo:
        _check_len(key)
        with self._lock:
            new_fp = key_fingerprint(bytes(key))
            if self._key is not None and not replace and not hmac.compare_digest(new_fp, self._fp or b""):
                raise InvalidRecoveryKeyError(
                    "A different master key is already loaded. Lock it before loading another key."
                )
            self._wipe()
            self._key = bytearray(key)
            self._fp = new_fp
            return KeyInfo(new_fp, format_fingerprint(new_fp))

    def info(self) -> KeyInfo:
        with self._lock:
            if self._fp is None:
                raise KeyNotLoadedError()
            return KeyInfo(self._fp, format_fingerprint(self._fp))

    def material(self) -> bytes:
        """Return an immutable copy for the cryptography API (see module docstring)."""
        with self._lock:
            if self._key is None:
                raise KeyNotLoadedError()
            return bytes(self._key)

    def recovery_string(self) -> str:
        return encode_recovery_key(self.material())

    def matches(self, candidate: bytes) -> bool:
        with self._lock:
            if self._key is None:
                raise KeyNotLoadedError()
            return len(candidate) == KEY_SIZE_BYTES and hmac.compare_digest(bytes(self._key), candidate)

    def _wipe(self) -> None:
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
        self._key = None
        self._fp = None

    def lock(self) -> None:
        """Best-effort removal of the key from application state."""
        with self._lock:
            self._wipe()
