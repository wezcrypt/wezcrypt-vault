"""Thin, validated wrapper around ``cryptography``'s AES-256-GCM.

No AES is implemented here; all primitives come from the ``cryptography``
library (OpenSSL backend).

CRITICAL: AES-GCM with the same key and the same nonce used twice is
catastrophic. It leaks the XOR of both plaintexts and lets an attacker forge
authentication tags (the GHASH key can be recovered). Because WezCrypt uses
ONE master key for every file, nonce uniqueness is enforced by
``crypto.nonce_manager`` (persistent reservation) and ``crypto.chunks``
(prefix || counter construction). Callers must never construct nonces
themselves.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.errors import AuthenticationFailedError, MasterKeyError

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
CIPHER_NAME = "AES-256-GCM"


class AES256GCM:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
            raise MasterKeyError("AES-256-GCM requires a 32-byte key.")
        self._aead = AESGCM(bytes(key))

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != NONCE_LEN:
            raise ValueError("AES-GCM nonce must be exactly 12 bytes.")
        return self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(nonce) != NONCE_LEN or len(ciphertext) < TAG_LEN:
            raise AuthenticationFailedError()
        try:
            return self._aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise AuthenticationFailedError() from exc
