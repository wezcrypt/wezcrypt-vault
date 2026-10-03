"""Chunk nonce construction and chunk AAD.

96-bit nonce layout (NIST SP 800-38D deterministic construction)::

    nonce = file_nonce_prefix (64 random bits, unique per file) || counter (32 bits, big-endian)

* The 64-bit prefix is drawn from the OS CSPRNG and reserved in the persistent
  nonce database BEFORE encryption, so no two files ever share a prefix.
* Chunk ``i`` uses counter ``i`` (0, 1, 2, ...). Counters never repeat inside a file.
* Counter ``0xFFFFFFFF`` is reserved for the encrypted metadata block and is
  never used for data chunks.
* The maximum chunk count is enforced; an overflowing file is refused.

Reusing (key, nonce) in AES-GCM is catastrophic (plaintext XOR leak and tag
forgery). Every function here refuses inputs that could cause reuse.
"""

from __future__ import annotations

import hashlib
import struct

from utils.errors import NonceReuseError, ValidationError

NONCE_PREFIX_LEN = 8
COUNTER_LIMIT = 0xFFFFFFFF            # 2**32 - 1
METADATA_COUNTER = 0xFFFFFFFF         # reserved, never a chunk index
MAX_CHUNKS = 0xFFFFFFFF               # chunk indices 0 .. 0xFFFFFFFE

MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 64 * 1024 * 1024     # bounds memory used per chunk on decrypt
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024

_CHUNK_AAD_DOMAIN = b"WEZCHUNK"


def validate_chunk_size(chunk_size: int) -> int:
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise ValidationError("Chunk size must be an integer.")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValidationError(
            f"Chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes."
        )
    return chunk_size


def total_chunks_for(size: int, chunk_size: int, max_chunks: int = MAX_CHUNKS) -> int:
    """A zero-byte file still has one (empty) authenticated chunk."""
    if size < 0:
        raise ValidationError("File size cannot be negative.")
    total = max(1, -(-size // chunk_size))
    if total > max_chunks:
        raise NonceReuseError(
            "File requires more chunks than the 32-bit nonce counter allows. "
            "Increase the chunk size. Encryption stopped."
        )
    return total


def chunk_nonce(prefix: bytes, index: int, max_chunks: int = MAX_CHUNKS) -> bytes:
    if len(prefix) != NONCE_PREFIX_LEN:
        raise NonceReuseError("Nonce prefix must be exactly 8 bytes.")
    if not 0 <= index < min(max_chunks, MAX_CHUNKS):
        raise NonceReuseError("Chunk counter overflow. Encryption stopped to prevent nonce reuse.")
    return prefix + struct.pack(">I", index)


def metadata_nonce(prefix: bytes) -> bytes:
    if len(prefix) != NONCE_PREFIX_LEN:
        raise NonceReuseError("Nonce prefix must be exactly 8 bytes.")
    return prefix + struct.pack(">I", METADATA_COUNTER)


def chunk_aad(
    *,
    version: int,
    cipher_id: int,
    file_id: bytes,
    index: int,
    total: int,
    header_hash: bytes,
    metadata_ct_hash: bytes,
) -> bytes:
    """Binds each chunk to its file, position, chunk count, header and metadata.

    Any chunk modification, deletion, insertion, duplication or reordering
    changes the AAD (or the index/total pair) and fails GCM authentication.
    """
    return b"".join(
        (
            _CHUNK_AAD_DOMAIN,
            struct.pack(">HB", version, cipher_id),
            file_id,
            struct.pack(">II", index, total),
            header_hash,
            metadata_ct_hash,
        )
    )


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
