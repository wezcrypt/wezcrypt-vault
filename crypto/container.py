"""WEZCRYPT v1 encrypted container (``.wezenc``).

Layout (all integers big-endian)::

    offset size  field
    0      8     magic            b"WEZCRYPT"
    8      2     version          1
    10     1     cipher id        1 = AES-256-GCM
    11     1     flags            0 (reserved, must be zero)
    12     32    file id          256 random bits
    44     8     nonce prefix     64 random bits, reserved in the nonce DB
    52     4     chunk size       plaintext bytes per chunk
    56     4     total chunks     >= 1
    60     16    key fingerprint  SHA-256(domain || key)[:16] (non-secret)
    76     4     metadata ct len  encrypted metadata length incl. 16-byte tag
    80     ...   encrypted metadata   AES-256-GCM(nonce = prefix||FFFFFFFF,
                                      AAD = "WEZMETA" || header[0:80])
    ...    ...   chunk 0 .. N-1   AES-256-GCM(nonce = prefix||index,
                                      AAD = see crypto.chunks.chunk_aad)

The header is authenticated as AAD of the metadata block and (via its hash)
of every chunk, so any change to version, algorithm, file id, nonce prefix,
chunk geometry or fingerprint fails authentication. The master key is never
stored in the container. Sensitive metadata (filename, extension, MIME type,
size, plaintext SHA-256) exists only inside the encrypted metadata block.

All parsing treats the container as hostile input: every length is bounded
before allocation, and the exact container size is cross-checked against the
authenticated metadata before any plaintext is written.
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from crypto.aes import AES256GCM, TAG_LEN
from crypto.chunks import (
    MAX_CHUNKS,
    NONCE_PREFIX_LEN,
    chunk_aad,
    chunk_nonce,
    metadata_nonce,
    total_chunks_for,
    validate_chunk_size,
)
from crypto.hashing import hashes_equal, sha256_file
from crypto.key_manager import key_fingerprint
from crypto.nonce_manager import NonceReservation, consume_reservation
from security.paths import (
    create_private_file,
    finalize_no_clobber,
    random_temp_path,
    safe_unlink,
    sanitize_filename,
    unique_output_path,
)
from utils.errors import (
    AuthenticationFailedError,
    ContainerFormatError,
    IntegrityError,
    OperationCancelled,
    SourceChangedError,
    UnsupportedVersionError,
    ValidationError,
    WrongKeyError,
)

MAGIC = b"WEZCRYPT"
VERSION = 1
CIPHER_AES_256_GCM = 1
CIPHER_NAMES = {CIPHER_AES_256_GCM: "AES-256-GCM"}
HEADER_STRUCT = struct.Struct(">8sHBB32s8sII16sI")
HEADER_LEN = HEADER_STRUCT.size  # 80
MAX_METADATA_PLAINTEXT = 16 * 1024
MAX_METADATA_CT = MAX_METADATA_PLAINTEXT + TAG_LEN
_META_AAD_DOMAIN = b"WEZMETA"
_META_KEYS = {"v", "name", "ext", "mime", "size", "sha256", "key_fp"}

ProgressFn = Callable[[str, int, int], None]


@dataclass(frozen=True)
class ContainerHeader:
    version: int
    cipher_id: int
    flags: int
    file_id: bytes
    nonce_prefix: bytes
    chunk_size: int
    total_chunks: int
    key_fingerprint: bytes
    metadata_ct_len: int
    raw: bytes

    @property
    def file_id_hex(self) -> str:
        return self.file_id.hex()

    @property
    def cipher_name(self) -> str:
        return CIPHER_NAMES.get(self.cipher_id, "unknown")


@dataclass(frozen=True)
class FileMetadata:
    name: str
    ext: str
    mime: str
    size: int
    sha256: str
    key_fp: str


@dataclass(frozen=True)
class EncryptResult:
    file_id: str
    plaintext_size: int
    plaintext_sha256: str
    encrypted_size: int
    encrypted_sha256: str
    total_chunks: int
    key_fingerprint: bytes


@dataclass(frozen=True)
class DecryptResult:
    file_id: str
    output_path: Path
    original_name: str
    size: int
    sha256: str
    mime: str


def _pack_header(
    file_id: bytes, prefix: bytes, chunk_size: int, total: int, fp: bytes, meta_len: int
) -> bytes:
    return HEADER_STRUCT.pack(
        MAGIC, VERSION, CIPHER_AES_256_GCM, 0, file_id, prefix, chunk_size, total, fp, meta_len
    )


def parse_header(data: bytes) -> ContainerHeader:
    """Strictly validate the fixed header. Never trusts any field."""
    if len(data) < HEADER_LEN:
        raise ContainerFormatError("Container is truncated (incomplete header).")
    raw = bytes(data[:HEADER_LEN])
    magic, version, cipher_id, flags, file_id, prefix, chunk_size, total, fp, meta_len = (
        HEADER_STRUCT.unpack(raw)
    )
    if magic != MAGIC:
        raise ContainerFormatError("Not a WezCrypt container (bad magic bytes).")
    if version != VERSION:
        raise UnsupportedVersionError(f"Unsupported container version {version}.")
    if cipher_id != CIPHER_AES_256_GCM:
        raise ContainerFormatError("Unexpected encryption algorithm in container.")
    if flags != 0:
        raise ContainerFormatError("Unsupported container flags.")
    if len(prefix) != NONCE_PREFIX_LEN:
        raise ContainerFormatError("Invalid nonce length.")
    try:
        validate_chunk_size(chunk_size)
    except ValidationError as exc:
        raise ContainerFormatError("Invalid chunk size in container.") from exc
    if not 1 <= total <= MAX_CHUNKS:
        raise ContainerFormatError("Invalid chunk count in container.")
    if not TAG_LEN + 2 <= meta_len <= MAX_METADATA_CT:
        raise ContainerFormatError("Invalid encrypted metadata length.")
    return ContainerHeader(
        version, cipher_id, flags, file_id, prefix, chunk_size, total, fp, meta_len, raw
    )


def read_header(path: str | Path) -> ContainerHeader:
    with Path(path).open("rb") as fh:
        return parse_header(fh.read(HEADER_LEN))


def _metadata_aad(header_raw: bytes) -> bytes:
    return _META_AAD_DOMAIN + header_raw


def _parse_metadata(blob: bytes) -> FileMetadata:
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerFormatError("Encrypted metadata is malformed.") from exc
    if not isinstance(obj, dict) or set(obj) != _META_KEYS or obj.get("v") != 1:
        raise ContainerFormatError("Encrypted metadata has unexpected fields.")
    size = obj["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ContainerFormatError("Invalid original size in metadata.")
    for k in ("name", "ext", "mime", "sha256", "key_fp"):
        if not isinstance(obj[k], str) or len(obj[k]) > 4096:
            raise ContainerFormatError("Invalid metadata field.")
    if len(obj["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in obj["sha256"]):
        raise ContainerFormatError("Invalid plaintext hash in metadata.")
    return FileMetadata(obj["name"], obj["ext"], obj["mime"], size, obj["sha256"], obj["key_fp"])


class _HashingWriter:
    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, data: bytes) -> None:
        self.fh.write(data)
        self.h.update(data)
        self.n += len(data)


def encrypt_file(
    src: str | Path,
    dst: BinaryIO,
    *,
    key: bytes,
    file_id: bytes,
    reservation: NonceReservation,
    chunk_size: int,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
    max_chunks: int = MAX_CHUNKS,
) -> EncryptResult:
    """Stream-encrypt ``src`` into ``dst``. Memory use is O(chunk_size).

    Pass 1 hashes the plaintext (the hash is part of the encrypted metadata).
    Pass 2 encrypts and re-hashes; if the source changed between passes the
    operation aborts and the caller discards the partial container.
    """
    validate_chunk_size(chunk_size)
    src = Path(src)
    if not src.is_file():
        raise ValidationError("Source is not a regular file.")
    size = src.stat().st_size
    total = total_chunks_for(size, chunk_size, max_chunks)

    def _p(stage: str, done: int, tot: int) -> None:
        if progress:
            progress(stage, done, tot)

    plain_sha, hashed = sha256_file(src, progress=lambda d, t: _p("hashing", d, t), cancel=cancel)
    if hashed != size:
        raise SourceChangedError("Source file changed while being read.")

    # Consume the one-time reservation only after all preconditions passed.
    prefix = consume_reservation(reservation, file_id)
    aead = AES256GCM(key)
    fp = key_fingerprint(key)

    name = sanitize_filename(src.name)
    ext = Path(name).suffix.lower()
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    meta = {
        "v": 1, "name": name, "ext": ext, "mime": mime,
        "size": size, "sha256": plain_sha, "key_fp": fp.hex(),
    }
    meta_plain = json.dumps(meta, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    if len(meta_plain) > MAX_METADATA_PLAINTEXT:
        raise ValidationError("File metadata is too large.")
    header = _pack_header(file_id, prefix, chunk_size, total, fp, len(meta_plain) + TAG_LEN)
    meta_ct = aead.encrypt(metadata_nonce(prefix), meta_plain, _metadata_aad(header))
    header_hash = hashlib.sha256(header).digest()
    meta_hash = hashlib.sha256(meta_ct).digest()

    out = _HashingWriter(dst)
    out.write(header)
    out.write(meta_ct)

    re_hash = hashlib.sha256()
    done = 0
    with src.open("rb") as fh:
        for index in range(total):
            if cancel is not None and cancel.is_set():
                raise OperationCancelled()
            expected = chunk_size if index < total - 1 else size - chunk_size * (total - 1)
            block = fh.read(expected)
            if len(block) != expected:
                raise SourceChangedError("Source file changed during encryption.")
            re_hash.update(block)
            aad = chunk_aad(
                version=VERSION, cipher_id=CIPHER_AES_256_GCM, file_id=file_id,
                index=index, total=total, header_hash=header_hash, metadata_ct_hash=meta_hash,
            )
            # Unique nonce per chunk: reserved prefix || chunk counter.
            out.write(aead.encrypt(chunk_nonce(prefix, index, max_chunks), block, aad))
            done += len(block)
            _p("encrypting", done, size)
        if fh.read(1):
            raise SourceChangedError("Source file grew during encryption.")
    if not hashes_equal(re_hash.hexdigest(), plain_sha):
        raise SourceChangedError("Source file changed during encryption.")
    return EncryptResult(
        file_id.hex(), size, plain_sha, out.n, out.h.hexdigest(), total, fp
    )


def decrypt_container(
    src: str | Path,
    out_dir: str | Path,
    *,
    key: bytes,
    expected_file_id: str | None = None,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> DecryptResult:
    """Authenticate and decrypt a container into ``out_dir``.

    Plaintext is streamed into a random, private ``.part`` file inside the
    output directory and published under the sanitized original name only
    after every chunk authenticated and the plaintext SHA-256 and size match
    the authenticated metadata. Any failure deletes the ``.part`` file, so
    no corrupted or partially decrypted output is ever left behind.
    """
    src = Path(src)
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        raise ValidationError("Output directory does not exist.")
    container_size = src.stat().st_size
    aead = AES256GCM(key)
    with src.open("rb") as fh:
        header = parse_header(fh.read(HEADER_LEN))
        if expected_file_id is not None and header.file_id_hex != expected_file_id:
            raise ContainerFormatError("Container File ID does not match the requested File ID.")
        if header.key_fingerprint != key_fingerprint(key):
            raise WrongKeyError()

        # Geometry check before reading anything large.
        base = HEADER_LEN + header.metadata_ct_len
        min_len = base + (header.total_chunks - 1) * (header.chunk_size + TAG_LEN) + TAG_LEN
        max_len = base + header.total_chunks * (header.chunk_size + TAG_LEN)
        if container_size < min_len:
            raise ContainerFormatError("Container is truncated.")
        if container_size > max_len:
            raise ContainerFormatError("Container has unexpected trailing data.")

        meta_ct = fh.read(header.metadata_ct_len)
        if len(meta_ct) != header.metadata_ct_len:
            raise ContainerFormatError("Container is truncated (metadata).")
        meta = _parse_metadata(
            aead.decrypt(metadata_nonce(header.nonce_prefix), meta_ct, _metadata_aad(header.raw))
        )
        if meta.key_fp != header.key_fingerprint.hex():
            raise AuthenticationFailedError()
        if total_chunks_for(meta.size, header.chunk_size) != header.total_chunks:
            raise ContainerFormatError("Chunk count does not match the original size.")
        if container_size != base + meta.size + TAG_LEN * header.total_chunks:
            raise ContainerFormatError("Container size does not match its metadata (truncated or padded).")

        header_hash = hashlib.sha256(header.raw).digest()
        meta_hash = hashlib.sha256(meta_ct).digest()
        safe_name = sanitize_filename(meta.name)
        part = random_temp_path(out_dir, ".part")
        fd = create_private_file(part)
        published = False
        try:
            h = hashlib.sha256()
            written = 0
            with os.fdopen(fd, "wb") as out:
                for index in range(header.total_chunks):
                    if cancel is not None and cancel.is_set():
                        raise OperationCancelled()
                    plain_len = (
                        header.chunk_size if index < header.total_chunks - 1
                        else meta.size - header.chunk_size * (header.total_chunks - 1)
                    )
                    ct = fh.read(plain_len + TAG_LEN)
                    if len(ct) != plain_len + TAG_LEN:
                        raise ContainerFormatError("Container is truncated (chunk data).")
                    aad = chunk_aad(
                        version=header.version, cipher_id=header.cipher_id,
                        file_id=header.file_id, index=index, total=header.total_chunks,
                        header_hash=header_hash, metadata_ct_hash=meta_hash,
                    )
                    block = aead.decrypt(chunk_nonce(header.nonce_prefix, index), ct, aad)
                    if len(block) != plain_len:
                        raise AuthenticationFailedError()
                    out.write(block)
                    h.update(block)
                    written += len(block)
                    if progress:
                        progress("decrypting", written, meta.size)
                if fh.read(1):
                    raise ContainerFormatError("Container has unexpected trailing data.")
                out.flush()
                os.fsync(out.fileno())
            if written != meta.size or not hashes_equal(h.hexdigest(), meta.sha256):
                raise IntegrityError("Restored plaintext does not match the authenticated hash.")
            final = unique_output_path(out_dir, safe_name)
            finalize_no_clobber(part, final)
            published = True
        finally:
            if not published:
                safe_unlink(part)
    return DecryptResult(header.file_id_hex, final, safe_name, meta.size, meta.sha256, meta.mime)
