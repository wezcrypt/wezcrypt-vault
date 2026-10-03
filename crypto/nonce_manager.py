"""Persistent nonce reservation.

WHY THIS EXISTS: the same AES-256 master key encrypts every file. In AES-GCM,
encrypting two messages under the same (key, nonce) pair is catastrophic:
an attacker learns P1 XOR P2 and can recover the GHASH authentication key,
which enables forging arbitrary ciphertexts. Probability alone is not
accepted as protection here.

Design:

1. A fresh 64-bit nonce prefix is drawn from ``os.urandom`` for each file.
2. Inside a SQLite ``BEGIN IMMEDIATE`` transaction (an exclusive write lock
   shared by threads, processes and multiple windows using the same database)
   the prefix hash is checked against ``used_nonces``.
3. A collision discards the candidate and draws again (bounded attempts).
4. The accepted prefix hash is committed BEFORE any encryption starts.
5. Each committed prefix owns the nonce space ``prefix || 0..2^32-1``
   (see ``crypto.chunks``), so recording the prefix records every nonce the
   file will use.

Reservations are never deleted, even if encryption later fails, so a nonce
prefix can never be handed out twice. If the database cannot be written,
encryption stops (``NonceReuseError``).

Limitation: the database protects one installation. Two machines sharing the
key keep independent databases; between them, uniqueness relies on 64 random
bits per file (collision probability ~ n^2 / 2^65 for n files in total).
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from crypto.chunks import NONCE_PREFIX_LEN
from utils.errors import NonceReuseError

_NONCE_HASH_DOMAIN = b"wezcrypt-nonce-prefix-v1\x00"
MAX_ATTEMPTS = 16

RandomSource = Callable[[int], bytes]


def nonce_hash(prefix: bytes) -> str:
    return hashlib.sha256(_NONCE_HASH_DOMAIN + prefix).hexdigest()


def generate_nonce() -> bytes:
    """A standalone random 96-bit nonce (used by stress tests and tooling)."""
    return os.urandom(12)


@dataclass(frozen=True)
class NonceReservation:
    """Proof that a prefix was durably reserved for ``file_id``.

    Only ``NonceManager.reserve`` creates these; the container encryptor
    refuses to run without one.
    """

    file_id: bytes
    prefix: bytes
    nonce_hash: str
    _token: object


_TOKEN = object()


class NonceManager:
    def __init__(self, db_path: str | Path, random_source: RandomSource = os.urandom) -> None:
        self._db_path = str(db_path)
        self._random = random_source
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS used_nonces ("
                " nonce_hash TEXT PRIMARY KEY NOT NULL,"
                " created_at TEXT NOT NULL,"
                " file_id TEXT NOT NULL)"
            )
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def is_used(self, prefix: bytes) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM used_nonces WHERE nonce_hash = ?", (nonce_hash(prefix),)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def count(self) -> int:
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM used_nonces").fetchone()[0])
        finally:
            conn.close()

    def record_external(self, prefix: bytes, file_id_hex: str) -> None:
        """Record a prefix seen elsewhere (e.g. decrypted/imported container) so it is never reused."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO used_nonces(nonce_hash, created_at, file_id) VALUES (?, ?, ?)",
                (nonce_hash(prefix), _now(), file_id_hex),
            )
        finally:
            conn.close()

    def reserve(self, file_id: bytes) -> NonceReservation:
        if len(file_id) != 32:
            raise NonceReuseError("File ID must be 32 bytes.")
        try:
            conn = self._connect()
        except sqlite3.Error as exc:
            raise NonceReuseError("Nonce database unavailable. Encryption stopped.") from exc
        try:
            for _ in range(MAX_ATTEMPTS):
                prefix = self._random(NONCE_PREFIX_LEN)
                if not isinstance(prefix, bytes) or len(prefix) != NONCE_PREFIX_LEN:
                    raise NonceReuseError("Random source returned an invalid nonce prefix.")
                h = nonce_hash(prefix)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    exists = conn.execute(
                        "SELECT 1 FROM used_nonces WHERE nonce_hash = ?", (h,)
                    ).fetchone()
                    if exists:
                        conn.execute("ROLLBACK")
                        continue  # collision: discard and draw a new prefix
                    conn.execute(
                        "INSERT INTO used_nonces(nonce_hash, created_at, file_id) VALUES (?, ?, ?)",
                        (h, _now(), file_id.hex()),
                    )
                    conn.execute("COMMIT")
                except sqlite3.IntegrityError:
                    conn.execute("ROLLBACK")
                    continue
                except sqlite3.Error as exc:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise NonceReuseError(
                        "Could not durably reserve a nonce. Encryption stopped."
                    ) from exc
                return NonceReservation(file_id, prefix, h, _TOKEN)
            raise NonceReuseError(
                "Repeated nonce collisions detected; the random source is not trustworthy. "
                "Encryption stopped."
            )
        finally:
            conn.close()


_consumed: set[str] = set()
_consumed_lock = threading.Lock()


def consume_reservation(res: NonceReservation, file_id: bytes) -> bytes:
    """Validate a reservation and mark it used. A reservation works exactly once."""
    if not isinstance(res, NonceReservation) or res._token is not _TOKEN:
        raise NonceReuseError("Encryption requires a nonce reservation from NonceManager.")
    if res.file_id != file_id:
        raise NonceReuseError("Nonce reservation belongs to a different file. Encryption stopped.")
    if len(res.prefix) != NONCE_PREFIX_LEN or nonce_hash(res.prefix) != res.nonce_hash:
        raise NonceReuseError("Corrupt nonce reservation. Encryption stopped.")
    with _consumed_lock:
        if res.nonce_hash in _consumed:
            raise NonceReuseError("Nonce reservation already used. Encryption stopped.")
        _consumed.add(res.nonce_hash)
    return res.prefix


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
