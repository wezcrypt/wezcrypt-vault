"""Local SQLite store (file registry, trusted host keys, operations journal).

Each call opens a short-lived connection so the class is safe to use from
Qt worker threads. WAL mode allows concurrent readers.
"""

from __future__ import annotations

import sqlite3
import sys
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from database.migrations import migrate


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class FileRecord:
    id: int
    file_id: str
    original_filename: str
    encrypted_filename: str
    original_size: int
    encrypted_size: int
    encrypted_hash: str
    created_at: str
    uploaded_at: str | None
    server_path: str | None
    status: str
    key_fingerprint: str
    local_container_path: str | None
    profile_id: int | None = None


@dataclass(frozen=True)
class Profile:
    id: int
    name: str
    backend: str
    host: str
    port: int
    username: str
    remote_path: str
    auth_method: str
    private_key_path: str
    https_base_url: str
    https_ca_bundle: str
    local_path: str
    connection_tested_at: str | None
    created_at: str
    updated_at: str

    @property
    def secret_ident(self) -> str:
        """Credential-store identifier; bound to the profile id, never the secret itself."""
        return f"profile:{self.id}"

    @property
    def label(self) -> str:
        if self.backend == "sftp":
            return f"sftp://{self.host}:{self.port}" if self.host else "Not configured"
        if self.backend == "https":
            return self.https_base_url or "Not configured"
        return f"local://{self.local_path}" if self.local_path else "Not configured"


PROFILE_FIELDS = (
    "name", "backend", "host", "port", "username", "remote_path", "auth_method",
    "private_key_path", "https_base_url", "https_ca_bundle", "local_path",
)


@dataclass(frozen=True)
class OperationRecord:
    id: int
    file_id: str
    kind: str
    status: str
    temp_path: str | None
    created_at: str
    updated_at: str
    error_category: str | None


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        new = not self.path.exists()
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            migrate(conn)
        if new and sys.platform != "win32":
            os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- files -----------------------------------------------------------
    def add_file(
        self, *, file_id: str, original_filename: str, encrypted_filename: str,
        original_size: int, encrypted_size: int, encrypted_hash: str,
        key_fingerprint: str, status: str, local_container_path: str | None,
        profile_id: int | None = None,
    ) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO files(file_id, original_filename, encrypted_filename, original_size,"
                " encrypted_size, encrypted_hash, created_at, status, key_fingerprint, local_container_path,"
                " profile_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (file_id, original_filename, encrypted_filename, original_size, encrypted_size,
                 encrypted_hash, utcnow(), status, key_fingerprint, local_container_path, profile_id),
            )

    def mark_uploaded(self, file_id: str, server_path: str, profile_id: int | None = None) -> None:
        with self.connect() as c:
            c.execute(
                "UPDATE files SET status='uploaded', uploaded_at=?, server_path=?,"
                " profile_id=COALESCE(?, profile_id) WHERE file_id=?",
                (utcnow(), server_path, profile_id, file_id),
            )

    def set_file_status(self, file_id: str, status: str) -> None:
        with self.connect() as c:
            c.execute("UPDATE files SET status=? WHERE file_id=?", (status, file_id))

    def set_local_container(self, file_id: str, path: str | None) -> None:
        with self.connect() as c:
            c.execute("UPDATE files SET local_container_path=? WHERE file_id=?", (path, file_id))

    def get_file(self, file_id: str) -> FileRecord | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM files WHERE file_id=?", (file_id,)).fetchone()
        return FileRecord(**dict(row)) if row else None

    def list_files(self) -> list[FileRecord]:
        with self.connect() as c:
            rows = c.execute("SELECT * FROM files ORDER BY id DESC").fetchall()
        return [FileRecord(**dict(r)) for r in rows]

    def remove_file(self, file_id: str) -> None:
        with self.connect() as c:
            c.execute("DELETE FROM files WHERE file_id=?", (file_id,))

    def stats(self) -> tuple[int, int]:
        with self.connect() as c:
            row = c.execute(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='uploaded' THEN encrypted_size END),0) FROM files"
            ).fetchone()
        return int(row[0]), int(row[1])

    def fingerprints_in_use(self) -> set[str]:
        with self.connect() as c:
            return {r[0] for r in c.execute("SELECT DISTINCT key_fingerprint FROM files")}

    # ---- trusted SSH host keys ------------------------------------------
    def get_host_key(self, host: str, port: int) -> tuple[str, str] | None:
        with self.connect() as c:
            row = c.execute(
                "SELECT key_type, host_key_fingerprint FROM servers WHERE host=? AND port=?", (host, port)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def trust_host_key(self, host: str, port: int, key_type: str, fingerprint: str) -> None:
        """Store a first-time trusted key. Never overwrites an existing different key."""
        existing = self.get_host_key(host, port)
        if existing is not None:
            if existing[1] != fingerprint:
                from utils.errors import HostKeyChangedError
                raise HostKeyChangedError(existing[1], fingerprint)
            return
        with self.connect() as c:
            c.execute(
                "INSERT INTO servers(host, port, key_type, host_key_fingerprint, trusted_at) VALUES (?,?,?,?,?)",
                (host, port, key_type, fingerprint, utcnow()),
            )

    def forget_host_key(self, host: str, port: int) -> None:
        """Explicit, user-initiated removal (Settings). Never called automatically."""
        with self.connect() as c:
            c.execute("DELETE FROM servers WHERE host=? AND port=?", (host, port))

    # ---- operations journal ----------------------------------------------
    def begin_operation(self, file_id: str, kind: str, temp_path: str | None) -> int:
        now = utcnow()
        with self.connect() as c:
            cur = c.execute(
                "INSERT INTO operations(file_id, kind, status, temp_path, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (file_id, kind, "running", temp_path, now, now),
            )
            return int(cur.lastrowid)

    def finish_operation(self, op_id: int, status: str, error_category: str | None = None) -> None:
        with self.connect() as c:
            c.execute(
                "UPDATE operations SET status=?, updated_at=?, error_category=? WHERE id=?",
                (status, utcnow(), error_category, op_id),
            )

    def update_operation_path(self, op_id: int, temp_path: str | None) -> None:
        with self.connect() as c:
            c.execute("UPDATE operations SET temp_path=?, updated_at=? WHERE id=?", (temp_path, utcnow(), op_id))

    def abandoned_operations(self) -> list[OperationRecord]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT * FROM operations WHERE status IN ('running','failed') ORDER BY id"
            ).fetchall()
        return [OperationRecord(**dict(r)) for r in rows]

    # ---- server profiles -------------------------------------------------------
    def list_profiles(self) -> list[Profile]:
        with self.connect() as c:
            rows = c.execute("SELECT * FROM profiles ORDER BY name COLLATE NOCASE").fetchall()
        return [Profile(**dict(r)) for r in rows]

    def get_profile(self, profile_id: int) -> Profile | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
        return Profile(**dict(row)) if row else None

    def insert_profile(self, values: dict[str, object]) -> int:
        cols = [k for k in PROFILE_FIELDS if k in values]
        now = utcnow()
        with self.connect() as c:
            cur = c.execute(
                f"INSERT INTO profiles({', '.join(cols)}, created_at, updated_at) "
                f"VALUES ({', '.join('?' for _ in cols)}, ?, ?)",
                (*[values[k] for k in cols], now, now),
            )
            return int(cur.lastrowid)

    def update_profile(self, profile_id: int, values: dict[str, object], *, reset_tested: bool) -> None:
        cols = [k for k in PROFILE_FIELDS if k in values]
        sets = ", ".join(f"{k}=?" for k in cols)
        extra = ", connection_tested_at=NULL" if reset_tested else ""
        with self.connect() as c:
            c.execute(
                f"UPDATE profiles SET {sets}, updated_at=?{extra} WHERE id=?",
                (*[values[k] for k in cols], utcnow(), profile_id),
            )

    def mark_profile_tested(self, profile_id: int) -> None:
        with self.connect() as c:
            c.execute("UPDATE profiles SET connection_tested_at=? WHERE id=?", (utcnow(), profile_id))

    def reset_profile_tested(self, profile_id: int) -> None:
        with self.connect() as c:
            c.execute("UPDATE profiles SET connection_tested_at=NULL WHERE id=?", (profile_id,))

    def delete_profile(self, profile_id: int) -> None:
        with self.connect() as c:
            c.execute("DELETE FROM profiles WHERE id=?", (profile_id,))

    def count_profiles_using(self, host: str, port: int, exclude_id: int | None = None) -> int:
        with self.connect() as c:
            row = c.execute(
                "SELECT COUNT(*) FROM profiles WHERE host=? AND port=? AND backend='sftp' AND id IS NOT ?",
                (host, port, exclude_id),
            ).fetchone()
        return int(row[0])

    # ---- settings -----------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO settings(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
