"""Schema migrations, tracked with ``PRAGMA user_version``.

No table ever stores the master key, passwords, passphrases or tokens.
"""

from __future__ import annotations

import sqlite3

MIGRATIONS: list[str] = [
    # v1
    """
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL UNIQUE,
        original_filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        original_size INTEGER NOT NULL,
        encrypted_size INTEGER NOT NULL,
        encrypted_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        uploaded_at TEXT,
        server_path TEXT,
        status TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        local_container_path TEXT
    );
    CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        key_type TEXT NOT NULL,
        host_key_fingerprint TEXT NOT NULL,
        trusted_at TEXT NOT NULL,
        UNIQUE(host, port)
    );
    CREATE TABLE IF NOT EXISTS used_nonces (
        nonce_hash TEXT PRIMARY KEY NOT NULL,
        created_at TEXT NOT NULL,
        file_id TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS operations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        temp_path TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        error_category TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_operations_status ON operations(status);
    """,
    # v2 (1.1.0): server profiles. Secrets are NOT stored here (OS credential store only).
    """
    CREATE TABLE IF NOT EXISTS profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        backend TEXT NOT NULL DEFAULT 'sftp',
        host TEXT NOT NULL DEFAULT '',
        port INTEGER NOT NULL DEFAULT 22,
        username TEXT NOT NULL DEFAULT '',
        remote_path TEXT NOT NULL DEFAULT '/storage/encrypted/',
        auth_method TEXT NOT NULL DEFAULT 'key',
        private_key_path TEXT NOT NULL DEFAULT '',
        https_base_url TEXT NOT NULL DEFAULT '',
        https_ca_bundle TEXT NOT NULL DEFAULT '',
        local_path TEXT NOT NULL DEFAULT '',
        connection_tested_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    ALTER TABLE files ADD COLUMN profile_id INTEGER;
    """,
]


def migrate(conn: sqlite3.Connection) -> int:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in range(current, len(MIGRATIONS)):
        conn.executescript("BEGIN;" + MIGRATIONS[version] + f"PRAGMA user_version = {version + 1}; COMMIT;")
    return len(MIGRATIONS)
