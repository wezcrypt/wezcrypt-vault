"""Per-user data layout and migration from the 1.0 layout.

Layout (mutable data never lives under Program Files)::

    <root>/
        data/     vault.db (file registry, trusted host keys, nonce reservations, profiles)
        config/   config.toml (non-secret preferences only)
        logs/     wezcrypt.log*
        cache/    disposable cache
        temp/     encrypted containers awaiting upload, partial downloads

<root> is:
    Windows  %LOCALAPPDATA%\\WezCryptVault
    macOS    ~/Library/Application Support/WezCryptVault
    Linux    $XDG_DATA_HOME/wezcrypt-vault (default ~/.local/share/wezcrypt-vault)
    any      $WEZCRYPT_HOME when set (tests, portable use)

Version 1.0 stored everything flat in %APPDATA%\\WezCryptVault (Windows) or
~/.config/wezcrypt-vault (Linux). ``migrate_legacy`` copies that state into
the new layout once, never overwriting existing new-layout files, and
rewrites temp-container paths stored in the database.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path

from security.paths import ensure_private_dir

APP_DIR_NAME = "WezCryptVault"
_DB_FILES = ("vault.db", "vault.db-wal", "vault.db-shm")


@dataclass(frozen=True)
class AppPaths:
    root: Path
    data: Path
    config: Path
    logs: Path
    cache: Path
    temp: Path

    @property
    def db_path(self) -> Path:
        return self.data / "vault.db"

    @property
    def config_file(self) -> Path:
        return self.config / "config.toml"

    @classmethod
    def from_root(cls, root: Path) -> "AppPaths":
        root = ensure_private_dir(Path(root))
        dirs = {name: ensure_private_dir(root / name) for name in ("data", "config", "logs", "cache", "temp")}
        return cls(root=root, **dirs)


def default_root() -> Path:
    override = os.environ.get("WEZCRYPT_HOME")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "wezcrypt-vault"


def legacy_roots() -> list[Path]:
    """Locations used by version 1.0 (flat layout)."""
    roots: list[Path] = []
    if os.environ.get("WEZCRYPT_HOME"):
        return roots  # explicit override: only the in-place flat layout is considered
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        roots.append(Path(appdata) / APP_DIR_NAME)
    elif sys.platform != "darwin":
        cfg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        roots.append(Path(cfg) / "wezcrypt-vault")
    return roots


def _copy_tree_no_overwrite(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    for item in src.rglob("*"):
        if item.is_symlink() or not item.is_file():
            continue
        target = dst / item.relative_to(src)
        if target.exists():
            continue
        ensure_private_dir(target.parent)
        shutil.copy2(item, target)


def _migrate_flat(src_root: Path, paths: AppPaths, *, move: bool) -> bool:
    """Bring a 1.0 flat layout at ``src_root`` into ``paths``. Returns True if anything migrated."""
    if not (src_root / "vault.db").is_file() and not (src_root / "config.toml").is_file():
        return False
    if paths.db_path.exists():
        return False  # new layout already in use: never overwrite user state
    transfer = os.replace if move else shutil.copy2
    for name in _DB_FILES:
        if (src_root / name).is_file():
            transfer(src_root / name, paths.data / name)
    if (src_root / "config.toml").is_file() and not paths.config_file.exists():
        transfer(src_root / "config.toml", paths.config_file)
    old_temp = src_root / "temp"
    if old_temp.is_dir() and old_temp.resolve() != paths.temp.resolve():
        _copy_tree_no_overwrite(old_temp, paths.temp)
        if move:
            shutil.rmtree(old_temp, ignore_errors=True)
    old_logs = src_root / "logs"
    if old_logs.is_dir() and old_logs.resolve() != paths.logs.resolve():
        _copy_tree_no_overwrite(old_logs, paths.logs)
    _rewrite_container_paths(paths.db_path, old_temp, paths.temp)
    (paths.data / ".migrated").write_text(f"migrated from {src_root}\n", encoding="utf-8")
    return True


def _rewrite_container_paths(db: Path, old_temp: Path, new_temp: Path) -> None:
    if not db.is_file():
        return
    conn = sqlite3.connect(str(db))
    try:
        has = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='files'"
        ).fetchone()
        if not has:
            return
        rows = conn.execute(
            "SELECT file_id, local_container_path FROM files WHERE local_container_path IS NOT NULL"
        ).fetchall()
        for fid, p in rows:
            name = Path(p).name
            if Path(p).parent == old_temp and (new_temp / name).exists():
                conn.execute("UPDATE files SET local_container_path=? WHERE file_id=?", (str(new_temp / name), fid))
        conn.commit()
    finally:
        conn.close()


def migrate_legacy(paths: AppPaths, extra_roots: list[Path] | None = None) -> Path | None:
    """Migrate 1.0 state into ``paths`` once. Returns the source root if migrated."""
    # Flat 1.0 layout inside the same root (macOS, WEZCRYPT_HOME): move in place.
    if _migrate_flat(paths.root, paths, move=True):
        return paths.root
    for legacy in (extra_roots if extra_roots is not None else legacy_roots()):
        if legacy.resolve() != paths.root.resolve() and _migrate_flat(legacy, paths, move=False):
            return legacy
    return None


def resolve_paths() -> AppPaths:
    paths = AppPaths.from_root(default_root())
    migrate_legacy(paths)
    return paths
