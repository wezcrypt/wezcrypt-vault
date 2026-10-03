"""Safe filesystem handling for hostile names and temporary files.

* Restored filenames come from decrypted metadata. Even authenticated metadata
  is treated as hostile: only a sanitized basename is ever used.
* Output files are created with O_EXCL (never overwrite, never follow an
  existing symlink) and finalized with a no-clobber hard link / rename.
* Temporary files get random names and 0600 permissions (POSIX). On Windows
  files inherit the ACL of the per-user application directory.

Secure deletion cannot be guaranteed on SSDs (wear levelling, TRIM),
copy-on-write or journaling filesystems; ``unlink`` only removes the name.
"""

from __future__ import annotations

import os
import secrets
import sys
import unicodedata
from pathlib import Path

from utils.errors import PathSafetyError

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
}
_FORBIDDEN_CHARS = set('<>:"/\\|?*')
MAX_NAME_BYTES = 200
DEFAULT_NAME = "restored_file"


def sanitize_filename(name: object) -> str:
    """Return a safe basename. Never contains separators, traversal or reserved names."""
    if not isinstance(name, str):
        return DEFAULT_NAME
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates / malformed Unicode
        return DEFAULT_NAME
    name = unicodedata.normalize("NFC", name)
    # Strip every directory component, whichever separator style was used.
    name = name.replace("\\", "/").split("/")[-1]
    cleaned = []
    for ch in name:
        cat = unicodedata.category(ch)
        if ch in _FORBIDDEN_CHARS or cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            cleaned.append("_")
        else:
            cleaned.append(ch)
    name = "".join(cleaned).strip(" .")
    if not name:
        return DEFAULT_NAME
    stem = name.split(".")[0]
    if stem.upper().rstrip(" ") in _WINDOWS_RESERVED:
        name = "_" + name
    name = _truncate_utf8(name, MAX_NAME_BYTES)
    if name in ("", ".", ".."):
        return DEFAULT_NAME
    return name


def _truncate_utf8(name: str, limit: int) -> str:
    if len(name.encode("utf-8")) <= limit:
        return name
    stem, dot, ext = name.rpartition(".")
    if not dot or len(ext.encode("utf-8")) > 20 or not stem:
        stem, ext, dot = name, "", ""
    budget = limit - len((dot + ext).encode("utf-8"))
    out = []
    used = 0
    for ch in stem:
        b = len(ch.encode("utf-8"))
        if used + b > budget:
            break
        out.append(ch)
        used += b
    result = ("".join(out).rstrip(" .") or "file") + dot + ext
    return result


def ensure_inside(base: Path, candidate: Path) -> Path:
    base_r = base.resolve(strict=True)
    cand_r = candidate.resolve(strict=False)
    if cand_r.parent != base_r:
        raise PathSafetyError("Refusing to write outside the selected output directory.")
    return cand_r


def unique_output_path(out_dir: Path, safe_name: str) -> Path:
    if not out_dir.is_dir():
        raise PathSafetyError("Output directory does not exist.")
    if safe_name != sanitize_filename(safe_name):
        raise PathSafetyError("Filename was not sanitized.")
    stem, dot, ext = safe_name.rpartition(".")
    if not dot or not stem:
        stem, dot, ext = safe_name, "", ""
    candidate = out_dir / safe_name
    n = 1
    while candidate.exists() or candidate.is_symlink():
        candidate = out_dir / f"{stem} ({n}){dot}{ext}"
        n += 1
        if n > 10000:
            raise PathSafetyError("Could not find a free output filename.")
    return ensure_inside(out_dir, candidate)


def create_private_file(path: Path) -> int:
    """Create a new file exclusively with 0600 permissions; never follows symlinks."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise PathSafetyError("Temporary file already exists; refusing to reuse it.") from exc


def random_temp_path(directory: Path, suffix: str) -> Path:
    return directory / f"{secrets.token_hex(16)}{suffix}"


def finalize_no_clobber(part: Path, final: Path) -> Path:
    """Atomically publish ``part`` as ``final`` without overwriting anything."""
    try:
        os.link(part, final)
    except FileExistsError as exc:
        raise PathSafetyError("Output file appeared concurrently; refusing to overwrite.") from exc
    except OSError:
        # Filesystems without hard links (FAT/exFAT). Windows rename never overwrites.
        if final.exists() or final.is_symlink():
            raise PathSafetyError("Output file already exists; refusing to overwrite.")
        os.rename(part, final)
        return final
    os.unlink(part)
    return final


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(path, 0o700)
    return path


def safe_unlink(path: Path) -> bool:
    """Remove a file name. NOTE: not a secure wipe (see module docstring)."""
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
