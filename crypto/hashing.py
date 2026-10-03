"""SHA-256 helpers (streaming, never loads whole files into RAM)."""

from __future__ import annotations

import hashlib
import hmac
import threading
from pathlib import Path
from typing import BinaryIO, Callable

from utils.errors import OperationCancelled

READ_BLOCK = 1024 * 1024
ProgressFn = Callable[[int, int], None]


def sha256_stream(
    fh: BinaryIO,
    *,
    limit: int | None = None,
    progress: ProgressFn | None = None,
    total: int = 0,
    cancel: threading.Event | None = None,
) -> tuple[str, int]:
    """Hash up to ``limit`` bytes from ``fh``. Returns (hex digest, bytes read)."""
    h = hashlib.sha256()
    done = 0
    while limit is None or done < limit:
        if cancel is not None and cancel.is_set():
            raise OperationCancelled()
        want = READ_BLOCK if limit is None else min(READ_BLOCK, limit - done)
        block = fh.read(want)
        if not block:
            break
        h.update(block)
        done += len(block)
        if progress:
            progress(done, total)
    return h.hexdigest(), done


def sha256_file(
    path: str | Path,
    *,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
) -> tuple[str, int]:
    p = Path(path)
    total = p.stat().st_size
    with p.open("rb") as fh:
        return sha256_stream(fh, progress=progress, total=total, cancel=cancel)


def hashes_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower().encode("ascii"), b.lower().encode("ascii"))
