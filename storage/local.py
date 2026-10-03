"""Local / mounted-directory backend (NAS share, external drive, test fixture).

Uses the same verified resumable protocol as SFTP.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

from storage.base import StreamStorageBackend
from utils.errors import StorageError


class LocalDirectoryBackend(StreamStorageBackend):
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    @property
    def description(self) -> str:
        return f"local://{self.root}"

    def connect(self) -> None:
        if not self.root.is_dir():
            raise StorageError("Storage directory does not exist.")

    def close(self) -> None:
        return None

    def remote_path(self, name: str) -> str:
        return str(self.root / name)

    def _stat_size(self, path: str) -> int | None:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        return st.st_size

    def _open_read(self, path: str, offset: int) -> BinaryIO:
        fh = open(path, "rb")
        fh.seek(offset)
        return fh

    def _open_write(self, path: str, append: bool) -> BinaryIO:
        return open(path, "ab" if append else "wb")

    def _rename(self, src: str, dst: str) -> None:
        if os.path.exists(dst):
            raise StorageError("Destination object already exists.")
        os.replace(src, dst)

    def _remove(self, path: str) -> None:
        os.remove(path)
