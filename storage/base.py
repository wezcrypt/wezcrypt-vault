"""Storage abstraction. Backends only ever receive encrypted containers.

``StorageBackend`` is the interface the application uses.
``StreamStorageBackend`` implements verified, resumable upload/download on
top of five small file primitives, shared by the SFTP and local-directory
backends.

Upload protocol (crash-safe on the server too):

1. Data is written to ``<file-id>.wezenc.part``.
2. Resume happens only after the existing remote ``.part`` prefix is read
   back and its SHA-256 matches the same prefix of the local container
   (File ID, size and offset are implied by the object name and checked).
3. After the last byte, the remote size is checked and (by default) the
   whole remote object is read back and its SHA-256 compared.
4. Only then is ``.part`` renamed to ``<file-id>.wezenc``.
"""

from __future__ import annotations

import hashlib
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from crypto.hashing import hashes_equal
from security.validators import CONTAINER_EXT, validate_file_id
from utils.errors import (
    NetworkInterruptedError,
    OperationCancelled,
    RemoteNotFoundError,
    UploadVerificationError,
    ValidationError,
)

BLOCK = 256 * 1024
TransferProgress = Callable[[int, int], None]


@dataclass(frozen=True)
class UploadResult:
    remote_path: str
    size: int
    resumed_from: int
    already_present: bool


def check_object_name(name: str) -> str:
    if not name.endswith(CONTAINER_EXT):
        raise ValidationError("Remote object names must be <file-id>.wezenc")
    stem = name[: -len(CONTAINER_EXT)]
    if validate_file_id(stem) != stem:
        raise ValidationError("Remote object names must be lowercase hex File IDs.")
    return name


class StorageBackend(ABC):
    """Interface used by the application. Never receives keys or plaintext."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Non-secret label for logs/UI, e.g. ``sftp://host:22``."""

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    @abstractmethod
    def remote_path(self, name: str) -> str: ...

    @abstractmethod
    def size(self, name: str) -> int | None: ...

    @abstractmethod
    def upload(
        self, local: Path, name: str, expected_sha256: str, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
        verify_readback: bool = True,
    ) -> UploadResult: ...

    @abstractmethod
    def download(
        self, name: str, local_part: Path, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
    ) -> int: ...

    @abstractmethod
    def delete(self, name: str) -> None: ...

    def __enter__(self) -> "StorageBackend":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class StreamStorageBackend(StorageBackend):
    """Resumable, verified transfers over simple file primitives."""

    transient_errors: tuple[type[BaseException], ...] = (OSError, EOFError)

    @abstractmethod
    def _stat_size(self, path: str) -> int | None: ...

    @abstractmethod
    def _open_read(self, path: str, offset: int) -> BinaryIO: ...

    @abstractmethod
    def _open_write(self, path: str, append: bool) -> BinaryIO: ...

    @abstractmethod
    def _rename(self, src: str, dst: str) -> None: ...

    @abstractmethod
    def _remove(self, path: str) -> None: ...

    # -- helpers --------------------------------------------------------------
    def size(self, name: str) -> int | None:
        check_object_name(name)
        return self._wrap(lambda: self._stat_size(self.remote_path(name)))

    def _wrap(self, fn: Callable[[], object]) -> object:
        try:
            return fn()
        except self.transient_errors as exc:
            raise NetworkInterruptedError(f"Connection to storage interrupted: {type(exc).__name__}") from exc

    def _remote_sha256(self, path: str, length: int, cancel: threading.Event | None) -> str:
        h = hashlib.sha256()
        remaining = length
        with self._open_read(path, 0) as fh:
            while remaining > 0:
                if cancel is not None and cancel.is_set():
                    raise OperationCancelled()
                block = fh.read(min(BLOCK, remaining))
                if not block:
                    break
                h.update(block)
                remaining -= len(block)
        if remaining:
            raise UploadVerificationError("Remote object is shorter than expected.")
        return h.hexdigest()

    @staticmethod
    def _local_prefix_sha256(local: Path, length: int) -> str:
        h = hashlib.sha256()
        remaining = length
        with local.open("rb") as fh:
            while remaining > 0:
                block = fh.read(min(BLOCK, remaining))
                if not block:
                    break
                h.update(block)
                remaining -= len(block)
        return h.hexdigest()

    # -- upload -----------------------------------------------------------------
    def upload(
        self, local: Path, name: str, expected_sha256: str, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
        verify_readback: bool = True,
    ) -> UploadResult:
        check_object_name(name)
        return self._wrap(lambda: self._upload(local, name, expected_sha256, progress, cancel, verify_readback))  # type: ignore[return-value]

    def _upload(
        self, local: Path, name: str, expected_sha256: str,
        progress: TransferProgress | None, cancel: threading.Event | None, verify_readback: bool,
    ) -> UploadResult:
        total = local.stat().st_size
        final = self.remote_path(name)
        part = final + ".part"

        existing = self._stat_size(final)
        if existing is not None:
            if existing == total and hashes_equal(self._remote_sha256(final, total, cancel), expected_sha256):
                return UploadResult(final, total, total, True)
            raise UploadVerificationError(
                "A different object with this File ID already exists remotely; refusing to overwrite."
            )

        offset = 0
        rsize = self._stat_size(part)
        if rsize is not None:
            if 0 < rsize <= total and hashes_equal(
                self._remote_sha256(part, rsize, cancel), self._local_prefix_sha256(local, rsize)
            ):
                offset = rsize  # verified resume point
            else:
                self._remove(part)  # unverifiable partial data is discarded, never trusted

        sent = offset
        with local.open("rb") as src, self._open_write(part, append=offset > 0) as dst:
            src.seek(offset)
            while True:
                if cancel is not None and cancel.is_set():
                    raise OperationCancelled()
                block = src.read(BLOCK)
                if not block:
                    break
                dst.write(block)
                sent += len(block)
                if progress:
                    progress(sent, total)

        rsize = self._stat_size(part)
        if rsize != total:
            raise UploadVerificationError("Remote size does not match the encrypted container.")
        if verify_readback and not hashes_equal(self._remote_sha256(part, total, cancel), expected_sha256):
            self._remove(part)
            raise UploadVerificationError("Remote SHA-256 does not match the encrypted container.")
        self._rename(part, final)
        return UploadResult(final, total, offset, False)

    # -- download ---------------------------------------------------------------
    def download(
        self, name: str, local_part: Path, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
    ) -> int:
        """Download into ``local_part``, resuming an existing partial file.

        Resumed downloads are only accepted after the caller verifies the
        full SHA-256 against the registry and/or AES-GCM authentication.
        """
        check_object_name(name)
        return self._wrap(lambda: self._download(name, local_part, progress, cancel))  # type: ignore[return-value]

    def _download(
        self, name: str, local_part: Path, progress: TransferProgress | None, cancel: threading.Event | None,
    ) -> int:
        path = self.remote_path(name)
        total = self._stat_size(path)
        if total is None:
            raise RemoteNotFoundError("Encrypted object not found on the server.")
        offset = local_part.stat().st_size if local_part.exists() else 0
        if offset > total:
            local_part.unlink()
            offset = 0
        got = offset
        with self._open_read(path, offset) as src, local_part.open("ab" if offset else "wb") as dst:
            while got < total:
                if cancel is not None and cancel.is_set():
                    raise OperationCancelled()
                block = src.read(min(BLOCK, total - got))
                if not block:
                    raise NetworkInterruptedError("Download ended early.")
                dst.write(block)
                got += len(block)
                if progress:
                    progress(got, total)
        return total

    def delete(self, name: str) -> None:
        check_object_name(name)
        path = self.remote_path(name)
        if self._wrap(lambda: self._stat_size(path)) is None:
            raise RemoteNotFoundError("Encrypted object not found on the server.")
        self._wrap(lambda: self._remove(path))
