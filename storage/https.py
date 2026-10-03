"""HTTPS object-store backend.

TLS certificate validation and hostname verification are always on
(``ssl.create_default_context``); there is no option to disable them. An
optional CA bundle path supports private PKI.

Expected server API (simple object store)::

    HEAD   {base}/objects/{name}   -> 200 + Content-Length | 404
    GET    {base}/objects/{name}   -> 200 / 206 with "Range: bytes=N-"
    PUT    {base}/objects/{name}   -> 201/200; body = full container;
                                      header X-Content-SHA256 = container hash
                                      (server should reject on mismatch)
    DELETE {base}/objects/{name}   -> 204/200

Authentication: ``Authorization: Bearer <token>`` loaded from the OS
credential store. Uploads over HTTPS restart from zero if interrupted
(remote completion is verified by size, and by read-back hash by default).
"""

from __future__ import annotations

import hashlib
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from crypto.hashing import hashes_equal
from security import credentials
from storage.base import BLOCK, StorageBackend, TransferProgress, UploadResult, check_object_name
from utils.errors import (
    ConfigError,
    NetworkInterruptedError,
    OperationCancelled,
    RemoteNotFoundError,
    StorageError,
    UploadVerificationError,
)


def make_tls_context(ca_bundle: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_bundle or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not ctx.check_hostname or ctx.verify_mode != ssl.CERT_REQUIRED:
        raise ConfigError("TLS verification must be enabled.")
    return ctx


class _ProgressReader:
    def __init__(self, fh: BinaryIO, total: int, progress: TransferProgress | None, cancel: threading.Event | None):
        self.fh, self.total, self.progress, self.cancel, self.sent = fh, total, progress, cancel, 0

    def __iter__(self) -> Iterator[bytes]:
        while True:
            if self.cancel is not None and self.cancel.is_set():
                raise OperationCancelled()
            block = self.fh.read(BLOCK)
            if not block:
                return
            self.sent += len(block)
            if self.progress:
                self.progress(self.sent, self.total)
            yield block


class HTTPSBackend(StorageBackend):
    def __init__(
        self, base_url: str, *, ca_bundle: str = "", timeout: int = 30,
        token_provider: Callable[[], str | None] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigError("HTTPS backend requires an https:// URL.")
        self.base = base_url.rstrip("/")
        self.host = parsed.hostname
        self.timeout = timeout
        self.ctx = make_tls_context(ca_bundle)
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx))
        self._token = token_provider or (lambda: credentials.get_secret("https-token", self.base))

    @property
    def description(self) -> str:
        return f"https://{self.host}"

    def connect(self) -> None:
        return None

    def close(self) -> None:
        return None

    def remote_path(self, name: str) -> str:
        return f"{self.base}/objects/{urllib.parse.quote(check_object_name(name))}"

    def _request(self, method: str, url: str, data: object = None, headers: dict[str, str] | None = None):
        req = urllib.request.Request(url, data=data, method=method)  # type: ignore[arg-type]
        token = self._token()
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            return self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RemoteNotFoundError("Encrypted object not found on the server.") from exc
            raise StorageError(f"Server returned HTTP {exc.code}.") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise NetworkInterruptedError("HTTPS connection failed or was interrupted.") from exc

    def size(self, name: str) -> int | None:
        try:
            with self._request("HEAD", self.remote_path(name)) as resp:
                return int(resp.headers.get("Content-Length", "-1"))
        except RemoteNotFoundError:
            return None

    def _remote_sha256(self, name: str, cancel: threading.Event | None) -> str:
        h = hashlib.sha256()
        with self._request("GET", self.remote_path(name)) as resp:
            while True:
                if cancel is not None and cancel.is_set():
                    raise OperationCancelled()
                block = resp.read(BLOCK)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()

    def upload(
        self, local: Path, name: str, expected_sha256: str, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
        verify_readback: bool = True,
    ) -> UploadResult:
        total = local.stat().st_size
        url = self.remote_path(name)
        existing = self.size(name)
        if existing is not None:
            if existing == total and hashes_equal(self._remote_sha256(name, cancel), expected_sha256):
                return UploadResult(url, total, total, True)
            raise UploadVerificationError("A different object with this File ID already exists remotely.")
        with local.open("rb") as fh:
            body = _ProgressReader(fh, total, progress, cancel)
            headers = {
                "Content-Length": str(total),
                "Content-Type": "application/octet-stream",
                "X-Content-SHA256": expected_sha256,
            }
            with self._request("PUT", url, data=iter(body), headers=headers) as resp:
                if resp.status not in (200, 201, 204):
                    raise UploadVerificationError(f"Unexpected upload status {resp.status}.")
        if self.size(name) != total:
            raise UploadVerificationError("Remote size does not match the encrypted container.")
        if verify_readback and not hashes_equal(self._remote_sha256(name, cancel), expected_sha256):
            raise UploadVerificationError("Remote SHA-256 does not match the encrypted container.")
        return UploadResult(url, total, 0, False)

    def download(
        self, name: str, local_part: Path, *,
        progress: TransferProgress | None = None, cancel: threading.Event | None = None,
    ) -> int:
        total = self.size(name)
        if total is None:
            raise RemoteNotFoundError("Encrypted object not found on the server.")
        offset = local_part.stat().st_size if local_part.exists() else 0
        if offset > total:
            local_part.unlink()
            offset = 0
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        with self._request("GET", self.remote_path(name), headers=headers) as resp:
            if offset and resp.status != 206:
                offset = 0  # server ignored Range: restart cleanly
            got = offset
            with local_part.open("ab" if offset else "wb") as dst:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise OperationCancelled()
                    block = resp.read(BLOCK)
                    if not block:
                        break
                    dst.write(block)
                    got += len(block)
                    if progress:
                        progress(got, total)
        if got != total:
            raise NetworkInterruptedError("Download ended early.")
        return total

    def delete(self, name: str) -> None:
        with self._request("DELETE", self.remote_path(name)) as resp:
            if resp.status not in (200, 202, 204):
                raise StorageError(f"Unexpected delete status {resp.status}.")
