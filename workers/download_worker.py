"""Download-and-decrypt by File ID, or decrypt a local .wezenc container."""

from __future__ import annotations

from pathlib import Path

from services.vault import VaultService
from workers.common import TaskWorker


class DownloadDecryptWorker(TaskWorker):
    def __init__(self, service: VaultService, file_id: str, out_dir: Path) -> None:
        super().__init__(
            lambda progress, cancel: service.download_and_decrypt(
                file_id, Path(out_dir), progress=progress, cancel=cancel
            ),
            "download_decrypt",
        )


class LocalDecryptWorker(TaskWorker):
    def __init__(self, service: VaultService, container: Path, out_dir: Path) -> None:
        super().__init__(
            lambda progress, cancel: service.decrypt_local(
                Path(container), Path(out_dir), progress=progress, cancel=cancel
            ),
            "decrypt_local",
        )
