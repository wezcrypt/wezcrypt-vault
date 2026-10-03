"""Encrypt (and optionally upload) a file in the background."""

from __future__ import annotations

from pathlib import Path

from services.vault import VaultService
from workers.common import TaskWorker


class EncryptWorker(TaskWorker):
    def __init__(self, service: VaultService, source: Path, *, upload: bool) -> None:
        self.source = Path(source)
        self.upload = upload

        def job(progress, cancel):
            if upload:
                return service.encrypt_and_upload(self.source, progress=progress, cancel=cancel)
            return service.encrypt(self.source, progress=progress, cancel=cancel)

        super().__init__(job, "encrypt_upload" if upload else "encrypt")
