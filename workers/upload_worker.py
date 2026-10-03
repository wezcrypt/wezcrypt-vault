"""Upload an already-encrypted container (new upload or crash-recovery resume)."""

from __future__ import annotations

from services.vault import RecoveryItem, VaultService
from workers.common import TaskWorker


class UploadWorker(TaskWorker):
    def __init__(self, service: VaultService, file_id: str) -> None:
        super().__init__(
            lambda progress, cancel: service.upload(file_id, progress=progress, cancel=cancel), "upload"
        )


class ResumeUploadWorker(TaskWorker):
    def __init__(self, service: VaultService, item: RecoveryItem) -> None:
        super().__init__(
            lambda progress, cancel: service.resume_upload(item, progress=progress, cancel=cancel), "resume_upload"
        )


class DeleteRemoteWorker(TaskWorker):
    def __init__(self, service: VaultService, file_id: str) -> None:
        super().__init__(lambda progress, cancel: service.delete_remote(file_id), "delete_remote")
