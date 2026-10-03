"""Encrypt & Upload page."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.common import AppContext, DropZone, ProgressPanel, human_size, page_header, warn
from workers.encrypt_worker import EncryptWorker

STAGES = ["Preparing", "Encrypting", "Uploading", "Verifying", "Complete"]
_STAGE_INDEX = {"preparing": 0, "hashing": 0, "encrypting": 1, "uploading": 2, "verifying": 3, "complete": 4}


class EncryptPage(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.path: Path | None = None
        self.worker: EncryptWorker | None = None
        self._uploading_seen = False

        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Encrypt & Upload", "Select or drop any file. It is encrypted on this "
                                                       "computer; only ciphertext leaves it."))
        self.drop = DropZone()
        self.drop.dropped.connect(self.set_file)
        lay.addWidget(self.drop)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        lay.addWidget(browse)

        form = QFormLayout()
        self.f = {}
        for name in ["Filename", "Size", "Type", "Destination", "Encryption Algorithm", "Chunk Size", "Key Fingerprint"]:
            lbl = QLabel("-")
            lbl.setWordWrap(True)
            form.addRow(name + ":", lbl)
            self.f[name] = lbl
        lay.addLayout(form)

        stages = QHBoxLayout()
        self.stage_lbls = []
        for s in STAGES:
            lbl = QLabel(f"○ {s}")
            lbl.setObjectName("subtitle")
            stages.addWidget(lbl)
            self.stage_lbls.append(lbl)
        lay.addLayout(stages)

        self.progress = ProgressPanel()
        lay.addWidget(self.progress)

        row = QHBoxLayout()
        self.go = QPushButton("Encrypt && Upload")
        self.go.setObjectName("primary")
        self.go.clicked.connect(lambda: self._start(upload=True))
        self.enc_only = QPushButton("Encrypt Only (upload later)")
        self.enc_only.clicked.connect(lambda: self._start(upload=False))
        self.cancel = QPushButton("Cancel")
        self.cancel.clicked.connect(self._cancel)
        self.cancel.setEnabled(False)
        row.addWidget(self.go)
        row.addWidget(self.enc_only)
        row.addWidget(self.cancel)
        lay.addLayout(row)
        lay.addStretch(1)

        ctx.key_changed.connect(self._refresh_static)
        ctx.config_changed.connect(self._refresh_static)
        ctx.profiles_changed.connect(self._refresh_static)
        self._refresh_static()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if path:
            self.set_file(path)

    def set_file(self, path: str) -> None:
        p = Path(path)
        if not p.is_file():
            warn(self, "Not a file", "Please choose a regular file.")
            return
        self.path = p
        self.f["Filename"].setText(p.name)
        self.f["Size"].setText(human_size(p.stat().st_size))
        self.f["Type"].setText(mimetypes.guess_type(p.name)[0] or "application/octet-stream")
        self._refresh_static()
        self.progress.reset()
        self.progress.stage.setText("Ready")
        self._mark_stage(-1)

    def _refresh_static(self) -> None:
        self.f["Destination"].setText(self.ctx.service.server_label())
        self.f["Encryption Algorithm"].setText("AES-256-GCM (unified master key, unique nonce per chunk)")
        self.f["Chunk Size"].setText(human_size(self.ctx.config.encryption.chunk_size))
        self.f["Key Fingerprint"].setText(
            self.ctx.master_key.info().display_fingerprint if self.ctx.master_key.is_loaded else "Locked"
        )
        idle = self.worker is None
        self.go.setEnabled(idle and self.path is not None)
        self.enc_only.setEnabled(idle and self.path is not None)

    def _mark_stage(self, idx: int) -> None:
        for i, lbl in enumerate(self.stage_lbls):
            lbl.setText(("● " if i <= idx else "○ ") + STAGES[i])

    def _start(self, upload: bool) -> None:
        if self.path is None:
            return
        if not self.ctx.master_key.is_loaded:
            warn(self, "Master key locked", "Unlock or import the master key on the Master Key page first.")
            return
        self.worker = EncryptWorker(self.ctx.service, self.path, upload=upload)
        self.worker.signals.progress.connect(self._on_progress)
        self.worker.signals.finished.connect(self._on_done)
        self.worker.signals.failed.connect(self._on_failed)
        self.progress.reset()
        self._uploading_seen = False
        self.cancel.setEnabled(True)
        self._refresh_static()
        self.ctx.start(self.worker)

    def _cancel(self) -> None:
        if self.worker is not None:
            self.worker.cancel()

    def _on_progress(self, stage: str, done: int, total: int) -> None:
        if stage == "uploading":
            self._uploading_seen = True
        idx = _STAGE_INDEX.get(stage, 0)
        if stage == "verifying" and not self._uploading_seen:
            idx = 1
        self._mark_stage(idx)
        self.progress.update_progress(stage, int(done), int(total))

    def _finish(self) -> None:
        self.worker = None
        self.cancel.setEnabled(False)
        self._refresh_static()
        self.ctx.files_changed.emit()

    def _on_done(self, result: object) -> None:
        upload = isinstance(result, tuple)
        self._mark_stage(4 if upload else 1)
        outcome = result[0] if upload else result
        self.progress.complete(f"Complete — File ID {outcome.result.file_id[:16]}…")
        self._finish()

    def _on_failed(self, message: str, category: str) -> None:
        self.progress.failed(message)
        self._finish()
        warn(self, "Operation failed", message)
