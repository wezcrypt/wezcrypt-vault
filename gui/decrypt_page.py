"""Download & Decrypt page (by File ID) and local .wezenc decryption."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QStandardPaths
from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from crypto.container import read_header
from gui.common import AppContext, ProgressPanel, page_header, warn
from security.validators import validate_file_id
from utils.errors import WezCryptError
from workers.download_worker import DownloadDecryptWorker, LocalDecryptWorker

STEPS = ["Download encrypted file", "Verify encrypted SHA-256", "Load master key", "Verify key fingerprint",
         "Authenticate container", "Decrypt locally", "Restore original filename"]


class DecryptPage(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.worker = None
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Download & Decrypt", "Decryption happens only on this computer. "
                                                         "Any tampering or a wrong key aborts with no output."))

        g1 = QGroupBox("From server (File ID)")
        l1 = QHBoxLayout(g1)
        self.file_id = QLineEdit()
        self.file_id.setPlaceholderText("64-character File ID")
        l1.addWidget(self.file_id)
        lay.addWidget(g1)

        g2 = QGroupBox("Or local encrypted file")
        l2 = QHBoxLayout(g2)
        self.local = QLineEdit()
        self.local.setPlaceholderText("Select a .wezenc file")
        b = QPushButton("Select .wezenc…")
        b.clicked.connect(self.choose_local)
        l2.addWidget(self.local)
        l2.addWidget(b)
        lay.addWidget(g2)

        g3 = QGroupBox("Output folder")
        l3 = QHBoxLayout(g3)
        self.out = QLineEdit(QStandardPaths.writableLocation(QStandardPaths.DownloadLocation))
        bo = QPushButton("Choose…")
        bo.clicked.connect(self._choose_out)
        l3.addWidget(self.out)
        l3.addWidget(bo)
        lay.addWidget(g3)

        self.steps = QLabel("  →  ".join(STEPS))
        self.steps.setObjectName("subtitle")
        self.steps.setWordWrap(True)
        lay.addWidget(self.steps)
        self.progress = ProgressPanel()
        lay.addWidget(self.progress)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        lay.addWidget(self.result)

        row = QHBoxLayout()
        self.go = QPushButton("Download && Decrypt")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self._start)
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(lambda: self.worker and self.worker.cancel())
        row.addWidget(self.go)
        row.addWidget(self.cancel)
        lay.addLayout(row)
        lay.addStretch(1)

    def set_file_id(self, fid: str) -> None:
        self.file_id.setText(fid)
        self.local.clear()

    def choose_local(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select encrypted file", "", "WezCrypt containers (*.wezenc);;All files (*)")
        if path:
            self.local.setText(path)
            self.file_id.clear()

    def _choose_out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose output folder", self.out.text())
        if d:
            self.out.setText(d)

    def _start(self) -> None:
        if not self.ctx.master_key.is_loaded:
            warn(self, "Master key locked", "Unlock or import the master key first.")
            return
        out = Path(self.out.text())
        if not out.is_dir():
            warn(self, "Output folder", "Choose an existing output folder.")
            return
        try:
            if self.local.text().strip():
                container = Path(self.local.text().strip())
                header = read_header(container)  # quick validation + fingerprint pre-check
                if header.key_fingerprint != self.ctx.master_key.info().fingerprint:
                    warn(self, "Different key", "This file appears to use a different master key.")
                    return
                self.worker = LocalDecryptWorker(self.ctx.service, container, out)
            else:
                fid = validate_file_id(self.file_id.text())
                self.worker = DownloadDecryptWorker(self.ctx.service, fid, out)
        except (WezCryptError, OSError) as exc:
            warn(self, "Cannot start", str(exc))
            return
        self.worker.signals.progress.connect(lambda s, d, t: self.progress.update_progress(s, int(d), int(t)))
        self.worker.signals.finished.connect(self._done)
        self.worker.signals.failed.connect(self._failed)
        self.progress.reset()
        self.result.clear()
        self.go.setEnabled(False)
        self.cancel.setEnabled(True)
        self.ctx.start(self.worker)

    def _reset(self) -> None:
        self.worker = None
        self.go.setEnabled(True)
        self.cancel.setEnabled(False)

    def _done(self, r: object) -> None:
        self._reset()
        self.progress.complete()
        self.result.setObjectName("ok")
        self.result.setText(f"Authenticated and restored: {r.output_path}")
        self.result.style().polish(self.result)

    def _failed(self, message: str, category: str) -> None:
        self._reset()
        self.progress.failed(message)
        self.result.setObjectName("bad")
        self.result.setText(message)
        self.result.style().polish(self.result)
        warn(self, "Decryption aborted", message)
