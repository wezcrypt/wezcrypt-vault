"""Dashboard: vault statistics, key status and quick actions."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from gui.common import AppContext, DropZone, StatCard, human_size, page_header


class DashboardPage(QWidget):
    navigate = Signal(str)          # page name
    file_chosen = Signal(str)       # local path to encrypt
    decrypt_local_requested = Signal()

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Dashboard", "Files are encrypted locally with AES-256-GCM before upload. "
                                               "The server never receives plaintext or the master key."))
        grid = QGridLayout()
        self.c_files = StatCard("Encrypted Files")
        self.c_storage = StatCard("Uploaded Storage")
        self.c_server = StatCard("Current Server")
        self.c_alg = StatCard("Encryption")
        self.c_key = StatCard("Master Key")
        self.c_fp = StatCard("Key Fingerprint")
        for i, c in enumerate([self.c_files, self.c_storage, self.c_server, self.c_alg, self.c_key, self.c_fp]):
            grid.addWidget(c, i // 3, i % 3)
        lay.addLayout(grid)

        actions = QHBoxLayout()
        b_add = QPushButton("Add File")
        b_enc = QPushButton("Encrypt && Upload")
        b_enc.setObjectName("primary")
        b_dl = QPushButton("Download File")
        b_dec = QPushButton("Decrypt Local File")
        b_add.clicked.connect(self._browse)
        b_enc.clicked.connect(lambda: self.navigate.emit("encrypt"))
        b_dl.clicked.connect(lambda: self.navigate.emit("decrypt"))
        b_dec.clicked.connect(self.decrypt_local_requested.emit)
        for b in (b_add, b_enc, b_dl, b_dec):
            actions.addWidget(b)
        lay.addLayout(actions)

        drop = DropZone("Drop any file here to encrypt and upload it")
        drop.dropped.connect(self.file_chosen.emit)
        lay.addWidget(drop)
        lay.addStretch(1)

        ctx.key_changed.connect(self.refresh)
        ctx.files_changed.connect(self.refresh)
        ctx.config_changed.connect(self.refresh)
        ctx.profiles_changed.connect(self.refresh)
        self.refresh()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if path:
            self.file_chosen.emit(path)

    def refresh(self) -> None:
        count, stored = self.ctx.service.db.stats()
        self.c_files.set(str(count))
        self.c_storage.set(human_size(stored))
        self.c_server.set(self.ctx.service.server_label())
        self.c_alg.set("AES-256-GCM")
        if self.ctx.master_key.is_loaded:
            self.c_key.set("Loaded", "ok")
            self.c_fp.set(self.ctx.master_key.info().display_fingerprint)
        else:
            self.c_key.set("Locked", "bad")
            self.c_fp.set("-")
