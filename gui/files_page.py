"""My Files: local registry of encrypted uploads (plaintext names stay local)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.common import AppContext, confirm, human_size, page_header, warn
from workers.upload_worker import DeleteRemoteWorker, UploadWorker

COLUMNS = ["File ID", "Filename", "Encrypted Size", "Upload Date", "Status", "Server Path"]


class FilesPage(QWidget):
    download_requested = Signal(str)

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("My Files", "Local registry. Original filenames are stored only on this "
                                               "computer; the server sees random object names."))
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table)

        row = QHBoxLayout()
        buttons = [
            ("Download && Decrypt", self._download),
            ("Upload / Retry", self._upload),
            ("Copy File ID", self._copy),
            ("Delete Remote File", self._delete_remote),
            ("Remove Local Record", self._remove),
            ("Refresh", self.refresh),
        ]
        for text, fn in buttons:
            b = QPushButton(text)
            if "Delete" in text:
                b.setObjectName("danger")
            b.clicked.connect(fn)
            row.addWidget(b)
        lay.addLayout(row)
        ctx.files_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        records = self.ctx.service.list_files()
        self.table.setRowCount(len(records))
        for r, rec in enumerate(records):
            values = [rec.file_id, rec.original_filename, human_size(rec.encrypted_size),
                      rec.uploaded_at or "-", rec.status, rec.server_path or "-"]
            for c, v in enumerate(values):
                item = QTableWidgetItem(v)
                if c == 0:
                    item.setData(Qt.UserRole, rec.file_id)
                    item.setToolTip(rec.file_id)
                self.table.setItem(r, c, item)
        self.table.resizeColumnsToContents()

    def _selected(self) -> str | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            warn(self, "No selection", "Select a file first.")
            return None
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole)

    def _download(self) -> None:
        fid = self._selected()
        if fid:
            self.download_requested.emit(fid)

    def _upload(self) -> None:
        fid = self._selected()
        if not fid:
            return
        w = UploadWorker(self.ctx.service, fid)
        w.signals.finished.connect(lambda *_: self.ctx.files_changed.emit())
        w.signals.failed.connect(lambda m, c: (warn(self, "Upload failed", m), self.ctx.files_changed.emit()))
        self.ctx.start(w)

    def _copy(self) -> None:
        fid = self._selected()
        if fid:
            QGuiApplication.clipboard().setText(fid)

    def _delete_remote(self) -> None:
        fid = self._selected()
        if not fid or not confirm(self, "Delete remote file",
                                  f"Permanently delete the encrypted object {fid[:16]}… from the server?"):
            return
        w = DeleteRemoteWorker(self.ctx.service, fid)
        w.signals.finished.connect(lambda *_: self.ctx.files_changed.emit())
        w.signals.failed.connect(lambda m, c: warn(self, "Delete failed", m))
        self.ctx.start(w)

    def _remove(self) -> None:
        fid = self._selected()
        if not fid or not confirm(self, "Remove local record",
                                  "Remove this record (and any local encrypted copy)? The remote object is "
                                  "not deleted, but you will need the File ID to download it again."):
            return
        self.ctx.service.remove_record(fid)
        self.ctx.files_changed.emit()
