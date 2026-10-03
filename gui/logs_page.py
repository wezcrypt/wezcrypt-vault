"""Logs: live view of privacy-safe structured log lines."""

from __future__ import annotations

from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from gui.common import AppContext, page_header
from utils.logging import add_listener, recent_lines


class _Bridge(QObject):
    line = Signal(str)


class LogsPage(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Logs", "Structured logs never contain keys, plaintext, passwords or tokens. "
                                           "Filenames are excluded while privacy logging is on."))
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(5000)
        self.view.setStyleSheet("font-family: Consolas, 'Cascadia Mono', monospace; font-size: 9pt;")
        lay.addWidget(self.view)
        row = QHBoxLayout()
        clear = QPushButton("Clear View")
        clear.clicked.connect(self.view.clear)
        folder = QPushButton("Open Log Folder")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ctx.home / "logs"))))
        row.addWidget(clear)
        row.addWidget(folder)
        row.addStretch(1)
        lay.addLayout(row)
        for line in recent_lines():
            self.view.appendPlainText(line)
        self._bridge = _Bridge()
        self._bridge.line.connect(self.view.appendPlainText)  # queued: safe from worker threads
        add_listener(self._bridge.line.emit)
