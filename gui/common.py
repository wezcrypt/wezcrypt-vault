"""Shared GUI pieces: application context, theme, and reusable widgets."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThreadPool, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from crypto.key_manager import MasterKey
from services.vault import VaultService
from utils.app_paths import AppPaths
from utils.config import AppConfig, save_config
from utils.logging import set_log_filenames
from workers.common import TaskWorker


class AppContext(QObject):
    """State shared by all pages. Emits signals so pages stay in sync."""

    key_changed = Signal()
    files_changed = Signal()
    config_changed = Signal()
    file_dropped = Signal(str)
    host_key_needed = Signal()
    profiles_changed = Signal()
    settings_needed = Signal(str)   # reason shown to the user

    def __init__(self, home: Path | AppPaths, config: AppConfig) -> None:
        super().__init__()
        self.paths = home if isinstance(home, AppPaths) else AppPaths.from_root(Path(home))
        self.home = self.paths.root
        self.config = config
        self.master_key = MasterKey()
        self.service = VaultService(self.paths, config, self.master_key)
        self.pool = QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(max(2, config.transfer.concurrent_uploads + 1))
        self._workers: set[TaskWorker] = set()

    def start(self, worker: TaskWorker) -> None:
        self._workers.add(worker)
        worker.signals.finished.connect(lambda *_: self._workers.discard(worker))
        worker.signals.failed.connect(lambda *_: self._workers.discard(worker))
        worker.signals.failed.connect(self._route_failure)
        self.pool.start(worker)

    def _route_failure(self, message: str, category: str) -> None:
        if category == "host_key_unknown":
            self.host_key_needed.emit()
        elif category in ("connection_test_required", "no_profile", "remote_dir_missing"):
            self.settings_needed.emit(message)

    def busy(self) -> bool:
        return bool(self._workers)

    def save_config(self) -> None:
        save_config(self.config, self.paths.config_file)
        set_log_filenames(self.config.privacy.log_filenames)
        self.pool.setMaxThreadCount(max(2, self.config.transfer.concurrent_uploads + 1))
        self.config_changed.emit()


def human_size(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def human_time(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 3600:d}:{s % 3600 // 60:02d}:{s % 60:02d}"


DARK_QSS = """
* { font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif; font-size: 10pt; }
QMainWindow, QWidget { background: #12151c; color: #e3e7ef; }
QLabel, QCheckBox { background: transparent; }
QListWidget#nav { background: #0c0f14; border: none; padding: 12px 6px; outline: 0; }
QListWidget#nav::item { padding: 10px 14px; border-radius: 6px; margin: 2px 4px; color: #aab2c2; }
QListWidget#nav::item:selected { background: #1f6feb; color: #ffffff; }
QListWidget#nav::item:hover:!selected { background: #1a1f29; }
QLabel#title { font-size: 18pt; font-weight: 600; }
QLabel#subtitle { color: #8b94a7; }
QLabel#warning { background: #3a1d1d; color: #ffb4a8; border: 1px solid #6b2a2a; border-radius: 6px; padding: 8px; }
QLabel#ok { color: #56d364; font-weight: 600; }
QLabel#bad { color: #ff7b72; font-weight: 600; }
QFrame#card { background: #181c25; border: 1px solid #252b38; border-radius: 10px; }
QFrame#drop { background: #151a23; border: 2px dashed #2f3a4f; border-radius: 12px; }
QFrame#drop[active="true"] { border-color: #1f6feb; background: #16233a; }
QPushButton { background: #232a37; border: 1px solid #2f3747; border-radius: 6px; padding: 7px 14px; color: #e3e7ef; }
QPushButton:hover { background: #2b3444; }
QPushButton:disabled { color: #5d6575; background: #1a1f29; }
QPushButton#primary { background: #1f6feb; border-color: #1f6feb; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #388bfd; }
QPushButton#primary:disabled { background: #1a2a45; border-color: #1a2a45; color: #6b7a96; }
QPushButton#danger { background: #5a1e1e; border-color: #8e2b2b; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTableWidget {
  background: #0f1218; border: 1px solid #2a3140; border-radius: 6px; padding: 5px; selection-background-color: #1f6feb; }
QHeaderView::section { background: #181c25; color: #aab2c2; border: none; padding: 6px; }
QProgressBar { background: #0f1218; border: 1px solid #2a3140; border-radius: 6px; text-align: center; height: 18px; }
QProgressBar::chunk { background: #1f6feb; border-radius: 5px; }
QCheckBox::indicator, QRadioButton::indicator { width: 16px; height: 16px; border: 1px solid #5d6b85; background: #0f1218; }
QCheckBox::indicator { border-radius: 4px; }
QRadioButton::indicator { border-radius: 8px; }
QCheckBox::indicator:checked, QRadioButton::indicator:checked { background: #1f6feb; border-color: #58a6ff; }
QWizard, QWizardPage { background: #12151c; }
QGroupBox { border: 1px solid #252b38; border-radius: 8px; margin-top: 14px; padding: 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #8b94a7; }
"""

LIGHT_QSS = """
* { font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif; font-size: 10pt; }
QListWidget#nav { background: #eef1f6; border: none; padding: 12px 6px; outline: 0; }
QListWidget#nav::item { padding: 10px 14px; border-radius: 6px; margin: 2px 4px; }
QListWidget#nav::item:selected { background: #1f6feb; color: #ffffff; }
QLabel#title { font-size: 18pt; font-weight: 600; }
QLabel#subtitle { color: #5b6476; }
QLabel#warning { background: #fff0ee; color: #8e1c12; border: 1px solid #f2b8b0; border-radius: 6px; padding: 8px; }
QLabel#ok { color: #1a7f37; font-weight: 600; }
QLabel#bad { color: #cf222e; font-weight: 600; }
QFrame#card { background: #ffffff; border: 1px solid #d8dee8; border-radius: 10px; }
QFrame#drop { background: #f7f9fc; border: 2px dashed #b7c2d4; border-radius: 12px; }
QFrame#drop[active="true"] { border-color: #1f6feb; }
QPushButton#primary { background: #1f6feb; color: white; font-weight: 600; border-radius: 6px; padding: 7px 14px; }
"""


def apply_theme(widget: QWidget, dark: bool) -> None:
    widget.setStyleSheet(DARK_QSS if dark else LIGHT_QSS)


def page_header(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 8)
    t = QLabel(title)
    t.setObjectName("title")
    s = QLabel(subtitle)
    s.setObjectName("subtitle")
    s.setWordWrap(True)
    lay.addWidget(t)
    lay.addWidget(s)
    return w


def warn(parent: QWidget, title: str, message: str) -> None:
    QMessageBox.warning(parent, title, message)


def confirm(parent: QWidget, title: str, message: str) -> bool:
    return QMessageBox.question(
        parent, title, message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No
    ) == QMessageBox.Yes


class StatCard(QFrame):
    def __init__(self, label: str) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        self.caption = QLabel(label)
        self.caption.setObjectName("subtitle")
        self.value = QLabel("-")
        self.value.setStyleSheet("font-size: 15pt; font-weight: 600;")
        lay.addWidget(self.caption)
        lay.addWidget(self.value)

    def set(self, text: str, obj_name: str = "") -> None:
        self.value.setText(text)
        if obj_name:
            self.value.setObjectName(obj_name)
            self.value.style().unpolish(self.value)
            self.value.style().polish(self.value)


class DropZone(QFrame):
    """Accepts a single local file via drag-and-drop."""

    dropped = Signal(str)

    def __init__(self, text: str = "Drop any file here") -> None:
        super().__init__()
        self.setObjectName("drop")
        self.setAcceptDrops(True)
        self.setMinimumHeight(120)
        lay = QVBoxLayout(self)
        lbl = QLabel(f"⇩\n{text}")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setObjectName("subtitle")
        lay.addWidget(lbl)

    def _set_active(self, on: bool) -> None:
        self.setProperty("active", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        urls = e.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile() and Path(urls[0].toLocalFile()).is_file():
            e.acceptProposedAction()
            self._set_active(True)
        else:
            e.ignore()

    def dragLeaveEvent(self, e) -> None:
        self._set_active(False)

    def dropEvent(self, e: QDropEvent) -> None:
        self._set_active(False)
        urls = e.mimeData().urls()
        if urls and urls[0].isLocalFile():
            self.dropped.emit(urls[0].toLocalFile())
            e.acceptProposedAction()


@dataclass
class _Rate:
    start: float = 0.0
    last_t: float = 0.0
    last_b: int = 0
    speed: float = 0.0


STAGE_LABELS = {
    "preparing": "Preparing", "hashing": "Preparing (hashing)", "encrypting": "Encrypting",
    "verifying": "Verifying", "uploading": "Uploading", "downloading": "Downloading",
    "decrypting": "Decrypting", "complete": "Complete",
}


class ProgressPanel(QFrame):
    """Percentage, bytes encrypted/uploaded, speed, elapsed, remaining."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        self.stage = QLabel("Idle")
        self.stage.setStyleSheet("font-weight: 600;")
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        grid = QGridLayout()
        self.lbl = {}
        for i, name in enumerate(["Encrypted", "Uploaded", "Speed", "Elapsed", "Remaining"]):
            cap = QLabel(name)
            cap.setObjectName("subtitle")
            val = QLabel("-")
            grid.addWidget(cap, 0, i)
            grid.addWidget(val, 1, i)
            self.lbl[name] = val
        lay.addWidget(self.stage)
        lay.addWidget(self.bar)
        lay.addLayout(grid)
        self._rate = _Rate()

    def reset(self) -> None:
        now = time.monotonic()
        self._rate = _Rate(now, now, 0, 0.0)
        self.bar.setValue(0)
        self.stage.setText("Starting…")
        for v in self.lbl.values():
            v.setText("-")

    def update_progress(self, stage: str, done: int, total: int) -> None:
        now = time.monotonic()
        r = self._rate
        if stage in ("encrypting", "uploading", "downloading", "decrypting"):
            dt = now - r.last_t
            if done < r.last_b:
                r.last_b = 0
            if dt >= 0.5:
                inst = (done - r.last_b) / dt
                r.speed = inst if r.speed == 0 else 0.7 * r.speed + 0.3 * inst
                r.last_t, r.last_b = now, done
        pct = (done / total) if total else 1.0
        self.bar.setValue(int(pct * 1000))
        self.bar.setFormat(f"{pct * 100:.1f}%")
        self.stage.setText(STAGE_LABELS.get(stage, stage.title()))
        if stage == "encrypting":
            self.lbl["Encrypted"].setText(f"{human_size(done)} / {human_size(total)}")
        if stage in ("uploading", "downloading"):
            self.lbl["Uploaded" if stage == "uploading" else "Encrypted"].setText(
                f"{human_size(done)} / {human_size(total)}"
            )
        self.lbl["Speed"].setText(f"{human_size(r.speed)}/s" if r.speed else "-")
        self.lbl["Elapsed"].setText(human_time(now - r.start))
        self.lbl["Remaining"].setText(human_size(max(0, total - done)))

    def complete(self, text: str = "Complete") -> None:
        self.bar.setValue(1000)
        self.bar.setFormat("100%")
        self.stage.setText(text)

    def failed(self, text: str) -> None:
        self.stage.setText(f"Failed: {text}")
