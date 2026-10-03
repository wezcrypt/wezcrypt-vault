"""Main window: sidebar navigation, page stack, drag-and-drop, startup recovery."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent, QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from gui.about_page import AboutPage
from gui.common import AppContext, apply_theme, confirm, warn
from gui.dashboard import DashboardPage
from gui.decrypt_page import DecryptPage
from gui.encrypt_page import EncryptPage
from gui.files_page import FilesPage
from gui.key_page import KeyPage
from gui.logs_page import LogsPage
from gui.settings_page import SettingsPage
from gui.setup_wizard import SetupWizard
from security import credentials
from utils.errors import WezCryptError
from wezcrypt_vault.app_info import APP_NAME
from wezcrypt_vault.version import __version__
from workers.upload_worker import ResumeUploadWorker

PAGES = [
    ("dashboard", "Dashboard"), ("encrypt", "Encrypt & Upload"), ("decrypt", "Download & Decrypt"),
    ("files", "My Files"), ("key", "Master Key"), ("settings", "Settings"), ("about", "About"),
    ("logs", "Logs"),
]


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext, icon: QIcon | None = None, icon_path: str | None = None,
                 *, run_startup: bool = True) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        if icon is not None:
            self.setWindowIcon(icon)
        self.resize(1180, 780)
        self.setAcceptDrops(True)

        self.pages = {
            "dashboard": DashboardPage(ctx), "encrypt": EncryptPage(ctx), "decrypt": DecryptPage(ctx),
            "files": FilesPage(ctx), "key": KeyPage(ctx), "settings": SettingsPage(ctx), "about": AboutPage(ctx, icon_path), "logs": LogsPage(ctx),
        }
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(210)
        brand = QLabel("  WezCrypt Vault")
        brand.setStyleSheet("font-size: 14pt; font-weight: 700; padding: 18px 8px 8px 8px;")
        self.stack = QStackedWidget()
        for key, label in PAGES:
            self.nav.addItem(label)
            page = QWidget()
            pl = QVBoxLayout(page)
            pl.setContentsMargins(28, 22, 28, 22)
            pl.addWidget(self.pages[key])
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        side = QWidget()
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)
        side.setStyleSheet("background: transparent;")
        sl.addWidget(brand)
        sl.addWidget(self.nav)
        root = QWidget()
        rl = QHBoxLayout(root)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        rl.addWidget(side)
        rl.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.key_status = QLabel()
        self.statusBar().addPermanentWidget(self.key_status)

        dash: DashboardPage = self.pages["dashboard"]  # type: ignore[assignment]
        dash.navigate.connect(self.go)
        dash.file_chosen.connect(self.encrypt_file)
        dash.decrypt_local_requested.connect(self._decrypt_local)
        files: FilesPage = self.pages["files"]  # type: ignore[assignment]
        files.download_requested.connect(self._download)
        ctx.key_changed.connect(self._update_status)
        ctx.config_changed.connect(lambda: apply_theme(self, ctx.config.ui.dark_mode))
        ctx.host_key_needed.connect(self._host_key_needed)
        ctx.settings_needed.connect(self._settings_needed)
        self.pages["settings"].run_wizard.connect(self.open_wizard)  # type: ignore[attr-defined]
        ctx.profiles_changed.connect(ctx.config_changed.emit)

        apply_theme(self, ctx.config.ui.dark_mode)
        self.nav.setCurrentRow(0)
        self._update_status()
        if run_startup:
            QTimer.singleShot(0, self._startup)

    # ---- navigation -------------------------------------------------------
    def go(self, name: str) -> None:
        self.nav.setCurrentRow([k for k, _ in PAGES].index(name))

    def encrypt_file(self, path: str) -> None:
        self.pages["encrypt"].set_file(path)  # type: ignore[attr-defined]
        self.go("encrypt")

    def _download(self, fid: str) -> None:
        self.pages["decrypt"].set_file_id(fid)  # type: ignore[attr-defined]
        self.go("decrypt")

    def _decrypt_local(self) -> None:
        self.go("decrypt")
        self.pages["decrypt"].choose_local()  # type: ignore[attr-defined]

    def _update_status(self) -> None:
        mk = self.ctx.master_key
        self.key_status.setText(
            f"🔓 Master key loaded · {mk.info().display_fingerprint}" if mk.is_loaded else "🔒 Master key locked"
        )

    def _settings_needed(self, reason: str) -> None:
        self.go("settings")
        QMessageBox.information(self, "Server setup needed", reason)

    def open_wizard(self) -> None:
        wiz = SetupWizard(self.ctx, self)
        wiz.exec()
        self.ctx.profiles_changed.emit()
        self.ctx.key_changed.emit()
        if wiz.result() and wiz.next_action == "settings":
            self.go("settings")
        elif wiz.result():
            self.go("dashboard")

    def _host_key_needed(self) -> None:
        self.go("settings")
        QMessageBox.information(self, "Verify server", "This server's SSH host key is not trusted yet. "
                                "Use Test Connection to view the fingerprint, verify it, and trust it.")

    # ---- drag & drop anywhere ----------------------------------------------
    def dragEnterEvent(self, e: QDragEnterEvent) -> None:
        urls = e.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile() and Path(urls[0].toLocalFile()).is_file():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent) -> None:
        urls = e.mimeData().urls()
        if urls and urls[0].isLocalFile():
            local = urls[0].toLocalFile()
            if local.lower().endswith(".wezenc"):
                self.pages["decrypt"].local.setText(local)  # type: ignore[attr-defined]
                self.go("decrypt")
            else:
                self.encrypt_file(local)

    # ---- startup -----------------------------------------------------------------
    def _startup(self) -> None:
        if self.ctx.config.encryption.key_storage == "os_keyring" and credentials.is_available():
            try:
                key = credentials.load_master_key()
                if key is not None:
                    self.ctx.master_key.load(key)
                    self.ctx.key_changed.emit()
            except WezCryptError as exc:
                warn(self, "Credential store", str(exc))
        if self.ctx.service.needs_setup():
            self.open_wizard()
        if not self.ctx.master_key.is_loaded:
            self.go("key")
        self._recover()

    def _recover(self) -> None:
        try:
            items = self.ctx.service.pending_recovery()
        except WezCryptError:
            return
        for item in items:
            fid = item.operation.file_id
            if item.resumable:
                box = QMessageBox(self)
                box.setWindowTitle("Interrupted operation")
                box.setText(f"{item.description}\nFile ID {fid[:16]}…")
                resume = box.addButton("Resume Upload", QMessageBox.AcceptRole)
                delete = box.addButton("Delete Temporary File", QMessageBox.DestructiveRole)
                box.addButton("Later", QMessageBox.RejectRole)
                box.exec()
                if box.clickedButton() is resume:
                    w = ResumeUploadWorker(self.ctx.service, item)
                    w.signals.finished.connect(lambda *_: self.ctx.files_changed.emit())
                    w.signals.failed.connect(lambda m, c: warn(self, "Resume failed", m))
                    self.ctx.start(w)
                elif box.clickedButton() is delete:
                    self.ctx.service.discard_recovery(item)
            elif confirm(self, "Incomplete operation",
                         f"{item.description} (File ID {fid[:16]}…). Incomplete ciphertext is never treated "
                         "as valid. Delete the temporary file?"):
                self.ctx.service.discard_recovery(item)
        if items:
            self.ctx.files_changed.emit()

    def closeEvent(self, e: QCloseEvent) -> None:
        if self.ctx.busy() and not confirm(self, "Operations running",
                                           "Transfers are still running. Quit anyway? They can be resumed later."):
            e.ignore()
            return
        for w in list(self.ctx._workers):
            w.cancel()
        self.ctx.pool.waitForDone(5000)
        self.ctx.master_key.lock()
        e.accept()

