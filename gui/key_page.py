"""Master Key page: generate, import, unlock, lock, back up and verify the unified key."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.common import AppContext, confirm, page_header, warn
from gui.key_actions import WARN_ALL, WARN_LOST, WARN_PROTECTS, KeyActions
from security import credentials
from utils.errors import WezCryptError


class KeyPage(QWidget):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.actions = KeyActions(ctx, self)

        lay = QVBoxLayout(self)
        lay.addWidget(page_header("Master Key", "One AES-256 master key protects every file. "
                                                 "It never leaves this computer and is never sent to the server."))
        for text in (WARN_PROTECTS + " " + WARN_ALL, WARN_LOST):
            w = QLabel("⚠ " + text)
            w.setObjectName("warning")
            w.setWordWrap(True)
            lay.addWidget(w)

        status = QGroupBox("Status")
        form = QFormLayout(status)
        self.status = QLabel()
        self.fp = QLabel()
        self.ack = QLabel()
        self.mode = QComboBox()
        self.mode.addItem("Manual — enter the key every time the app starts", "manual")
        self.mode.addItem("OS credential store (Windows Credential Manager / Keychain / Secret Service)", "os_keyring")
        self.mode.setCurrentIndex(0 if ctx.config.encryption.key_storage == "manual" else 1)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        form.addRow("Master Key Status:", self.status)
        form.addRow("Key Fingerprint:", self.fp)
        form.addRow("Backup acknowledged:", self.ack)
        form.addRow("Key storage:", self.mode)
        lay.addWidget(status)

        rec = QGroupBox("MASTER RECOVERY KEY")
        rl = QVBoxLayout(rec)
        self.key_field = QLineEdit()
        self.key_field.setReadOnly(True)
        self.key_field.setEchoMode(QLineEdit.Password)
        self.key_field.setStyleSheet("font-family: Consolas, 'Cascadia Mono', monospace; font-size: 11pt;")
        rl.addWidget(self.key_field)
        grid = QGridLayout()
        self.b_copy = QPushButton("Copy Key")
        self.b_save = QPushButton("Save Recovery Key")
        self.b_show = QPushButton("Show / Hide")
        self.b_verify = QPushButton("Verify Backup")
        self.b_print = QPushButton("Print Recovery Key")
        self.b_offline = QPushButton("Create Offline Backup")
        for i, (b, fn) in enumerate([
            (self.b_copy, self.actions.copy), (self.b_save, self._save), (self.b_show, self._toggle),
            (self.b_verify, self._verify), (self.b_print, self.actions.print_key),
            (self.b_offline, self.actions.offline_backup),
        ]):
            b.clicked.connect(fn)
            grid.addWidget(b, i // 3, i % 3)
        rl.addLayout(grid)
        lay.addWidget(rec)

        row = QHBoxLayout()
        self.b_gen = QPushButton("Generate Key")
        self.b_import = QPushButton("Import Existing Master Key")
        self.b_unlock = QPushButton("Unlock")
        self.b_lock = QPushButton("Lock Master Key")
        self.b_unlock.setObjectName("primary")
        self.b_gen.clicked.connect(self._generate)
        self.b_import.clicked.connect(self._import)
        self.b_unlock.clicked.connect(self.unlock)
        self.b_lock.clicked.connect(self._lock)
        for b in (self.b_gen, self.b_import, self.b_unlock, self.b_lock):
            row.addWidget(b)
        lay.addLayout(row)

        note = QLabel("Locking removes the key from application state. Python cannot guarantee that "
                      "every copy is wiped from memory (immutable buffers used by the crypto library, "
                      "Qt widgets and the clipboard may persist until reused). Close the app to release "
                      "all process memory.")
        note.setObjectName("subtitle")
        note.setWordWrap(True)
        lay.addWidget(note)
        lay.addStretch(1)
        ctx.key_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        loaded = self.ctx.master_key.is_loaded
        self.status.setText("Loaded" if loaded else "Locked")
        self.status.setObjectName("ok" if loaded else "bad")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.fp.setText(self.ctx.master_key.info().display_fingerprint if loaded else "-")
        self.ack.setText("Yes" if self.ctx.service.backup_acknowledged() else "No — required before first upload")
        self.key_field.setText(self.ctx.master_key.recovery_string() if loaded else "")
        self.key_field.setEchoMode(QLineEdit.Password)
        for b in (self.b_copy, self.b_save, self.b_show, self.b_verify, self.b_print, self.b_offline, self.b_lock):
            b.setEnabled(loaded)
        self.b_unlock.setEnabled(not loaded)
        self.b_gen.setEnabled(not loaded)
        self.b_import.setEnabled(not loaded)

    def _generate(self) -> None:
        if self.actions.generate():
            self.actions.save_backup()
            self.actions.request_acknowledgment()
            self.refresh()

    def _import(self) -> None:
        if self.actions.import_key():
            self.actions.request_acknowledgment()
            self.refresh()

    def unlock(self) -> None:
        self.actions.unlock()

    def _save(self) -> None:
        if self.actions.save_backup():
            self.actions.request_acknowledgment()
            self.refresh()

    def _verify(self) -> None:
        if self.actions.verify_backup():
            self.actions.request_acknowledgment()
            self.refresh()

    def _lock(self) -> None:
        if self.ctx.busy() and not confirm(self, "Operations running",
                                           "Operations are still running. Lock anyway after they finish?"):
            return
        self.key_field.clear()
        self.actions.lock()

    def _toggle(self) -> None:
        self.key_field.setEchoMode(
            QLineEdit.Normal if self.key_field.echoMode() == QLineEdit.Password else QLineEdit.Password
        )

    def _mode_changed(self) -> None:
        mode = self.mode.currentData()
        if mode == self.ctx.config.encryption.key_storage:
            return
        if mode == "os_keyring":
            if not credentials.is_available():
                warn(self, "Unavailable", "No secure OS credential store is available on this system. "
                     "The key stays in manual mode (entered at each start).")
                self.mode.setCurrentIndex(0)
                return
            if self.ctx.master_key.is_loaded:
                try:
                    credentials.store_master_key(self.ctx.master_key.material())
                except WezCryptError as exc:
                    warn(self, "Credential store", str(exc))
                    self.mode.setCurrentIndex(0)
                    return
        else:
            if credentials.is_available() and confirm(
                self, "Remove stored key", "Also remove the master key from the OS credential store?"
            ):
                credentials.delete_master_key()
        self.ctx.config.encryption.key_storage = mode
        self.ctx.save_config()
