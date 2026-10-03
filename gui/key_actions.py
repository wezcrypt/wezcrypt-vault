"""Master-key actions shared by the Master Key page and the Setup Wizard."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QObject, QTimer
from PySide6.QtGui import QGuiApplication, QTextDocument
from PySide6.QtWidgets import QCheckBox, QFileDialog, QInputDialog, QLineEdit, QMessageBox, QWidget

from crypto.key_manager import (
    decode_recovery_key,
    extract_key_from_backup_text,
    format_fingerprint,
    generate_master_key,
    key_fingerprint,
    recovery_file_text,
)
from gui.common import AppContext, confirm, warn
from security import credentials
from security.paths import create_private_file
from utils.errors import WezCryptError
from utils.logging import log_event

WARN_PROTECTS = "Your unified master key protects all files encrypted with it."
WARN_ALL = "Anyone who obtains this key may be able to decrypt all files protected by it."
WARN_LOST = "If this key is lost, encrypted files may become permanently unrecoverable."
ACK_TEXT = ("I have saved an offline backup of my master key and understand that losing it makes my "
            "encrypted files permanently unrecoverable.")


class KeyActions(QObject):
    def __init__(self, ctx: AppContext, parent: QWidget) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.w = parent
        self._clip_value: str | None = None
        self._clip_timer = QTimer(self)
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self.clear_clipboard)

    # ---- load / create ----------------------------------------------------------
    def accept_key(self, key: bytes, *, source: str) -> bool:
        fp_disp = format_fingerprint(key_fingerprint(key))
        known = self.ctx.service.db.fingerprints_in_use()
        if known and fp_disp not in known:
            if not confirm(self.w, "Different key", "None of your registered files were encrypted with this key "
                           f"(fingerprint {fp_disp}). Existing files will not decrypt with it. Continue?"):
                return False
        self.ctx.master_key.load(key)
        if self.ctx.config.encryption.key_storage == "os_keyring":
            try:
                credentials.store_master_key(key)
            except WezCryptError as exc:
                warn(self.w, "Credential store", f"{exc}\nThe key is loaded for this session only.")
        log_event("master_key", status=source)
        self.ctx.key_changed.emit()
        return True

    def generate(self) -> bool:
        if self.ctx.master_key.is_loaded:
            warn(self.w, "Key already loaded", "Lock the current key before generating a new one.")
            return False
        existing_files = bool(self.ctx.service.db.fingerprints_in_use())
        stored = False
        if self.ctx.config.encryption.key_storage == "os_keyring" and credentials.is_available():
            try:
                stored = credentials.load_master_key() is not None
            except WezCryptError:
                stored = False
        if existing_files or stored:
            text, ok = QInputDialog.getText(
                self.w, "Generate a NEW master key?",
                "A master key already exists for this vault. A new key CANNOT decrypt existing files.\n"
                "Type NEW KEY to continue:")
            if not ok or text.strip() != "NEW KEY":
                return False
            if stored:
                credentials.delete_master_key()
        elif not confirm(self.w, "Generate master key", "Generate a new 256-bit master key now?"):
            return False
        return self.accept_key(generate_master_key(), source="generated")

    def import_key(self) -> bool:
        text, ok = QInputDialog.getText(self.w, "Import Existing Master Key", "Recovery key (wezcrypt-v1-…):",
                                        QLineEdit.Password)
        if not ok or not text.strip():
            return False
        try:
            key = extract_key_from_backup_text(text)
        except WezCryptError as exc:
            warn(self.w, "Invalid key", str(exc))
            return False
        if self.accept_key(key, source="imported"):
            QMessageBox.information(self.w, "Master key", "Master key accepted.")
            return True
        return False

    def unlock(self) -> bool:
        if self.ctx.config.encryption.key_storage == "os_keyring":
            try:
                key = credentials.load_master_key()
            except WezCryptError as exc:
                warn(self.w, "Credential store", str(exc))
                key = None
            if key is not None:
                self.ctx.master_key.load(key)
                log_event("master_key", status="unlocked_keyring")
                self.ctx.key_changed.emit()
                return True
        text, ok = QInputDialog.getText(self.w, "Unlock", "Enter your master recovery key:", QLineEdit.Password)
        if not ok or not text.strip():
            return False
        try:
            key = decode_recovery_key(text)
        except WezCryptError as exc:
            warn(self.w, "Invalid key", str(exc))
            return False
        return self.accept_key(key, source="unlocked_manual")

    def lock(self) -> None:
        self.clear_clipboard()
        self.ctx.master_key.lock()
        log_event("master_key", status="locked")
        self.ctx.key_changed.emit()

    # ---- backup ---------------------------------------------------------------------
    def copy(self) -> None:
        value = self.ctx.master_key.recovery_string()
        QGuiApplication.clipboard().setText(value)
        self._clip_value = value
        secs = self.ctx.config.privacy.clipboard_clear_seconds
        self._clip_timer.start(secs * 1000)
        QMessageBox.information(self.w, "Copied",
                                f"Master key copied. Clipboard will be cleared automatically in {secs} seconds.")

    def clear_clipboard(self) -> None:
        cb = QGuiApplication.clipboard()
        if self._clip_value is not None and cb.text() == self._clip_value:
            cb.clear()  # only clear if it still holds exactly what we copied
        self._clip_value = None

    def write_recovery_file(self, path: Path) -> bool:
        text = recovery_file_text(self.ctx.master_key.material())
        if path.exists():
            if not confirm(self.w, "Overwrite?", f"{path.name} exists. Replace it?"):
                return False
            path.unlink()
        fd = create_private_file(path)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        log_event("backup_key", status="saved")
        return True

    def save_backup(self) -> bool:
        path, _ = QFileDialog.getSaveFileName(self.w, "Save Recovery Key", "wezcrypt-recovery-key.txt",
                                              "Text files (*.txt)")
        if not path:
            return False
        try:
            return self.write_recovery_file(Path(path))
        except (OSError, WezCryptError) as exc:
            warn(self.w, "Save failed", str(exc))
            return False

    def offline_backup(self) -> None:
        d = QFileDialog.getExistingDirectory(self.w, "Choose removable drive / offline folder")
        if not d:
            return
        try:
            if not self.write_recovery_file(Path(d) / "wezcrypt-recovery-key.txt"):
                return
        except (OSError, WezCryptError) as exc:
            warn(self.w, "Backup failed", str(exc))
            return
        QMessageBox.information(self.w, "Offline backup", "Backup written. Eject the drive and store it "
                                "physically separate from this computer. Then use Verify Backup.")

    def print_key(self) -> None:
        try:
            from PySide6.QtPrintSupport import QPrintDialog, QPrinter
        except ImportError:
            warn(self.w, "Printing unavailable", "Qt print support is not available in this build.")
            return
        printer = QPrinter(QPrinter.HighResolution)
        if QPrintDialog(printer, self.w).exec() != QPrintDialog.Accepted:
            return
        doc = QTextDocument()
        doc.setPlainText(recovery_file_text(self.ctx.master_key.material()))
        doc.print_(printer)

    def verify_backup(self) -> bool:
        path, _ = QFileDialog.getOpenFileName(self.w, "Select backup to verify (Cancel to paste instead)",
                                              "", "Text files (*.txt);;All files (*)")
        if path:
            try:
                text = Path(path).read_text(encoding="utf-8")[:10000]
            except (OSError, UnicodeDecodeError) as exc:
                warn(self.w, "Verify Backup", f"Cannot read file: {type(exc).__name__}")
                return False
        else:
            text, ok = QInputDialog.getText(self.w, "Verify Backup", "Paste the backed-up recovery key:",
                                            QLineEdit.Password)
            if not ok:
                return False
        try:
            ok_match = self.ctx.master_key.matches(extract_key_from_backup_text(text))
        except WezCryptError as exc:
            warn(self.w, "Verify Backup", f"Backup is NOT valid: {exc}")
            return False
        if ok_match:
            QMessageBox.information(self.w, "Verify Backup", "Backup verified: it matches the loaded master key.")
            return True
        warn(self.w, "Verify Backup", "Backup does NOT match the loaded master key.")
        return False

    def request_acknowledgment(self) -> bool:
        """Modal confirmation that the user owns the backup responsibility."""
        if self.ctx.service.backup_acknowledged():
            return True
        box = QMessageBox(self.w)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Back up your master key")
        box.setText(f"{WARN_PROTECTS}\n\n{WARN_LOST}\n\n{WARN_ALL}\n\n{ACK_TEXT}")
        cb = QCheckBox("I understand and accept this responsibility")
        box.setCheckBox(cb)
        ok_btn = box.addButton("Continue", QMessageBox.AcceptRole)
        box.addButton("Not yet", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is ok_btn and cb.isChecked():
            self.ctx.service.acknowledge_backup()
            return True
        return False
