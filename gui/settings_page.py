"""Settings: server profiles (with connection test and host-key trust), encryption,
transfers, privacy and appearance."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from crypto.chunks import MAX_CHUNK_SIZE, MIN_CHUNK_SIZE
from database.database import Profile
from gui.common import AppContext, confirm, page_header, warn
from gui.server_widgets import ConnectionTestPanel, ProfileForm
from utils.errors import WezCryptError


class SettingsPage(QWidget):
    run_wizard = Signal()

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.current_id: int | None = None
        outer = QVBoxLayout(self)
        outer.addWidget(page_header("Settings", "Passwords, passphrases and tokens are stored only in the OS "
                                                 "credential store, never in configuration files."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll)

        # ---- profiles --------------------------------------------------------------
        g = QGroupBox("Server profiles")
        gl = QVBoxLayout(g)
        prow = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.currentIndexChanged.connect(self._select)
        b_new = QPushButton("New Profile")
        b_new.clicked.connect(self._new)
        self.b_active = QPushButton("Use This Profile")
        self.b_active.clicked.connect(self._make_active)
        self.b_delete = QPushButton("Delete Profile")
        self.b_delete.setObjectName("danger")
        self.b_delete.clicked.connect(self._delete)
        b_wiz = QPushButton("Run Setup Wizard")
        b_wiz.clicked.connect(self.run_wizard.emit)
        prow.addWidget(QLabel("Profile:"))
        prow.addWidget(self.combo, 1)
        for b in (b_new, self.b_active, self.b_delete, b_wiz):
            prow.addWidget(b)
        gl.addLayout(prow)
        self.form = ProfileForm(allow_local=True)
        gl.addWidget(self.form)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setObjectName("subtitle")
        gl.addWidget(self.status)
        srow = QHBoxLayout()
        self.b_save = QPushButton("Save Profile")
        self.b_save.setObjectName("primary")
        self.b_save.clicked.connect(self._save_profile)
        self.b_forget = QPushButton("Forget Trusted Host Key")
        self.b_forget.setObjectName("danger")
        self.b_forget.clicked.connect(self._forget)
        srow.addWidget(self.b_save)
        srow.addWidget(self.b_forget)
        srow.addStretch(1)
        gl.addLayout(srow)
        self.test = ConnectionTestPanel(ctx, self._current_profile)
        self.test.finished.connect(lambda _: self._update_status())
        gl.addWidget(self.test)
        lay.addWidget(g)

        # ---- encryption / transfers ---------------------------------------------------
        g = QGroupBox("Encryption && transfers")
        f = QFormLayout(g)
        self.chunk = QSpinBox()
        self.chunk.setRange(MIN_CHUNK_SIZE // 1024, MAX_CHUNK_SIZE // 1024)
        self.chunk.setSuffix(" KiB")
        self.chunk.setValue(ctx.config.encryption.chunk_size // 1024)
        self.concurrent = QSpinBox()
        self.concurrent.setRange(1, 8)
        self.concurrent.setValue(ctx.config.transfer.concurrent_uploads)
        self.readback = QCheckBox("Verify uploads by reading back and hashing the remote object")
        self.readback.setChecked(ctx.config.transfer.verify_upload_readback)
        self.autodel = QCheckBox("Auto-delete encrypted temp files after successful upload")
        self.autodel.setChecked(ctx.config.transfer.auto_delete_temp)
        f.addRow("Chunk size:", self.chunk)
        f.addRow("Concurrent uploads:", self.concurrent)
        f.addRow(self.readback)
        f.addRow(self.autodel)
        note = QLabel("Deleting temp files removes their names; secure erasure cannot be guaranteed on SSDs "
                      "(wear levelling, TRIM) or journaling/copy-on-write filesystems.")
        note.setObjectName("subtitle")
        note.setWordWrap(True)
        f.addRow(note)
        lay.addWidget(g)

        g = QGroupBox("Privacy && appearance")
        f = QFormLayout(g)
        self.clip = QSpinBox()
        self.clip.setRange(5, 600)
        self.clip.setSuffix(" s")
        self.clip.setValue(ctx.config.privacy.clipboard_clear_seconds)
        self.privlog = QCheckBox("Privacy logging (exclude plaintext filenames from logs)")
        self.privlog.setChecked(not ctx.config.privacy.log_filenames)
        self.dark = QCheckBox("Dark mode")
        self.dark.setChecked(ctx.config.ui.dark_mode)
        f.addRow("Clipboard timeout:", self.clip)
        f.addRow(self.privlog)
        f.addRow(self.dark)
        loc = QLabel(f"User data folder: {ctx.paths.root}")
        loc.setObjectName("subtitle")
        loc.setWordWrap(True)
        f.addRow(loc)
        lay.addWidget(g)

        save = QPushButton("Save Settings")
        save.setObjectName("primary")
        save.clicked.connect(self._save_settings)
        outer.addWidget(save)

        ctx.profiles_changed.connect(self.reload_profiles)
        self.reload_profiles()

    # ---- profiles ---------------------------------------------------------------------
    def _current_profile(self) -> Profile | None:
        return self.ctx.service.profiles.get(self.current_id) if self.current_id is not None else None

    def reload_profiles(self) -> None:
        pm = self.ctx.service.profiles
        keep = self.current_id
        active = pm.active()
        self.combo.blockSignals(True)
        self.combo.clear()
        for p in pm.list():
            self.combo.addItem(p.name + ("  (active)" if active and p.id == active.id else ""), p.id)
        target = keep if keep is not None else (active.id if active else None)
        idx = self.combo.findData(target) if target is not None else -1
        self.combo.setCurrentIndex(idx if idx >= 0 else (0 if self.combo.count() else -1))
        self.combo.blockSignals(False)
        self._select()

    def _select(self) -> None:
        pid = self.combo.currentData()
        self.current_id = int(pid) if pid is not None else None
        self.form.load(self._current_profile())
        has = self.current_id is not None
        for w in (self.b_active, self.b_delete, self.b_forget, self.test.btn):
            w.setEnabled(has)
        self._update_status()

    def _update_status(self) -> None:
        p = self._current_profile()
        if p is None:
            self.status.setText("No profile selected. Create one with New Profile or run the Setup Wizard.")
            return
        parts = [f"Server: {p.label}"]
        if p.backend == "sftp":
            hk = self.ctx.service.db.get_host_key(p.host, p.port)
            parts.append(f"Trusted host key: {hk[0]} {hk[1]}" if hk else "Trusted host key: none (verify on test)")
            secret = "ssh-password" if p.auth_method == "password" else "ssh-key-passphrase"
            parts.append(f"{'Password' if p.auth_method == 'password' else 'Key passphrase'}: "
                         f"{'stored' if self.ctx.service.profiles.has_secret(p, secret) else 'not stored'}")
        parts.append("Connection test: passed" if p.connection_tested_at
                     else "Connection test: REQUIRED before transfers")
        self.status.setText("   ·   ".join(parts))

    def _new(self) -> None:
        name, ok = QInputDialog.getText(self, "New Profile", "Profile name (e.g. Backup Server):")
        if not ok or not name.strip():
            return
        self.current_id = None
        self.form.load(None)
        self.form.name.setText(name.strip())
        self.combo.blockSignals(True)
        self.combo.setCurrentIndex(-1)
        self.combo.blockSignals(False)
        self.status.setText("Fill in the details and click Save Profile.")

    def _save_profile(self) -> None:
        pm = self.ctx.service.profiles
        values = self.form.values()
        try:
            if self.current_id is None:
                prof = pm.create(values)
            else:
                before = pm.get(self.current_id)
                prof = pm.update(self.current_id, values)
                if before and before.backend == "sftp" and (before.host, before.port) != (prof.host, prof.port):
                    QMessageBox.information(self, "Server changed", "Host or port changed: the server's SSH "
                                            "fingerprint must be verified again with Test Connection.")
            persisted = True
            secrets = self.form.secrets()
            for kind, value in secrets.items():
                persisted = pm.set_secret(prof, kind, value).persisted and persisted
            if secrets and not persisted:
                QMessageBox.information(self, "Credential storage", "No secure OS credential store is "
                                        "available; the secret is kept in memory for this session only.")
        except WezCryptError as exc:
            warn(self, "Invalid profile", str(exc))
            return
        finally:
            self.form.clear_secrets()
        self.current_id = prof.id
        self.ctx.profiles_changed.emit()
        if prof.connection_tested_at is None:
            self.status.setText(self.status.text() + "   ·   Run Test Connection now.")

    def _make_active(self) -> None:
        if self.current_id is not None:
            self.ctx.service.profiles.set_active(self.current_id)
            self.ctx.profiles_changed.emit()
            self.ctx.config_changed.emit()

    def _delete(self) -> None:
        p = self._current_profile()
        if p is None or not confirm(self, "Delete profile", f"Delete profile '{p.name}' and its stored "
                                    "credentials? Encrypted files on the server are not touched."):
            return
        self.ctx.service.profiles.delete(p.id)
        self.current_id = None
        self.ctx.profiles_changed.emit()
        self.ctx.config_changed.emit()

    def _forget(self) -> None:
        p = self._current_profile()
        if p is None or p.backend != "sftp":
            return
        if confirm(self, "Forget host key", "Remove the trusted host key? You will have to verify the server "
                   "fingerprint again on the next connection. Only do this if your administrator confirmed "
                   "the server key was legitimately changed."):
            self.ctx.service.db.forget_host_key(p.host, p.port)
            self.ctx.service.db.reset_profile_tested(p.id)
            self._update_status()

    # ---- general settings ---------------------------------------------------------------
    def _save_settings(self) -> None:
        c = self.ctx.config
        try:
            c.encryption.chunk_size = self.chunk.value() * 1024
            c.transfer.concurrent_uploads = self.concurrent.value()
            c.transfer.verify_upload_readback = self.readback.isChecked()
            c.transfer.auto_delete_temp = self.autodel.isChecked()
            c.privacy.clipboard_clear_seconds = self.clip.value()
            c.privacy.log_filenames = not self.privlog.isChecked()
            c.ui.dark_mode = self.dark.isChecked()
            self.ctx.save_config()
        except WezCryptError as exc:
            warn(self, "Invalid settings", str(exc))
            return
        QMessageBox.information(self, "Settings", "Settings saved.")
