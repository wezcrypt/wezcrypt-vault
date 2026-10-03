"""Reusable server widgets: profile form, connection test panel, E2E test panel."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from database.database import Profile
from gui.common import AppContext, confirm
from services.diagnostics import CONNECTION_STAGES, E2E_STAGES, FAIL, PASS, RUN, TestReport
from services.diagnostics import run_connection_test, run_end_to_end_test
from workers.common import TaskWorker

_STATUS_STYLE = {PASS: ("✔", "#56d364"), FAIL: ("✖", "#ff7b72"), RUN: ("…", "#79c0ff")}


class ProfileForm(QWidget):
    """Edit a server profile. Secrets are returned separately and never pre-filled."""

    changed = Signal()

    def __init__(self, *, show_name: bool = True, allow_local: bool = True) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        top = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("Personal VPS")
        self.backend = QComboBox()
        self.backend.addItem("SFTP Server", "sftp")
        self.backend.addItem("HTTPS API", "https")
        if allow_local:
            self.backend.addItem("Local / mounted folder", "local")
        if show_name:
            top.addRow("Profile name:", self.name)
        top.addRow("Storage type:", self.backend)
        lay.addLayout(top)

        self.stack = QStackedWidget()
        # SFTP
        sftp = QWidget()
        f = QFormLayout(sftp)
        f.setContentsMargins(0, 0, 0, 0)
        self.host = QLineEdit()
        self.host.setPlaceholderText("example.com")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)
        self.user = QLineEdit()
        self.user.setPlaceholderText("storageuser")
        self.rpath = QLineEdit()
        self.rpath.setPlaceholderText("/storage/encrypted/")
        f.addRow("Server Host / IP:", self.host)
        f.addRow("SSH Port:", self.port)
        f.addRow("Username:", self.user)
        f.addRow("Remote Storage Path:", self.rpath)
        self.auth_key = QRadioButton("SSH Private Key (recommended)")
        self.auth_pw = QRadioButton("SSH Password")
        self.auth_key.setChecked(True)
        grp = QButtonGroup(self)
        grp.addButton(self.auth_key)
        grp.addButton(self.auth_pw)
        arow = QHBoxLayout()
        arow.addWidget(self.auth_key)
        arow.addWidget(self.auth_pw)
        arow.addStretch(1)
        f.addRow("Authentication:", arow)
        self.keypath = QLineEdit()
        self.keypath.setPlaceholderText("C:/Users/you/.ssh/id_ed25519")
        kb = QPushButton("Browse…")
        kb.clicked.connect(self._browse_key)
        krow = QHBoxLayout()
        krow.addWidget(self.keypath)
        krow.addWidget(kb)
        self.key_row = QWidget()
        self.key_row.setLayout(krow)
        krow.setContentsMargins(0, 0, 0, 0)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.Password)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        f.addRow("Private Key Path:", self.key_row)
        f.addRow("Key Passphrase (optional):", self.passphrase)
        f.addRow("SSH Password:", self.password)
        self._sftp_form = f
        self.stack.addWidget(sftp)
        # HTTPS
        https = QWidget()
        f2 = QFormLayout(https)
        f2.setContentsMargins(0, 0, 0, 0)
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://storage.example.com/api")
        self.ca = QLineEdit()
        self.ca.setPlaceholderText("optional private CA bundle (.pem)")
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.Password)
        f2.addRow("API address:", self.url)
        f2.addRow("CA bundle:", self.ca)
        f2.addRow("API token:", self.token)
        note = QLabel("TLS certificate and hostname verification are always on.")
        note.setObjectName("subtitle")
        f2.addRow(note)
        self.stack.addWidget(https)
        # Local
        local = QWidget()
        f3 = QFormLayout(local)
        f3.setContentsMargins(0, 0, 0, 0)
        self.local = QLineEdit()
        lb = QPushButton("Browse…")
        lb.clicked.connect(lambda: self.local.setText(
            QFileDialog.getExistingDirectory(self, "Storage folder") or self.local.text()))
        lrow = QHBoxLayout()
        lrow.addWidget(self.local)
        lrow.addWidget(lb)
        f3.addRow("Storage folder:", lrow)
        self.stack.addWidget(local)
        lay.addWidget(self.stack)

        self.backend.currentIndexChanged.connect(lambda *_: self._sync())
        self.auth_key.toggled.connect(lambda *_: self._sync())
        for w in (self.name, self.host, self.user, self.rpath, self.keypath, self.url, self.ca, self.local,
                  self.password, self.passphrase, self.token):
            w.textChanged.connect(lambda *_: self.changed.emit())
        self.port.valueChanged.connect(lambda *_: self.changed.emit())
        self._sync()

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH private key")
        if path:
            self.keypath.setText(path)

    def _sync(self) -> None:
        self.stack.setCurrentIndex(self.backend.currentIndex())
        key = self.auth_key.isChecked()
        for w, visible in ((self.key_row, key), (self.passphrase, key), (self.password, not key)):
            w.setVisible(visible)
            self._sftp_form.labelForField(w).setVisible(visible)
        self.changed.emit()

    def load(self, p: Profile | None) -> None:
        self.name.setText(p.name if p else "")
        idx = self.backend.findData(p.backend if p else "sftp")
        self.backend.setCurrentIndex(max(0, idx))
        self.host.setText(p.host if p else "")
        self.port.setValue(p.port if p else 22)
        self.user.setText(p.username if p else "")
        self.rpath.setText(p.remote_path if p else "")
        (self.auth_pw if p and p.auth_method == "password" else self.auth_key).setChecked(True)
        self.keypath.setText(p.private_key_path if p else "")
        self.url.setText(p.https_base_url if p else "")
        self.ca.setText(p.https_ca_bundle if p else "")
        self.local.setText(p.local_path if p else "")
        for w in (self.password, self.passphrase, self.token):
            w.clear()
            w.setPlaceholderText("leave empty to keep the current value" if p else "")
        self._sync()

    def values(self) -> dict[str, object]:
        return {
            "name": self.name.text().strip() or "Default",
            "backend": self.backend.currentData(),
            "host": self.host.text().strip(), "port": self.port.value(),
            "username": self.user.text().strip(), "remote_path": self.rpath.text().strip(),
            "auth_method": "key" if self.auth_key.isChecked() else "password",
            "private_key_path": self.keypath.text().strip() if self.auth_key.isChecked() else "",
            "https_base_url": self.url.text().strip(), "https_ca_bundle": self.ca.text().strip(),
            "local_path": self.local.text().strip(),
        }

    def secrets(self) -> dict[str, str]:
        out = {}
        if self.backend.currentData() == "sftp":
            if self.auth_key.isChecked() and self.passphrase.text():
                out["ssh-key-passphrase"] = self.passphrase.text()
            if not self.auth_key.isChecked() and self.password.text():
                out["ssh-password"] = self.password.text()
        elif self.backend.currentData() == "https" and self.token.text():
            out["https-token"] = self.token.text()
        return out

    def clear_secrets(self) -> None:
        for w in (self.password, self.passphrase, self.token):
            w.clear()


class StageList(QFrame):
    def __init__(self, stages: list[str]) -> None:
        super().__init__()
        self.setObjectName("card")
        self.grid = QGridLayout(self)
        self.rows: dict[str, tuple[QLabel, QLabel, QLabel]] = {}
        self.set_stages(stages)

    def set_stages(self, stages: list[str]) -> None:
        while self.grid.count():
            w = self.grid.takeAt(0).widget()
            if w is not None:
                w.deleteLater()
        self.rows = {}
        for i, name in enumerate(stages):
            icon, lbl, msg = QLabel("○"), QLabel(name), QLabel("")
            lbl.setStyleSheet("font-weight: 600;")
            msg.setObjectName("subtitle")
            msg.setWordWrap(True)
            msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.grid.addWidget(icon, i, 0)
            self.grid.addWidget(lbl, i, 1)
            self.grid.addWidget(msg, i, 2)
            self.rows[name] = (icon, lbl, msg)
        self.grid.setColumnStretch(2, 1)

    def update_stage(self, name: str, status: str, message: str) -> None:
        if name not in self.rows:
            return
        icon, _, msg = self.rows[name]
        sym, color = _STATUS_STYLE.get(status, ("○", "#8b94a7"))
        icon.setText(sym)
        icon.setStyleSheet(f"color: {color}; font-weight: 700;")
        msg.setText(f"{status}" + (f" — {message}" if message else ""))

    def reset(self) -> None:
        for name in self.rows:
            icon, _, msg = self.rows[name]
            icon.setText("○")
            icon.setStyleSheet("")
            msg.setText("")


class _DiagWorker(TaskWorker):
    def __init__(self, fn: Callable[..., TestReport], operation: str) -> None:
        def job(progress, cancel):
            return fn(callback=lambda n, st, m: progress(n, st, m), cancel=cancel)
        super().__init__(job, operation)


class ConnectionTestPanel(QWidget):
    """Test Connection + SSH host key trust + remote directory creation."""

    finished = Signal(bool)

    def __init__(self, ctx: AppContext, profile_getter: Callable[[], Profile | None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.get_profile = profile_getter
        self.worker: _DiagWorker | None = None
        self.last_ok = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.btn = QPushButton("Test Connection")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(lambda: self.run(False))
        row.addWidget(self.btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.stages = StageList(CONNECTION_STAGES)
        lay.addWidget(self.stages)

        # SSH host key verification (shown only for unknown keys)
        self.hk = QFrame()
        self.hk.setObjectName("card")
        hl = QVBoxLayout(self.hk)
        t = QLabel("Server Host Key")
        t.setStyleSheet("font-size: 12pt; font-weight: 600;")
        self.hk_alg = QLabel()
        self.hk_fp = QLabel()
        self.hk_fp.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hk_fp.setStyleSheet("font-family: Consolas, 'Cascadia Mono', monospace; font-size: 11pt;")
        expl = QLabel("Verify this fingerprint against the fingerprint shown directly on your server before "
                      "trusting it. On the server run:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
        expl.setWordWrap(True)
        expl.setObjectName("warning")
        hb = QHBoxLayout()
        self.trust_btn = QPushButton("Trust This Server")
        self.trust_btn.setObjectName("primary")
        self.trust_btn.clicked.connect(self._trust)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(lambda: self.hk.setVisible(False))
        hb.addWidget(self.trust_btn)
        hb.addWidget(cancel)
        hb.addStretch(1)
        for w in (t, self.hk_alg, self.hk_fp, expl):
            hl.addWidget(w)
        hl.addLayout(hb)
        lay.addWidget(self.hk)
        self.hk.setVisible(False)
        self._pending_key: tuple[str, str] | None = None

        self.changed_warn = QLabel("Server host key changed. Connection blocked for security.\n"
                                   "If your administrator confirms the server was legitimately re-installed, "
                                   "remove the old trusted key in Settings and verify the new fingerprint.")
        self.changed_warn.setObjectName("warning")
        self.changed_warn.setWordWrap(True)
        self.changed_warn.setVisible(False)
        lay.addWidget(self.changed_warn)

        self.mkdir_btn = QPushButton("Create Remote Directory")
        self.mkdir_btn.clicked.connect(self._create_dir)
        self.mkdir_btn.setVisible(False)
        lay.addWidget(self.mkdir_btn)

    def run(self, create_dir: bool) -> None:
        profile = self.get_profile()
        if profile is None:
            return
        self.hk.setVisible(False)
        self.changed_warn.setVisible(False)
        self.mkdir_btn.setVisible(False)
        names = CONNECTION_STAGES if profile.backend == "sftp" else \
            ["Host Reachable", "Remote Path", "Writable", "Readable"]
        self.stages.set_stages(names)
        self.btn.setEnabled(False)
        self.worker = _DiagWorker(
            lambda callback, cancel: run_connection_test(self.ctx.service, profile, create_remote_dir=create_dir,
                                                         callback=callback, cancel=cancel),
            "connection_test",
        )
        self.worker.signals.progress.connect(lambda n, st, m: self.stages.update_stage(n, st, str(m)))
        self.worker.signals.finished.connect(self._done)
        self.worker.signals.failed.connect(self._failed)
        self.ctx.start(self.worker)

    def _done(self, report: TestReport) -> None:
        self.btn.setEnabled(True)
        self.worker = None
        if report.host_key is not None:
            self._pending_key = report.host_key
            self.hk_alg.setText(f"Algorithm: {report.host_key[0]}")
            self.hk_fp.setText(f"Fingerprint: {report.host_key[1]}")
            self.hk.setVisible(True)
        self.changed_warn.setVisible(report.host_key_changed)
        self.mkdir_btn.setVisible(report.remote_missing)
        self.last_ok = report.ok
        self.ctx.profiles_changed.emit()
        self.finished.emit(report.ok)

    def _failed(self, message: str, category: str) -> None:
        self.btn.setEnabled(True)
        self.worker = None
        self.last_ok = False
        first = next(iter(self.stages.rows), "")
        self.stages.update_stage(first, FAIL, message)
        self.finished.emit(False)

    def _trust(self) -> None:
        profile = self.get_profile()
        if profile is None or self._pending_key is None:
            return
        key_type, fp = self._pending_key
        self.ctx.service.db.trust_host_key(profile.host, profile.port, key_type, fp)
        self._pending_key = None
        self.hk.setVisible(False)
        self.run(False)

    def _create_dir(self) -> None:
        profile = self.get_profile()
        if profile is None:
            return
        if confirm(self, "Create Remote Directory",
                   f"Create the folder {profile.remote_path} on {profile.host}?"):
            self.run(True)


class EndToEndPanel(QWidget):
    finished = Signal(bool)

    def __init__(self, ctx: AppContext, profile_getter: Callable[[], Profile | None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.get_profile = profile_getter
        self.last_ok = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        self.btn = QPushButton("Run End-to-End Test")
        self.btn.setObjectName("primary")
        self.btn.clicked.connect(self.run)
        row.addWidget(self.btn)
        row.addStretch(1)
        lay.addLayout(row)
        self.stages = StageList(E2E_STAGES)
        lay.addWidget(self.stages)
        self.note = QLabel("A small random file is encrypted with your real master key, uploaded as an encrypted "
                           "container, downloaded, decrypted, compared byte for byte, then deleted everywhere.")
        self.note.setObjectName("subtitle")
        self.note.setWordWrap(True)
        lay.addWidget(self.note)

    def run(self) -> None:
        profile = self.get_profile()
        if profile is None or not self.ctx.master_key.is_loaded:
            self.stages.update_stage("Encryption", FAIL, "Master key is locked")
            return
        self.stages.reset()
        self.btn.setEnabled(False)
        w = _DiagWorker(
            lambda callback, cancel: run_end_to_end_test(self.ctx.service, profile, callback=callback,
                                                         cancel=cancel),
            "e2e_test",
        )
        w.signals.progress.connect(lambda n, st, m: self.stages.update_stage(n, st, str(m)))
        w.signals.finished.connect(self._done)
        w.signals.failed.connect(lambda m, c: self._fail(m))
        self.ctx.start(w)

    def _done(self, report: TestReport) -> None:
        self.btn.setEnabled(True)
        self.last_ok = report.ok
        self.finished.emit(report.ok)

    def _fail(self, message: str) -> None:
        self.btn.setEnabled(True)
        self.last_ok = False
        self.stages.update_stage("Encryption", FAIL, message)
        self.finished.emit(False)
