"""First-run Setup Wizard.

Welcome → Master Key → Storage Type → Server Details → Authentication →
Server Identity (SSH fingerprint) → Test Connection (incl. remote directory)
→ End-to-End Test → Setup Complete.

Server credentials are only ever collected here inside the app (never by the
installer) and are stored in the OS credential store, or kept in memory for
this session when no secure store exists.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from database.database import Profile
from gui.common import AppContext, apply_theme, warn
from gui.key_actions import ACK_TEXT, WARN_ALL, WARN_LOST, WARN_PROTECTS, KeyActions
from gui.server_widgets import ConnectionTestPanel, EndToEndPanel
from services.profiles import normalize_profile
from storage.sftp import fetch_host_key
from utils.errors import WezCryptError
from workers.common import TaskWorker
from wezcrypt_vault.app_info import APP_DESCRIPTION, APP_NAME

P_WELCOME, P_KEY, P_TYPE, P_DETAILS, P_AUTH, P_HOSTKEY, P_TEST, P_E2E, P_DONE = range(9)


def _text(t: str, obj: str = "") -> QLabel:
    lbl = QLabel(t)
    lbl.setWordWrap(True)
    if obj:
        lbl.setObjectName(obj)
    return lbl


class WelcomePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle(f"Welcome to {APP_NAME}")
        self.setSubTitle(APP_DESCRIPTION)
        lay = QVBoxLayout(self)
        lay.addWidget(_text("WezCrypt Vault encrypts files locally before uploading them to your configured "
                            "storage server."))
        lay.addWidget(_text("The storage server receives encrypted file containers and does not require access "
                            "to your master encryption key."))
        lay.addWidget(_text("This wizard sets up your master key, connects your storage server, verifies its "
                            "identity and runs a real encrypted round-trip test.", "subtitle"))
        lay.addStretch(1)
        self.setButtonText(QWizard.NextButton, "Start Setup")


class MasterKeyPage(QWizardPage):
    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.actions = KeyActions(ctx, self)
        self.setTitle("Master Key")
        self.setSubTitle("One 256-bit AES master key protects every file you encrypt.")
        lay = QVBoxLayout(self)
        for t in (WARN_PROTECTS, WARN_LOST, WARN_ALL):
            lay.addWidget(_text("⚠ " + t, "warning"))
        row = QHBoxLayout()
        self.b_gen = QPushButton("Generate New Master Key")
        self.b_gen.setObjectName("primary")
        self.b_imp = QPushButton("Import Existing Master Key")
        self.b_gen.clicked.connect(lambda: self.actions.generate() and self._refresh())
        self.b_imp.clicked.connect(lambda: self.actions.import_key() and self._refresh())
        row.addWidget(self.b_gen)
        row.addWidget(self.b_imp)
        lay.addLayout(row)
        self.status = _text("")
        lay.addWidget(self.status)
        self.field = QLineEdit()
        self.field.setReadOnly(True)
        self.field.setEchoMode(QLineEdit.Password)
        self.field.setStyleSheet("font-family: Consolas, 'Cascadia Mono', monospace;")
        lay.addWidget(self.field)
        brow = QHBoxLayout()
        self.b_show = QPushButton("Show / Hide")
        self.b_copy = QPushButton("Copy")
        self.b_save = QPushButton("Save Backup")
        self.b_verify = QPushButton("Verify Backup")
        self.b_show.clicked.connect(lambda: self.field.setEchoMode(
            QLineEdit.Normal if self.field.echoMode() == QLineEdit.Password else QLineEdit.Password))
        self.b_copy.clicked.connect(self.actions.copy)
        self.b_save.clicked.connect(self.actions.save_backup)
        self.b_verify.clicked.connect(self.actions.verify_backup)
        for b in (self.b_show, self.b_copy, self.b_save, self.b_verify):
            brow.addWidget(b)
        lay.addLayout(brow)
        lay.addWidget(_text(ACK_TEXT, "subtitle"))
        self.ack = QCheckBox("I understand and accept this responsibility")
        self.ack.toggled.connect(lambda *_: self.completeChanged.emit())
        lay.addWidget(self.ack)
        lay.addStretch(1)
        ctx.key_changed.connect(lambda *_: self._refresh())

    def initializePage(self) -> None:
        self.ack.setChecked(self.ctx.service.backup_acknowledged())
        self._refresh()

    def _refresh(self) -> bool:
        loaded = self.ctx.master_key.is_loaded
        self.status.setText(f"✔ Master key loaded — fingerprint {self.ctx.master_key.info().display_fingerprint}"
                            if loaded else "No master key loaded yet.")
        self.field.setText(self.ctx.master_key.recovery_string() if loaded else "")
        self.field.setEchoMode(QLineEdit.Password)
        for b in (self.b_show, self.b_copy, self.b_save, self.b_verify):
            b.setEnabled(loaded)
        self.b_gen.setEnabled(not loaded)
        self.b_imp.setEnabled(not loaded)
        self.completeChanged.emit()
        return True

    def isComplete(self) -> bool:
        return self.ctx.master_key.is_loaded and self.ack.isChecked()

    def validatePage(self) -> bool:
        self.ctx.service.acknowledge_backup()
        self.field.clear()
        return True


class StorageTypePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Storage Type")
        self.setSubTitle("Where should encrypted containers be stored?")
        lay = QVBoxLayout(self)
        self.sftp = QRadioButton("SFTP Server (recommended) — any Linux/BSD server or VPS with SSH")
        self.https = QRadioButton("HTTPS API — an object-storage API you operate (TLS always verified)")
        self.sftp.setChecked(True)
        g = QButtonGroup(self)
        g.addButton(self.sftp)
        g.addButton(self.https)
        lay.addWidget(self.sftp)
        lay.addWidget(self.https)
        lay.addStretch(1)

    @property
    def backend(self) -> str:
        return "sftp" if self.sftp.isChecked() else "https"


class ServerDetailsPage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("Server Details")
        self.setSubTitle("The example values are placeholders only.")
        lay = QVBoxLayout(self)
        f = QFormLayout()
        self.name = QLineEdit("Personal VPS")
        self.host = QLineEdit()
        self.host.setPlaceholderText("example.com")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)
        self.user = QLineEdit()
        self.user.setPlaceholderText("storageuser")
        self.rpath = QLineEdit()
        self.rpath.setPlaceholderText("/storage/encrypted/")
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://storage.example.com/api")
        self.ca = QLineEdit()
        self.ca.setPlaceholderText("optional private CA bundle (.pem)")
        f.addRow("Profile name:", self.name)
        self._rows_sftp = [("Server Host / IP:", self.host), ("SSH Port:", self.port),
                           ("Username:", self.user), ("Remote Storage Path:", self.rpath)]
        self._rows_https = [("API address:", self.url), ("CA bundle:", self.ca)]
        for label, w in self._rows_sftp + self._rows_https:
            f.addRow(label, w)
        self.form = f
        lay.addLayout(f)
        lay.addStretch(1)
        for w in (self.name, self.host, self.user, self.rpath, self.url):
            w.textChanged.connect(lambda *_: self.completeChanged.emit())

    def initializePage(self) -> None:
        sftp = self.wiz.type_page.backend == "sftp"
        for _, w in self._rows_sftp:
            w.setVisible(sftp)
            self.form.labelForField(w).setVisible(sftp)
        for _, w in self._rows_https:
            w.setVisible(not sftp)
            self.form.labelForField(w).setVisible(not sftp)

    def isComplete(self) -> bool:
        if not self.name.text().strip():
            return False
        if self.wiz.type_page.backend == "sftp":
            return bool(self.host.text().strip() and self.user.text().strip() and self.rpath.text().strip())
        return self.url.text().strip().startswith("https://")


class AuthPage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("Authentication")
        self.setSubTitle("SSH public-key authentication is recommended. Secrets are stored in the OS "
                         "credential store, never in plain-text files.")
        lay = QVBoxLayout(self)
        self.key = QRadioButton("SSH Private Key")
        self.pw = QRadioButton("SSH Password")
        self.key.setChecked(True)
        g = QButtonGroup(self)
        g.addButton(self.key)
        g.addButton(self.pw)
        r = QHBoxLayout()
        r.addWidget(self.key)
        r.addWidget(self.pw)
        r.addStretch(1)
        self.method_row = QWidget()
        self.method_row.setLayout(r)
        lay.addWidget(self.method_row)
        f = QFormLayout()
        self.keypath = QLineEdit()
        self.keypath.setPlaceholderText("C:/Users/you/.ssh/id_ed25519")
        kb = QPushButton("Browse...")
        kb.clicked.connect(self._browse)
        kr = QHBoxLayout()
        kr.setContentsMargins(0, 0, 0, 0)
        kr.addWidget(self.keypath)
        kr.addWidget(kb)
        self.key_row = QWidget()
        self.key_row.setLayout(kr)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.Password)
        self.passphrase.setPlaceholderText("only if the key is encrypted")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.Password)
        f.addRow("Private Key Path:", self.key_row)
        f.addRow("Private Key Passphrase:", self.passphrase)
        f.addRow("SSH Password:", self.password)
        f.addRow("API token:", self.token)
        self.form = f
        lay.addLayout(f)
        self.store_note = _text("", "subtitle")
        lay.addWidget(self.store_note)
        lay.addStretch(1)
        self.key.toggled.connect(lambda *_: self._sync())
        for w in (self.keypath, self.password, self.token):
            w.textChanged.connect(lambda *_: self.completeChanged.emit())

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH private key")
        if path:
            self.keypath.setText(path)

    def initializePage(self) -> None:
        self._sync()

    def _sync(self) -> None:
        sftp = self.wiz.type_page.backend == "sftp"
        key = self.key.isChecked()
        self.method_row.setVisible(sftp)
        for w, vis in ((self.key_row, sftp and key), (self.passphrase, sftp and key),
                       (self.password, sftp and not key), (self.token, not sftp)):
            w.setVisible(vis)
            self.form.labelForField(w).setVisible(vis)
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        if self.wiz.type_page.backend != "sftp":
            return True
        return bool(self.keypath.text().strip()) if self.key.isChecked() else bool(self.password.text())

    def validatePage(self) -> bool:
        d = self.wiz.details_page
        sftp = self.wiz.type_page.backend == "sftp"
        values = {
            "name": d.name.text().strip(), "backend": self.wiz.type_page.backend,
            "host": d.host.text().strip(), "port": d.port.value(), "username": d.user.text().strip(),
            "remote_path": d.rpath.text().strip(), "auth_method": "key" if self.key.isChecked() else "password",
            "private_key_path": self.keypath.text().strip() if self.key.isChecked() else "",
            "https_base_url": d.url.text().strip(), "https_ca_bundle": d.ca.text().strip(),
        }
        try:
            normalize_profile(values)
            pm = self.wiz.ctx.service.profiles
            if self.wiz.profile_id is None:
                prof = pm.create(values, make_active=True)
                self.wiz.profile_id = prof.id
            else:
                prof = pm.update(self.wiz.profile_id, values)
                pm.set_active(prof.id)
            secrets = {}
            if sftp and self.key.isChecked():
                secrets["ssh-key-passphrase"] = self.passphrase.text()
            elif sftp:
                secrets["ssh-password"] = self.password.text()
            else:
                secrets["https-token"] = self.token.text()
            persisted = True
            for kind, value in secrets.items():
                persisted = pm.set_secret(prof, kind, value).persisted and persisted
            if secrets and any(secrets.values()) and not persisted:
                QMessageBox.information(self, "Credential storage",
                                        "No secure OS credential store is available, so the secret is kept in "
                                        "memory for this session only. You will be asked again next time.")
        except WezCryptError as exc:
            warn(self, "Check the details", str(exc))
            return False
        self.wiz.ctx.profiles_changed.emit()
        return True


class HostKeyPage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("Server Identity")
        self.setSubTitle("Verify the server's SSH host key before any credential is sent to it.")
        lay = QVBoxLayout(self)
        self.state = _text("")
        self.alg = _text("")
        self.fp = QLabel("")
        self.fp.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.fp.setStyleSheet("font-family: Consolas, 'Cascadia Mono', monospace; font-size: 12pt;")
        self.expl = _text("Verify this fingerprint against the fingerprint shown directly on your server before "
                          "trusting it. On the server run:\n    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub",
                          "warning")
        row = QHBoxLayout()
        self.trust = QPushButton("Trust This Server")
        self.trust.setObjectName("primary")
        self.trust.clicked.connect(self._trust)
        self.retry = QPushButton("Retrieve Fingerprint Again")
        self.retry.clicked.connect(self.initializePage)
        row.addWidget(self.trust)
        row.addWidget(self.retry)
        row.addStretch(1)
        for w in (self.state, self.alg, self.fp, self.expl):
            lay.addWidget(w)
        lay.addLayout(row)
        lay.addStretch(1)
        self._key: tuple[str, str] | None = None
        self._trusted = False

    def _profile(self) -> Profile:
        p = self.wiz.ctx.service.profiles.get(self.wiz.profile_id)  # type: ignore[arg-type]
        assert p is not None
        return p

    def initializePage(self) -> None:
        p = self._profile()
        self._key, self._trusted = None, False
        self.trust.setVisible(False)
        self.expl.setVisible(False)
        self.alg.setText("")
        self.fp.setText("")
        self.state.setText(f"Connecting to {p.host}:{p.port} …")
        self.retry.setEnabled(False)
        worker = TaskWorker(lambda progress, cancel: fetch_host_key(p.host, p.port, timeout=15), "fetch_host_key")
        worker.signals.finished.connect(self._fetched)
        worker.signals.failed.connect(self._fetch_failed)
        self.wiz.ctx.start(worker)
        self.completeChanged.emit()

    def _fetch_failed(self, message: str, category: str) -> None:
        self.retry.setEnabled(True)
        self.state.setText("✖ " + message)
        self.completeChanged.emit()

    def _fetched(self, result: tuple[str, str]) -> None:
        self.retry.setEnabled(True)
        p = self._profile()
        key_type, fp = result
        stored = self.wiz.ctx.service.db.get_host_key(p.host, p.port)
        self.alg.setText(f"Algorithm: {key_type}")
        self.fp.setText(f"Fingerprint: {fp}")
        if stored is not None and stored == (key_type, fp):
            self._trusted = True
            self.state.setText("✔ This server is already trusted and its key matches.")
        elif stored is not None:
            self.state.setText("✖ Server host key changed. Connection blocked for security. "
                               "There is no way to continue with this key.")
        else:
            self._key = (key_type, fp)
            self.state.setText("First connection to this server.")
            self.trust.setVisible(True)
            self.expl.setVisible(True)
        self.completeChanged.emit()

    def _trust(self) -> None:
        if self._key is None:
            return
        p = self._profile()
        self.wiz.ctx.service.db.trust_host_key(p.host, p.port, *self._key)
        self._trusted = True
        self.trust.setVisible(False)
        self.state.setText("✔ Server trusted. Its fingerprint is saved; any future change will be blocked.")
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        return self._trusted


class TestPage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("Test Connection")
        self.setSubTitle("Checks reachability, SSH, authentication, the remote folder, and write/read access "
                         "with a temporary probe that is deleted immediately. No user data is uploaded.")
        lay = QVBoxLayout(self)
        self.panel = ConnectionTestPanel(wizard.ctx, lambda: wizard.ctx.service.profiles.get(wizard.profile_id))
        self.panel.finished.connect(lambda *_: self.completeChanged.emit())
        lay.addWidget(self.panel)
        lay.addStretch(1)

    def initializePage(self) -> None:
        self.panel.last_ok = False
        self.panel.run(False)

    def isComplete(self) -> bool:
        return self.panel.last_ok


class E2EPage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("End-to-End Test")
        self.setSubTitle("Proves the full encrypted path works before you store real files.")
        lay = QVBoxLayout(self)
        self.panel = EndToEndPanel(wizard.ctx, lambda: wizard.ctx.service.profiles.get(wizard.profile_id))
        self.panel.finished.connect(lambda *_: self.completeChanged.emit())
        lay.addWidget(self.panel)
        lay.addStretch(1)

    def isComplete(self) -> bool:
        return self.panel.last_ok


class DonePage(QWizardPage):
    def __init__(self, wizard: "SetupWizard") -> None:
        super().__init__()
        self.wiz = wizard
        self.setTitle("Setup Complete")
        lay = QVBoxLayout(self)
        t = QLabel("WezCrypt Vault is ready.")
        t.setStyleSheet("font-size: 16pt; font-weight: 600;")
        lay.addWidget(t)
        lay.addWidget(_text("Keep at least one secure offline backup of your master key.", "subtitle"))
        row = QHBoxLayout()
        start = QPushButton("Start Using WezCrypt Vault")
        start.setObjectName("primary")
        settings = QPushButton("Open Settings")
        start.clicked.connect(lambda: self._finish("start"))
        settings.clicked.connect(lambda: self._finish("settings"))
        row.addWidget(start)
        row.addWidget(settings)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addStretch(1)
        self.setFinalPage(True)

    def initializePage(self) -> None:
        self.wiz.ctx.service.mark_setup_completed()

    def _finish(self, action: str) -> None:
        self.wiz.next_action = action
        self.wiz.accept()


class SetupWizard(QWizard):
    def __init__(self, ctx: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.next_action = "start"
        active = ctx.service.profiles.active()
        self.profile_id: int | None = active.id if active else None
        self.setWindowTitle(f"{APP_NAME} Setup")
        self.setWizardStyle(QWizard.ModernStyle)
        self.setOption(QWizard.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.NoCancelButtonOnLastPage, True)
        self.setMinimumSize(760, 600)
        self.type_page = StorageTypePage()
        self.details_page = ServerDetailsPage(self)
        self.setPage(P_WELCOME, WelcomePage())
        self.setPage(P_KEY, MasterKeyPage(ctx))
        self.setPage(P_TYPE, self.type_page)
        self.setPage(P_DETAILS, self.details_page)
        self.setPage(P_AUTH, AuthPage(self))
        self.setPage(P_HOSTKEY, HostKeyPage(self))
        self.setPage(P_TEST, TestPage(self))
        self.setPage(P_E2E, E2EPage(self))
        self.setPage(P_DONE, DonePage(self))
        if active is not None:
            self._prefill(active)
        apply_theme(self, ctx.config.ui.dark_mode)

    def _prefill(self, p: Profile) -> None:
        d = self.details_page
        (self.type_page.https if p.backend == "https" else self.type_page.sftp).setChecked(True)
        d.name.setText(p.name)
        d.host.setText(p.host)
        d.port.setValue(p.port)
        d.user.setText(p.username)
        d.rpath.setText(p.remote_path)
        d.url.setText(p.https_base_url)
        d.ca.setText(p.https_ca_bundle)

    def nextId(self) -> int:
        cur = self.currentId()
        if cur == P_AUTH and self.type_page.backend != "sftp":
            return P_TEST
        return super().nextId()
