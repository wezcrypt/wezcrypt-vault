"""About page: product, developer, security summary and privacy notice.

Links open with QDesktopServices (no shell execution). Never shows key
material, passwords, passphrases, private keys or tokens.
"""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication, QPixmap
from PySide6.QtWidgets import (
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from gui.common import AppContext
from wezcrypt_vault.app_info import (
    APP_DESCRIPTION,
    APP_NAME,
    COPYRIGHT,
    DEVELOPER_NAME,
    DEVELOPER_ROLES,
    GITHUB_URL,
    REPOSITORY_URL,
    WEBSITE_URL,
    app_information,
)
from wezcrypt_vault.version import __version__

SECURITY_SUMMARY = [
    ("Encryption", "AES-256-GCM"),
    ("Encryption Location", "Client-side"),
    ("Master Key", "256-bit unified key"),
    ("Integrity", "Authenticated encryption"),
    ("Remote Storage", "Encrypted file containers only"),
    ("SSH", "Strict host-key verification"),
]


class AboutPage(QWidget):
    def __init__(self, ctx: AppContext, icon_path: str | None = None) -> None:
        super().__init__()
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        scroll.setWidget(body)
        outer.addWidget(scroll)

        head = QHBoxLayout()
        if icon_path:
            pix = QPixmap(icon_path)
            if not pix.isNull():
                logo = QLabel()
                logo.setPixmap(pix.scaled(72, 72))
                head.addWidget(logo)
        tl = QVBoxLayout()
        title = QLabel(APP_NAME)
        title.setObjectName("title")
        sub = QLabel(APP_DESCRIPTION)
        sub.setObjectName("subtitle")
        ver = QLabel(f"Version {__version__}  ·  {COPYRIGHT}")
        ver.setObjectName("subtitle")
        for w in (title, sub, ver):
            tl.addWidget(w)
        head.addLayout(tl)
        head.addStretch(1)
        lay.addLayout(head)

        dev = QGroupBox("Developer")
        df = QFormLayout(dev)
        df.addRow("Developer:", QLabel(DEVELOPER_NAME))
        df.addRow("Roles:", QLabel(" · ".join(DEVELOPER_ROLES)))
        for label, url in (("Website:", WEBSITE_URL), ("GitHub:", GITHUB_URL), ("Repository:", REPOSITORY_URL)):
            link = QLabel(url)
            link.setTextInteractionFlags(link.textInteractionFlags())
            df.addRow(label, link)
        lay.addWidget(dev)

        grid = QGridLayout()
        buttons = [
            ("Visit Website", lambda: self._open(WEBSITE_URL)),
            ("GitHub Profile", lambda: self._open(GITHUB_URL)),
            ("Open Repository", lambda: self._open(REPOSITORY_URL)),
            ("Copy Website", lambda: self._copy(WEBSITE_URL)),
            ("Copy GitHub URL", lambda: self._copy(GITHUB_URL)),
            ("Copy Repository URL", lambda: self._copy(REPOSITORY_URL)),
            ("Copy App Information", lambda: self._copy(app_information())),
        ]
        self.buttons: dict[str, QPushButton] = {}
        for i, (text, fn) in enumerate(buttons):
            b = QPushButton(text)
            b.clicked.connect(fn)
            grid.addWidget(b, i // 3, i % 3)
            self.buttons[text] = b
        lay.addLayout(grid)
        self.feedback = QLabel("")
        self.feedback.setObjectName("subtitle")
        lay.addWidget(self.feedback)

        sec = QGroupBox("Security Summary")
        sf = QFormLayout(sec)
        for k, v in SECURITY_SUMMARY:
            sf.addRow(f"{k}:", QLabel(v))
        lay.addWidget(sec)

        priv = QGroupBox("Privacy")
        pl = QVBoxLayout(priv)
        for t in ("WezCrypt Vault encrypts files locally before upload.",
                  "The configured storage server receives encrypted file containers and does not require "
                  "access to the master encryption key."):
            lbl = QLabel(t)
            lbl.setWordWrap(True)
            pl.addWidget(lbl)
        lay.addWidget(priv)

        notice = QLabel(
            "Important security notice\n\n"
            "Your unified master key protects all files encrypted with it.\n"
            "Keep at least one secure offline backup.\n"
            "Loss of the key may make encrypted files permanently unrecoverable.\n"
            "Anyone who obtains the key may be able to decrypt all protected files."
        )
        notice.setObjectName("warning")
        notice.setWordWrap(True)
        lay.addWidget(notice)
        lay.addStretch(1)

    def _open(self, url: str) -> None:
        # QDesktopServices hands the URL to the OS handler; no shell is invoked.
        ok = QDesktopServices.openUrl(QUrl(url))
        self.feedback.setText(f"Opened {url}" if ok else f"Could not open a browser. Link: {url}")

    def _copy(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self.feedback.setText("Copied to clipboard.")
