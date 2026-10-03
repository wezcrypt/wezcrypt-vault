from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def test_main_window_builds_and_runs_workers(app, tmp_path, key, remote_dir, monkeypatch):
    from PySide6.QtCore import QEventLoop, QTimer

    from gui.common import AppContext
    from gui.main_window import MainWindow
    from utils.config import AppConfig
    from conftest import write_file

    monkeypatch.setattr(MainWindow, "_startup", lambda self: None)
    dialogs = []
    for name in ("warning", "information", "critical"):
        monkeypatch.setattr(QtWidgets.QMessageBox, name, staticmethod(lambda *a, **k: dialogs.append(a[1:3])))
    cfg = AppConfig()
    cfg.server.backend = "local"
    cfg.server.local_path = str(remote_dir)
    cfg.encryption.chunk_size = 4096
    ctx = AppContext(tmp_path / "home", cfg)
    win = MainWindow(ctx)
    win.show()
    for name in ("dashboard", "encrypt", "decrypt", "files", "key", "settings", "logs"):
        win.go(name)
        app.processEvents()
    ctx.master_key.load(key)
    ctx.key_changed.emit()
    ctx.service.acknowledge_backup()
    from services.diagnostics import run_connection_test
    assert run_connection_test(ctx.service, ctx.service.profiles.require_active()).ok
    assert "loaded" in win.key_status.text().lower()

    page = win.pages["encrypt"]
    page.set_file(str(write_file(tmp_path / "doc.pdf", 50_000)))
    loop = QEventLoop()
    done = {}
    page.progress.stage.setText("x")
    def finished(r):
        done["r"] = r
        loop.quit()
    def failed(m, c):
        done["err"] = m
        loop.quit()
    page._start(upload=True)
    page.worker.signals.finished.connect(finished)
    page.worker.signals.failed.connect(failed)
    QTimer.singleShot(30000, loop.quit)
    loop.exec()
    assert "err" not in done, done.get("err")
    app.processEvents()
    assert win.pages["files"].table.rowCount() == 1
    assert len(list(remote_dir.iterdir())) == 1
    win.close()


def test_about_page_links_and_no_secrets(app, tmp_path, key, monkeypatch):
    from PySide6.QtGui import QDesktopServices, QGuiApplication

    from gui.about_page import AboutPage
    from gui.common import AppContext
    from crypto.key_manager import encode_recovery_key
    from utils.config import AppConfig
    from wezcrypt_vault.app_info import GITHUB_URL, REPOSITORY_URL, WEBSITE_URL

    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toString()) or True))
    ctx = AppContext(tmp_path / "home", AppConfig())
    ctx.master_key.load(key)
    page = AboutPage(ctx)
    for label in ("Visit Website", "GitHub Profile", "Open Repository"):
        page.buttons[label].click()
    assert opened == [WEBSITE_URL, GITHUB_URL, REPOSITORY_URL]
    page.buttons["Copy Repository URL"].click()
    assert QGuiApplication.clipboard().text() == REPOSITORY_URL
    page.buttons["Copy App Information"].click()
    info = QGuiApplication.clipboard().text()
    assert "AES-256-GCM" in info and encode_recovery_key(key) not in info
    texts = " ".join(w.text() for w in page.findChildren(QtWidgets.QLabel))
    assert "wezcrypt-v1-" not in texts and key.hex() not in texts
    for expected in ("AES-256-GCM", "Client-side", "256-bit unified key", "Strict host-key verification"):
        assert expected in texts
