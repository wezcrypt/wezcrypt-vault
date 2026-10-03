"""Drive the real first-run Setup Wizard end to end against a live in-process SFTP server."""

from __future__ import annotations

import os
import time

import paramiko
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def wait_for(app, cond, timeout=30.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_first_run_wizard_complete_flow(app, tmp_path, key, monkeypatch):
    import gui.server_widgets as sw
    from gui.common import AppContext
    from gui.setup_wizard import P_AUTH, P_DETAILS, P_DONE, P_E2E, P_HOSTKEY, P_KEY, P_TEST, P_TYPE, SetupWizard
    from sftp_server import LocalSFTPServer
    from utils.config import AppConfig

    for name in ("warning", "information", "critical"):
        monkeypatch.setattr(QtWidgets.QMessageBox, name, staticmethod(lambda *a, **k: None))
    monkeypatch.setattr(sw, "confirm", lambda *a, **k: True)  # user confirms "Create Remote Directory"

    host_key, client_key = paramiko.ECDSAKey.generate(bits=256), paramiko.ECDSAKey.generate(bits=256)
    kp = tmp_path / "id_ecdsa"
    client_key.write_private_key_file(str(kp))
    root = tmp_path / "sftproot"
    root.mkdir()
    srv = LocalSFTPServer(root, "storageuser", client_key, host_key)
    try:
        ctx = AppContext(tmp_path / "home", AppConfig())
        assert ctx.service.needs_setup()
        wiz = SetupWizard(ctx)
        wiz.show()
        assert wiz.currentId() == 0
        wiz.next()
        assert wiz.currentId() == P_KEY and not wiz.currentPage().isComplete()
        ctx.master_key.load(key)
        ctx.key_changed.emit()
        assert not wiz.currentPage().isComplete(), "acknowledgment required"
        wiz.currentPage().ack.setChecked(True)
        assert wiz.currentPage().isComplete()
        wiz.next()
        assert wiz.currentId() == P_TYPE and ctx.service.backup_acknowledged()
        wiz.next()
        assert wiz.currentId() == P_DETAILS
        d = wiz.details_page
        d.host.setText("127.0.0.1")
        d.port.setValue(srv.port)
        d.user.setText("storageuser")
        d.rpath.setText("/storage/encrypted/")
        wiz.next()
        assert wiz.currentId() == P_AUTH
        wiz.currentPage().keypath.setText(str(kp))
        wiz.next()
        assert wiz.currentId() == P_HOSTKEY
        page = wiz.currentPage()
        assert wait_for(app, lambda: page.trust.isVisible()), page.state.text()
        assert not srv.auth_attempted.is_set()
        assert "SHA256:" in page.fp.text() and not page.isComplete()
        page.trust.click()
        assert page.isComplete()
        wiz.next()
        assert wiz.currentId() == P_TEST
        tp = wiz.currentPage()
        assert wait_for(app, lambda: tp.panel.mkdir_btn.isVisible()), "missing directory offered for creation"
        assert not (root / "storage").exists()
        tp.panel.mkdir_btn.click()
        assert wait_for(app, tp.isComplete), [r[2].text() for r in tp.panel.stages.rows.values()]
        assert (root / "storage" / "encrypted").is_dir()
        wiz.next()
        assert wiz.currentId() == P_E2E
        ep = wiz.currentPage()
        ep.panel.btn.click()
        assert wait_for(app, ep.isComplete), [r[2].text() for r in ep.panel.stages.rows.values()]
        assert all(r[2].text().startswith("PASS") for r in ep.panel.stages.rows.values())
        wiz.next()
        assert wiz.currentId() == P_DONE
        assert ctx.service.setup_completed() and not ctx.service.needs_setup()
        prof = ctx.service.profiles.active()
        assert prof.connection_tested_at is not None and prof.host == "127.0.0.1"
        assert list((root / "storage" / "encrypted").iterdir()) == []
        wiz.close()
    finally:
        srv.close()
