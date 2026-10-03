"""Packaged-application smoke test (``WezCryptVault.exe --self-test``).

Runs inside the real frozen binary to prove the bundle is complete:
Qt platform/image/style plugins load, every page renders, bundled crypto
and SSH libraries import and work, the keyring backend loads without
crashing, user-data directories resolve, and a real encrypt/decrypt round
trip succeeds. Uses an isolated temporary data folder and a throwaway key;
the user's real vault is never touched.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Callable

from wezcrypt_vault.version import __version__


class _Checks:
    def __init__(self) -> None:
        self.results: list[dict[str, object]] = []

    def run(self, name: str, fn: Callable[[], str]) -> None:
        try:
            detail = fn()
            self.results.append({"name": name, "ok": True, "detail": detail})
        except Exception as exc:  # recorded, never raised
            self.results.append({"name": name, "ok": False,
                                 "detail": f"{type(exc).__name__}: {exc}",
                                 "trace": traceback.format_exc(limit=4)})

    @property
    def ok(self) -> bool:
        return bool(self.results) and all(r["ok"] for r in self.results)


def run_self_test(report: Path | None, icon_path: Path) -> int:
    checks = _Checks()
    tmp_root = Path(tempfile.mkdtemp(prefix="wezcrypt-selftest-"))
    real_home = os.environ.get("WEZCRYPT_HOME")

    def user_dirs() -> str:
        from utils.app_paths import default_root

        if real_home is None:
            os.environ.pop("WEZCRYPT_HOME", None)
        root = default_root()
        anchor = root
        while not anchor.exists():  # the app creates missing folders below the first existing one
            if anchor.parent == anchor:
                raise RuntimeError(f"no existing ancestor for {root}")
            anchor = anchor.parent
        if not anchor.is_dir() or not os.access(anchor, os.W_OK):
            raise RuntimeError(f"user data location is not writable: {anchor}")
        return f"{root} (writable via {anchor})"

    checks.run("user-data directories", user_dirs)
    os.environ["WEZCRYPT_HOME"] = str(tmp_root / "home")

    def imports() -> str:
        import bcrypt
        import cffi
        import cryptography
        import nacl.bindings
        import paramiko
        import PySide6
        import sqlite3
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        AESGCM(AESGCM.generate_key(bit_length=256)).encrypt(os.urandom(12), b"x", b"")
        paramiko.ECDSAKey.generate(bits=256)
        bcrypt.kdf(b"p", b"saltsalt", 16, 1, ignore_few_rounds=True)
        nacl.bindings.crypto_sign_keypair()
        return (f"cryptography {cryptography.__version__}, paramiko {paramiko.__version__}, "
                f"PySide6 {PySide6.__version__}, cffi {cffi.__version__}, sqlite {sqlite3.sqlite_version}")

    checks.run("bundled libraries", imports)

    def keyring_ok() -> str:
        from security import credentials

        name = credentials.backend_name()
        return f"{name} (secure={credentials.is_available()})"

    checks.run("keyring integration", keyring_ok)

    from PySide6.QtGui import QImageReader, QPixmap
    from PySide6.QtWidgets import QApplication, QStyleFactory

    app = QApplication.instance() or QApplication([sys.argv[0]])

    def qt_runtime() -> str:
        platform = QApplication.platformName()
        if not platform:
            raise RuntimeError("no Qt platform plugin loaded")
        fmts = {bytes(f).decode() for f in QImageReader.supportedImageFormats()}
        missing = {"png", "ico", "jpg"} - fmts
        if missing:
            raise RuntimeError(f"image format plugins missing: {sorted(missing)}")
        if not QStyleFactory.keys():
            raise RuntimeError("no Qt styles available")
        if icon_path.exists() and QPixmap(str(icon_path)).isNull():
            raise RuntimeError("bundled icon could not be loaded")
        return f"platform={platform}, styles={QStyleFactory.keys()}, icon={'yes' if icon_path.exists() else 'no'}"

    checks.run("Qt runtime and plugins", qt_runtime)

    state: dict[str, object] = {}

    def main_window() -> str:
        from PySide6.QtGui import QIcon

        from gui.common import AppContext
        from gui.main_window import PAGES, MainWindow
        from utils.app_paths import resolve_paths
        from utils.config import AppConfig
        from utils.logging import configure_logging

        paths = resolve_paths()
        configure_logging(paths.logs)
        ctx = AppContext(paths, AppConfig())
        win = MainWindow(ctx, QIcon(str(icon_path)), str(icon_path), run_startup=False)
        win.show()
        rendered = []
        for key, label in PAGES:
            win.go(key)
            app.processEvents()
            if win.grab().isNull():
                raise RuntimeError(f"page {label} did not render")
            rendered.append(label)
        state["ctx"], state["win"] = ctx, win
        return "rendered: " + ", ".join(rendered)

    checks.run("main window and all pages", main_window)

    def wizard() -> str:
        from gui.setup_wizard import SetupWizard

        ctx = state["ctx"]
        wiz = SetupWizard(ctx)  # type: ignore[arg-type]
        wiz.show()
        app.processEvents()
        ok = not wiz.grab().isNull()
        wiz.close()
        if not ok:
            raise RuntimeError("setup wizard did not render")
        return f"needs_setup={ctx.service.needs_setup()}"  # type: ignore[attr-defined]

    checks.run("first-run setup wizard", wizard)

    def crypto_round_trip() -> str:
        from crypto.key_manager import generate_master_key

        ctx = state["ctx"]
        ctx.master_key.load(generate_master_key())  # type: ignore[attr-defined]
        svc = ctx.service  # type: ignore[attr-defined]
        src = tmp_root / "selftest-input.bin"
        data = os.urandom(300_000)
        src.write_bytes(data)
        outcome = svc.encrypt(src)
        if data[:4096] in outcome.container_path.read_bytes():
            raise RuntimeError("plaintext visible in container")
        out = tmp_root / "restored"
        out.mkdir()
        res = svc.decrypt_local(outcome.container_path, out)
        if res.output_path.read_bytes() != data:
            raise RuntimeError("decrypted data differs")
        ctx.master_key.lock()  # type: ignore[attr-defined]
        return f"{len(data)} bytes, {outcome.result.total_chunks} chunk(s), AES-256-GCM"

    checks.run("encryption and decryption", crypto_round_trip)

    win = state.get("win")
    if win is not None:
        win.close()  # type: ignore[attr-defined]
    payload = {"app_version": __version__, "frozen": bool(getattr(sys, "frozen", False)),
               "ok": checks.ok, "checks": checks.results}
    text = json.dumps(payload, indent=2)
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(text, encoding="utf-8")
    if sys.stdout is not None:
        try:
            print(text)
        except OSError:
            pass
    shutil.rmtree(tmp_root, ignore_errors=True)
    if real_home is None:
        os.environ.pop("WEZCRYPT_HOME", None)
    else:
        os.environ["WEZCRYPT_HOME"] = real_home
    return 0 if checks.ok else 1
