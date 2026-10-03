"""WezCrypt Vault entry point.

No keys or credentials live in this file. The master key is generated or
imported by the user at runtime (Setup Wizard or Master Key page).

``WezCryptVault.exe --self-test --report <file.json>`` runs the packaged-app
smoke test used by the release pipeline (isolated temporary data folder;
never touches the user's real vault).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from wezcrypt_vault.app_info import APP_ID, APP_NAME, DEVELOPER_NAME, WEBSITE_URL
from wezcrypt_vault.version import __version__


def resource_path(rel: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / rel


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=APP_ID, description=f"{APP_NAME} {__version__}")
    p.add_argument("--self-test", action="store_true", help="run the packaged-application smoke test and exit")
    p.add_argument("--report", type=Path, help="write the self-test JSON report to this file")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    args, _qt_args = p.parse_known_args(argv[1:])
    return args


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    args = parse_args(argv)
    if args.self_test:
        from selftest import run_self_test

        return run_self_test(args.report, resource_path("assets/icon.png"))

    from gui.common import AppContext
    from gui.main_window import MainWindow
    from utils.app_paths import resolve_paths
    from utils.config import load_config
    from utils.errors import ConfigError
    from utils.logging import configure_logging, log_event

    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(DEVELOPER_NAME)
    app.setOrganizationDomain(WEBSITE_URL.split("//", 1)[-1])
    icon_file = resource_path("assets/icon.png")
    icon = QIcon(str(icon_file)) if icon_file.exists() else None
    if icon is not None:
        app.setWindowIcon(icon)

    try:
        paths = resolve_paths()
    except OSError as exc:
        QMessageBox.critical(None, APP_NAME, f"The user data folder could not be created ({exc.strerror}).")
        return 2
    try:
        config = load_config(paths.config_file)
    except ConfigError as exc:
        QMessageBox.critical(None, "Configuration error",
                             f"{exc}\n\nFix or delete {paths.config_file} and restart.")
        return 2
    configure_logging(paths.logs, log_filenames=config.privacy.log_filenames)
    log_event("startup", status="ok", detail=f"version={__version__}")
    try:
        ctx = AppContext(paths, config)
    except Exception as exc:  # e.g. locked/corrupt database: friendly message, no traceback dialog
        from utils.friendly import describe_error

        QMessageBox.critical(None, APP_NAME, describe_error(exc)[0])
        return 2
    window = MainWindow(ctx, icon, str(icon_file) if icon_file.exists() else None)
    window.show()
    code = app.exec()
    log_event("shutdown", status="ok")
    return code


if __name__ == "__main__":
    sys.exit(main())
