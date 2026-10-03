"""Release consistency: single version source, metadata, packaging inputs, no unsafe patterns."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from wezcrypt_vault import app_info
from wezcrypt_vault.version import __version__, version_tuple

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_single_source():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)
    assert version_tuple()[:3] == tuple(int(x) for x in __version__.split("."))
    py = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert py["project"]["dynamic"] == ["version"]
    assert py["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "wezcrypt_vault.version.__version__"
    spec = (ROOT / "packaging" / "WezCryptVault.spec").read_text(encoding="utf-8")
    assert "from wezcrypt_vault.version import" in spec
    iss = (ROOT / "packaging" / "WezCryptVault.iss").read_text(encoding="utf-8")
    assert "AppVersion={#AppVersion}" in iss and "OutputBaseFilename=WezCryptVault-Setup-{#AppVersion}" in iss
    assert "wezcrypt_vault.version" in (ROOT / "scripts" / "build_release.ps1").read_text(encoding="utf-8")
    assert app_info.installer_name() == f"WezCryptVault-Setup-{__version__}.exe"
    assert __version__ in (ROOT / "README.md").read_text(encoding="utf-8")
    # no stale hard-coded versions elsewhere
    for f in ("main.py", "packaging/WezCryptVault.spec", "packaging/WezCryptVault.iss"):
        assert not re.search(r"\b1\.0\.0\b", (ROOT / f).read_text(encoding="utf-8")), f


def test_metadata_constants():
    assert app_info.APP_NAME == "WezCrypt Vault"
    assert app_info.DEVELOPER_NAME == "wezcrypt"
    assert app_info.WEBSITE_URL == "https://wezcrypt.com"
    assert app_info.GITHUB_URL == "https://github.com/wezcrypt"
    assert app_info.REPOSITORY_URL == "https://github.com/wezcrypt/wezcrypt-vault"
    assert app_info.COPYRIGHT == "Copyright © 2026 wezcrypt"


def test_installer_preserves_user_data():
    iss = (ROOT / "packaging" / "WezCryptVault.iss").read_text(encoding="utf-8")
    assert "{localappdata}" in iss and "DelTree" in iss
    assert "MB_DEFBUTTON2" in iss, "removing user data must default to No"
    assert "UninstallSilent()" in iss
    files = re.findall(r'^Source:\s*"([^"]+)"', iss, re.M)
    assert all(not re.search(r"\.(db|toml|env|pem|key|pfx)", f, re.I) for f in files), files
    assert re.search(r"AppId=\{\{[0-9A-F-]{36}\}", iss), "fixed AppId keeps upgrades in place"


def test_spec_bundles_runtime_not_tests():
    spec = (ROOT / "packaging" / "WezCryptVault.spec").read_text(encoding="utf-8")
    for needed in ("keyring.backends", "bcrypt", "nacl", "cffi", "assets", "copy_metadata"):
        assert needed in spec
    assert '"pytest"' in spec and "excludes" in spec
    assert "upx=False" in spec and "console=False" in spec


def test_assets_present():
    assert (ROOT / "assets" / "icon.ico").read_bytes()[:4] == b"\x00\x00\x01\x00"
    assert (ROOT / "assets" / "icon.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_no_shell_url_opening():
    about = (ROOT / "gui" / "about_page.py").read_text(encoding="utf-8")
    assert "QDesktopServices.openUrl(QUrl(" in about
    for f in (ROOT / "gui").glob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert "subprocess" not in text and "os.system" not in text and "webbrowser" not in text, f
