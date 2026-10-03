# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for WezCrypt Vault (self-contained, windowed, single EXE).
#
# Build:  python -m PyInstaller --noconfirm --clean packaging/WezCryptVault.spec
# Output: dist/WezCryptVault.exe   (Windows)   /   dist/WezCryptVault (other OS, for CI smoke tests)
#
# Bundles: Python runtime, PySide6 + Qt platform/style/image/print plugins, cryptography (OpenSSL),
# paramiko + bcrypt + PyNaCl + cffi, keyring (+ its entry-point metadata and Windows backend),
# sqlite3, application icons. Test-only packages (pytest) are excluded.
# Contains NO keys, credentials, databases or user configuration.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

ROOT = Path(SPECPATH).resolve().parent
sys.path.insert(0, str(ROOT))

from wezcrypt_vault import app_info  # noqa: E402
from wezcrypt_vault.version import __version__, version_tuple  # noqa: E402

hiddenimports = []
hiddenimports += collect_submodules("keyring.backends")
hiddenimports += ["keyring.backends.Windows", "keyring.backends.macOS", "keyring.backends.SecretService"]
for optional in ("win32ctypes", "win32ctypes.core", "win32ctypes.pywin32"):
    try:
        __import__(optional)
        hiddenimports += collect_submodules(optional)
    except ImportError:
        pass
hiddenimports += ["bcrypt", "nacl", "nacl.bindings", "cffi", "_cffi_backend", "sqlite3",
                  "PySide6.QtPrintSupport", "selftest"]

datas = [
    (str(ROOT / "assets" / "icon.png"), "assets"),
    (str(ROOT / "assets" / "icon.ico"), "assets"),
]
# keyring discovers its backends through package entry points -> needs distribution metadata.
for dist in ("keyring", "jaraco.classes", "jaraco.functools", "jaraco.context"):
    try:
        datas += copy_metadata(dist)
    except Exception:
        pass

excludes = [
    "tkinter", "_tkinter", "pytest", "_pytest", "pluggy", "py", "IPython", "numpy", "PyInstaller",
    # Unused, large Qt modules
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets", "PySide6.Qt3DCore", "PySide6.Qt3DRender",
    "PySide6.Qt3DInput", "PySide6.Qt3DExtras", "PySide6.Qt3DAnimation", "PySide6.Qt3DLogic",
    "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQuickWidgets", "PySide6.QtQml",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtCharts",
    "PySide6.QtDataVisualization", "PySide6.QtGraphs", "PySide6.QtLocation", "PySide6.QtPositioning",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtSensors", "PySide6.QtSerialPort",
    "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtSpatialAudio", "PySide6.QtTextToSpeech", "PySide6.QtHttpServer",
]

version_resource = None
if sys.platform == "win32":
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
    )

    file_version = ".".join(str(p) for p in version_tuple())
    version_resource = VSVersionInfo(
        ffi=FixedFileInfo(filevers=version_tuple(), prodvers=version_tuple(), mask=0x3F, flags=0x0,
                          OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", app_info.DEVELOPER_NAME),
                StringStruct("FileDescription", app_info.APP_DESCRIPTION),
                StringStruct("FileVersion", file_version),
                StringStruct("InternalName", app_info.APP_ID),
                StringStruct("LegalCopyright", app_info.COPYRIGHT),
                StringStruct("OriginalFilename", app_info.EXE_NAME),
                StringStruct("ProductName", app_info.APP_NAME),
                StringStruct("ProductVersion", __version__),
                StringStruct("Comments", app_info.WEBSITE_URL),
            ])]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WezCryptVault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX-packed binaries trigger antivirus false positives
    runtime_tmpdir=None,
    console=False,             # windowed GUI application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "assets" / "icon.ico"),
    version=version_resource,
)
