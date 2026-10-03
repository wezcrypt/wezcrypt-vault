from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from security.paths import (
    create_private_file,
    finalize_no_clobber,
    sanitize_filename,
    unique_output_path,
)
from security.validators import validate_file_id, validate_remote_dir
from utils.errors import PathSafetyError, ValidationError

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name,expected", [
    ("../../Windows/System32/file.exe", "file.exe"),
    ("..\\..\\boot.ini", "boot.ini"),
    ("/etc/passwd", "passwd"),
    ("C:\\Users\\bob\\x.txt", "x.txt"),
    ("..", "restored_file"),
    ("", "restored_file"),
    ("CON", "_CON"),
    ("nul.txt", "_nul.txt"),
    ("com1.tar.gz", "_com1.tar.gz"),
    ("a<b>c:d|e?f*.txt", "a_b_c_d_e_f_.txt"),
    ("evil\u202egnp.exe", "evil_gnp.exe"),
    ("tab\there", "tab_here"),
    ("trailing. . ", "trailing"),
    ("\ud800bad", "restored_file"),
    (None, "restored_file"),
])
def test_sanitize(name, expected):
    assert sanitize_filename(name) == expected


def test_sanitize_long_keeps_extension():
    out = sanitize_filename("x" * 1000 + ".tar.gz")
    assert len(out.encode()) <= 200 and out.endswith(".gz")


def test_unique_output_never_overwrites(tmp_path):
    (tmp_path / "a.txt").write_text("orig")
    p = unique_output_path(tmp_path, "a.txt")
    assert p.name == "a (1).txt"


def test_symlink_target_not_followed(tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    link = tmp_path / "out.txt"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("creating symlinks requires extra privileges on this Windows machine")
    with pytest.raises(PathSafetyError):
        create_private_file(link)
    assert unique_output_path(tmp_path, "out.txt").name == "out (1).txt"
    assert target.read_text() == "keep"


def test_finalize_no_clobber(tmp_path):
    part = tmp_path / "x.part"
    part.write_text("new")
    final = tmp_path / "final"
    final.write_text("old")
    with pytest.raises(PathSafetyError):
        finalize_no_clobber(part, final)
    assert final.read_text() == "old"


def test_private_file_permissions(tmp_path):
    fd = create_private_file(tmp_path / "t")
    os.close(fd)
    if os.name == "posix":
        assert (tmp_path / "t").stat().st_mode & 0o077 == 0


def test_file_id_validation():
    assert validate_file_id("AB" * 32) == "ab" * 32
    for bad in ("../x", "ab" * 31, "zz" * 32, "ab" * 32 + "/x"):
        with pytest.raises(ValidationError):
            validate_file_id(bad)


def test_remote_dir_validation():
    assert validate_remote_dir("/storage/encrypted") == "/storage/encrypted/"
    with pytest.raises(ValidationError):
        validate_remote_dir("/storage/../etc")


def _scanner():
    import importlib.util

    spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts" / "secret_scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_repository_contains_no_secrets():
    assert _scanner().scan(ROOT) == []


def test_secret_scan_detects_and_excludes(tmp_path):
    scan = _scanner().scan
    (tmp_path / "app.py").write_text("PASSWORD = 'hunter2hunter2'\n" + "verify=" + "False\n")
    (tmp_path / ".env").write_text("X=1")
    (tmp_path / "id_ed25519").write_text("k")
    (tmp_path / "key.txt").write_text("wezcrypt" + "-v1-" + "A" * 43)
    site = tmp_path / ".venv" / "lib" / "site-packages"
    site.mkdir(parents=True)
    (site / "dep.py").write_text("password = 'dependency-code-is-not-ours'")
    findings = scan(tmp_path)
    assert any("hardcoded credential" in f for f in findings)
    assert any("TLS verification" in f for f in findings)
    assert any(".env" in f for f in findings) and any("id_ed25519" in f for f in findings)
    assert any("recovery key" in f for f in findings)
    assert not any("site-packages" in f for f in findings), "installed dependencies are not project source"


def test_no_forbidden_primitives_in_source():
    bad = re.compile(rb"\b(MODE_ECB|modes\.ECB|TripleDES|ARC4|DES3|hashlib\.md5|hashlib\.sha1|random\.random|random\.randint)\b")
    for f, rel in _scanner().iter_project_files(ROOT):  # project files only, never .venv/site-packages
        if f.suffix != ".py" or rel.parts[0] in ("tests", "scripts"):
            continue
        assert not bad.search(f.read_bytes()), f
