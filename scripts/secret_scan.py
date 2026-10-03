#!/usr/bin/env python3
"""Release secret scan for PROJECT-OWNED files only.

Excludes virtual environments, build output, VCS data, caches and installed
third-party packages, so dependency code is never mistaken for project
source. Exit code 0 = clean, 1 = findings.

Usage:  python scripts/secret_scan.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

EXCLUDED_DIRS = {
    ".venv", "venv", "env", "build", "dist", ".git", "__pycache__", ".pytest_cache", "site-packages",
    "node_modules", ".mypy_cache", ".ruff_cache", ".tox", ".idea", ".vscode",
}
BINARY_EXT = {".png", ".ico", ".jpg", ".jpeg", ".gif", ".pyc", ".pyo", ".pyd", ".dll", ".exe", ".zip",
              ".whl", ".so", ".dylib", ".icns"}
# Files that must never be part of the repository / release.
FORBIDDEN_NAMES = re.compile(
    r"(^\.env$|^\.env\.(?!example$).+|\.pem$|\.key$|\.pfx$|\.p12$|^id_(rsa|ed25519|ecdsa|dsa)$|"
    r"\.db$|\.sqlite3?$|^config\.toml$|^settings\.json$|^wezcrypt-recovery-key.*\.txt$|\.wezenc(\.part)?$)",
    re.IGNORECASE,
)
# Patterns are assembled from pieces so this file does not match itself.
_B = "-----BEGIN "
CONTENT_RULES: list[tuple[str, re.Pattern[str], bool]] = [
    # (rule, pattern, applies_to_tests)
    ("wezcrypt master/recovery key", re.compile("wezcrypt" + r"-v1-[A-Za-z0-9_-]{43}"), True),
    ("private key block", re.compile(_B + r"(RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), True),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), True),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), True),
    ("hardcoded credential",
     re.compile(r"(?i)\b(password|passphrase|passwd|api_token|secret_key|auth_token)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]"),
     False),  # test fixtures legitimately use throwaway credentials for the in-process test server
    ("TLS verification disabled", re.compile(r"verify\s*=\s*" + "False"), True),
    ("host key auto-accept", re.compile("Auto" + r"AddPolicy|Warning" + "Policy"), True),
    ("shell execution", re.compile(r"shell\s*=\s*" + "True"), True),
]


def iter_project_files(root: Path):
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.is_file():
            yield path, rel


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path, rel in iter_project_files(root):
        if FORBIDDEN_NAMES.search(path.name):
            findings.append(f"{rel}: forbidden file type in repository/release")
            continue
        if path.suffix.lower() in BINARY_EXT or path.stat().st_size > 5_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        in_tests = rel.parts[0] == "tests"
        for rule, pattern, applies_to_tests in CONTENT_RULES:
            if in_tests and not applies_to_tests:
                continue
            for m in pattern.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append(f"{rel}:{line}: {rule}")
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    findings = scan(root)
    files = sum(1 for _ in iter_project_files(root))
    if findings:
        print(f"SECRET SCAN: FAIL ({len(findings)} finding(s) in {files} project files)")
        for f in findings:
            print("  " + f)
        return 1
    print(f"SECRET SCAN: PASS ({files} project files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
