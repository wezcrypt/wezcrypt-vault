"""Input validators for untrusted values (File IDs, hosts, remote paths)."""

from __future__ import annotations

import re

from utils.errors import ValidationError

FILE_ID_BYTES = 32
_FILE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")
_USER_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,64}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
CONTAINER_EXT = ".wezenc"


def validate_file_id(value: str) -> str:
    v = (value or "").strip().lower()
    if v.endswith(CONTAINER_EXT):
        v = v[: -len(CONTAINER_EXT)]
    if not _FILE_ID_RE.fullmatch(v):
        raise ValidationError("File ID must be 64 hexadecimal characters (256 bits).")
    return v


def remote_object_name(file_id_hex: str) -> str:
    return validate_file_id(file_id_hex) + CONTAINER_EXT


def validate_sha256_hex(value: str) -> str:
    v = (value or "").strip().lower()
    if not _SHA256_HEX_RE.fullmatch(v):
        raise ValidationError("Expected a SHA-256 hex digest.")
    return v


def validate_host(value: str) -> str:
    v = (value or "").strip()
    if not _HOST_RE.fullmatch(v):
        raise ValidationError("Invalid server host.")
    return v


def validate_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValidationError("Port must be between 1 and 65535.")
    return value


def validate_username(value: str) -> str:
    v = (value or "").strip()
    if not _USER_RE.fullmatch(v):
        raise ValidationError("Invalid server username.")
    return v


def validate_remote_dir(value: str) -> str:
    v = (value or "").strip().replace("\\", "/")
    if not v:
        raise ValidationError("Remote path is required.")
    if "\x00" in v or any(part == ".." for part in v.split("/")):
        raise ValidationError("Remote path must not contain '..' or NUL.")
    return v.rstrip("/") + "/" if v != "/" else "/"
