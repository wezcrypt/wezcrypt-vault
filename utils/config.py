"""Application configuration (TOML) and per-user directories.

The config file holds only non-secret settings. Passwords, passphrases,
API tokens and the master key live in the OS credential store
(``security.credentials``) and are rejected if they appear here.
"""

from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from crypto.chunks import DEFAULT_CHUNK_SIZE, validate_chunk_size
from security.paths import ensure_private_dir
from utils.errors import ConfigError, ValidationError

APP_NAME = "WezCryptVault"
_FORBIDDEN_KEYS = {"password", "passphrase", "token", "api_token", "master_key", "secret", "aes_key"}


def app_home() -> Path:
    """Root of the per-user data layout (see ``utils.app_paths``)."""
    from utils.app_paths import resolve_paths

    return ensure_private_dir(resolve_paths().root)


def _default_config_file() -> Path:
    from utils.app_paths import resolve_paths

    return resolve_paths().config_file


@dataclass
class ServerConfig:
    """Legacy (1.0) single-server settings. Read for migration into server profiles."""

    backend: str = "sftp"            # "sftp" | "https" | "local"
    host: str = ""
    port: int = 22
    username: str = ""
    remote_path: str = "/storage/encrypted/"
    private_key_path: str = ""
    https_base_url: str = ""
    https_ca_bundle: str = ""
    local_path: str = ""
    connect_timeout: int = 20


@dataclass
class EncryptionConfig:
    chunk_size: int = DEFAULT_CHUNK_SIZE
    key_storage: str = "manual"      # "manual" | "os_keyring"


@dataclass
class TransferConfig:
    concurrent_uploads: int = 2
    verify_upload_readback: bool = True
    auto_delete_temp: bool = True


@dataclass
class PrivacyConfig:
    log_filenames: bool = False
    clipboard_clear_seconds: int = 30


@dataclass
class UIConfig:
    dark_mode: bool = True


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    transfer: TransferConfig = field(default_factory=TransferConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    ui: UIConfig = field(default_factory=UIConfig)

    def validate(self) -> None:
        try:
            validate_chunk_size(self.encryption.chunk_size)
        except ValidationError as exc:
            raise ConfigError(str(exc)) from exc
        if self.encryption.key_storage not in ("manual", "os_keyring"):
            raise ConfigError("encryption.key_storage must be 'manual' or 'os_keyring'.")
        if self.server.backend not in ("sftp", "https", "local"):
            raise ConfigError("server.backend must be 'sftp', 'https' or 'local'.")
        if not 1 <= self.server.port <= 65535:
            raise ConfigError("server.port must be 1-65535.")
        if not 1 <= self.transfer.concurrent_uploads <= 8:
            raise ConfigError("transfer.concurrent_uploads must be 1-8.")
        if not 5 <= self.privacy.clipboard_clear_seconds <= 600:
            raise ConfigError("privacy.clipboard_clear_seconds must be 5-600.")
        if self.server.https_base_url and not self.server.https_base_url.startswith("https://"):
            raise ConfigError("HTTPS backend URL must start with https://")


_SECTIONS = {
    "server": ServerConfig, "encryption": EncryptionConfig, "transfer": TransferConfig,
    "privacy": PrivacyConfig, "ui": UIConfig,
}


def load_config(path: Path | None = None) -> AppConfig:
    path = path or _default_config_file()
    cfg = AppConfig()
    if not path.exists():
        return cfg
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Invalid config file: {exc}") from exc
    for section, values in data.items():
        if section not in _SECTIONS or not isinstance(values, dict):
            raise ConfigError(f"Unknown config section [{section}].")
        target = getattr(cfg, section)
        for k, v in values.items():
            if k.lower() in _FORBIDDEN_KEYS:
                raise ConfigError(
                    f"Secret '{k}' must not be stored in the config file; use the OS credential store."
                )
            if not hasattr(target, k):
                raise ConfigError(f"Unknown config key {section}.{k}.")
            expected = type(getattr(target, k))
            if expected is int and (isinstance(v, bool) or not isinstance(v, int)):
                raise ConfigError(f"{section}.{k} must be an integer.")
            if expected is not int and not isinstance(v, expected):
                raise ConfigError(f"{section}.{k} has the wrong type.")
            setattr(target, k, v)
    cfg.validate()
    return cfg


def _toml_value(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{s}"'


def save_config(cfg: AppConfig, path: Path | None = None) -> Path:
    cfg.validate()
    path = path or _default_config_file()
    lines: list[str] = []
    for section, values in asdict(cfg).items():
        lines.append(f"[{section}]")
        lines.extend(f"{k} = {_toml_value(v)}" for k, v in values.items())
        lines.append("")
    tmp = path.with_suffix(".toml.part")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path
