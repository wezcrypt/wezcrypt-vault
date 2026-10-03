"""Server profiles (e.g. "Personal VPS", "Backup Server", "Office Storage").

Profiles hold only non-secret connection settings in SQLite. Passwords and
key passphrases are kept in the OS credential store under the profile's id;
if no secure store exists they are held in memory for the current session
only (never written to disk in plaintext).

Trust and test invalidation rules:
* Changing host or port forgets the trusted host key of the old endpoint
  (unless another profile still uses it) - the new endpoint must be verified.
* Changing any connection or authentication field clears the profile's
  "connection tested" flag; uploads require a fresh successful test.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from database.database import PROFILE_FIELDS, Database, Profile
from security import credentials
from security.validators import validate_host, validate_port, validate_remote_dir, validate_username
from storage.sftp import AUTH_METHODS
from utils.config import ServerConfig
from utils.errors import NoProfileError, ValidationError, WezCryptError

ACTIVE_KEY = "active_profile_id"
SECRET_KINDS = ("ssh-password", "ssh-key-passphrase", "https-token")
_TEST_RELEVANT = ("backend", "host", "port", "username", "remote_path", "auth_method",
                  "private_key_path", "https_base_url", "https_ca_bundle", "local_path")


@dataclass(frozen=True)
class SecretSaveResult:
    persisted: bool  # True = OS credential store, False = session memory only


def normalize_profile(values: dict[str, object]) -> dict[str, object]:
    v = {k: values[k] for k in PROFILE_FIELDS if k in values}
    name = str(v.get("name", "")).strip()
    if not name or len(name) > 64:
        raise ValidationError("Profile name must be 1-64 characters.")
    v["name"] = name
    backend = v.get("backend", "sftp")
    if backend not in ("sftp", "https", "local"):
        raise ValidationError("Unknown storage type.")
    if backend == "sftp":
        v["host"] = validate_host(str(v.get("host", "")))
        v["port"] = validate_port(int(v.get("port", 22)))  # type: ignore[arg-type]
        v["username"] = validate_username(str(v.get("username", "")))
        v["remote_path"] = validate_remote_dir(str(v.get("remote_path", "")))
        if v.get("auth_method", "key") not in AUTH_METHODS:
            raise ValidationError("Authentication method must be SSH key or password.")
        if v.get("auth_method", "key") == "key" and not str(v.get("private_key_path", "")).strip():
            raise ValidationError("Choose an SSH private key file, or switch to password authentication.")
    elif backend == "https":
        url = str(v.get("https_base_url", "")).strip()
        if not url.startswith("https://"):
            raise ValidationError("The HTTPS API address must start with https://")
        v["https_base_url"] = url.rstrip("/")
    else:
        if not str(v.get("local_path", "")).strip():
            raise ValidationError("Choose a storage folder.")
    return v


class ProfileManager:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._session: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    # ---- CRUD -------------------------------------------------------------------
    def list(self) -> list[Profile]:
        return self.db.list_profiles()

    def get(self, profile_id: int) -> Profile | None:
        return self.db.get_profile(profile_id)

    def create(self, values: dict[str, object], *, make_active: bool | None = None) -> Profile:
        v = normalize_profile(values)
        if any(p.name.lower() == str(v["name"]).lower() for p in self.list()):
            raise ValidationError("A profile with this name already exists.")
        pid = self.db.insert_profile(v)
        if make_active or (make_active is None and self.active() is None):
            self.set_active(pid)
        prof = self.db.get_profile(pid)
        assert prof is not None
        return prof

    def update(self, profile_id: int, values: dict[str, object]) -> Profile:
        old = self.db.get_profile(profile_id)
        if old is None:
            raise NoProfileError()
        merged = {k: getattr(old, k) for k in PROFILE_FIELDS}
        merged.update({k: values[k] for k in PROFILE_FIELDS if k in values})
        v = normalize_profile(merged)
        if any(p.id != profile_id and p.name.lower() == str(v["name"]).lower() for p in self.list()):
            raise ValidationError("A profile with this name already exists.")
        changed = {k for k in _TEST_RELEVANT if v.get(k) != getattr(old, k)}
        endpoint_changed = old.backend == "sftp" and (old.host != v.get("host") or old.port != v.get("port")
                                                    or v.get("backend") != "sftp")
        self.db.update_profile(profile_id, v, reset_tested=bool(changed))
        if endpoint_changed and old.host:
            self._forget_trust_if_unused(old.host, old.port, profile_id)
        new = self.db.get_profile(profile_id)
        assert new is not None
        return new

    def delete(self, profile_id: int) -> None:
        old = self.db.get_profile(profile_id)
        if old is None:
            return
        for kind in SECRET_KINDS:
            self.set_secret(old, kind, "")
        self.db.delete_profile(profile_id)
        if old.backend == "sftp" and old.host:
            self._forget_trust_if_unused(old.host, old.port, profile_id)
        if self.db.get_setting(ACTIVE_KEY) == str(profile_id):
            remaining = self.list()
            self.db.set_setting(ACTIVE_KEY, str(remaining[0].id) if remaining else "")

    def _forget_trust_if_unused(self, host: str, port: int, exclude_id: int) -> None:
        if self.db.count_profiles_using(host, port, exclude_id) == 0:
            self.db.forget_host_key(host, port)

    # ---- active profile ---------------------------------------------------------------
    def active(self) -> Profile | None:
        raw = self.db.get_setting(ACTIVE_KEY, "")
        if raw and raw.isdigit():
            prof = self.db.get_profile(int(raw))
            if prof is not None:
                return prof
        return None

    def require_active(self) -> Profile:
        prof = self.active()
        if prof is None:
            raise NoProfileError()
        return prof

    def set_active(self, profile_id: int) -> None:
        if self.db.get_profile(profile_id) is None:
            raise NoProfileError()
        self.db.set_setting(ACTIVE_KEY, str(profile_id))

    # ---- secrets ------------------------------------------------------------------------
    def set_secret(self, profile: Profile, kind: str, value: str) -> SecretSaveResult:
        """Store in the OS credential store; fall back to session memory (never disk)."""
        if kind not in SECRET_KINDS:
            raise ValidationError("Unknown secret kind.")
        key = (kind, profile.secret_ident)
        with self._lock:
            if value:
                self._session[key] = value
            else:
                self._session.pop(key, None)
        if credentials.is_available():
            try:
                credentials.set_secret(kind, profile.secret_ident, value)
                return SecretSaveResult(True)
            except WezCryptError:
                return SecretSaveResult(False)
        return SecretSaveResult(False)

    def get_secret(self, kind: str, ident: str) -> str | None:
        with self._lock:
            if (kind, ident) in self._session:
                return self._session[(kind, ident)]
        return credentials.get_secret(kind, ident)

    def has_secret(self, profile: Profile, kind: str) -> bool:
        return bool(self.get_secret(kind, profile.secret_ident))

    # ---- 1.0 -> 1.1 migration -------------------------------------------------------------
    def migrate_from_config(self, server: ServerConfig) -> Profile | None:
        """Create a 'Default' profile from a 1.0 [server] section (once)."""
        if self.list():
            return None
        values = {
            "name": "Default", "backend": server.backend, "host": server.host, "port": server.port,
            "username": server.username, "remote_path": server.remote_path,
            "auth_method": "key" if server.private_key_path else "password",
            "private_key_path": server.private_key_path, "https_base_url": server.https_base_url,
            "https_ca_bundle": server.https_ca_bundle, "local_path": server.local_path,
        }
        try:
            prof = self.create(values, make_active=True)
        except ValidationError:
            return None  # incomplete 1.0 configuration: the setup wizard will collect it
        old_ident = f"{server.username}@{server.host}:{server.port}"
        for kind in ("ssh-password", "ssh-key-passphrase"):
            old = credentials.get_secret(kind, old_ident)
            if old:
                self.set_secret(prof, kind, old)
        token = credentials.get_secret("https-token", server.https_base_url.rstrip("/"))
        if token:
            self.set_secret(prof, "https-token", token)
        # A 1.0 install that was already uploading was implicitly tested.
        if self.db.list_files():
            self.db.mark_profile_tested(prof.id)
        return self.db.get_profile(prof.id)
