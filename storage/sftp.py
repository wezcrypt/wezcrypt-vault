"""SFTP backend (Paramiko) with mandatory strict host-key checking.

* First connection: the presented key fingerprint is shown to the user, who
  must explicitly trust it (``HostKeyUnknownError`` -> UI dialog ->
  ``Database.trust_host_key``). Unknown keys are NEVER auto-accepted.
* Later connections: the fingerprint must match exactly, otherwise the
  connection is closed before any credential is sent (``HostKeyChangedError``).
  There is no "continue anyway"; only an explicit "Forget Trusted Key"
  action in Settings removes a trusted key.
* Authentication methods: SSH private key (optional passphrase) or password.
  Secrets come from a ``SecretProvider`` (OS credential store or a
  session-only in-memory value), never from config files.
* The remote directory is never created implicitly; ``create_remote_dir``
  is only called after the user confirms.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import posixpath
import socket
import stat as _stat
from pathlib import Path
from typing import BinaryIO, Callable

import paramiko

from database.database import Database
from security.validators import validate_host, validate_port, validate_remote_dir, validate_username
from storage.base import StreamStorageBackend
from utils.errors import (
    ConnectionTimeoutError,
    HostKeyChangedError,
    HostKeyUnknownError,
    PermissionDeniedError,
    RemoteDirectoryMissingError,
    SecretUnavailableError,
    ServerUnreachableError,
    SSHAuthenticationError,
    SSHKeyFileError,
    SSHNegotiationError,
    StorageError,
    ValidationError,
)

AUTH_METHODS = ("key", "password")
# (kind, ident) -> secret or None. kind is "ssh-password" or "ssh-key-passphrase".
SecretProvider = Callable[[str, str], "str | None"]


def host_key_fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH-style ``SHA256:<base64>`` fingerprint."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class HostKeyVerifier:
    def __init__(self, db: Database) -> None:
        self.db = db

    def verify(self, host: str, port: int, key: paramiko.PKey) -> str:
        fp = host_key_fingerprint(key)
        stored = self.db.get_host_key(host, port)
        if stored is None:
            raise HostKeyUnknownError(host, port, key.get_name(), fp)
        key_type, expected = stored
        if key_type != key.get_name() or not hmac.compare_digest(expected, fp):
            raise HostKeyChangedError(expected, fp)
        return fp


def _no_secrets(kind: str, ident: str) -> str | None:
    return None


def open_transport(host: str, port: int, timeout: int) -> paramiko.Transport:
    """DNS + TCP + SSH negotiation, with understandable errors."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ServerUnreachableError(f"The server name '{host}' could not be resolved. Check the host name.") from exc
    last: OSError | None = None
    sock = None
    for family, socktype, proto, _, addr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(addr)
            break
        except OSError as exc:
            last = exc
            if sock is not None:
                sock.close()
            sock = None
    if sock is None:
        if isinstance(last, (socket.timeout, TimeoutError)):
            raise ConnectionTimeoutError(f"Connection to {host}:{port} timed out.") from last
        if isinstance(last, ConnectionRefusedError):
            raise ServerUnreachableError(f"{host} refused the connection on port {port}. Is SSH running there?") from last
        raise ServerUnreachableError(f"Cannot reach {host}:{port}.") from last
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
    except (paramiko.SSHException, EOFError, OSError) as exc:
        transport.close()
        raise SSHNegotiationError(
            f"{host}:{port} did not complete an SSH handshake. Check that the port belongs to an SSH server."
        ) from exc
    return transport


def map_sftp_error(exc: BaseException, path: str) -> StorageError:
    if isinstance(exc, PermissionError) or getattr(exc, "errno", None) == errno.EACCES:
        return PermissionDeniedError(f"Permission denied on the server for {path}.")
    if isinstance(exc, FileNotFoundError):
        return RemoteDirectoryMissingError(f"Remote path {path} does not exist.")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ConnectionTimeoutError("The server stopped responding (timeout).")
    return StorageError(f"Server error on {path}: {type(exc).__name__}.")


class SFTPBackend(StreamStorageBackend):
    transient_errors = (OSError, EOFError, paramiko.SSHException)

    def __init__(
        self, db: Database, *, host: str, port: int, username: str, remote_dir: str,
        auth_method: str = "key", private_key_path: str = "", secret_ident: str | None = None,
        secrets: SecretProvider = _no_secrets, timeout: int = 20,
    ) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.username = validate_username(username)
        self.remote_dir = validate_remote_dir(remote_dir)
        if auth_method not in AUTH_METHODS:
            raise ValidationError("Authentication method must be 'key' or 'password'.")
        self.auth_method = auth_method
        self.private_key_path = private_key_path
        self.secret_ident = secret_ident or f"{self.username}@{self.host}:{self.port}"
        self.secrets = secrets
        self.timeout = timeout
        self.verifier = HostKeyVerifier(db)
        self._transport: paramiko.Transport | None = None
        self._sftp: paramiko.SFTPClient | None = None

    @property
    def description(self) -> str:
        return f"sftp://{self.host}:{self.port}"

    # ---- connection steps (used individually by the connection test) -------------
    def step_transport(self) -> paramiko.Transport:
        self._transport = open_transport(self.host, self.port, self.timeout)
        return self._transport

    def step_verify_host_key(self) -> tuple[str, str]:
        assert self._transport is not None
        key = self._transport.get_remote_server_key()
        # Strict host-key check BEFORE sending any credentials.
        fp = self.verifier.verify(self.host, self.port, key)
        return key.get_name(), fp

    def step_authenticate(self) -> None:
        t = self._transport
        assert t is not None
        try:
            if self.auth_method == "key":
                if not self.private_key_path:
                    raise SSHKeyFileError("No SSH private key file is configured.")
                passphrase = self.secrets("ssh-key-passphrase", self.secret_ident)
                path = Path(self.private_key_path).expanduser()
                if not path.is_file():
                    raise SSHKeyFileError(f"SSH private key file not found: {path.name}")
                try:
                    pkey = paramiko.PKey.from_path(path, passphrase)
                except paramiko.PasswordRequiredException as exc:
                    raise SSHKeyFileError("The SSH private key is encrypted. Enter its passphrase.") from exc
                except (paramiko.SSHException, ValueError) as exc:
                    raise SSHKeyFileError(
                        "The SSH private key could not be opened: wrong passphrase or unsupported key format."
                    ) from exc
                except OSError as exc:
                    raise SSHKeyFileError("The SSH private key file could not be read.") from exc
                t.auth_publickey(self.username, pkey)
            else:
                password = self.secrets("ssh-password", self.secret_ident)
                if not password:
                    raise SecretUnavailableError("No SSH password is stored for this server. Enter it in Settings.")
                t.auth_password(self.username, password)
        except paramiko.BadAuthenticationType as exc:
            allowed = ", ".join(exc.allowed_types) or "none"
            raise SSHAuthenticationError(
                f"The server does not accept this authentication method (allowed: {allowed})."
            ) from exc
        except paramiko.AuthenticationException as exc:
            what = "SSH key" if self.auth_method == "key" else "password"
            raise SSHAuthenticationError(
                f"Authentication failed for user '{self.username}'. Check the username and {what}."
            ) from exc
        except paramiko.SSHException as exc:
            raise SSHNegotiationError("The SSH connection failed during authentication.") from exc
        if not t.is_authenticated():
            raise SSHAuthenticationError("SSH authentication failed.")

    def step_open_sftp(self) -> paramiko.SFTPClient:
        assert self._transport is not None
        try:
            sftp = paramiko.SFTPClient.from_transport(self._transport)
        except paramiko.SSHException as exc:
            raise StorageError("The server does not provide SFTP access for this account.") from exc
        if sftp is None:
            raise StorageError("Could not open an SFTP session.")
        sftp.get_channel().settimeout(self.timeout * 3)
        self._sftp = sftp
        return sftp

    def remote_dir_exists(self) -> bool:
        try:
            st = self.sftp.stat(self.remote_dir)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise map_sftp_error(exc, self.remote_dir) from exc
        if not _stat.S_ISDIR(st.st_mode or 0):
            raise RemoteDirectoryMissingError(f"{self.remote_dir} exists on the server but is not a directory.")
        return True

    def create_remote_dir(self) -> None:
        """Create the configured directory (mkdir -p). Call only after user confirmation."""
        current = "/" if self.remote_dir.startswith("/") else ""
        for part in [p for p in self.remote_dir.split("/") if p]:
            current = posixpath.join(current, part) if current else part
            try:
                self.sftp.stat(current)
            except FileNotFoundError:
                try:
                    self.sftp.mkdir(current, mode=0o700)
                except OSError as exc:
                    raise map_sftp_error(exc, current) from exc

    def connect(self) -> None:
        if self._sftp is not None:
            return
        try:
            self.step_transport()
            self.step_verify_host_key()
            self.step_authenticate()
            self.step_open_sftp()
            if not self.remote_dir_exists():
                raise RemoteDirectoryMissingError(
                    f"Remote storage folder {self.remote_dir} does not exist. "
                    "Create it from Settings → Test Connection."
                )
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._sftp is not None:
            self._sftp.close()
        if self._transport is not None:
            self._transport.close()
        self._sftp = None
        self._transport = None

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            raise StorageError("Not connected.")
        return self._sftp

    def remote_path(self, name: str) -> str:
        return posixpath.join(self.remote_dir, name)

    def _stat_size(self, path: str) -> int | None:
        try:
            return int(self.sftp.stat(path).st_size or 0)
        except FileNotFoundError:
            return None

    def _open_read(self, path: str, offset: int) -> BinaryIO:
        fh = self.sftp.open(path, "rb")
        fh.prefetch()
        fh.seek(offset)
        return fh  # type: ignore[return-value]

    def _open_write(self, path: str, append: bool) -> BinaryIO:
        try:
            fh = self.sftp.open(path, "ab" if append else "wb")
        except PermissionError as exc:
            raise map_sftp_error(exc, self.remote_dir) from exc
        fh.set_pipelined(True)
        if not append:
            self.sftp.chmod(path, 0o600)
        return fh  # type: ignore[return-value]

    def _rename(self, src: str, dst: str) -> None:
        self.sftp.posix_rename(src, dst)

    def _remove(self, path: str) -> None:
        self.sftp.remove(path)


def fetch_host_key(host: str, port: int, timeout: int = 20) -> tuple[str, str]:
    """Connect without authenticating and return (key type, fingerprint) for the trust dialog."""
    transport = open_transport(validate_host(host), validate_port(port), timeout)
    try:
        key = transport.get_remote_server_key()
        return key.get_name(), host_key_fingerprint(key)
    finally:
        transport.close()
