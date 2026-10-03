"""Translate any exception into a message a normal user understands.

Returns (message, category). Messages never contain tracebacks, keys,
passwords or file contents. Detailed technical information goes to the
structured log as an error category only.
"""

from __future__ import annotations

import errno
import socket
import sqlite3

from utils.errors import WezCryptError

_ERRNO_MESSAGES = {
    errno.ENOSPC: ("The disk is full. Free some space and try again.", "disk_full"),
    errno.EACCES: ("Permission denied. Check that you can write to the chosen folder.", "permission_denied"),
    errno.EPERM: ("Permission denied by the operating system.", "permission_denied"),
    errno.EROFS: ("The destination is read-only.", "permission_denied"),
    errno.ENOENT: ("A file or folder could not be found.", "not_found"),
}


def describe_error(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, WezCryptError):
        return str(exc), exc.error_category
    try:
        import paramiko
    except ImportError:  # pragma: no cover - paramiko is a hard dependency
        paramiko = None  # type: ignore[assignment]
    if paramiko is not None:
        if isinstance(exc, paramiko.PasswordRequiredException):
            return "The SSH private key is encrypted. Enter its passphrase in Settings.", "ssh_key_file"
        if isinstance(exc, paramiko.AuthenticationException):
            return "SSH authentication failed. Check the username, password or key.", "ssh_auth"
        if isinstance(exc, paramiko.SSHException):
            return "The SSH connection failed or was interrupted. Try again.", "ssh_negotiation"
    if isinstance(exc, socket.gaierror):
        return "The server name could not be resolved. Check the host name and your internet connection.", "server_unreachable"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "The connection timed out. The server may be offline or blocked by a firewall.", "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "The server refused the connection. Check the host and port.", "server_unreachable"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError)):
        return "The connection was interrupted. You can retry; uploads resume safely.", "network_interrupted"
    if isinstance(exc, sqlite3.Error):
        return "The local database could not be accessed. Close other WezCrypt Vault windows and retry.", "database"
    try:
        from keyring.errors import KeyringError
        if isinstance(exc, KeyringError):
            return ("The Windows Credential Manager / system keyring is unavailable. "
                    "Use manual key entry, or retry."), "credential_store"
    except ImportError:  # pragma: no cover
        pass
    if isinstance(exc, PermissionError):
        return _ERRNO_MESSAGES[errno.EACCES]
    if isinstance(exc, OSError) and exc.errno in _ERRNO_MESSAGES:
        return _ERRNO_MESSAGES[exc.errno]
    if isinstance(exc, OSError):
        return "A system error occurred while accessing files or the network.", "os_error"
    return f"Unexpected error ({type(exc).__name__}). Details were written to the log.", "unexpected"
