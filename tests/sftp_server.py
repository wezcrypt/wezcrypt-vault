"""Minimal in-process SFTP server (test fixture) backed by a local directory.

Used to exercise the real ``SFTPBackend`` (Paramiko transport, strict
host-key checking, public-key auth, resumable upload, rename) end to end.
"""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface
from paramiko.sftp import SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK


class _Server(paramiko.ServerInterface):
    def __init__(self, user: str, client_key: paramiko.PKey, password: str | None = None) -> None:
        self.user, self.client_key, self.password = user, client_key, password

    def check_auth_password(self, username, password):
        if self.password is not None and username == self.user and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username == self.user and key.asbytes() == self.client_key.asbytes():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey,password" if self.password is not None else "publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class _Handle(SFTPHandle):
    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno() if hasattr(self, "readfile") else self.writefile.fileno()))


class _SFTP(SFTPServerInterface):
    ROOT: Path = Path(".")

    def _real(self, path: str) -> str:
        p = (self.ROOT / path.lstrip("/")).resolve()
        if self.ROOT.resolve() not in (p, *p.parents):
            raise PermissionError(path)
        return str(p)

    def _err(self, e: OSError) -> int:
        return SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._real(path)))
        except FileNotFoundError:
            return SFTP_NO_SUCH_FILE
        except OSError as e:
            return self._err(e)

    lstat = stat

    def open(self, path, flags, attr):
        real = self._real(path)
        try:
            fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o600)
        except OSError as e:
            return self._err(e)
        if flags & os.O_WRONLY:
            mode = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            mode = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            mode = "rb"
        f = os.fdopen(fd, mode)
        h = _Handle(flags)
        h.filename = real
        h.readfile = f
        h.writefile = f
        return h

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as e:
            return self._err(e)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        try:
            os.replace(self._real(oldpath), self._real(newpath))
        except OSError as e:
            return self._err(e)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        return self.posix_rename(oldpath, newpath)

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._real(path))
        except OSError as e:
            return self._err(e)
        return SFTP_OK

    def chattr(self, path, attr):
        return SFTP_OK

    def list_folder(self, path):
        try:
            real = self._real(path)
            return [SFTPAttributes.from_stat(os.stat(os.path.join(real, n)), n) for n in os.listdir(real)]
        except OSError as e:
            return self._err(e)

    def canonicalize(self, path):
        return "/" + path.lstrip("/")


class LocalSFTPServer:
    def __init__(self, root: Path, user: str, client_key: paramiko.PKey, host_key: paramiko.PKey,
                 password: str | None = None) -> None:
        self.root, self.user, self.client_key, self.host_key = root, user, client_key, host_key
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.auth_attempted = threading.Event()
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        t = paramiko.Transport(conn)
        t.add_server_key(self.host_key)
        root = self.root

        class Iface(_SFTP):
            ROOT = root

        t.set_subsystem_handler("sftp", SFTPServer, Iface)
        server = _Server(self.user, self.client_key, self.password)
        outer = self

        class Tracking(type(server)):
            def check_auth_publickey(self, username, key):
                outer.auth_attempted.set()
                return super().check_auth_publickey(username, key)

        server.__class__ = Tracking
        try:
            t.start_server(server=server)
            while t.is_active():
                t.join(0.2)
        except Exception:
            pass

    def close(self) -> None:
        self._stop = True
        self.sock.close()


__all__ = ["LocalSFTPServer", "SFTP_FAILURE"]
