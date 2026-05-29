from __future__ import annotations

import posixpath

from .base import BaseFS
from .overlay import OverlayFS


def resolve(cwd: str, path: str, home: str = "/root") -> str:
    """Normalize a user-supplied path against cwd.

    Handles:
      - empty / "." -> cwd
      - "~" or "~/..." -> home-relative
      - absolute paths -> normalized as-is
      - relative paths -> joined against cwd, then normalized

    Walks above "/" are clamped (so "/.." stays "/").
    """
    if not path:
        return posixpath.normpath(cwd) or "/"

    if path == "~" or path.startswith("~/"):
        rest = path[1:]
        path = home + rest

    if path.startswith("/"):
        result = posixpath.normpath(path)
    else:
        result = posixpath.normpath(posixpath.join(cwd, path))

    if not result.startswith("/"):
        result = "/" + result
    return result


class VFS:
    """Session-facing facade combining BaseFS + OverlayFS + cwd state.

    The shell layer talks only to VFS, never to BaseFS/OverlayFS directly.
    """

    def __init__(self, base: BaseFS, cwd: str = "/root", home: str = "/root") -> None:
        self._overlay = OverlayFS(base)
        self._cwd = resolve("/", cwd, home)
        self._home = home

    @property
    def cwd(self) -> str:
        return self._cwd

    @property
    def home(self) -> str:
        return self._home

    def resolve(self, path: str) -> str:
        return resolve(self._cwd, path, self._home)

    def chdir(self, path: str) -> str:
        target = self.resolve(path)
        node = self._overlay.stat(target)
        if node is None:
            raise FileNotFoundError(target)
        if not node.is_dir:
            raise NotADirectoryError(target)
        self._cwd = target
        return target

    def stat(self, path: str):
        return self._overlay.stat(self.resolve(path))

    def exists(self, path: str) -> bool:
        return self._overlay.exists(self.resolve(path))

    def is_dir(self, path: str) -> bool:
        return self._overlay.is_dir(self.resolve(path))

    def is_file(self, path: str) -> bool:
        return self._overlay.is_file(self.resolve(path))

    def list(self, path: str = ".") -> list[str]:
        result = self._overlay.list(self.resolve(path))
        if result is None:
            raise NotADirectoryError(self.resolve(path))
        return result

    def read(self, path: str) -> bytes:
        return self._overlay.read(self.resolve(path))

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read(path).decode(encoding, errors="replace")

    def write(self, path: str, data: bytes) -> None:
        self._overlay.write(self.resolve(path), data)

    def write_text(self, path: str, text: str, encoding: str = "utf-8") -> None:
        self.write(path, text.encode(encoding))

    def append(self, path: str, data: bytes) -> None:
        self._overlay.append(self.resolve(path), data)

    def mkdir(self, path: str, exist_ok: bool = False) -> None:
        self._overlay.mkdir(self.resolve(path), exist_ok=exist_ok)

    def touch(self, path: str) -> None:
        target = self.resolve(path)
        if not self._overlay.exists(target):
            self._overlay.write(target, b"")

    def unlink(self, path: str) -> None:
        self._overlay.unlink(self.resolve(path))

    def rmdir(self, path: str) -> None:
        self._overlay.rmdir(self.resolve(path))
