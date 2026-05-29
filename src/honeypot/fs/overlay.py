from __future__ import annotations

import posixpath
from typing import Optional, Union

from .base import BaseFS, Node, _normalize


class _Tombstone:
    """Marker for entries deleted in the overlay but present in the base."""

    __slots__ = ()


TOMBSTONE: _Tombstone = _Tombstone()

OverlayEntry = Union[Node, _Tombstone]


class OverlayFS:
    """Copy-on-write overlay over a read-only BaseFS.

    All mutating operations (write/mkdir/unlink/rmdir) modify only the
    in-memory overlay. The BaseFS layer is never touched, so the same base
    can be shared across many sessions safely.
    """

    def __init__(self, base: BaseFS) -> None:
        self._base = base
        self._overlay: dict[str, OverlayEntry] = {}

    def _effective(self, path: str) -> Optional[Node]:
        norm = _normalize(path)
        if norm in self._overlay:
            v = self._overlay[norm]
            if isinstance(v, _Tombstone):
                return None
            return v
        return self._base.get(norm)

    def stat(self, path: str) -> Optional[Node]:
        return self._effective(path)

    def exists(self, path: str) -> bool:
        return self._effective(path) is not None

    def is_dir(self, path: str) -> bool:
        node = self._effective(path)
        return node is not None and node.is_dir

    def is_file(self, path: str) -> bool:
        node = self._effective(path)
        return node is not None and node.is_file

    def list(self, path: str) -> Optional[list[str]]:
        norm = _normalize(path)
        node = self._effective(norm)
        if node is None or not node.is_dir:
            return None
        prefix = "/" if norm == "/" else norm + "/"

        names: set[str] = set()
        base_list = self._base.list(norm)
        if base_list:
            names.update(base_list)
        for p in self._overlay:
            if not p.startswith(prefix):
                continue
            rest = p[len(prefix):]
            if "/" in rest:
                continue
            names.add(rest)

        result: list[str] = []
        for name in names:
            full = prefix + name
            v = self._overlay.get(full)
            if isinstance(v, _Tombstone):
                continue
            result.append(name)
        return sorted(result)

    def read(self, path: str) -> bytes:
        node = self._effective(path)
        if node is None:
            raise FileNotFoundError(path)
        if not node.is_file:
            raise IsADirectoryError(path)
        return node.content

    def write(self, path: str, data: bytes) -> None:
        norm = _normalize(path)
        parent = posixpath.dirname(norm) or "/"
        p_node = self._effective(parent)
        if p_node is None or not p_node.is_dir:
            raise FileNotFoundError(f"parent missing: {parent}")
        existing = self._effective(norm)
        if existing is not None and existing.is_dir:
            raise IsADirectoryError(norm)
        self._overlay[norm] = Node(type="file", content=data)

    def append(self, path: str, data: bytes) -> None:
        try:
            current = self.read(path)
        except FileNotFoundError:
            current = b""
        self.write(path, current + data)

    def mkdir(self, path: str, exist_ok: bool = False) -> None:
        norm = _normalize(path)
        if self._effective(norm) is not None:
            if exist_ok:
                return
            raise FileExistsError(norm)
        parent = posixpath.dirname(norm) or "/"
        p_node = self._effective(parent)
        if p_node is None or not p_node.is_dir:
            raise FileNotFoundError(f"parent missing: {parent}")
        self._overlay[norm] = Node(type="dir")

    def unlink(self, path: str) -> None:
        norm = _normalize(path)
        node = self._effective(norm)
        if node is None:
            raise FileNotFoundError(norm)
        if node.is_dir:
            raise IsADirectoryError(norm)
        if self._base.get(norm) is not None:
            self._overlay[norm] = TOMBSTONE
        else:
            self._overlay.pop(norm, None)

    def rmdir(self, path: str) -> None:
        norm = _normalize(path)
        node = self._effective(norm)
        if node is None:
            raise FileNotFoundError(norm)
        if not node.is_dir:
            raise NotADirectoryError(norm)
        if norm == "/":
            raise PermissionError("cannot remove /")
        if self.list(norm):
            raise OSError(f"directory not empty: {norm}")
        if self._base.get(norm) is not None:
            self._overlay[norm] = TOMBSTONE
        else:
            self._overlay.pop(norm, None)
