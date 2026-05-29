from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Node:
    type: str  # "dir" | "file"
    content: bytes = b""
    mode: int = 0o755
    uid: int = 0
    gid: int = 0
    mtime: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_dir(self) -> bool:
        return self.type == "dir"

    @property
    def is_file(self) -> bool:
        return self.type == "file"


def _normalize(path: str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    norm = posixpath.normpath(path)
    return norm or "/"


def _to_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


class BaseFS:
    """Read-only base layer loaded from a YAML template.

    Internally stores nodes in a flat dict keyed by normalized absolute path.
    """

    def __init__(self, raw: Optional[dict[str, Any]] = None) -> None:
        self._nodes: dict[str, Node] = {"/": Node(type="dir")}
        entries: dict[str, Any] = {}
        if raw:
            entries = raw.get("entries") or {}
        for path, entry in entries.items():
            norm = _normalize(path)
            self._nodes[norm] = self._make_node(entry)
        self._ensure_parents()

    @staticmethod
    def _make_node(entry: dict[str, Any]) -> Node:
        t = entry.get("type", "file")
        if t == "dir":
            return Node(
                type="dir",
                mode=entry.get("mode", 0o755),
                uid=entry.get("uid", 0),
                gid=entry.get("gid", 0),
            )
        return Node(
            type="file",
            content=_to_bytes(entry.get("content", "")),
            mode=entry.get("mode", 0o644),
            uid=entry.get("uid", 0),
            gid=entry.get("gid", 0),
        )

    def _ensure_parents(self) -> None:
        # Auto-create any missing parent directories so the tree is well-formed.
        missing: set[str] = set()
        for path in list(self._nodes):
            parent = posixpath.dirname(path)
            while parent and parent != "/" and parent not in self._nodes:
                missing.add(parent)
                parent = posixpath.dirname(parent)
        for p in missing:
            self._nodes[p] = Node(type="dir")

    def get(self, path: str) -> Optional[Node]:
        return self._nodes.get(_normalize(path))

    def exists(self, path: str) -> bool:
        return _normalize(path) in self._nodes

    def list(self, path: str) -> Optional[list[str]]:
        norm = _normalize(path)
        node = self._nodes.get(norm)
        if node is None or not node.is_dir:
            return None
        prefix = "/" if norm == "/" else norm + "/"
        names: list[str] = []
        for p in self._nodes:
            if p == norm or not p.startswith(prefix):
                continue
            rest = p[len(prefix):]
            if "/" in rest:
                continue
            names.append(rest)
        return sorted(names)

    def paths(self) -> list[str]:
        return sorted(self._nodes.keys())
