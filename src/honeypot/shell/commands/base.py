from __future__ import annotations

from abc import ABC, abstractmethod

from ..context import ShellContext


class Command(ABC):
    """Base interface for a shell command.

    Each implementation sets ``name`` and provides ``run``. Conventions:
      - return 0 on success, non-zero on error
      - write to ``ctx.write`` / ``ctx.error`` instead of returning text
      - never touch ctx.vfs internals - go through public VFS methods
    """

    name: str = ""

    @abstractmethod
    def run(self, args: list[str], ctx: ShellContext) -> int: ...
