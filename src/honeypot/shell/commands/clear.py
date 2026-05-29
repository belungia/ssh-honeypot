from __future__ import annotations

from ..context import ShellContext
from .base import Command


class ClearCommand(Command):
    name = "clear"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.write("\x1b[H\x1b[2J")
        return 0
