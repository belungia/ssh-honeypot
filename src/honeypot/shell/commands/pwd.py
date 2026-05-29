from __future__ import annotations

from ..context import ShellContext
from .base import Command


class PwdCommand(Command):
    name = "pwd"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(ctx.vfs.cwd)
        return 0
