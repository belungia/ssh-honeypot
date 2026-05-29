from __future__ import annotations

from ..context import ShellContext
from .base import Command


class WhoamiCommand(Command):
    name = "whoami"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(ctx.username)
        return 0
