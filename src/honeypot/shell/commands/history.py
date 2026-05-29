from __future__ import annotations

from ..context import ShellContext
from .base import Command


class HistoryCommand(Command):
    name = "history"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if args and args[0] == "-c":
            ctx.history.clear()
            return 0

        limit = None
        if args:
            try:
                limit = int(args[0])
            except ValueError:
                ctx.error(f"history: {args[0]}: numeric argument required\n")
                return 1

        entries = ctx.history
        if limit is not None and limit >= 0:
            entries = entries[-limit:]

        offset = len(ctx.history) - len(entries) + 1
        for idx, line in enumerate(entries):
            ctx.writeln(f"{offset + idx:>5}  {line}")
        return 0
