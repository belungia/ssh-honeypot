from __future__ import annotations

from ..context import ShellContext
from .base import Command


class CatCommand(Command):
    name = "cat"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if not args:
            data = ctx.read_stdin()
            if data:
                ctx.write(data)
                if not data.endswith("\n"):
                    ctx.write("\n")
            return 0

        rc = 0
        for path in args:
            try:
                data = ctx.vfs.read_text(path)
            except FileNotFoundError:
                ctx.error(f"cat: {path}: No such file or directory\n")
                rc = 1
                continue
            except IsADirectoryError:
                ctx.error(f"cat: {path}: Is a directory\n")
                rc = 1
                continue
            ctx.write(data)
            if data and not data.endswith("\n"):
                ctx.write("\n")
        return rc
