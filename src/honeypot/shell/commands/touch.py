from __future__ import annotations

from ..context import ShellContext
from .base import Command


class TouchCommand(Command):
    name = "touch"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            ctx.error("touch: missing file operand\n")
            return 1
        rc = 0
        for path in paths:
            try:
                ctx.vfs.touch(path)
            except FileNotFoundError:
                ctx.error(f"touch: cannot touch '{path}': No such file or directory\n")
                rc = 1
            except IsADirectoryError:
                pass
        return rc
