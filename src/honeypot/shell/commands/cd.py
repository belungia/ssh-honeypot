from __future__ import annotations

from ..context import ShellContext
from .base import Command


class CdCommand(Command):
    name = "cd"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if len(args) > 1:
            ctx.error("bash: cd: too many arguments\n")
            return 1

        target = args[0] if args else ctx.home()
        if target == "-":
            target = ctx.previous_cwd

        old = ctx.vfs.cwd
        try:
            ctx.vfs.chdir(target)
        except FileNotFoundError as e:
            ctx.error(f"bash: cd: {e}: No such file or directory\n")
            return 1
        except NotADirectoryError as e:
            ctx.error(f"bash: cd: {e}: Not a directory\n")
            return 1

        ctx.remember_cwd(old)
        if args and args[0] == "-":
            ctx.writeln(ctx.vfs.cwd)
        return 0
