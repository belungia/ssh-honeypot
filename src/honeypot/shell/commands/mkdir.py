from __future__ import annotations

import posixpath

from ..context import ShellContext
from .base import Command


class MkdirCommand(Command):
    name = "mkdir"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        parents = False
        paths: list[str] = []
        for a in args:
            if a == "-p" or a == "--parents":
                parents = True
            elif a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                for flag in a[1:]:
                    if flag == "p":
                        parents = True
                    else:
                        ctx.error(f"mkdir: invalid option -- '{flag}'\n")
                        return 2
            else:
                paths.append(a)

        if not paths:
            ctx.error("mkdir: missing operand\n")
            return 1

        rc = 0
        for path in paths:
            try:
                if parents:
                    self._mkdir_p(path, ctx)
                else:
                    ctx.vfs.mkdir(path)
            except FileExistsError:
                ctx.error(f"mkdir: cannot create directory '{path}': File exists\n")
                rc = 1
            except FileNotFoundError:
                ctx.error(f"mkdir: cannot create directory '{path}': No such file or directory\n")
                rc = 1
        return rc

    @staticmethod
    def _mkdir_p(path: str, ctx: ShellContext) -> None:
        resolved = ctx.vfs.resolve(path)
        parts = [p for p in resolved.split("/") if p]
        current = ""
        for part in parts:
            current = current + "/" + part
            if not ctx.vfs.exists(current):
                ctx.vfs.mkdir(current)
            elif not ctx.vfs.is_dir(current):
                raise FileExistsError(current)
