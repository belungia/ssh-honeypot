from __future__ import annotations

from ..context import ShellContext
from .base import Command


class RmCommand(Command):
    name = "rm"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        recursive = False
        force = False
        paths: list[str] = []
        for a in args:
            if a in ("-r", "-R", "--recursive"):
                recursive = True
            elif a == "-f" or a == "--force":
                force = True
            elif a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                for flag in a[1:]:
                    if flag in ("r", "R"):
                        recursive = True
                    elif flag == "f":
                        force = True
                    else:
                        ctx.error(f"rm: invalid option -- '{flag}'\n")
                        return 2
            else:
                paths.append(a)

        if not paths:
            if force:
                return 0
            ctx.error("rm: missing operand\n")
            return 1

        rc = 0
        for path in paths:
            target = ctx.vfs.resolve(path)
            if not ctx.vfs.exists(target):
                if force:
                    continue
                ctx.error(f"rm: cannot remove '{path}': No such file or directory\n")
                rc = 1
                continue
            if ctx.vfs.is_dir(target):
                if not recursive:
                    ctx.error(f"rm: cannot remove '{path}': Is a directory\n")
                    rc = 1
                    continue
                try:
                    self._rm_tree(target, ctx)
                except Exception as e:  # noqa: BLE001
                    ctx.error(f"rm: cannot remove '{path}': {e}\n")
                    rc = 1
            else:
                try:
                    ctx.vfs.unlink(target)
                except Exception as e:  # noqa: BLE001
                    ctx.error(f"rm: cannot remove '{path}': {e}\n")
                    rc = 1
        return rc

    @staticmethod
    def _rm_tree(path: str, ctx: ShellContext) -> None:
        if ctx.vfs.is_dir(path):
            for child in list(ctx.vfs.list(path)):
                full = path.rstrip("/") + "/" + child if path != "/" else "/" + child
                RmCommand._rm_tree(full, ctx)
            ctx.vfs.rmdir(path)
        else:
            ctx.vfs.unlink(path)
