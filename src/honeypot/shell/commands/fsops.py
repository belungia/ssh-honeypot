"""File-tree mutating commands: cp, mv, chmod, chown.

chmod/chown succeed silently (we don't enforce permissions).
"""
from __future__ import annotations

import posixpath

from ..context import ShellContext
from .base import Command


def _copy_tree(src: str, dst: str, ctx: ShellContext) -> None:
    if ctx.vfs.is_dir(src):
        ctx.vfs.mkdir(dst, exist_ok=True)
        for name in ctx.vfs.list(src):
            _copy_tree(
                src.rstrip("/") + "/" + name if src != "/" else "/" + name,
                dst.rstrip("/") + "/" + name if dst != "/" else "/" + name,
                ctx,
            )
    else:
        ctx.vfs.write(dst, ctx.vfs.read(src))


class CpCommand(Command):
    name = "cp"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        recursive = False
        positional: list[str] = []
        for a in args:
            if a in ("-r", "-R", "--recursive"):
                recursive = True
            elif a.startswith("-") and len(a) > 1:
                for f in a[1:]:
                    if f in ("r", "R"):
                        recursive = True
            else:
                positional.append(a)

        if len(positional) < 2:
            ctx.error("cp: missing destination file operand\n")
            return 1

        *sources, dest = positional
        dest_resolved = ctx.vfs.resolve(dest)
        dest_is_dir = ctx.vfs.is_dir(dest_resolved)
        rc = 0
        for s in sources:
            src = ctx.vfs.resolve(s)
            if not ctx.vfs.exists(src):
                ctx.error(f"cp: cannot stat '{s}': No such file or directory\n")
                rc = 1
                continue
            if ctx.vfs.is_dir(src) and not recursive:
                ctx.error(f"cp: -r not specified; omitting directory '{s}'\n")
                rc = 1
                continue
            if dest_is_dir:
                target = dest_resolved.rstrip("/") + "/" + posixpath.basename(src)
                if dest_resolved == "/":
                    target = "/" + posixpath.basename(src)
            else:
                target = dest_resolved
            try:
                _copy_tree(src, target, ctx)
            except Exception as e:  # noqa: BLE001
                ctx.error(f"cp: cannot copy '{s}' to '{dest}': {e}\n")
                rc = 1
        return rc


class MvCommand(Command):
    name = "mv"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) < 2:
            ctx.error("mv: missing destination file operand\n")
            return 1
        *sources, dest = positional
        dest_resolved = ctx.vfs.resolve(dest)
        dest_is_dir = ctx.vfs.is_dir(dest_resolved)
        rc = 0
        for s in sources:
            src = ctx.vfs.resolve(s)
            if not ctx.vfs.exists(src):
                ctx.error(f"mv: cannot stat '{s}': No such file or directory\n")
                rc = 1
                continue
            if dest_is_dir:
                target = dest_resolved.rstrip("/") + "/" + posixpath.basename(src)
                if dest_resolved == "/":
                    target = "/" + posixpath.basename(src)
            else:
                target = dest_resolved
            try:
                _copy_tree(src, target, ctx)
                # remove source (file or directory)
                if ctx.vfs.is_dir(src):
                    self._rmtree(src, ctx)
                else:
                    ctx.vfs.unlink(src)
            except Exception as e:  # noqa: BLE001
                ctx.error(f"mv: cannot move '{s}' to '{dest}': {e}\n")
                rc = 1
        return rc

    @staticmethod
    def _rmtree(path: str, ctx: ShellContext) -> None:
        if ctx.vfs.is_dir(path):
            for child in list(ctx.vfs.list(path)):
                full = path.rstrip("/") + "/" + child if path != "/" else "/" + child
                MvCommand._rmtree(full, ctx)
            ctx.vfs.rmdir(path)
        else:
            ctx.vfs.unlink(path)


class ChmodCommand(Command):
    name = "chmod"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        # We accept the call to look legit; permissions are not enforced.
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            ctx.error("chmod: missing operand\n")
            return 1
        for path in targets[1:]:
            if not ctx.vfs.exists(path):
                ctx.error(f"chmod: cannot access '{path}': No such file or directory\n")
                return 1
        return 0


class ChownCommand(Command):
    name = "chown"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        targets = [a for a in args if not a.startswith("-")]
        if len(targets) < 2:
            ctx.error("chown: missing operand\n")
            return 1
        for path in targets[1:]:
            if not ctx.vfs.exists(path):
                ctx.error(f"chown: cannot access '{path}': No such file or directory\n")
                return 1
        return 0


class LnCommand(Command):
    name = "ln"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        # Doesn't model symlinks - `ln -s` just copies the path text into the target file
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) != 2:
            ctx.error("ln: usage error\n")
            return 1
        src, dst = positional
        try:
            ctx.vfs.write_text(dst, src + "\n")
        except Exception as e:  # noqa: BLE001
            ctx.error(f"ln: {dst}: {e}\n")
            return 1
        return 0
