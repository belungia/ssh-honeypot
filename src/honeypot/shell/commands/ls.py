from __future__ import annotations

from ..context import ShellContext
from .base import Command


def _format_mode(node) -> str:
    type_char = "d" if node.is_dir else "-"
    mode = node.mode
    perms = ""
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 7
        perms += "r" if bits & 4 else "-"
        perms += "w" if bits & 2 else "-"
        perms += "x" if bits & 1 else "-"
    return type_char + perms


def _owner(uid: int) -> str:
    return "root" if uid == 0 else "user"


class LsCommand(Command):
    name = "ls"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        long_format = False
        show_all = False
        paths: list[str] = []
        for a in args:
            if a.startswith("-") and len(a) > 1:
                for flag in a[1:]:
                    if flag == "l":
                        long_format = True
                    elif flag == "a":
                        show_all = True
                    elif flag == "h":
                        pass  # human-readable: simulated
                    else:
                        ctx.error(f"ls: invalid option -- '{flag}'\n")
                        return 2
            else:
                paths.append(a)

        if not paths:
            paths = [ctx.vfs.cwd]

        rc = 0
        for idx, path in enumerate(paths):
            if len(paths) > 1:
                if idx > 0:
                    ctx.writeln()
                ctx.writeln(f"{path}:")
            rc = max(rc, self._list_one(path, long_format, show_all, ctx))
        return rc

    def _list_one(self, path: str, long_format: bool, show_all: bool, ctx: ShellContext) -> int:
        try:
            node = ctx.vfs.stat(path)
            if node is None:
                ctx.error(f"ls: cannot access '{path}': No such file or directory\n")
                return 2
            if node.is_file:
                ctx.writeln(path)
                return 0
            names = ctx.vfs.list(path)
        except NotADirectoryError:
            ctx.error(f"ls: cannot access '{path}': Not a directory\n")
            return 2

        if show_all:
            names = [".", ".."] + names

        if not long_format:
            ctx.writeln("  ".join(names))
            return 0

        lines: list[str] = []
        total = 0
        for name in names:
            full = path.rstrip("/") + "/" + name if path != "/" else "/" + name
            if name == ".":
                child = node
            elif name == "..":
                child = ctx.vfs.stat(full) or node
            else:
                child = ctx.vfs.stat(full)
            if child is None:
                continue
            size = len(child.content) if child.is_file else 4096
            total += (size + 4095) // 4096
            mode_str = _format_mode(child)
            lines.append(
                f"{mode_str} 1 {_owner(child.uid)} {_owner(child.gid)} "
                f"{size:>8} Jan  1 00:00 {name}"
            )
        ctx.writeln(f"total {total}")
        for line in lines:
            ctx.writeln(line)
        return 0
