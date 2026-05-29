from __future__ import annotations

from ..context import ShellContext
from .base import Command


class _ShellLike(Command):
    """Common implementation behind ``bash``/``sh``.

    Handles three real-world invocations:
      - ``bash -c "<cmd>"``   -> dispatch <cmd> through the current shell
      - ``bash <file>``       -> read the file from the VFS and dispatch each non-blank, non-comment line
      - ``bash``              -> no-op success (we don't actually fork a nested shell)
    """

    name = "bash"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if not args:
            return 0

        i = 0
        while i < len(args) and args[i].startswith("-"):
            flag = args[i]
            if flag == "-c":
                if i + 1 >= len(args):
                    ctx.error(f"{self.name}: -c: option requires an argument\n")
                    return 2
                return ctx.dispatch(args[i + 1])
            i += 1

        rest = args[i:]
        if not rest:
            return 0

        script_path = rest[0]
        try:
            content = ctx.vfs.read_text(script_path)
        except FileNotFoundError:
            ctx.error(f"{self.name}: {script_path}: No such file or directory\n")
            return 127
        except IsADirectoryError:
            ctx.error(f"{self.name}: {script_path}: Is a directory\n")
            return 126

        last_rc = 0
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            last_rc = ctx.dispatch(line)
        return last_rc


class BashCommand(_ShellLike):
    name = "bash"


class ShCommand(_ShellLike):
    name = "sh"
