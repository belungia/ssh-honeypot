from __future__ import annotations

from ..context import ShellContext
from .base import Command


class EchoCommand(Command):
    name = "echo"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        trailing_newline = True
        i = 0
        while i < len(args) and args[i].startswith("-") and args[i] != "-":
            flag = args[i]
            if flag == "-n":
                trailing_newline = False
                i += 1
            elif flag == "--":
                i += 1
                break
            else:
                break
        text = " ".join(args[i:])
        ctx.write(text + ("\n" if trailing_newline else ""))
        return 0
