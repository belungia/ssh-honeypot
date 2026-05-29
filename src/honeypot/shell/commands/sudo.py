from __future__ import annotations

from ..context import ShellContext
from .base import Command


class SudoCommand(Command):
    name = "sudo"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--":
                i += 1
                break
            if a in ("-u", "-g", "-p", "-h", "-c"):
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            break
        rest = args[i:]
        if not rest:
            ctx.error("usage: sudo command [args ...]\n")
            return 1
        return ctx.dispatch(" ".join(_quote(t) for t in rest))


def _quote(token: str) -> str:
    if not token:
        return "''"
    if any(c.isspace() or c in "\"'\\;|&" for c in token):
        return "'" + token.replace("'", "'\\''") + "'"
    return token
