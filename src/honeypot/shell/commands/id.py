from __future__ import annotations

from ..context import ShellContext
from .base import Command


class IdCommand(Command):
    name = "id"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        uid, gid = ctx.uid, ctx.gid
        user = ctx.username
        groups = "0(root)" if ctx.is_root else f"{gid}({user}),100(users)"
        ctx.writeln(f"uid={uid}({user}) gid={gid}({user}) groups={groups}")
        return 0
