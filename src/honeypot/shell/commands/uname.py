from __future__ import annotations

from ..context import ShellContext
from .base import Command


class UnameCommand(Command):
    name = "uname"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        p = ctx.system_profile.get("uname", {}) or {}
        kernel_name = p.get("kernel_name", "Linux")
        nodename = p.get("nodename", ctx.hostname)
        kernel_release = p.get("kernel_release", "5.15.0")
        kernel_version = p.get("kernel_version", "#1 SMP")
        machine = p.get("machine", "x86_64")
        processor = p.get("processor", machine)
        hardware = p.get("hardware_platform", machine)
        os_name = p.get("os", "GNU/Linux")

        if not args or args == ["-s"]:
            ctx.writeln(kernel_name)
            return 0

        flags: set[str] = set()
        for a in args:
            if a == "-a":
                flags.update("snrvmpio")
            elif a.startswith("-") and len(a) > 1:
                for ch in a[1:]:
                    flags.add(ch)
            else:
                ctx.error(f"uname: extra operand '{a}'\n")
                return 1

        parts: list[str] = []
        if "s" in flags:
            parts.append(kernel_name)
        if "n" in flags:
            parts.append(nodename)
        if "r" in flags:
            parts.append(kernel_release)
        if "v" in flags:
            parts.append(kernel_version)
        if "m" in flags:
            parts.append(machine)
        if "p" in flags:
            parts.append(processor)
        if "i" in flags:
            parts.append(hardware)
        if "o" in flags:
            parts.append(os_name)

        ctx.writeln(" ".join(parts) if parts else kernel_name)
        return 0
