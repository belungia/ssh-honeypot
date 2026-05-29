from __future__ import annotations

from ..context import ShellContext
from .base import Command


_FAKE_PROCS = [
    ("    1", "?",     "00:00:01", "/sbin/init"),
    ("  402", "?",     "00:00:00", "/lib/systemd/systemd-journald"),
    ("  457", "?",     "00:00:00", "/lib/systemd/systemd-udevd"),
    ("  612", "?",     "00:00:00", "/usr/sbin/cron -f"),
    ("  624", "?",     "00:00:00", "/usr/sbin/rsyslogd -n"),
    ("  730", "?",     "00:00:00", "/usr/sbin/sshd -D"),
    (" 1245", "?",     "00:00:00", "/usr/bin/dbus-daemon --system --address=systemd:"),
]


class PsCommand(Command):
    name = "ps"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        verbose = any(a in ("aux", "-aux", "-ef", "-Af", "-A", "-e") for a in args)
        if verbose:
            ctx.writeln(
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
            )
            for pid, _tty, time, cmd in _FAKE_PROCS:
                ctx.writeln(
                    f"root      {pid.strip():>5}  0.0  0.1  10024  4892 ?        Ss   May24   {time} {cmd}"
                )
            # current session processes
            tty = "pts/0"
            ctx.writeln(
                f"{ctx.username:<8}    {2841:>5}  0.0  0.0  17536  3320 {tty}     Ss   12:00   00:00:00 -bash"
            )
            ctx.writeln(
                f"{ctx.username:<8}    {2855:>5}  0.0  0.0  17876  3604 {tty}     R+   12:00   00:00:00 ps {' '.join(args)}".rstrip()
            )
        else:
            ctx.writeln("  PID TTY          TIME CMD")
            ctx.writeln(" 2841 pts/0    00:00:00 bash")
            ctx.writeln(f" 2855 pts/0    00:00:00 ps {' '.join(args)}".rstrip())
        return 0
