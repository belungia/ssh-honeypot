"""System-info reconnaissance commands.

All output is synthesized from config (`system_profile.yaml`) plus
hard-coded fixtures, never from the real host. Bot reconnaissance scripts
typically scrape this output to fingerprint the box - making it look
believable is the whole point of the honeypot.
"""
from __future__ import annotations

from datetime import datetime

from ..context import ShellContext
from .base import Command


class HostnameCommand(Command):
    name = "hostname"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(ctx.hostname)
        return 0


class DateCommand(Command):
    name = "date"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        now = datetime.now().astimezone()
        ctx.writeln(now.strftime("%a %b %e %H:%M:%S %Z %Y").replace("  ", " "))
        return 0


class UptimeCommand(Command):
    name = "uptime"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        now = datetime.now().strftime("%H:%M:%S")
        ctx.writeln(
            f" {now} up 24 days,  3:14,  1 user,  load average: 0.08, 0.12, 0.15"
        )
        return 0


class EnvCommand(Command):
    name = "env"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        is_root = ctx.is_root
        env = {
            "SHELL": "/bin/bash",
            "USER": ctx.username,
            "LOGNAME": ctx.username,
            "HOME": ctx.home(),
            "PWD": ctx.vfs.cwd,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "TERM": "xterm-256color",
            "HOSTNAME": ctx.hostname,
            "MAIL": f"/var/mail/{ctx.username}",
        }
        if is_root:
            env["SUDO_USER"] = "root"
        for k, v in env.items():
            ctx.writeln(f"{k}={v}")
        return 0


class ExportCommand(Command):
    name = "export"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        return 0


class WhichCommand(Command):
    name = "which"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if not args:
            return 0
        from . import default_registry
        registered = set(default_registry().keys())
        rc = 0
        for name in args:
            if name in registered:
                ctx.writeln(f"/usr/bin/{name}")
            else:
                rc = 1
        return rc


class WhereisCommand(Command):
    name = "whereis"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        from . import default_registry
        registered = set(default_registry().keys())
        for name in args:
            if name in registered:
                ctx.writeln(
                    f"{name}: /usr/bin/{name} /usr/share/man/man1/{name}.1.gz"
                )
            else:
                ctx.writeln(f"{name}:")
        return 0


class IfconfigCommand(Command):
    name = "ifconfig"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        ether 02:42:0a:00:00:2a  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 184293  bytes 24102481 (22.9 MiB)\n"
            "        RX errors 0  dropped 0  overruns 0  frame 0\n"
            "        TX packets 83214  bytes 9214083 (8.7 MiB)\n"
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
            "        RX packets 0  bytes 0 (0.0 B)\n"
            "        TX packets 0  bytes 0 (0.0 B)"
        )
        return 0


class IpCommand(Command):
    name = "ip"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if not args:
            ctx.error("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n")
            return 1
        sub = args[0]
        if sub in ("a", "addr", "address"):
            ctx.writeln(
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                "    link/ether 02:42:0a:00:00:2a brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever"
            )
            return 0
        if sub in ("r", "route"):
            ctx.writeln(
                "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.42 metric 100\n"
                "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.42"
            )
            return 0
        if sub in ("link",):
            ctx.writeln(
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                "    link/ether 02:42:0a:00:00:2a brd ff:ff:ff:ff:ff:ff"
            )
            return 0
        ctx.error(f"Object \"{sub}\" is unknown, try \"ip help\".\n")
        return 1


class NetstatCommand(Command):
    name = "netstat"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 10.0.0.42:22            10.0.0.4:54012          ESTABLISHED\n"
            "tcp6       0      0 :::22                   :::*                    LISTEN\n"
            "udp        0      0 0.0.0.0:68              0.0.0.0:*"
        )
        return 0


class SsCommand(Command):
    name = "ss"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "Netid State      Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "tcp   LISTEN     0      128    0.0.0.0:22          0.0.0.0:*\n"
            "tcp   LISTEN     0      100    127.0.0.1:25        0.0.0.0:*\n"
            "tcp   ESTAB      0      0      10.0.0.42:22        10.0.0.4:54012"
        )
        return 0


class MountCommand(Command):
    name = "mount"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
            "tmpfs on /run type tmpfs (rw,nosuid,nodev,size=204852k,mode=755)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
            "devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620)"
        )
        return 0


class DfCommand(Command):
    name = "df"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        human = any("h" in a for a in args if a.startswith("-"))
        if human:
            ctx.writeln(
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        40G   12G   27G  31% /\n"
                "tmpfs           200M     0  200M   0% /run\n"
                "tmpfs            48M     0   48M   0% /dev/shm\n"
                "tmpfs            16M  4.0K   16M   1% /tmp"
            )
        else:
            ctx.writeln(
                "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
                "/dev/sda1       41284928 12189412 27001236  31% /\n"
                "tmpfs             204852        0   204852   0% /run\n"
                "tmpfs              49152        0    49152   0% /dev/shm\n"
                "tmpfs              16384        4    16380   1% /tmp"
            )
        return 0


class FreeCommand(Command):
    name = "free"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        human = any("h" in a for a in args if a.startswith("-"))
        if human:
            ctx.writeln(
                "              total        used        free      shared  buff/cache   available\n"
                "Mem:           1.9Gi       402Mi       1.0Gi        12Mi       515Mi       1.4Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi"
            )
        else:
            ctx.writeln(
                "              total        used        free      shared  buff/cache   available\n"
                "Mem:        2048124      411284     1085412       12288      527512     1462128\n"
                "Swap:       2097148           0     2097148"
            )
        return 0


class DmesgCommand(Command):
    name = "dmesg"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "[    0.000000] Linux version 5.15.0-91-generic (buildd@lcy02-amd64-031) (gcc-11)\n"
            "[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-5.15.0-91-generic root=UUID=... ro\n"
            "[    0.000000] KERNEL supported cpus: Intel, AMD, Hygon, Centaur, Zhaoxin\n"
            "[    0.001234] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'\n"
            "[    0.123456] ACPI: Local APIC address 0xfee00000\n"
            "[    0.234567] DMAR: Host address width 39\n"
            "[    1.024781] systemd[1]: systemd 249.11-0ubuntu3.12 running in system mode."
        )
        return 0


class LastCommand(Command):
    name = "last"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(
            "root     pts/0        10.0.0.4         Mon May 27 09:14   still logged in\n"
            "root     pts/0        10.0.0.4         Sun May 26 22:01 - 22:47  (00:46)\n"
            "reboot   system boot  5.15.0-91-generi Sat May  4 12:00 - 11:59 (24+23:59)\n"
            "\n"
            "wtmp begins Sat May  4 12:00:00 2026"
        )
        return 0


class WhoCommand(Command):
    name = "who"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        ctx.writeln(f"{ctx.username:<8} pts/0        2026-05-27 09:14 (10.0.0.4)")
        return 0


class WCommand(Command):
    name = "w"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        now = datetime.now().strftime("%H:%M:%S")
        ctx.writeln(
            f" {now} up 24 days,  3:14,  1 user,  load average: 0.08, 0.12, 0.15\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{ctx.username:<8} pts/0    10.0.0.4         09:14    0.00s  0.05s  0.00s w"
        )
        return 0


class CrontabCommand(Command):
    name = "crontab"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if args and args[0] == "-l":
            try:
                data = ctx.vfs.read_text(f"/var/spool/cron/crontabs/{ctx.username}")
            except FileNotFoundError:
                ctx.error(f"no crontab for {ctx.username}\n")
                return 1
            ctx.write(data)
            if data and not data.endswith("\n"):
                ctx.write("\n")
            return 0
        if args and args[0] == "-r":
            try:
                ctx.vfs.unlink(f"/var/spool/cron/crontabs/{ctx.username}")
            except FileNotFoundError:
                pass
            return 0
        return 0


class AptCommand(Command):
    name = "apt-get"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        if not args:
            ctx.error("apt-get: no command supplied\n")
            return 1
        sub = args[0]
        if sub == "update":
            ctx.writeln(
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Hit:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n"
                "Hit:3 http://archive.ubuntu.com/ubuntu jammy-security InRelease\n"
                "Reading package lists... Done"
            )
            return 0
        if sub in ("install", "remove"):
            pkgs = [a for a in args[1:] if not a.startswith("-")]
            if not pkgs:
                ctx.error("E: Invalid operation\n")
                return 100
            ctx.writeln(
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                f"E: Unable to locate package {pkgs[0]}"
            )
            return 100
        ctx.error(f"E: Invalid operation {sub}\n")
        return 1


class AptCommandAlias(AptCommand):
    name = "apt"
