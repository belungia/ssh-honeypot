"""Smoke tests for the new reconnaissance / fs-mutating commands."""

import pytest

from honeypot.audit import AuditRecorder
from honeypot.fs import BaseFS, VFS
from honeypot.shell import ShellContext
from honeypot.shell.commands import default_registry


class MemorySink:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture
def env():
    base = BaseFS(
        {
            "entries": {
                "/": {"type": "dir"},
                "/etc": {"type": "dir"},
                "/etc/passwd": {"type": "file", "content": "root:x:0:0::/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n"},
                "/etc/hostname": {"type": "file", "content": "srv-prod-01\n"},
                "/etc/issue": {"type": "file", "content": "Ubuntu 22.04.3 LTS\n"},
                "/root": {"type": "dir"},
                "/tmp": {"type": "dir"},
                "/var": {"type": "dir"},
                "/var/log": {"type": "dir"},
                "/var/log/auth.log": {"type": "file", "content": "May 27 09:14 sshd[123]: Accepted password for root from 10.0.0.4\n" * 3},
                "/var/spool": {"type": "dir"},
                "/var/spool/cron": {"type": "dir"},
                "/var/spool/cron/crontabs": {"type": "dir"},
            }
        }
    )
    vfs = VFS(base, cwd="/root", home="/root")
    out: list[str] = []
    sink = MemorySink()
    audit = AuditRecorder(sink)
    ctx = ShellContext(
        vfs=vfs,
        audit=audit,
        system_profile={"hostname": "srv-prod-01", "uname": {"kernel_name": "Linux"}},
        session_id="sid",
        src="1.2.3.4",
        username="root",
        pty_allocated=False,
    )
    ctx.attach_writer(out.append)
    return ctx, default_registry(), out, sink


def run_cmd(ctx, reg, name, *args):
    return reg[name].run(list(args), ctx)


# ---- sysinfo: hostname / date / uptime / env / which --------------------

def test_hostname(env):
    ctx, reg, out, _ = env
    out.clear()
    assert run_cmd(ctx, reg, "hostname") == 0
    assert out[0].strip() == "srv-prod-01"


def test_env_lists_basic_vars(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "env")
    text = "".join(out)
    assert "USER=root" in text
    assert "HOME=/root" in text
    assert "PATH=" in text


def test_which_known_and_unknown(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "which", "cat", "no_such_cmd", "wget")
    text = "".join(out)
    assert "/usr/bin/cat" in text
    assert "/usr/bin/wget" in text
    # which returns non-zero if ANY arg was unknown
    assert rc == 1


def test_ifconfig_eth0(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "ifconfig")
    text = "".join(out)
    assert "eth0" in text and "inet 10.0.0.42" in text


def test_ip_addr(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "ip", "a")
    text = "".join(out)
    assert "eth0" in text


def test_netstat(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "netstat")
    text = "".join(out)
    assert "LISTEN" in text and "ESTABLISHED" in text


def test_df_and_free(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "df")
    text = "".join(out)
    assert "Filesystem" in text and "/dev/sda1" in text
    out.clear()
    run_cmd(ctx, reg, "free")
    text = "".join(out)
    assert "Mem:" in text


def test_apt_update_and_install(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "apt-get", "update")
    assert rc == 0
    assert "Reading package lists" in "".join(out)
    out.clear()
    rc = run_cmd(ctx, reg, "apt-get", "install", "nmap")
    assert rc == 100  # bots get "unable to locate"
    assert "Unable to locate" in "".join(out)


# ---- textproc: head / tail / wc / grep / find ---------------------------

def test_head_default_10(env):
    ctx, reg, out, _ = env
    ctx.vfs.write_text("/tmp/lines", "\n".join(str(i) for i in range(20)) + "\n")
    out.clear()
    run_cmd(ctx, reg, "head", "/tmp/lines")
    text = "".join(out)
    assert "0\n" in text and "9\n" in text and "10\n" not in text


def test_head_n_flag(env):
    ctx, reg, out, _ = env
    ctx.vfs.write_text("/tmp/lines", "\n".join(str(i) for i in range(20)) + "\n")
    out.clear()
    run_cmd(ctx, reg, "head", "-n", "3", "/tmp/lines")
    assert "".join(out).strip() == "0\n1\n2".strip()


def test_tail_default(env):
    ctx, reg, out, _ = env
    ctx.vfs.write_text("/tmp/lines", "\n".join(str(i) for i in range(20)) + "\n")
    out.clear()
    run_cmd(ctx, reg, "tail", "/tmp/lines")
    text = "".join(out)
    # default tail prints last 10 lines -> "10".."19"
    lines = [ln for ln in text.split("\n") if ln]
    assert lines == [str(i) for i in range(10, 20)]


def test_wc_counts(env):
    ctx, reg, out, _ = env
    ctx.vfs.write_text("/tmp/x", "one two\nthree four five\n")
    out.clear()
    run_cmd(ctx, reg, "wc", "-l", "/tmp/x")
    assert "2" in "".join(out)
    out.clear()
    run_cmd(ctx, reg, "wc", "-w", "/tmp/x")
    assert "5" in "".join(out)


def test_grep_basic(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "grep", "root", "/etc/passwd")
    assert rc == 0
    assert "root:x:0:0" in "".join(out)


def test_grep_no_match(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "grep", "no_such_user", "/etc/passwd")
    assert rc == 1


def test_grep_recursive(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "grep", "-r", "Accepted", "/var/log")
    assert rc == 0
    assert "auth.log" in "".join(out)


def test_find_by_name(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "find", "/etc", "-name", "passwd")
    assert "/etc/passwd" in "".join(out)


def test_find_type_d(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "find", "/etc", "-type", "d")
    assert "/etc" in "".join(out)
    # files should not appear when -type d
    assert "/etc/passwd" not in "".join(out)


# ---- fsops: cp / mv / chmod / chown / ln --------------------------------

def test_cp_file(env):
    ctx, reg, _, _ = env
    ctx.vfs.write_text("/tmp/a", "hi")
    assert run_cmd(ctx, reg, "cp", "/tmp/a", "/tmp/b") == 0
    assert ctx.vfs.read_text("/tmp/b") == "hi"


def test_cp_into_directory(env):
    ctx, reg, _, _ = env
    ctx.vfs.write_text("/tmp/a", "hi")
    assert run_cmd(ctx, reg, "cp", "/tmp/a", "/root") == 0
    assert ctx.vfs.read_text("/root/a") == "hi"


def test_cp_dir_requires_r(env):
    ctx, reg, out, _ = env
    out.clear()
    rc = run_cmd(ctx, reg, "cp", "/etc", "/tmp/etc-copy")
    assert rc == 1
    assert "not specified" in "".join(out)


def test_cp_recursive(env):
    ctx, reg, _, _ = env
    rc = run_cmd(ctx, reg, "cp", "-r", "/etc", "/tmp/etc-copy")
    assert rc == 0
    assert ctx.vfs.read_text("/tmp/etc-copy/passwd").startswith("root:x:0:0")


def test_mv_file(env):
    ctx, reg, _, _ = env
    ctx.vfs.write_text("/tmp/a", "x")
    rc = run_cmd(ctx, reg, "mv", "/tmp/a", "/tmp/b")
    assert rc == 0
    assert not ctx.vfs.exists("/tmp/a")
    assert ctx.vfs.read_text("/tmp/b") == "x"


def test_chmod_succeeds_silently(env):
    ctx, reg, _, _ = env
    ctx.vfs.write_text("/tmp/script", "#!/bin/sh\n")
    rc = run_cmd(ctx, reg, "chmod", "+x", "/tmp/script")
    assert rc == 0


def test_chmod_missing_target(env):
    ctx, reg, _, _ = env
    rc = run_cmd(ctx, reg, "chmod", "755", "/nope/x")
    assert rc == 1
