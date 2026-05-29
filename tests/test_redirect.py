import pytest

from honeypot.audit import AuditRecorder
from honeypot.fs import BaseFS, VFS
from honeypot.shell import ShellContext, ShellEmulator
from honeypot.shell.redirect import Redirect, extract, normalize


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
                "/etc/passwd": {"type": "file", "content": "root:x:0:0::/root:/bin/bash\n"},
                "/root": {"type": "dir"},
                "/tmp": {"type": "dir"},
                "/dev": {"type": "dir"},
                "/dev/null": {"type": "file", "content": ""},
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
        system_profile={"hostname": "h"},
        session_id="sid",
        src="1.2.3.4",
        username="root",
        pty_allocated=False,
    )
    ctx.attach_writer(out.append)
    emu = ShellEmulator(ctx)
    return ctx, emu, out, sink


def run(emu, line):
    return emu._dispatch(line)


# ---- normalize / extract -----------------------------------------------

@pytest.mark.parametrize(
    "raw,expected_tokens",
    [
        ("echo hi>a",   ["echo", "hi", ">", "a"]),
        ("echo hi >>a", ["echo", "hi", ">>", "a"]),
        ("echo hi 2>e", ["echo", "hi", "2>", "e"]),
        ("cmd &>both",  ["cmd", "&>", "both"]),
        ("cat <in",     ["cat", "<", "in"]),
    ],
)
def test_normalize_then_shlex(raw, expected_tokens):
    import shlex
    assert shlex.split(normalize(raw)) == expected_tokens


def test_normalize_keeps_quotes_intact():
    import shlex
    line = 'echo "hi>not_op" > real'
    assert shlex.split(normalize(line)) == ["echo", "hi>not_op", ">", "real"]


def test_extract_basic():
    cmd, redirs = extract(["echo", "hi", ">", "a", "2>", "b"])
    assert cmd == ["echo", "hi"]
    assert redirs == [Redirect(">", "a"), Redirect("2>", "b")]


def test_extract_missing_target_raises():
    with pytest.raises(ValueError):
        extract(["echo", "hi", ">"])


# ---- stdout redirect ---------------------------------------------------

def test_stdout_overwrite(env):
    ctx, emu, out, _ = env
    assert run(emu, "echo hello > /tmp/a") == 0
    assert ctx.vfs.read_text("/tmp/a") == "hello\n"
    # nothing leaked to the terminal
    assert "hello" not in "".join(out)


def test_stdout_append(env):
    ctx, emu, _, _ = env
    run(emu, "echo a > /tmp/x")
    run(emu, "echo b >> /tmp/x")
    assert ctx.vfs.read_text("/tmp/x") == "a\nb\n"


def test_stdout_overwrite_truncates(env):
    ctx, emu, _, _ = env
    run(emu, "echo one > /tmp/y")
    run(emu, "echo two > /tmp/y")
    assert ctx.vfs.read_text("/tmp/y") == "two\n"


def test_redirect_to_missing_parent_fails(env):
    ctx, emu, out, _ = env
    rc = run(emu, "echo hi > /nope/inner/a")
    assert rc == 1
    text = "".join(out)
    assert "cannot write redirect target" in text or "No such file" in text


# ---- stdin redirect ----------------------------------------------------

def test_cat_reads_from_stdin_redirect(env):
    ctx, emu, out, _ = env
    out.clear()
    rc = run(emu, "cat < /etc/passwd")
    assert rc == 0
    assert "root:x:0:0" in "".join(out)


def test_stdin_redirect_missing_file(env):
    ctx, emu, out, _ = env
    out.clear()
    rc = run(emu, "cat < /nope")
    assert rc == 1
    assert "No such file" in "".join(out)


# ---- stderr redirect ---------------------------------------------------

def test_stderr_only_to_file(env):
    ctx, emu, out, _ = env
    out.clear()
    rc = run(emu, "cat /missing 2> /tmp/err")
    # cat failed -> rc 1, error text captured to file, NOT terminal
    assert rc == 1
    err_text = ctx.vfs.read_text("/tmp/err")
    assert "No such file" in err_text
    assert "No such file" not in "".join(out)


def test_combined_redirect(env):
    ctx, emu, out, _ = env
    out.clear()
    rc = run(emu, "cat /missing &> /tmp/both")
    text = ctx.vfs.read_text("/tmp/both")
    assert "No such file" in text
    assert "No such file" not in "".join(out)


def test_stdout_and_stderr_separate(env):
    ctx, emu, out, _ = env
    out.clear()
    # cat one missing + one existing: stdout gets passwd, stderr gets error
    run(emu, "cat /etc/passwd /missing > /tmp/o 2> /tmp/e")
    assert "root:x:0:0" in ctx.vfs.read_text("/tmp/o")
    assert "No such file" in ctx.vfs.read_text("/tmp/e")


# ---- redirect persists across commands ---------------------------------

def test_streams_restored_between_commands(env):
    ctx, emu, out, _ = env
    out.clear()
    run(emu, "echo hidden > /tmp/h")
    run(emu, "echo visible")
    assert "visible" in "".join(out)
    assert "hidden" not in "".join(out)


# ---- unknown command + redirect still creates file ---------------------

def test_unknown_command_still_creates_file(env):
    ctx, emu, _, _ = env
    rc = run(emu, "nosuchcmd > /tmp/empty")
    # rc reflects the unknown command (127)
    assert rc == 127
    assert ctx.vfs.exists("/tmp/empty")
    assert ctx.vfs.read_text("/tmp/empty") == ""


# ---- /dev/null discard --------------------------------------------------

def test_devnull_swallows_output(env):
    ctx, emu, _, _ = env
    run(emu, "echo loud > /dev/null")
    # the file content gets overwritten in overlay; that's acceptable -
    # what matters is no crash and nothing on the terminal
    assert ctx.vfs.exists("/dev/null")
