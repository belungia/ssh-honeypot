"""Unit tests for non-IO bits of the emulator: escape parsing, word movement,
Tab completion logic, and bash/sudo command dispatch via ctx.dispatch."""

import pytest

from honeypot.audit import AuditRecorder
from honeypot.fs import BaseFS, VFS
from honeypot.shell import ShellContext, ShellEmulator
from honeypot.shell.emulator import (
    _common_prefix,
    _parse_escape,
    _word_left_pos,
    _word_right_pos,
)


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
                "/etc/passwd": {"type": "file", "content": "root:x:0\n"},
                "/etc/hostname": {"type": "file", "content": "h\n"},
                "/root": {"type": "dir"},
                "/tmp": {"type": "dir"},
                "/usr": {"type": "dir"},
                "/usr/bin": {"type": "dir"},
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


# ---- escape parser -----------------------------------------------------

@pytest.mark.parametrize(
    "seq,expected_action,expected_consumed",
    [
        ("\x1b[A",     "up",         3),
        ("\x1b[B",     "down",       3),
        ("\x1b[C",     "right",      3),
        ("\x1b[D",     "left",       3),
        ("\x1b[H",     "home",       3),
        ("\x1b[F",     "end",        3),
        ("\x1b[3~",    "delete",     4),
        ("\x1b[1;5C",  "word_right", 6),
        ("\x1b[1;5D",  "word_left",  6),
        ("\x1b[1;3C",  "word_right", 6),
        ("\x1b[1;3D",  "word_left",  6),
        ("\x1bf",      "word_right", 2),
        ("\x1bb",      "word_left",  2),
    ],
)
def test_parse_escape(seq, expected_action, expected_consumed):
    assert _parse_escape(seq, 0) == (expected_action, expected_consumed)


def test_parse_escape_unknown_csi():
    action, consumed = _parse_escape("\x1b[Z", 0)
    assert action == ""
    assert consumed == 3


def test_parse_escape_incomplete():
    action, consumed = _parse_escape("\x1b[1;5", 0)
    assert action == ""
    assert consumed == 5  # whole remainder consumed


# ---- word movement -----------------------------------------------------

@pytest.mark.parametrize(
    "buf,cursor,expected",
    [
        (list("one two three"), 13, 8),   # at end -> start of "three" (index 8)
        (list("one two three"),  9, 8),   # one past 't' of three -> 't' of three
        (list("one two three"),  8, 4),   # at "t" of three -> "two" start
        (list("one two three"),  3, 0),   # after "one" -> start
        (list("one"),            3, 0),
        (list(""),               0, 0),
    ],
)
def test_word_left_pos(buf, cursor, expected):
    assert _word_left_pos(buf, cursor) == expected


@pytest.mark.parametrize(
    "buf,cursor,expected",
    [
        (list("one two three"), 0, 3),
        (list("one two three"), 3, 7),
        (list("one two three"), 7, 13),
        (list("one"),           0, 3),
        (list(""),              0, 0),
    ],
)
def test_word_right_pos(buf, cursor, expected):
    assert _word_right_pos(buf, cursor) == expected


# ---- common-prefix helper ---------------------------------------------

def test_common_prefix_basic():
    assert _common_prefix(["cat", "cd", "clear"]) == "c"
    assert _common_prefix(["wget", "whoami", "which", "w", "who", "whereis"]) == "w"
    assert _common_prefix(["cat", "cd"]) == "c"
    assert _common_prefix(["cat"]) == "cat"
    assert _common_prefix([]) == ""


# ---- Tab completion (command names) -----------------------------------

def test_tab_single_command_match(env):
    ctx, emu, out, _ = env
    out.clear()
    # Type "wge" then Tab -> "wget "
    buf, cursor = emu._handle_tab(list("wge"), 3)
    assert "".join(buf) == "wget "
    assert cursor == len("wget ")


def test_tab_extends_to_common_prefix(env):
    ctx, emu, _, _ = env
    # "c" matches at least cat, cd, clear, crontab, curl, cp, chmod, chown
    # common prefix is "c" → already typed → no change BUT next Tab shows list
    buf, cursor = emu._handle_tab(list("c"), 1)
    # No extension if common == partial
    assert "".join(buf) == "c"


def test_tab_extension_to_unique_prefix(env):
    ctx, emu, _, _ = env
    # "su" matches only "sudo" - should become "sudo "
    buf, cursor = emu._handle_tab(list("su"), 2)
    assert "".join(buf) == "sudo "


def test_tab_no_match_is_noop(env):
    ctx, emu, _, _ = env
    buf, cursor = emu._handle_tab(list("zxq"), 3)
    assert "".join(buf) == "zxq"
    assert cursor == 3


# ---- Tab completion (paths) -------------------------------------------

def test_tab_path_unique_file(env):
    ctx, emu, _, _ = env
    # `cat /etc/pas` -> `cat /etc/passwd `
    buf = list("cat /etc/pas")
    new_buf, new_cursor = emu._handle_tab(buf, len(buf))
    assert "".join(new_buf) == "cat /etc/passwd "


def test_tab_path_unique_dir(env):
    ctx, emu, _, _ = env
    # `ls /et` -> `ls /etc/`
    buf = list("ls /et")
    new_buf, new_cursor = emu._handle_tab(buf, len(buf))
    assert "".join(new_buf) == "ls /etc/"


def test_tab_path_extension_only(env):
    ctx, emu, _, _ = env
    # In /etc, files are hostname + passwd → common prefix beyond "" is "h"/"p"
    # so for prefix "/etc/h" → "/etc/hostname " uniquely
    buf = list("cat /etc/h")
    new_buf, _ = emu._handle_tab(buf, len(buf))
    assert "".join(new_buf) == "cat /etc/hostname "


# ---- bash / sh / sudo via ctx.dispatch --------------------------------

def test_bash_dash_c_executes_inner(env):
    ctx, emu, out, _ = env
    out.clear()
    rc = emu._dispatch('bash -c "whoami; pwd"')
    text = "".join(out)
    assert "root" in text
    assert "/root" in text
    assert rc == 0


def test_bash_no_args_succeeds(env):
    _, emu, _, _ = env
    assert emu._dispatch("bash") == 0


def test_bash_runs_script_file(env):
    ctx, emu, out, _ = env
    ctx.vfs.write_text("/tmp/job.sh", "# comment\nwhoami\nuname\n")
    out.clear()
    rc = emu._dispatch("bash /tmp/job.sh")
    text = "".join(out)
    assert "root" in text
    assert "Linux" in text
    assert rc == 0


def test_sh_dash_c_alias(env):
    _, emu, out, _ = env
    out.clear()
    emu._dispatch('sh -c "echo via_sh"')
    assert "via_sh" in "".join(out)


def test_sudo_passes_through(env):
    _, emu, out, _ = env
    out.clear()
    emu._dispatch("sudo whoami")
    assert "root" in "".join(out)


def test_sudo_strips_flags(env):
    _, emu, out, _ = env
    out.clear()
    emu._dispatch("sudo -u nobody id")
    assert "uid=" in "".join(out)


# ---- bash NO LONGER yields "command not found" -------------------------

def test_bash_is_registered(env):
    _, emu, out, _ = env
    out.clear()
    emu._dispatch("bash -c 'echo ok'")
    assert "command not found" not in "".join(out)
    assert "ok" in "".join(out)
