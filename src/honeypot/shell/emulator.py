from __future__ import annotations

import shlex
from typing import Optional

import asyncssh

from . import redirect
from .commands import Command, default_registry
from .context import ShellContext

_HISTORY_LIMIT = 1000


# ---- command-line segmentation -----------------------------------------

def _tokenize_segments(line: str) -> list[tuple[str, str]]:
    """Split a command line on ``;``, ``&&``, ``||`` honoring quotes/escapes.

    Returns ``[(sep, segment), ...]`` where ``sep`` is the operator BEFORE
    the segment. The first segment always uses ``";"`` (unconditional).
    """
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    sep = ";"
    in_single = False
    in_double = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(line[i + 1])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            if ch == ";":
                out.append((sep, "".join(buf)))
                buf = []
                sep = ";"
                i += 1
                continue
            if ch == "&" and i + 1 < n and line[i + 1] == "&":
                out.append((sep, "".join(buf)))
                buf = []
                sep = "&&"
                i += 2
                continue
            if ch == "|" and i + 1 < n and line[i + 1] == "|":
                out.append((sep, "".join(buf)))
                buf = []
                sep = "||"
                i += 2
                continue
        buf.append(ch)
        i += 1
    out.append((sep, "".join(buf)))
    return out


# ---- escape-sequence parsing -------------------------------------------

# CSI tail (everything after ESC[) -> semantic action.
_ESCAPE_MAP = {
    "A": "up", "B": "down", "C": "right", "D": "left",
    "H": "home", "F": "end",
    "1~": "home", "4~": "end", "7~": "home", "8~": "end",
    "3~": "delete",
    "1;5C": "word_right", "1;5D": "word_left",   # Ctrl-arrow (xterm)
    "1;3C": "word_right", "1;3D": "word_left",   # Alt-arrow
    "5C": "word_right",   "5D": "word_left",     # legacy
}


def _parse_escape(data: str, i: int) -> tuple[str, int]:
    """Parse an escape sequence starting at ``data[i]`` (``data[i] == '\\x1b'``).

    Recognizes both CSI sequences (``ESC [ ... <final>``) and plain
    ``ESC <letter>`` (``ESC f`` / ``ESC b`` for word movement).

    Returns ``(action, consumed)``. ``action`` is one of
    ``up/down/left/right/home/end/delete/word_left/word_right`` or ``""``.
    """
    n = len(data)
    if i + 1 >= n:
        return "", 1
    c = data[i + 1]

    # ESC f / ESC b - Alt-f / Alt-b in readline = word-wise navigation
    if c == "f":
        return "word_right", 2
    if c == "b":
        return "word_left", 2

    if c != "[":
        return "", 2  # unknown ESC <x> - skip both

    # CSI: scan to the final byte (letter or '~')
    j = i + 2
    while j < n:
        ch = data[j]
        if ch == "~" or ch.isalpha():
            seq = data[i + 2:j + 1]
            return _ESCAPE_MAP.get(seq, ""), (j - i + 1)
        j += 1
    return "", n - i  # incomplete sequence - drop


# ---- word boundary helpers ---------------------------------------------

def _word_left_pos(buf: list[str], cursor: int) -> int:
    i = cursor
    while i > 0 and not buf[i - 1].isalnum():
        i -= 1
    while i > 0 and buf[i - 1].isalnum():
        i -= 1
    return i


def _word_right_pos(buf: list[str], cursor: int) -> int:
    n = len(buf)
    i = cursor
    while i < n and not buf[i].isalnum():
        i += 1
    while i < n and buf[i].isalnum():
        i += 1
    return i


def _common_prefix(strings: list[str]) -> str:
    if not strings:
        return ""
    base = strings[0]
    for s in strings[1:]:
        k = 0
        while k < len(base) and k < len(s) and base[k] == s[k]:
            k += 1
        base = base[:k]
        if not base:
            break
    return base


# ---- emulator ---------------------------------------------------------

class ShellEmulator:
    """Drives an interactive shell or single-command exec over an SSH process."""

    def __init__(self, ctx: ShellContext, registry: Optional[dict[str, Command]] = None) -> None:
        self._ctx = ctx
        self._registry = registry if registry is not None else default_registry()
        # Expose dispatch to commands like `bash -c "..."`.
        ctx.set_dispatcher(self._dispatch)

    # ---- public entry points -----------------------------------------

    async def run_interactive(self, process: asyncssh.SSHServerProcess) -> int:
        self._write_motd()
        while True:
            self._ctx.write(self._ctx.prompt())
            try:
                line = await self._read_line(process)
            except EOFError:
                break
            if line is None:
                self._ctx.write("logout\n")
                break
            line = line.strip()
            if not line:
                continue
            self._remember(line)
            if line in ("exit", "logout"):
                self._ctx.write("logout\n")
                break
            rc = self._dispatch(line)
            self._ctx.set_last_exit(rc)
            if self._ctx.exit_requested:
                break
        return self._ctx.last_exit

    async def run_exec(self, command: str) -> int:
        rc = self._dispatch(command)
        self._ctx.set_last_exit(rc)
        return rc

    # ---- dispatch ----------------------------------------------------

    def _dispatch(self, line: str) -> int:
        last_rc = 0
        for sep, segment in _tokenize_segments(line):
            segment = segment.strip()
            if not segment:
                continue
            if sep == "&&" and last_rc != 0:
                continue
            if sep == "||" and last_rc == 0:
                continue
            normalized = redirect.normalize(segment)
            try:
                tokens = shlex.split(normalized, posix=True)
            except ValueError as e:
                self._ctx.error(f"bash: syntax error: {e}\n")
                last_rc = 2
                continue
            if not tokens:
                continue
            try:
                cmd_tokens, redirs = redirect.extract(tokens)
            except ValueError as e:
                self._ctx.error(f"bash: {e}\n")
                last_rc = 2
                continue
            last_rc = self._run_one(cmd_tokens, redirs)
        return last_rc

    def _run_one(self, tokens: list[str], redirs: list[redirect.Redirect]) -> int:
        if not tokens:
            if not redirs:
                return 0
            try:
                finalize = redirect.apply(redirs, self._ctx)
            except FileNotFoundError as e:
                self._ctx.error(f"bash: {e}: No such file or directory\n")
                return 1
            except Exception as e:  # noqa: BLE001
                self._ctx.error(f"bash: redirect: {e}\n")
                return 1
            try:
                finalize()
            except Exception as e:  # noqa: BLE001
                self._ctx.error(f"bash: cannot write redirect target: {e}\n")
                return 1
            return 0

        name, args = tokens[0], tokens[1:]
        cmd = self._registry.get(name)

        try:
            finalize = redirect.apply(redirs, self._ctx)
        except FileNotFoundError as e:
            self._ctx.error(f"bash: {e}: No such file or directory\n")
            return 1
        except Exception as e:  # noqa: BLE001
            self._ctx.error(f"bash: redirect: {e}\n")
            return 1

        try:
            if cmd is None:
                self._ctx.error(f"bash: {name}: command not found\n")
                self._ctx.audit.unknown_command(
                    src=self._ctx.src,
                    username=self._ctx.username,
                    session_id=self._ctx.session_id,
                    name=name,
                    args=args,
                    cwd=self._ctx.vfs.cwd,
                )
                rc = 127
            else:
                try:
                    rc = cmd.run(args, self._ctx)
                except Exception as e:  # noqa: BLE001
                    self._ctx.error(f"bash: {name}: internal error: {e}\n")
                    rc = 1
        finally:
            try:
                finalize()
            except Exception as e:  # noqa: BLE001
                self._ctx.error(f"bash: cannot write redirect target: {e}\n")
                try:
                    rc  # type: ignore[used-before-def]
                except NameError:
                    rc = 1
                else:
                    if rc == 0:
                        rc = 1

        if cmd is not None:
            self._ctx.audit.command(
                src=self._ctx.src,
                username=self._ctx.username,
                session_id=self._ctx.session_id,
                name=name,
                args=args,
                cwd=self._ctx.vfs.cwd,
                exit_code=rc,
            )
        return rc

    # ---- line editing ------------------------------------------------

    def _remember(self, line: str) -> None:
        h = self._ctx.history
        if not h or h[-1] != line:
            h.append(line)
            if len(h) > _HISTORY_LIMIT:
                del h[: len(h) - _HISTORY_LIMIT]

    async def _read_line(self, process: asyncssh.SSHServerProcess) -> Optional[str]:
        """Read a single command line with inline editing.

        Keys:
          - printable / Tab-completion
          - Backspace / Delete
          - Ctrl-C (cancel) / Ctrl-D (EOF when buffer empty)
          - Left/Right cursor / Home/End
          - Ctrl+Left, Ctrl+Right, Alt-b, Alt-f - word movement
          - Up/Down - history
        """
        write = self._ctx.write
        buf: list[str] = []
        cursor: int = 0
        hist_idx: int = 0

        while True:
            try:
                data = await process.stdin.read(1024)
            except asyncssh.BreakReceived:
                write("^C\n")
                buf, cursor, hist_idx = [], 0, 0
                write(self._ctx.prompt())
                continue
            except asyncssh.TerminalSizeChanged:
                continue
            except asyncssh.SignalReceived:
                continue
            except (asyncssh.ConnectionLost, BrokenPipeError, ConnectionResetError):
                raise EOFError

            if not data:
                if buf:
                    return "".join(buf)
                return None

            i = 0
            n = len(data)
            while i < n:
                ch = data[i]

                if ch == "\x1b":
                    action, consumed = _parse_escape(data, i)
                    i += consumed
                    cursor = self._handle_escape(action, buf, cursor)
                    if action in ("up", "down"):
                        result = self._navigate_history(hist_idx, up=(action == "up"))
                        if result is not None:
                            new_text, new_idx = result
                            buf, cursor = self._replace_line(buf, cursor, new_text)
                            hist_idx = new_idx
                    continue

                if ch == "\x03":  # Ctrl-C
                    write("^C\n")
                    buf, cursor, hist_idx = [], 0, 0
                    write(self._ctx.prompt())
                    i += 1
                    continue

                if ch == "\x04":  # Ctrl-D
                    if not buf:
                        return None
                    i += 1
                    continue

                if ch in ("\r", "\n"):
                    if cursor < len(buf):
                        write("".join(buf[cursor:]))
                    write("\n")
                    return "".join(buf)

                if ch in ("\x7f", "\x08"):  # Backspace
                    if cursor > 0:
                        del buf[cursor - 1]
                        cursor -= 1
                        write("\b")
                        tail = "".join(buf[cursor:]) + " "
                        write(tail)
                        write("\b" * len(tail))
                    i += 1
                    continue

                if ch == "\t":
                    buf, cursor = self._handle_tab(buf, cursor)
                    i += 1
                    continue

                # Printable
                if ch >= " ":
                    buf.insert(cursor, ch)
                    write(ch)
                    if cursor < len(buf) - 1:
                        tail = "".join(buf[cursor + 1:])
                        write(tail)
                        write("\b" * len(tail))
                    cursor += 1
                i += 1

    def _handle_escape(self, action: str, buf: list[str], cursor: int) -> int:
        """Pure-cursor escape actions. Returns new cursor."""
        write = self._ctx.write
        if action == "left":
            if cursor > 0:
                write("\b")
                return cursor - 1
        elif action == "right":
            if cursor < len(buf):
                write(buf[cursor])
                return cursor + 1
        elif action == "home":
            if cursor > 0:
                write("\b" * cursor)
                return 0
        elif action == "end":
            if cursor < len(buf):
                write("".join(buf[cursor:]))
                return len(buf)
        elif action == "delete":
            if cursor < len(buf):
                del buf[cursor]
                tail = "".join(buf[cursor:]) + " "
                write(tail)
                write("\b" * len(tail))
        elif action == "word_left":
            new = _word_left_pos(buf, cursor)
            if new < cursor:
                write("\b" * (cursor - new))
                return new
        elif action == "word_right":
            new = _word_right_pos(buf, cursor)
            if new > cursor:
                write("".join(buf[cursor:new]))
                return new
        return cursor

    # ---- Tab completion ---------------------------------------------

    def _handle_tab(self, buf: list[str], cursor: int) -> tuple[list[str], int]:
        # Locate the word being completed.
        word_start = cursor
        while word_start > 0 and not buf[word_start - 1].isspace():
            word_start -= 1
        partial = "".join(buf[word_start:cursor])

        # First word (command) vs later word (path)?
        head_text = "".join(buf[:word_start]).lstrip()
        is_first_word = head_text == ""

        if is_first_word:
            matches = sorted(n for n in self._registry if n.startswith(partial))
            is_dir: dict[str, bool] = {}
            trailing_for_unique = " "
        else:
            matches, is_dir = self._path_completions(partial)
            trailing_for_unique = ""  # decided per-match below

        if not matches:
            return buf, cursor

        if len(matches) == 1:
            only = matches[0]
            if is_first_word:
                replacement = only + trailing_for_unique
            else:
                replacement = only + ("/" if is_dir.get(only) else " ")
            return self._splice(buf, cursor, word_start, replacement)

        common = _common_prefix(matches)
        if len(common) > len(partial):
            return self._splice(buf, cursor, word_start, common)

        # Multiple options, no further common prefix - show them.
        self._show_completions(buf, cursor, matches)
        return buf, cursor

    def _splice(
        self,
        buf: list[str],
        cursor: int,
        word_start: int,
        replacement: str,
    ) -> tuple[list[str], int]:
        write = self._ctx.write
        # Move visible cursor to end of current text.
        tail = "".join(buf[cursor:])
        if tail:
            write(tail)
        # Erase everything from word_start to end-of-line.
        wipe = len(buf) - word_start
        if wipe:
            write("\b" * wipe + " " * wipe + "\b" * wipe)
        # Compose the new buffer.
        new_buf = buf[:word_start] + list(replacement) + buf[cursor:]
        new_cursor = word_start + len(replacement)
        # Re-emit from word_start onwards.
        write("".join(new_buf[word_start:]))
        # Move cursor back to its logical position.
        right_of_cursor = len(new_buf) - new_cursor
        if right_of_cursor:
            write("\b" * right_of_cursor)
        return new_buf, new_cursor

    def _show_completions(self, buf: list[str], cursor: int, matches: list[str]) -> None:
        write = self._ctx.write
        if cursor < len(buf):
            write("".join(buf[cursor:]))
        write("\n")
        write("  ".join(matches))
        write("\n")
        write(self._ctx.prompt())
        write("".join(buf))
        right = len(buf) - cursor
        if right:
            write("\b" * right)

    def _path_completions(self, partial: str) -> tuple[list[str], dict[str, bool]]:
        if "/" in partial:
            cut = partial.rfind("/") + 1
            dir_part = partial[:cut]
            name_prefix = partial[cut:]
        else:
            dir_part = ""
            name_prefix = partial

        try:
            base_dir = self._ctx.vfs.resolve(dir_part) if dir_part else self._ctx.vfs.cwd
            if not self._ctx.vfs.is_dir(base_dir):
                return [], {}
            names = self._ctx.vfs.list(base_dir)
        except Exception:  # noqa: BLE001
            return [], {}

        matches: list[str] = []
        is_dir: dict[str, bool] = {}
        for name in names:
            if not name.startswith(name_prefix):
                continue
            full = dir_part + name
            matches.append(full)
            child = base_dir.rstrip("/") + "/" + name if base_dir != "/" else "/" + name
            is_dir[full] = self._ctx.vfs.is_dir(child)
        matches.sort()
        return matches, is_dir

    # ---- history navigation ----------------------------------------

    def _navigate_history(self, idx: int, up: bool) -> Optional[tuple[str, int]]:
        h = self._ctx.history
        if not h:
            return None
        if up:
            if idx < len(h):
                new_idx = idx + 1
                return h[-new_idx], new_idx
            return None
        if idx > 1:
            new_idx = idx - 1
            return h[-new_idx], new_idx
        if idx == 1:
            return "", 0
        return None

    def _replace_line(self, buf: list[str], cursor: int, new_text: str) -> tuple[list[str], int]:
        write = self._ctx.write
        if cursor < len(buf):
            write("".join(buf[cursor:]))
        n = len(buf)
        if n:
            write("\b" * n)
            write(" " * n)
            write("\b" * n)
        write(new_text)
        return list(new_text), len(new_text)

    def _write_motd(self) -> None:
        motd = self._ctx.system_profile.get("motd", "")
        if motd:
            self._ctx.write(motd)
            if not motd.endswith("\n"):
                self._ctx.write("\n")
