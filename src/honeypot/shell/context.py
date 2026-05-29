from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..audit import AuditRecorder
from ..fs import VFS


@dataclass
class ShellContext:
    """Per-session shell state and I/O surface.

    Commands receive a ShellContext and never touch the SSH process directly.
    Three independent text streams are exposed:
      - ``write(text)`` / ``writeln(...)`` -> stdout
      - ``error(text)``                    -> stderr
      - ``read_stdin()``                   -> string from ``< file`` redirect

    The redirection layer (``shell.redirect``) swaps the sinks for the
    duration of a single command, so commands stay completely unaware of
    whether their output is going to the terminal or a captured buffer.
    """

    vfs: VFS
    audit: AuditRecorder
    system_profile: dict[str, Any]
    session_id: str
    src: str
    username: str
    env: dict[str, str] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)
    pty_allocated: bool = True

    _stdout: Optional[Callable[[str], None]] = None
    _stderr: Optional[Callable[[str], None]] = None
    _stdin: str = ""
    _previous_cwd: str = "/"
    _last_exit: int = 0
    _should_exit: bool = False
    _dispatcher: Optional[Callable[[str], int]] = None

    def attach_writer(self, writer: Callable[[str], None]) -> None:
        """Bind the terminal-side writer.

        PTY ``\\n`` -> ``\\r\\n`` translation happens here, once, so that
        redirect buffers receive raw bytes without CR pollution.
        """
        pty = self.pty_allocated

        def terminal(text: str) -> None:
            if not text:
                return
            if pty:
                text = text.replace("\r\n", "\n").replace("\n", "\r\n")
            writer(text)

        self._stdout = terminal
        self._stderr = terminal

    # ---- stream access (used by the redirection layer) ----------------

    def get_stdout(self) -> Optional[Callable[[str], None]]:
        return self._stdout

    def get_stderr(self) -> Optional[Callable[[str], None]]:
        return self._stderr

    def get_stdin(self) -> str:
        return self._stdin

    def set_stdout(self, writer: Optional[Callable[[str], None]]) -> None:
        self._stdout = writer

    def set_stderr(self, writer: Optional[Callable[[str], None]]) -> None:
        self._stderr = writer

    def set_stdin(self, data: str) -> None:
        self._stdin = data

    # ---- command I/O API ---------------------------------------------

    def write(self, text: str) -> None:
        if self._stdout and text:
            self._stdout(text)

    def writeln(self, text: str = "") -> None:
        self.write(text + "\n")

    def error(self, text: str) -> None:
        if self._stderr and text:
            self._stderr(text)

    def read_stdin(self) -> str:
        return self._stdin

    # ---- shell re-entry (used by ``bash -c`` / ``sh -c`` / scripted bash) --

    def set_dispatcher(self, fn: Optional[Callable[[str], int]]) -> None:
        self._dispatcher = fn

    def dispatch(self, line: str) -> int:
        if self._dispatcher is None:
            return 127
        return self._dispatcher(line)

    # ---- session-level state -----------------------------------------

    @property
    def hostname(self) -> str:
        return str(self.system_profile.get("hostname", "localhost"))

    @property
    def last_exit(self) -> int:
        return self._last_exit

    def set_last_exit(self, code: int) -> None:
        self._last_exit = code

    @property
    def previous_cwd(self) -> str:
        return self._previous_cwd

    def remember_cwd(self, path: str) -> None:
        self._previous_cwd = path

    def request_exit(self) -> None:
        self._should_exit = True

    @property
    def exit_requested(self) -> bool:
        return self._should_exit

    @property
    def is_root(self) -> bool:
        return self.username == "root"

    @property
    def uid(self) -> int:
        return 0 if self.is_root else 1000

    @property
    def gid(self) -> int:
        return 0 if self.is_root else 1000

    def home(self) -> str:
        return "/root" if self.is_root else f"/home/{self.username}"

    def prompt(self) -> str:
        cwd = self.vfs.cwd
        home = self.home()
        if cwd == home:
            display = "~"
        elif cwd.startswith(home + "/"):
            display = "~" + cwd[len(home):]
        else:
            display = cwd
        sigil = "#" if self.is_root else "$"
        return f"{self.username}@{self.hostname}:{display}{sigil} "
