from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .context import ShellContext


@dataclass(frozen=True)
class Redirect:
    op: str       # ">", ">>", "<", "2>", "&>"
    target: str   # path in the VFS


_REDIRECT_OPS = {">", ">>", "<", "2>", "&>"}


def normalize(line: str) -> str:
    """Insert whitespace around redirection operators outside quotes.

    Without this step, ``echo hi>file`` would survive ``shlex.split`` as a
    single token. After normalize() the line is safe to hand to shlex.
    """
    out: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(line[i + 1])
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if not in_single and not in_double:
            two = line[i:i + 2]
            if two == ">>":
                out.append(" >> ")
                i += 2
                continue
            if two == "2>":
                out.append(" 2> ")
                i += 2
                continue
            if two == "&>":
                out.append(" &> ")
                i += 2
                continue
            if ch in (">", "<"):
                out.append(f" {ch} ")
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def extract(tokens: list[str]) -> tuple[list[str], list[Redirect]]:
    """Split tokens into ``(command_tokens, redirects)``.

    Raises ``ValueError`` if a redirect op has no following target.
    """
    cmd: list[str] = []
    redirs: list[Redirect] = []
    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]
        if t in _REDIRECT_OPS:
            if i + 1 >= n:
                raise ValueError("syntax error near unexpected token `newline'")
            redirs.append(Redirect(t, tokens[i + 1]))
            i += 2
        else:
            cmd.append(t)
            i += 1
    return cmd, redirs


def apply(redirs: list[Redirect], ctx: ShellContext) -> Callable[[], None]:
    """Swap ctx streams according to ``redirs`` and return a ``finalize()``
    callable that flushes captured buffers to the VFS and restores streams.

    May raise ``FileNotFoundError`` when ``< file`` points at a missing path.
    Stream state is rolled back automatically in that case.
    """
    saved_stdout = ctx.get_stdout()
    saved_stderr = ctx.get_stderr()
    saved_stdin = ctx.get_stdin()

    stdout_target: tuple[str, str] | None = None  # (path, "w"|"a")
    stderr_target: tuple[str, str] | None = None
    stdout_buf: list[str] = []
    stderr_buf: list[str] = []
    combined = False  # &> -> stderr piggy-backs on stdout_buf, no separate file

    try:
        for r in redirs:
            if r.op == "<":
                ctx.set_stdin(ctx.vfs.read_text(r.target))
            elif r.op == ">":
                stdout_target = (r.target, "w")
                stdout_buf.clear()
                ctx.set_stdout(stdout_buf.append)
            elif r.op == ">>":
                stdout_target = (r.target, "a")
                stdout_buf.clear()
                ctx.set_stdout(stdout_buf.append)
            elif r.op == "2>":
                stderr_target = (r.target, "w")
                stderr_buf.clear()
                ctx.set_stderr(stderr_buf.append)
                combined = False
            elif r.op == "&>":
                stdout_target = (r.target, "w")
                stdout_buf.clear()
                ctx.set_stdout(stdout_buf.append)
                ctx.set_stderr(stdout_buf.append)
                combined = True
                stderr_target = None
    except Exception:
        ctx.set_stdout(saved_stdout)
        ctx.set_stderr(saved_stderr)
        ctx.set_stdin(saved_stdin)
        raise

    def finalize() -> None:
        try:
            if stdout_target is not None:
                path, mode = stdout_target
                data = "".join(stdout_buf).encode("utf-8")
                if mode == "a":
                    ctx.vfs.append(path, data)
                else:
                    ctx.vfs.write(path, data)
            if stderr_target is not None and not combined:
                path, mode = stderr_target
                data = "".join(stderr_buf).encode("utf-8")
                if mode == "a":
                    ctx.vfs.append(path, data)
                else:
                    ctx.vfs.write(path, data)
        finally:
            ctx.set_stdout(saved_stdout)
            ctx.set_stderr(saved_stderr)
            ctx.set_stdin(saved_stdin)

    return finalize
