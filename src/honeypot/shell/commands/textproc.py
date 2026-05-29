"""Simple text-processing commands: head, tail, wc, grep, find.

These read files via the VFS only - no stdin support - which is enough to
fool common reconnaissance scripts.
"""
from __future__ import annotations

import posixpath
import re

from ..context import ShellContext
from .base import Command


def _parse_n(args: list[str], default: int) -> tuple[int, list[str]]:
    """Extract ``-n N`` / ``-N`` style count; returns (n, remaining_args)."""
    n = default
    rest: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-n" and i + 1 < len(args):
            try:
                n = int(args[i + 1])
            except ValueError:
                pass
            i += 2
            continue
        if a.startswith("-") and a[1:].lstrip("-").isdigit():
            n = int(a.lstrip("-"))
            i += 1
            continue
        rest.append(a)
        i += 1
    return n, rest


class HeadCommand(Command):
    name = "head"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        count, files = _parse_n(args, 10)
        rc = 0
        for idx, path in enumerate(files):
            try:
                lines = ctx.vfs.read_text(path).splitlines()
            except FileNotFoundError:
                ctx.error(f"head: cannot open '{path}' for reading: No such file or directory\n")
                rc = 1
                continue
            except IsADirectoryError:
                ctx.error(f"head: error reading '{path}': Is a directory\n")
                rc = 1
                continue
            if len(files) > 1:
                if idx > 0:
                    ctx.writeln()
                ctx.writeln(f"==> {path} <==")
            for line in lines[:count]:
                ctx.writeln(line)
        if not files:
            data = ctx.read_stdin()
            for line in data.splitlines()[:count]:
                ctx.writeln(line)
        return rc


class TailCommand(Command):
    name = "tail"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        args = [a for a in args if a != "-f"]
        count, files = _parse_n(args, 10)
        rc = 0
        for idx, path in enumerate(files):
            try:
                lines = ctx.vfs.read_text(path).splitlines()
            except FileNotFoundError:
                ctx.error(f"tail: cannot open '{path}' for reading: No such file or directory\n")
                rc = 1
                continue
            except IsADirectoryError:
                ctx.error(f"tail: error reading '{path}': Is a directory\n")
                rc = 1
                continue
            if len(files) > 1:
                if idx > 0:
                    ctx.writeln()
                ctx.writeln(f"==> {path} <==")
            for line in lines[-count:] if count else []:
                ctx.writeln(line)
        if not files:
            data = ctx.read_stdin()
            for line in data.splitlines()[-count:] if count else []:
                ctx.writeln(line)
        return rc


class WcCommand(Command):
    name = "wc"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        flags = {"l": False, "w": False, "c": False}
        files: list[str] = []
        for a in args:
            if a.startswith("-") and len(a) > 1:
                for f in a[1:]:
                    if f in flags:
                        flags[f] = True
            else:
                files.append(a)
        if not any(flags.values()):
            flags = {"l": True, "w": True, "c": True}

        def fmt(text: str, label: str) -> str:
            parts: list[str] = []
            if flags["l"]:
                parts.append(f"{text.count(chr(10)):>7}")
            if flags["w"]:
                parts.append(f"{len(text.split()):>7}")
            if flags["c"]:
                parts.append(f"{len(text.encode('utf-8')):>7}")
            if label:
                parts.append(label)
            return " ".join(parts)

        if not files:
            data = ctx.read_stdin()
            ctx.writeln(fmt(data, ""))
            return 0

        rc = 0
        totals_l = totals_w = totals_c = 0
        for path in files:
            try:
                data = ctx.vfs.read_text(path)
            except FileNotFoundError:
                ctx.error(f"wc: {path}: No such file or directory\n")
                rc = 1
                continue
            except IsADirectoryError:
                ctx.error(f"wc: {path}: Is a directory\n")
                rc = 1
                continue
            totals_l += data.count("\n")
            totals_w += len(data.split())
            totals_c += len(data.encode("utf-8"))
            ctx.writeln(fmt(data, path))
        if len(files) > 1:
            ctx.writeln(fmt("", "total").replace(
                "",
                "",
            ))
        return rc


class GrepCommand(Command):
    name = "grep"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        case_insensitive = False
        invert = False
        show_lineno = False
        recursive = False
        positional: list[str] = []
        for a in args:
            if a.startswith("-") and not a.startswith("--") and len(a) > 1:
                for f in a[1:]:
                    if f == "i":
                        case_insensitive = True
                    elif f == "v":
                        invert = True
                    elif f == "n":
                        show_lineno = True
                    elif f in ("r", "R"):
                        recursive = True
                    elif f == "E":
                        pass
                continue
            positional.append(a)

        if len(positional) < 1:
            ctx.error("Usage: grep [OPTION]... PATTERN [FILE]...\n")
            return 2

        pattern = positional[0]
        files = positional[1:]
        flags = re.IGNORECASE if case_insensitive else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            ctx.error(f"grep: Invalid regular expression: {e}\n")
            return 2

        any_match = False
        rc = 1

        def scan(path: str, content: str, show_path: bool) -> None:
            nonlocal any_match, rc
            for lineno, line in enumerate(content.splitlines(), 1):
                m = regex.search(line)
                if (m is not None) ^ invert:
                    any_match = True
                    rc = 0
                    prefix = f"{path}:" if show_path else ""
                    if show_lineno:
                        prefix += f"{lineno}:"
                    ctx.writeln(prefix + line)

        if not files:
            scan("(stdin)", ctx.read_stdin(), False)
            return rc

        targets: list[str] = []
        for f in files:
            if recursive:
                self._walk(f, targets, ctx)
            else:
                targets.append(f)

        for path in targets:
            try:
                data = ctx.vfs.read_text(path)
            except FileNotFoundError:
                ctx.error(f"grep: {path}: No such file or directory\n")
                rc = 2 if not any_match else rc
                continue
            except IsADirectoryError:
                if not recursive:
                    ctx.error(f"grep: {path}: Is a directory\n")
                    rc = 2 if not any_match else rc
                continue
            scan(path, data, show_path=len(targets) > 1 or recursive)
        return rc

    @staticmethod
    def _walk(start: str, out: list[str], ctx: ShellContext) -> None:
        try:
            if ctx.vfs.is_file(start):
                out.append(start)
                return
            if not ctx.vfs.is_dir(start):
                return
        except Exception:
            return
        stack = [start]
        while stack:
            cur = stack.pop()
            try:
                names = ctx.vfs.list(cur)
            except Exception:
                continue
            for name in names:
                child = cur.rstrip("/") + "/" + name if cur != "/" else "/" + name
                try:
                    if ctx.vfs.is_dir(child):
                        stack.append(child)
                    elif ctx.vfs.is_file(child):
                        out.append(child)
                except Exception:
                    continue


class FindCommand(Command):
    name = "find"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        paths: list[str] = []
        name_pat: str | None = None
        type_filter: str | None = None
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-name" and i + 1 < len(args):
                name_pat = args[i + 1]
                i += 2
                continue
            if a == "-type" and i + 1 < len(args):
                type_filter = args[i + 1]
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            paths.append(a)
            i += 1

        if not paths:
            paths = ["."]

        import fnmatch

        rc = 0
        for start in paths:
            root = ctx.vfs.resolve(start)
            if not ctx.vfs.exists(root):
                ctx.error(f"find: '{start}': No such file or directory\n")
                rc = 1
                continue
            stack = [root]
            while stack:
                cur = stack.pop()
                node = ctx.vfs.stat(cur)
                if node is None:
                    continue
                base = posixpath.basename(cur) or cur
                ok_name = name_pat is None or fnmatch.fnmatch(base, name_pat)
                ok_type = (
                    type_filter is None
                    or (type_filter == "f" and node.is_file)
                    or (type_filter == "d" and node.is_dir)
                )
                if ok_name and ok_type:
                    ctx.writeln(cur)
                if node.is_dir:
                    try:
                        names = ctx.vfs.list(cur)
                    except Exception:
                        names = []
                    for name in reversed(names):
                        stack.append(cur.rstrip("/") + "/" + name if cur != "/" else "/" + name)
        return rc
