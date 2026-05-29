from __future__ import annotations

import posixpath
from urllib.parse import urlparse

from ..context import ShellContext
from .base import Command

_FAKE_CONTENT = b"#!/bin/sh\n# (===DOWNLOADED CONTENT===)\n"
_FAKE_LENGTH = len(_FAKE_CONTENT)


class CurlCommand(Command):
    name = "curl"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        output_name: str | None = None
        remote_name = False
        silent = False
        urls: list[str] = []

        i = 0
        while i < len(args):
            a = args[i]
            if a == "-o" and i + 1 < len(args):
                output_name = args[i + 1]
                i += 2
                continue
            if a == "-O":
                remote_name = True
                i += 1
                continue
            if a in ("-s", "--silent"):
                silent = True
                i += 1
                continue
            if a.startswith("-") and a != "-":
                i += 1
                continue
            urls.append(a)
            i += 1

        if not urls:
            ctx.error("curl: try 'curl --help' for more information\n")
            return 2

        rc = 0
        for url in urls:
            rc = max(rc, self._fetch_one(url, output_name, remote_name, silent, ctx))
        return rc

    def _fetch_one(
        self,
        url: str,
        output_name: str | None,
        remote_name: bool,
        silent: bool,
        ctx: ShellContext,
    ) -> int:
        raw = url if "://" in url else "http://" + url
        parsed = urlparse(raw)
        host = parsed.hostname or "unknown"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        filename: str | None = None
        if output_name:
            filename = output_name
        elif remote_name:
            filename = posixpath.basename(parsed.path) or "index.html"

        ctx.audit.download_attempt(
            src=ctx.src,
            username=ctx.username,
            session_id=ctx.session_id,
            url=url,
            host=host,
            port=port,
            tool="curl",
            filename=filename or "(stdout)",
            cwd=ctx.vfs.cwd,
        )

        if filename:
            if not silent:
                ctx.error(
                    "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100  {_FAKE_LENGTH:>4}  100  {_FAKE_LENGTH:>4}    0     0  {_FAKE_LENGTH:>4}      0 --:--:-- --:--:-- --:--:--  {_FAKE_LENGTH}\n"
                )
            try:
                ctx.vfs.write(filename, _FAKE_CONTENT)
            except Exception as e:  # noqa: BLE001
                ctx.error(f"curl: cannot write '{filename}': {e}\n")
                return 1
        else:
            ctx.write(_FAKE_CONTENT.decode("utf-8", errors="replace"))
        return 0
