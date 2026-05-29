from __future__ import annotations

import posixpath
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..context import ShellContext
from .base import Command

_FAKE_CONTENT = b"#!/bin/sh\n# (===DOWNLOADED CONTENT===)\n"
_FAKE_LENGTH = len(_FAKE_CONTENT)


class WgetCommand(Command):
    name = "wget"

    def run(self, args: list[str], ctx: ShellContext) -> int:
        output_name: str | None = None
        urls: list[str] = []

        i = 0
        while i < len(args):
            a = args[i]
            if a == "-O" and i + 1 < len(args):
                output_name = args[i + 1]
                i += 2
                continue
            if a.startswith("--output-document="):
                output_name = a.split("=", 1)[1]
                i += 1
                continue
            if a.startswith("-") and a != "-":
                i += 1
                continue
            urls.append(a)
            i += 1

        if not urls:
            ctx.error("wget: missing URL\n")
            ctx.error("Usage: wget [OPTION]... [URL]...\n")
            return 1

        rc = 0
        for url in urls:
            rc = max(rc, self._fetch_one(url, output_name, ctx))
        return rc

    def _fetch_one(self, url: str, output_name: str | None, ctx: ShellContext) -> int:
        raw = url if "://" in url else "http://" + url
        parsed = urlparse(raw)
        host = parsed.hostname or "unknown"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        filename = output_name or posixpath.basename(path) or "index.html"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        ctx.writeln(f"--{now}--  {url}")
        ctx.writeln(f"Resolving {host} ({host})... 93.184.216.34")
        ctx.writeln(f"Connecting to {host} ({host})|93.184.216.34|:{port}... connected.")
        ctx.writeln("HTTP request sent, awaiting response... 200 OK")
        ctx.writeln(f"Length: {_FAKE_LENGTH} [application/octet-stream]")
        ctx.writeln(f"Saving to: '{filename}'")
        ctx.writeln()
        ctx.writeln(
            f"{filename:<24}100%[===================>]  {_FAKE_LENGTH:>5}  --.-KB/s    in 0s"
        )
        ctx.writeln()
        ctx.writeln(
            f"{now} ({_FAKE_LENGTH}B/s) - '{filename}' saved "
            f"[{_FAKE_LENGTH}/{_FAKE_LENGTH}]"
        )
        ctx.writeln()

        ctx.audit.download_attempt(
            src=ctx.src,
            username=ctx.username,
            session_id=ctx.session_id,
            url=url,
            host=host,
            port=port,
            tool="wget",
            filename=filename,
            cwd=ctx.vfs.cwd,
        )

        try:
            ctx.vfs.write(filename, _FAKE_CONTENT)
        except Exception as e:
            ctx.error(f"wget: cannot write '{filename}': {e}\n")
            return 1
        return 0
