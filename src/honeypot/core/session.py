from __future__ import annotations

import logging
import uuid
from typing import Any

import asyncssh

from ..audit import AuditRecorder
from ..fs import BaseFS, VFS
from ..shell import ShellContext, ShellEmulator

log = logging.getLogger(__name__)


class HoneypotSessionFactory:
    """Factory bound to shared resources (BaseFS, audit, profile).

    Each SSH channel call invokes ``handle`` and a fresh per-session state is
    materialized: VFS overlay, ShellContext, ShellEmulator.
    """

    def __init__(
        self,
        audit: AuditRecorder,
        base_fs: BaseFS,
        system_profile: dict[str, Any],
    ) -> None:
        self._audit = audit
        self._base_fs = base_fs
        self._profile = system_profile

    async def handle(self, process: asyncssh.SSHServerProcess) -> None:
        session_id = uuid.uuid4().hex
        peer = process.get_extra_info("peername")
        src = peer[0] if peer else ""
        username = process.get_extra_info("username") or ""
        pty_allocated = process.get_terminal_type() is not None
        command = process.command  # None for interactive shell

        home = "/root" if username == "root" else f"/home/{username}"
        vfs = VFS(self._base_fs, cwd=home if self._base_fs.exists(home) else "/", home=home)

        ctx = ShellContext(
            vfs=vfs,
            audit=self._audit,
            system_profile=self._profile,
            session_id=session_id,
            src=src,
            username=username,
            pty_allocated=pty_allocated,
        )
        ctx.attach_writer(process.stdout.write)

        self._audit.session_start(
            src=src,
            username=username,
            session_id=session_id,
            mode="exec" if command else ("shell" if pty_allocated else "shell-nopty"),
            command=command or "",
        )

        emulator = ShellEmulator(ctx)
        rc = 0
        try:
            if command is not None:
                rc = await emulator.run_exec(command)
            else:
                rc = await emulator.run_interactive(process)
        except Exception:  # noqa: BLE001 - never leak a Python traceback to the attacker
            log.exception("session %s crashed", session_id)
            rc = 1
            try:
                process.stderr.write("\nconnection error\n")
            except Exception:
                pass
        finally:
            self._audit.session_end(
                src=src,
                username=username,
                session_id=session_id,
                exit_code=rc,
            )
            try:
                process.exit(rc)
            except Exception:
                pass
