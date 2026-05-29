from __future__ import annotations

import logging
from typing import Optional

import asyncssh

from ..audit import AuditRecorder
from ..config import Config

log = logging.getLogger(__name__)


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, cfg: Config, audit: AuditRecorder) -> None:
        self._cfg = cfg
        self._audit = audit
        self._peer: Optional[tuple[str, int]] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        self._peer = (peer[0], peer[1]) if peer else ("?", 0)
        self._audit.session_connect(src=self._peer[0], port=self._peer[1])
        log.info("Connection from %s:%s", *self._peer)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._peer:
            return
        self._audit.session_disconnect(
            src=self._peer[0],
            port=self._peer[1],
            reason=str(exc) if exc else "ok",
        )

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        policy = self._cfg.auth.policy
        if policy == "accept_all":
            accepted = True
        elif policy == "dictionary":
            accepted = any(
                c.get("username") == username and c.get("password") == password
                for c in self._cfg.auth.credentials
            )
        else:
            accepted = False

        src = self._peer[0] if self._peer else ""
        self._audit.auth(src=src, username=username, password=password, accepted=accepted)
        return accepted

    def public_key_auth_supported(self) -> bool:
        return False
