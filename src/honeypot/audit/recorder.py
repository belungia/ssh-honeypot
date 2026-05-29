from __future__ import annotations

from typing import Any, Iterable, Protocol

from . import event_types as et
from .events import Event


class EventSink(Protocol):
    """Anything that can swallow an Event - CefLogger in production,
    a memory list in tests."""

    def emit(self, event: Event) -> None: ...


class AuditRecorder:
    """High-level audit API.

    Every audit call in the codebase goes through this class. Concrete event
    schemas (IDs, names, severities, CEF field mapping) live here and only
    here. The sink (CefLogger / memory list) just receives ready Events.
    """

    def __init__(self, sink: EventSink) -> None:
        self._sink = sink

    # ---- low-level helper --------------------------------------------

    def _emit(self, kind: et.EventType, **fields: Any) -> None:
        extension = {k: v for k, v in fields.items() if v is not None and v != ""}
        self._sink.emit(
            Event(
                event_id=kind.id,
                name=kind.name,
                severity=kind.severity,
                extension=extension,
            )
        )

    # ---- session lifecycle -------------------------------------------

    def session_connect(self, *, src: str, port: int) -> None:
        self._emit(et.SESSION_CONNECT, src=src, spt=port)

    def session_disconnect(self, *, src: str, port: int, reason: str = "ok") -> None:
        self._emit(et.SESSION_DISCONNECT, src=src, spt=port, reason=reason)

    def session_start(
        self,
        *,
        src: str,
        username: str,
        session_id: str,
        mode: str,
        command: str = "",
    ) -> None:
        self._emit(
            et.SESSION_START,
            src=src,
            suser=username,
            sessionId=session_id,
            mode=mode,
            cmd=command,
        )

    def session_end(
        self,
        *,
        src: str,
        username: str,
        session_id: str,
        exit_code: int,
    ) -> None:
        self._emit(
            et.SESSION_END,
            src=src,
            suser=username,
            sessionId=session_id,
            exitCode=str(exit_code),
        )

    # ---- authentication ----------------------------------------------

    def auth(self, *, src: str, username: str, password: str, accepted: bool) -> None:
        kind = et.AUTH_SUCCESS if accepted else et.AUTH_FAIL
        self._emit(
            kind,
            src=src,
            suser=username,
            cs1Label="password",
            cs1=password,
            outcome="success" if accepted else "fail",
        )

    # ---- shell activity ----------------------------------------------

    def command(
        self,
        *,
        src: str,
        username: str,
        session_id: str,
        name: str,
        args: Iterable[str] | str,
        cwd: str,
        exit_code: int,
    ) -> None:
        args_str = args if isinstance(args, str) else " ".join(args)
        self._emit(
            et.COMMAND,
            src=src,
            suser=username,
            sessionId=session_id,
            cmd=name,
            args=args_str,
            cwd=cwd,
            cs2Label="exitCode",
            cs2=str(exit_code),
        )

    def unknown_command(
        self,
        *,
        src: str,
        username: str,
        session_id: str,
        name: str,
        args: Iterable[str] | str,
        cwd: str,
    ) -> None:
        args_str = args if isinstance(args, str) else " ".join(args)
        self._emit(
            et.UNKNOWN_COMMAND,
            src=src,
            suser=username,
            sessionId=session_id,
            cmd=name,
            args=args_str,
            cwd=cwd,
        )

    # ---- malicious activity ------------------------------------------

    def download_attempt(
        self,
        *,
        src: str,
        username: str,
        session_id: str,
        url: str,
        host: str,
        port: int,
        tool: str,
        filename: str,
        cwd: str,
    ) -> None:
        self._emit(
            et.DOWNLOAD_ATTEMPT,
            src=src,
            suser=username,
            sessionId=session_id,
            requestUrl=url,
            destinationHostName=host,
            destinationPort=port,
            tool=tool,
            filename=filename,
            cwd=cwd,
        )
