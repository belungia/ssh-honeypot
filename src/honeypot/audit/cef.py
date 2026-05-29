from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .events import Event

CEF_VERSION = 0
VENDOR = "Coursework"
PRODUCT = "SSHHoneypot"
VERSION = "0.1.0"


def _escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_ext(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def format_cef(event: Event) -> str:
    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            _escape_header(VENDOR),
            _escape_header(PRODUCT),
            _escape_header(VERSION),
            _escape_header(event.event_id),
            _escape_header(event.name),
            str(event.severity),
        ]
    )
    ext_parts = [f"rt={int(event.timestamp.timestamp() * 1000)}"]
    for k, v in event.extension.items():
        ext_parts.append(f"{k}={_escape_ext(str(v))}")
    return header + "|" + " ".join(ext_parts)


class CefLogger:
    def __init__(
        self,
        path: Path,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("honeypot.cef")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                str(path),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def emit(self, event: Event) -> None:
        self._logger.info(format_cef(event))
