from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import asyncssh

from .audit import AuditRecorder, CefLogger
from .config import load_config
from .core.server import HoneypotSSHServer
from .core.session import HoneypotSessionFactory
from .fs import BaseFS

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"


def ensure_host_key(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(str(path))


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = load_config(CONFIG_DIR)
    host_key_path = ROOT / cfg.server.host_key
    ensure_host_key(host_key_path)

    cef_sink = CefLogger(
        path=ROOT / cfg.logging.path,
        max_bytes=cfg.logging.max_bytes,
        backup_count=cfg.logging.backup_count,
    )
    audit = AuditRecorder(cef_sink)

    base_fs = BaseFS(cfg.filesystem)
    session_factory = HoneypotSessionFactory(audit, base_fs, cfg.system_profile)

    await asyncssh.create_server(
        lambda: HoneypotSSHServer(cfg, audit),
        host=cfg.server.host,
        port=cfg.server.port,
        server_host_keys=[str(host_key_path)],
        process_factory=session_factory.handle,
        line_editor=False,
    )

    logging.info(
        "SSH honeypot listening on %s:%d (policy=%s)",
        cfg.server.host,
        cfg.server.port,
        cfg.auth.policy,
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
