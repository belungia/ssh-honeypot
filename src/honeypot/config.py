from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 2222
    host_key: str = "keys/ssh_host_rsa_key"


@dataclass
class AuthConfig:
    policy: str = "accept_all"
    credentials: list[dict[str, str]] = field(default_factory=list)


@dataclass
class LoggingConfig:
    path: str = "logs/honeypot.cef"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    system_profile: dict[str, Any] = field(default_factory=dict)
    filesystem: dict[str, Any] = field(default_factory=dict)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_config(config_dir: Path) -> Config:
    raw = _read_yaml(config_dir / "config.yaml")
    return Config(
        server=ServerConfig(**raw.get("server", {})),
        auth=AuthConfig(**raw.get("auth", {})),
        logging=LoggingConfig(**raw.get("logging", {})),
        system_profile=_read_yaml(config_dir / "system_profile.yaml"),
        filesystem=_read_yaml(config_dir / "filesystem.yaml"),
    )
