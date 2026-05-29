from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    event_id: str
    name: str
    severity: int = 3
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extension: dict[str, Any] = field(default_factory=dict)
