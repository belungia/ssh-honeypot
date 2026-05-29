from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EventType:
    """Static descriptor of an audit event kind.

    Bundles together the three CEF header fields that are constant for any
    given event class: the numeric ID, the human name, and the severity.
    """

    id: str
    name: str
    severity: int


# ---- session lifecycle -------------------------------------------------

SESSION_CONNECT = EventType("100", "session_connect", 3)
SESSION_DISCONNECT = EventType("101", "session_disconnect", 3)
SESSION_START = EventType("110", "session_start", 3)
SESSION_END = EventType("111", "session_end", 3)

# ---- authentication ----------------------------------------------------

AUTH_SUCCESS = EventType("200", "auth_success", 5)
AUTH_FAIL = EventType("201", "auth_attempt", 4)

# ---- shell activity ----------------------------------------------------

COMMAND = EventType("300", "command", 3)
UNKNOWN_COMMAND = EventType("301", "unknown_command", 4)

# ---- malicious activity indicators ------------------------------------

DOWNLOAD_ATTEMPT = EventType("320", "download_attempt", 7)


# Convenience registry - useful for documentation / dashboards / tests.
ALL: tuple[EventType, ...] = (
    SESSION_CONNECT,
    SESSION_DISCONNECT,
    SESSION_START,
    SESSION_END,
    AUTH_SUCCESS,
    AUTH_FAIL,
    COMMAND,
    UNKNOWN_COMMAND,
    DOWNLOAD_ATTEMPT,
)
