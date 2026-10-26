"""ThreatLens - OpenSSH Log Parser (Module A compatible bridge).

Parses raw OpenSSH authentication logs into structured Event objects.
Conforms to the interface required by the Detection Engine (Module C)
and Backend Ingestion API (Module B).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

# Event type constants
ACCEPTED_LOGIN = "accepted_login"
INVALID_USER = "invalid_user"
FAILED_LOGIN = "failed_login"
DISCONNECT = "disconnect"
UNKNOWN = "unknown"

# Regex patterns for syslog timestamp and OpenSSH grammar
SYSLOG_HEADER_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\.\-]+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

# OpenSSH message patterns
FAILED_RE = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
INVALID_RE = re.compile(
    r"^Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)
ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
DISCONNECT_RE = re.compile(
    r"^Disconnected from\s+(?:invalid user\s+)?(?P<user>\S+)?\s*(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


@dataclass
class Event:
    timestamp: datetime
    host: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    port: Optional[int]
    method: Optional[str]
    outcome: str
    event_type: str
    raw_line: str
    line_hash: str
    id: Optional[int] = None
    is_invalid_user: bool = False
    parsed_event: Optional[Any] = None


@dataclass
class ParseResult:
    events: List[Event]
    malformed_count: int


def _compute_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()[:16]


def parse_line(line: str, year: int) -> Optional[Event]:
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None

    m = SYSLOG_HEADER_RE.match(raw)
    if not m:
        return None

    month = MONTH_MAP.get(m.group("month"), 1)
    day = int(m.group("day"))
    h, mn, s = map(int, m.group("time").split(":"))
    try:
        timestamp = datetime(year, month, day, h, mn, s)
    except ValueError:
        return None

    host = m.group("host")
    msg = m.group("msg")

    # Match OpenSSH event types
    failed_m = FAILED_RE.match(msg)
    if failed_m:
        return Event(
            timestamp=timestamp,
            host=host,
            username=failed_m.group("user"),
            source_ip=failed_m.group("ip"),
            port=int(failed_m.group("port")),
            method=failed_m.group("method"),
            outcome="failure",
            event_type=FAILED_LOGIN,
            raw_line=raw,
            line_hash=_compute_hash(raw),
        )

    invalid_m = INVALID_RE.match(msg)
    if invalid_m:
        port = int(invalid_m.group("port")) if invalid_m.group("port") else None
        return Event(
            timestamp=timestamp,
            host=host,
            username=invalid_m.group("user"),
            source_ip=invalid_m.group("ip"),
            port=port,
            method=None,
            outcome="failure",
            event_type=INVALID_USER,
            raw_line=raw,
            line_hash=_compute_hash(raw),
        )

    accepted_m = ACCEPTED_RE.match(msg)
    if accepted_m:
        return Event(
            timestamp=timestamp,
            host=host,
            username=accepted_m.group("user"),
            source_ip=accepted_m.group("ip"),
            port=int(accepted_m.group("port")),
            method=accepted_m.group("method"),
            outcome="success",
            event_type=ACCEPTED_LOGIN,
            raw_line=raw,
            line_hash=_compute_hash(raw),
        )

    disconnect_m = DISCONNECT_RE.match(msg)
    if disconnect_m:
        return Event(
            timestamp=timestamp,
            host=host,
            username=disconnect_m.group("user"),
            source_ip=disconnect_m.group("ip"),
            port=int(disconnect_m.group("port")),
            method=None,
            outcome="unknown",
            event_type=DISCONNECT,
            raw_line=raw,
            line_hash=_compute_hash(raw),
        )

    return None


def parse_text(text: str, year: int) -> ParseResult:
    events = []
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        ev = parse_line(line, year)
        if ev:
            events.append(ev)
        else:
            malformed += 1
    return ParseResult(events=events, malformed_count=malformed)


def parse_file(filepath: str, year: int) -> ParseResult:
    path = Path(filepath)
    if not path.exists():
        return ParseResult(events=[], malformed_count=0)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_text(f.read(), year)
