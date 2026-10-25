"""ThreatLens - Parser Adapter & Bridge Layer (Module B Integration).

Adapts Module A's parser output (Muaz's `ParsedAuthEvent` / `OpenSSH` parser)
into normalized `Event` dataclass objects consumed by:
1. SQLite Database Storage (Adnan — Module B)
2. Detection Engine (Yamlak — Module C)

Supports both:
- Native `app.parsers.openssh` (when Module A is merged/imported)
- Fallback internal parser (for standalone testing and CLI operations)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.parser import (
    ACCEPTED_LOGIN,
    DISCONNECT,
    FAILED_LOGIN,
    INVALID_USER,
    UNKNOWN,
    Event,
    ParseResult,
    parse_text as fallback_parse_text,
)


def _compute_line_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def adapt_muaz_event(muaz_event: Any) -> Event:
    """Transform a Pydantic `ParsedAuthEvent` from Module A into an internal `Event`.

    Mapping rules per consensus with Module A:
    - AuthEventType.FAILED_LOGIN  -> event_type: "failed_login",  outcome: "failure"
    - AuthEventType.ACCEPTED_LOGIN -> event_type: "accepted_login", outcome: "success"
    - AuthEventType.INVALID_USER   -> event_type: "invalid_user",   outcome: "failure", method: None
    - AuthEventType.DISCONNECT     -> event_type: "disconnect",     outcome: "unknown"
    """
    raw_log = getattr(muaz_event, "raw_log", "")
    ts = getattr(muaz_event, "timestamp", None)
    if ts is None:
        ts = datetime.now(timezone.utc)
    elif isinstance(ts, datetime) and ts.tzinfo is not None:
        # Normalize timezone to naive or UTC ISO representation
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

    # Determine event type & outcome mapping
    raw_ev_type = str(getattr(muaz_event, "event_type", "")).lower()
    if "failed" in raw_ev_type:
        ev_type = FAILED_LOGIN
        outcome = "failure"
        method = getattr(muaz_event, "auth_method", "password") or "password"
    elif "accepted" in raw_ev_type:
        ev_type = ACCEPTED_LOGIN
        outcome = "success"
        method = getattr(muaz_event, "auth_method", "password") or "password"
    elif "invalid" in raw_ev_type:
        ev_type = INVALID_USER
        outcome = "failure"
        method = None
    elif "disconnect" in raw_ev_type:
        ev_type = DISCONNECT
        outcome = "unknown"
        method = None
    else:
        ev_type = UNKNOWN
        outcome = "unknown"
        method = getattr(muaz_event, "auth_method", None)

    return Event(
        timestamp=ts,
        host=getattr(muaz_event, "hostname", "web01"),
        username=getattr(muaz_event, "username", None),
        source_ip=getattr(muaz_event, "src_ip", None),
        port=getattr(muaz_event, "src_port", None),
        method=method,
        outcome=outcome,
        event_type=ev_type,
        raw_line=raw_log,
        line_hash=_compute_line_hash(raw_log),
    )


def parse_and_adapt(text: str, year: int) -> ParseResult:
    """Unified parser entry point: uses Module A's parser if installed, with seamless fallback."""
    try:
        from app.parsers.openssh import parse_openssh_line
        events = []
        malformed = 0
        ref_time = datetime(year, 1, 1, tzinfo=timezone.utc)
        for idx, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            parsed = parse_openssh_line(line, reference_time=ref_time, line_number=idx)
            if getattr(parsed, "is_malformed", False) or getattr(parsed, "event_type", None) == "unknown":
                # Check if it was parseable by fallback
                fb = fallback_parse_text(line, year)
                if fb.events:
                    events.extend(fb.events)
                else:
                    malformed += 1
            else:
                events.append(adapt_muaz_event(parsed))
        return ParseResult(events=events, malformed_count=malformed)
    except (ImportError, Exception):
        # Module A parser not imported in current environment, use fallback parser
        return fallback_parse_text(text, year)
