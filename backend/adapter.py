"""Compatibility bridge between Module A parsing and the SIEM backend."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from datetime import datetime, timezone
from typing import Any, List, Optional

from app.models.events import AuthEventType, IngestionReport, ParsedAuthEvent
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

EVENT_TYPE_MAP = {
    AuthEventType.FAILED_LOGIN: FAILED_LOGIN,
    AuthEventType.INVALID_USER: INVALID_USER,
    AuthEventType.ACCEPTED_LOGIN: ACCEPTED_LOGIN,
    AuthEventType.DISCONNECT: DISCONNECT,
    AuthEventType.UNKNOWN: UNKNOWN,
}


def compute_line_hash(raw_line: str) -> str:
    """Generate a deterministic 16-character SHA-256 line identifier."""
    return hashlib.sha256(
        raw_line.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


def _compute_line_hash(raw_line: str) -> str:
    """Backward-compatible alias used by the backend adapter."""
    return compute_line_hash(raw_line)


def map_event_type(auth_type: AuthEventType) -> str:
    """Map Module A event types to backend event-type constants."""
    return EVENT_TYPE_MAP.get(auth_type, UNKNOWN)


def derive_outcome(auth_type: AuthEventType) -> str:
    """Return the backend's supported outcome value."""
    if auth_type in (AuthEventType.FAILED_LOGIN, AuthEventType.INVALID_USER):
        return "failure"
    if auth_type == AuthEventType.ACCEPTED_LOGIN:
        return "success"
    return "unknown"


def to_backend_event(parsed_event: ParsedAuthEvent) -> Optional[Event]:
    """Convert a valid Module A event to the backend event model."""
    if parsed_event.is_malformed or parsed_event.timestamp is None:
        return None

    return Event(
        timestamp=parsed_event.timestamp,
        host=parsed_event.hostname,
        username=parsed_event.username,
        source_ip=parsed_event.src_ip,
        port=parsed_event.src_port,
        method=parsed_event.auth_method,
        outcome=derive_outcome(parsed_event.event_type),
        event_type=map_event_type(parsed_event.event_type),
        raw_line=parsed_event.raw_log,
        line_hash=compute_line_hash(parsed_event.raw_log),
        is_invalid_user=parsed_event.is_invalid_user,
        parsed_event=parsed_event,
    )


def adapt_muaz_event(muaz_event: Any) -> Event:
    """Backward-compatible adapter for callers using Module A event objects."""
    event_type = getattr(muaz_event, "event_type", AuthEventType.UNKNOWN)
    if not isinstance(event_type, AuthEventType):
        try:
            event_type = AuthEventType(event_type)
        except (ValueError, TypeError):
            event_type = AuthEventType.UNKNOWN

    timestamp = getattr(muaz_event, "timestamp", None)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    elif timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    parsed = ParsedAuthEvent(
        raw_log=getattr(muaz_event, "raw_log", ""),
        timestamp=timestamp,
        hostname=getattr(muaz_event, "hostname", None),
        event_type=event_type,
        auth_method=getattr(muaz_event, "auth_method", None),
        username=getattr(muaz_event, "username", None),
        src_ip=getattr(muaz_event, "src_ip", None),
        src_port=getattr(muaz_event, "src_port", None),
        is_invalid_user=getattr(muaz_event, "is_invalid_user", False),
    )
    event = to_backend_event(parsed)
    if event is None:
        raise ValueError("Cannot adapt a malformed event or event without a timestamp")
    return event


@dataclass
class AdaptedIngestionResult:
    """Adapted events plus ingestion accounting and diagnostic details."""

    events: List[Event]
    malformed_count: int
    malformed_events: List[ParsedAuthEvent]
    report: IngestionReport
    parser_malformed_count: int = 0
    missing_timestamp_count: int = 0


def adapt_ingestion_report(report: IngestionReport) -> AdaptedIngestionResult:
    """Adapt an ingestion report while retaining malformed-event diagnostics."""
    valid_events: List[Event] = []
    malformed_events: List[ParsedAuthEvent] = []
    parser_malformed_count = 0
    missing_timestamp_count = 0

    for parsed_event in report.events:
        if parsed_event.is_malformed:
            parser_malformed_count += 1
            malformed_events.append(parsed_event)
        elif parsed_event.timestamp is None:
            missing_timestamp_count += 1
            if not parsed_event.parsing_error:
                parsed_event.parsing_error = (
                    "Missing mandatory timestamp required for SIEM ingestion"
                )
            malformed_events.append(parsed_event)
        else:
            event = to_backend_event(parsed_event)
            if event is None:
                malformed_events.append(parsed_event)
            else:
                valid_events.append(event)

    total_malformed = len(malformed_events)
    report.statistics.malformed_count = total_malformed
    report.statistics.parsed_count = len(valid_events)

    return AdaptedIngestionResult(
        events=valid_events,
        malformed_count=total_malformed,
        malformed_events=malformed_events,
        report=report,
        parser_malformed_count=parser_malformed_count,
        missing_timestamp_count=missing_timestamp_count,
    )


def parse_and_adapt(text: str, year: int) -> ParseResult:
    """Backward-compatible parser entry point with the legacy parser as fallback."""
    try:
        from app.parsers.openssh import parse_openssh_line
    except ImportError:
        return fallback_parse_text(text, year)

    events: List[Event] = []
    malformed = 0
    reference_time = datetime(year, 1, 1, tzinfo=timezone.utc)

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue

        try:
            parsed = parse_openssh_line(
                line,
                reference_time=reference_time,
                line_number=line_number,
            )
            if parsed.is_malformed or parsed.event_type == AuthEventType.UNKNOWN:
                fallback = fallback_parse_text(line, year)
                if fallback.events:
                    events.extend(fallback.events)
                else:
                    malformed += 1
                continue

            event = to_backend_event(parsed)
            if event is None:
                malformed += 1
            else:
                events.append(event)
        except Exception:
            # Isolate failures to this line, rather than losing the entire batch.
            fallback = fallback_parse_text(line, year)
            if fallback.events:
                events.extend(fallback.events)
            else:
                malformed += 1

    return ParseResult(events=events, malformed_count=malformed)
