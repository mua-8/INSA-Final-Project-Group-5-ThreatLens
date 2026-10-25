"""ThreatLens - Ingestion & Parser Compatibility Adapter (Module A to B/C Bridge).

Converts normalized `ParsedAuthEvent` instances produced by Module A
(app.services.ingestion & app.parsers.openssh) into backend `Event` instances
expected by the Database (Module B) and Detection Engine (Module C).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import List, Optional

from app.models.events import AuthEventType, IngestionReport, ParsedAuthEvent
from backend.parser import (
    ACCEPTED_LOGIN,
    DISCONNECT,
    FAILED_LOGIN,
    INVALID_USER,
    UNKNOWN,
    Event,
)

# Explicit mapping between Module A AuthEventType enum and backend event_type strings
EVENT_TYPE_MAP = {
    AuthEventType.FAILED_LOGIN: FAILED_LOGIN,
    AuthEventType.INVALID_USER: INVALID_USER,
    AuthEventType.ACCEPTED_LOGIN: ACCEPTED_LOGIN,
    AuthEventType.DISCONNECT: DISCONNECT,
    AuthEventType.UNKNOWN: UNKNOWN,
}


def compute_line_hash(raw_line: str) -> str:
    """Generate a deterministic 16-character SHA-256 line identifier."""
    return hashlib.sha256(raw_line.encode("utf-8", errors="replace")).hexdigest()[:16]


def map_event_type(auth_type: AuthEventType) -> str:
    """Map Module A AuthEventType enum to backend event type constant."""
    return EVENT_TYPE_MAP.get(auth_type, UNKNOWN)


def derive_outcome(auth_type: AuthEventType) -> str:
    """Derive backend outcome category ('success', 'failure', or 'unknown').

    Consistent with SQLite CHECK constraint: outcome IN ('success','failure','unknown').
    """
    if auth_type in (AuthEventType.FAILED_LOGIN, AuthEventType.INVALID_USER):
        return "failure"
    elif auth_type == AuthEventType.ACCEPTED_LOGIN:
        return "success"
    else:
        return "unknown"


def to_backend_event(parsed_event: ParsedAuthEvent) -> Optional[Event]:
    """Convert a single ParsedAuthEvent to a backend Event dataclass instance.

    Returns None if the event is marked malformed or lacks a valid timestamp,
    ensuring unparseable data is never passed to database/detection layers.
    """
    if parsed_event.is_malformed or parsed_event.timestamp is None:
        return None

    # Derive fields according to backend requirements
    backend_event_type = map_event_type(parsed_event.event_type)
    outcome = derive_outcome(parsed_event.event_type)
    line_hash = compute_line_hash(parsed_event.raw_log)

    event = Event(
        timestamp=parsed_event.timestamp,
        host=parsed_event.hostname,
        username=parsed_event.username,
        source_ip=parsed_event.src_ip,
        port=parsed_event.src_port,
        method=parsed_event.auth_method,
        outcome=outcome,
        event_type=backend_event_type,
        raw_line=parsed_event.raw_log,
        line_hash=line_hash,
        is_invalid_user=getattr(parsed_event, "is_invalid_user", False),
        parsed_event=parsed_event,
    )

    return event


@dataclass
class AdaptedIngestionResult:
    """Container for adapted events and ingestion accounting."""

    events: List[Event]
    malformed_count: int
    malformed_events: List[ParsedAuthEvent]
    report: IngestionReport
    parser_malformed_count: int = 0
    missing_timestamp_count: int = 0


def adapt_ingestion_report(report: IngestionReport) -> AdaptedIngestionResult:
    """Convert an IngestionReport into a collection of backend Events.

    Separates valid events with timestamps from malformed / unparseable events,
    preserving exact metrics and diagnostic details.
    """
    valid_events: List[Event] = []
    malformed_events: List[ParsedAuthEvent] = []
    parser_malformed_count = 0
    missing_timestamp_count = 0

    for pe in report.events:
        if pe.is_malformed:
            parser_malformed_count += 1
            malformed_events.append(pe)
        elif pe.timestamp is None:
            # Headerless event: parsed payload syntax is recognized, but lacks
            # the mandatory timestamp required for SIEM persistence and time-window correlation.
            missing_timestamp_count += 1
            if not pe.parsing_error:
                pe.parsing_error = "Missing mandatory timestamp required for SIEM ingestion"
            malformed_events.append(pe)
        else:
            be = to_backend_event(pe)
            if be is not None:
                valid_events.append(be)
            else:
                malformed_events.append(pe)

    # Total malformed count across parser errors and database schema constraints
    total_malformed = len(malformed_events)

    # Synchronize IngestionReport statistics so report and adapter remain fully aligned
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
