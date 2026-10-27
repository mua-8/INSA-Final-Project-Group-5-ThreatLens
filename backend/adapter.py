"""Compatibility bridge between Module A parsing and the SIEM backend."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
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

ENDPOINT_EVENT_TYPE_MAP = {
    "ssh_auth_failure": (FAILED_LOGIN, "failure"),
    "failed_login": (FAILED_LOGIN, "failure"),
    "ssh_invalid_user": (INVALID_USER, "failure"),
    "invalid_user": (INVALID_USER, "failure"),
    "ssh_auth_success": (ACCEPTED_LOGIN, "success"),
    "accepted_login": (ACCEPTED_LOGIN, "success"),
    "ssh_disconnect": (DISCONNECT, "unknown"),
    "disconnect": (DISCONNECT, "unknown"),
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


SUPPORTED_FILE_EVENT_TYPES = {
    "file_created",
    "file_modified",
    "file_renamed",
    "file_deleted",
}


def is_file_event(data: Any) -> bool:
    """Return True if the record or payload represents a file-system telemetry event."""
    if data is None:
        return False
    if hasattr(data, "keys"):
        d = dict(data)
    elif isinstance(data, dict):
        d = data
    else:
        return False

    source = (d.get("source") or "").strip().lower()
    event_type = (d.get("event_type") or "").strip().lower()

    return source in ("file_monitor", "linux_fs") or event_type in SUPPORTED_FILE_EVENT_TYPES


def validate_file_event_payload(data: dict[str, Any]) -> tuple[bool, Optional[str], dict[str, Any]]:
    """Strictly validate normalized file-system event payload and attributes.

    Returns (is_valid, error_message, normalized_dict).
    Enforces:
    - Supported event_type in ('file_created', 'file_modified', 'file_renamed', 'file_deleted')
    - Required non-empty file_path without null bytes or control characters
    - Valid previous_path for file_renamed events when present
    - Optional positive process_id and process_name
    - Derivation of file_extension if omitted
    """
    if not isinstance(data, dict):
        return False, "File event must be a JSON dictionary.", {}

    event_type = str(data.get("event_type") or "").strip().lower()
    if event_type not in SUPPORTED_FILE_EVENT_TYPES:
        return False, f"Invalid file event_type '{event_type}'. Must be one of {sorted(SUPPORTED_FILE_EVENT_TYPES)}.", {}

    attrs = data.get("attributes")
    if attrs is None:
        attrs = {}
    elif isinstance(attrs, str):
        try:
            attrs = json.loads(attrs)
        except Exception:
            return False, "Field 'attributes' must be a valid JSON dictionary or object.", {}
    elif not isinstance(attrs, dict):
        return False, "Field 'attributes' must be a dictionary.", {}

    # Extract file_path from attributes or top-level
    file_path = attrs.get("file_path") or data.get("file_path")
    if not file_path or not isinstance(file_path, str) or not file_path.strip():
        return False, "File event requires a non-empty 'file_path' in attributes or event root.", {}

    clean_path = file_path.strip()
    if "\x00" in clean_path:
        return False, "File path must not contain null bytes.", {}
    if ".." in clean_path.replace("\\", "/").split("/"):
        return False, "File path must not contain path traversal sequences ('..').", {}

    # File extension
    file_ext = attrs.get("file_extension") or data.get("file_extension")
    if file_ext is not None:
        clean_ext = str(file_ext).strip().lower()
        if clean_ext and not clean_ext.startswith("."):
            clean_ext = f".{clean_ext}"
    else:
        last_dot = clean_path.rfind(".")
        last_slash = max(clean_path.rfind("/"), clean_path.rfind("\\"))
        if last_dot > last_slash and last_dot < len(clean_path) - 1:
            clean_ext = clean_path[last_dot:].lower()
        else:
            clean_ext = ""

    # Previous path (rename)
    previous_path = attrs.get("previous_path") or data.get("previous_path")
    clean_prev: Optional[str] = None
    if previous_path is not None:
        if not isinstance(previous_path, str) or not previous_path.strip():
            return False, "Field 'previous_path' must be a non-empty string when provided.", {}
        clean_prev = previous_path.strip()
        if "\x00" in clean_prev:
            return False, "Field 'previous_path' must not contain null bytes.", {}
        if ".." in clean_prev.replace("\\", "/").split("/"):
            return False, "Field 'previous_path' must not contain path traversal sequences ('..').", {}

    # Process attribution (strictly optional)
    proc_id = attrs["process_id"] if "process_id" in attrs else data.get("process_id")
    clean_proc_id: Optional[int] = None
    if proc_id is not None:
        try:
            clean_proc_id = int(proc_id)
            if clean_proc_id <= 0:
                return False, "Field 'process_id' must be a positive integer.", {}
        except (ValueError, TypeError):
            return False, "Field 'process_id' must be an integer.", {}

    proc_name = attrs["process_name"] if "process_name" in attrs else data.get("process_name")
    clean_proc_name: Optional[str] = None
    if proc_name is not None:
        if not isinstance(proc_name, str) or not proc_name.strip():
            return False, "Field 'process_name' must be a non-empty string when provided.", {}
        clean_proc_name = proc_name.strip()

    normalized_record = {
        "event_type": event_type,
        "file_path": clean_path,
        "file_extension": clean_ext,
        "previous_path": clean_prev,
        "process_id": clean_proc_id,
        "process_name": clean_proc_name,
        "attributes": dict(attrs),
    }
    # Update attributes with canonical extracted fields
    normalized_record["attributes"]["file_path"] = clean_path
    normalized_record["attributes"]["file_extension"] = clean_ext
    if clean_prev:
        normalized_record["attributes"]["previous_path"] = clean_prev
    if clean_proc_id:
        normalized_record["attributes"]["process_id"] = clean_proc_id
    if clean_proc_name:
        normalized_record["attributes"]["process_name"] = clean_proc_name

    return True, None, normalized_record


def adapt_endpoint_event_to_backend(data: Any) -> Optional[Event]:
    """Convert an endpoint event record or dictionary to a backend Event.

    Converts valid SSH authentication, invalid user, and disconnect telemetry
    from endpoint agents into backend.parser.Event instances.

    Explicitly ignores non-SSH sources (such as windows_event, sysmon, file_monitor,
    linux_fs) and unsupported event types, safely returning None without
    corrupting SIEM event state or misclassifying telemetry into SSH detection rules.
    """
    if data is None:
        return None

    if hasattr(data, "keys"):
        d = dict(data)
    elif isinstance(data, dict):
        d = data
    else:
        return None

    source = (d.get("source") or "").strip().lower()
    # Explicitly reject non-SSH sources (e.g. Windows logon, Sysmon, File-system telemetry)
    if source in ("windows_event", "sysmon", "file_monitor", "linux_fs"):
        return None

    event_type = (d.get("event_type") or "").strip().lower()
    # Explicitly reject file-system events from SSH detection engine
    if event_type in SUPPORTED_FILE_EVENT_TYPES:
        return None

    if event_type not in ENDPOINT_EVENT_TYPE_MAP:
        return None

    backend_type, outcome = ENDPOINT_EVENT_TYPE_MAP[event_type]

    # Parse attributes
    attrs = d.get("attributes")
    if isinstance(attrs, str):
        try:
            attrs = json.loads(attrs)
        except Exception:
            attrs = {}
    elif not isinstance(attrs, dict):
        attrs = {}

    # Parse timestamp
    ts_raw = d.get("timestamp")
    if not ts_raw:
        return None
    try:
        ts_parse = str(ts_raw).strip()
        if ts_parse.endswith("Z") or ts_parse.endswith("z"):
            ts_parse = ts_parse[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_parse)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

    # Derive host (preserve target_host if provided by collector, else host, else device_id)
    host = attrs.get("target_host") or attrs.get("host") or d.get("device_id")
    if host is not None:
        host = str(host).strip()

    # Username
    username = d.get("username") or attrs.get("username")
    if username is not None:
        username = str(username).strip()

    # Source IP
    source_ip = d.get("source_ip")
    if source_ip is not None:
        source_ip = str(source_ip).strip().strip("[]")

    # Port
    port = attrs.get("port") or d.get("port")
    port_val = None
    if port is not None:
        try:
            port_val = int(port)
        except (ValueError, TypeError):
            port_val = None

    # Method & invalid_user flag
    is_invalid_user = bool(attrs.get("invalid_user", False)) or (backend_type == INVALID_USER)

    if backend_type == FAILED_LOGIN:
        failure_reason = attrs.get("failure_reason")
        if failure_reason in ("preauth_connection_closed", "max_attempts_exceeded"):
            method = attrs.get("auth_method")
        else:
            method = attrs.get("auth_method") or "password"
    elif backend_type == ACCEPTED_LOGIN:
        method = attrs.get("auth_method") or "password"
    else:
        method = None

    # Raw line
    raw_event = d.get("raw_event")
    if raw_event and str(raw_event).strip():
        raw_line = str(raw_event).strip()
    else:
        raw_line = f"{dt.isoformat()} {host or 'unknown'} sshd: {event_type} for {username or 'unknown'} from {source_ip or 'unknown'}"

    # Line hash: deterministic per event_id to prevent collision between distinct events
    eid = d.get("event_id")
    if eid:
        line_hash = compute_line_hash(f"endpoint:{eid}")
    else:
        line_hash = compute_line_hash(raw_line)

    return Event(
        timestamp=dt,
        host=host,
        username=username,
        source_ip=source_ip,
        port=port_val,
        method=method,
        outcome=outcome,
        event_type=backend_type,
        raw_line=raw_line,
        line_hash=line_hash,
        is_invalid_user=is_invalid_user,
    )
