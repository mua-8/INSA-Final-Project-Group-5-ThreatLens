"""OpenSSH authentication log parsing engine for ThreatLens SIEM.

This module provides parsing and event normalization for Linux OpenSSH logs,
supporting both RFC 3164 (BSD syslog) and RFC 5424 / ISO-8601 formats.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import re
from typing import Optional
from pydantic import ValidationError

from app.models.events import AuthEventType, ParsedAuthEvent

# Mapping of three-letter month abbreviations to month integers (1-12)
MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

# RFC 3164 BSD Syslog Header: e.g. "Oct 25 10:14:22 host sshd[123]: " or "Oct  5 10:14:22 host sshd: "
BSD_HEADER_RE = re.compile(
    r"^(?:<\d+>(?:1 )?)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<hostname>[^\s:]+))?"
    r"(?:\s+(?P<service>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?)?:\s*"
    r"(?P<payload>.*)$"
)

# RFC 5424 / ISO-8601 Syslog Header: e.g. "2026-10-25T10:14:22.123456+00:00 host sshd[123]: "
ISO_HEADER_RE = re.compile(
    r"^(?:<\d+>(?:1 )?)?"
    r"(?P<iso_ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"(?:\s+(?P<hostname>[^\s:]+))?"
    r"(?:\s+(?P<service>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?)?:\s*"
    r"(?P<payload>.*)$"
)

# Fallback service prefix: e.g. "sshd[1234]: <payload>" or "sshd: <payload>"
SERVICE_PREFIX_RE = re.compile(
    r"^(?P<service>[a-zA-Z0-9_.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<payload>.*)$"
)

# OpenSSH Payload Grammar Patterns
FAILED_RE = re.compile(
    r"^Failed (?P<auth_method>[\w-]+) for (?P<invalid>invalid user )?(?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"^Accepted (?P<auth_method>[\w-]+) for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<username>\S+) from (?P<src_ip>\S+)(?: port (?P<src_port>\d+))?"
)

DISCONNECT_RE = re.compile(
    r"^(?:Disconnected from|Connection closed by|Connection reset by|Received disconnect from)"
    r"(?: (?P<user_type>authenticating user|invalid user|user) (?P<username>\S+))?"
    r" (?P<src_ip>\S+)(?: port (?P<src_port>\d+))?"
)


def infer_syslog_timestamp(
    month_str: str,
    day_str: str,
    time_str: str,
    reference_time: Optional[datetime] = None,
) -> datetime:
    """Infer full UTC timestamp from syslog date components lacking a year.

    Inference Policy:
    1. Default to the calendar year of `reference_time` (or current UTC time if omitted).
    2. Allow a 24-hour future skew buffer to account for minor clock drift or timezone delta.
    3. If the candidate timestamp exceeds the reference time + 24 hours, the event is
       inferred to have occurred in the preceding calendar year (handling year-end rollover
       e.g., Dec 31 log ingested on Jan 2).
    4. If the reference time is late December and the candidate date is early January (within 24 hours),
       the candidate is inferred as `ref_year + 1`.
    5. Structural components that are non-existent (e.g. Feb 30, Oct 35) raise ValueError.
    """
    ref_utc = reference_time or datetime.now(timezone.utc)
    if ref_utc.tzinfo is None:
        ref_utc = ref_utc.replace(tzinfo=timezone.utc)
    else:
        ref_utc = ref_utc.astimezone(timezone.utc)

    month = MONTH_MAP[month_str]
    day = int(day_str)
    hour_str, minute_str, second_str = time_str.split(":")
    hour, minute, second = int(hour_str), int(minute_str), int(second_str)

    ref_year = ref_utc.year
    skew_tolerance = timedelta(days=1)

    # Validate basic ranges before constructing datetime to ensure deterministic error messaging
    if not (1 <= day <= 31 and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 60):
        raise ValueError(f"Time or date component out of range: {month_str} {day_str} {time_str}")

    try:
        candidate = datetime(ref_year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        # Check if leap day in previous year
        try:
            candidate = datetime(ref_year - 1, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError(f"Invalid calendar date: {month_str} {day_str} {time_str}") from exc

    # Check year-end rollover: candidate in the future beyond skew tolerance
    if candidate > ref_utc + skew_tolerance:
        try:
            candidate = datetime(ref_year - 1, month, day, hour, minute, second, tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError(f"Invalid calendar date for previous year: {exc}") from exc
    elif ref_utc.month == 12 and month == 1 and day <= 2:
        # Check near-midnight rollover when reference clock is slightly behind
        try:
            cand_next = datetime(ref_year + 1, month, day, hour, minute, second, tzinfo=timezone.utc)
            if cand_next <= ref_utc + skew_tolerance:
                candidate = cand_next
        except ValueError:
            pass

    return candidate


def parse_iso_timestamp(iso_str: str) -> datetime:
    """Parse ISO-8601 timestamp string and convert to UTC datetime."""
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_openssh_line(
    raw_log: str,
    reference_time: Optional[datetime] = None,
    line_number: Optional[int] = None,
) -> ParsedAuthEvent:
    """Parse an OpenSSH authentication log line into a normalized ParsedAuthEvent.

    Args:
        raw_log: The exact raw log line to parse.
        reference_time: Optional reference UTC datetime for syslog year inference.
        line_number: Optional 1-based line number for tracking in batch uploads.

    Returns:
        ParsedAuthEvent preserving `raw_log` and containing structured metadata,
        or flagged with `is_malformed=True` and `parsing_error` if unparseable.
    """
    # 1. Handle empty / whitespace lines safely
    if not raw_log or not raw_log.strip():
        return ParsedAuthEvent(
            raw_log=raw_log,
            is_malformed=True,
            parsing_error="Empty or whitespace-only log line",
            line_number=line_number,
        )

    working = raw_log.strip()
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    service: Optional[str] = "sshd"
    has_syslog_header = False

    # 2. Extract Syslog Header (RFC 3164 or RFC 5424)
    bsd_match = BSD_HEADER_RE.match(working)
    iso_match = ISO_HEADER_RE.match(working)

    if bsd_match:
        has_syslog_header = True
        hostname = bsd_match.group("hostname")
        service = bsd_match.group("service") or "sshd"
        payload = bsd_match.group("payload")
        try:
            timestamp = infer_syslog_timestamp(
                bsd_match.group("month"),
                bsd_match.group("day"),
                bsd_match.group("time"),
                reference_time=reference_time,
            )
        except ValueError as exc:
            return ParsedAuthEvent(
                raw_log=raw_log,
                hostname=hostname,
                service=service,
                is_malformed=True,
                parsing_error=f"Invalid timestamp in syslog header: {exc}",
                line_number=line_number,
            )
    elif iso_match:
        has_syslog_header = True
        hostname = iso_match.group("hostname")
        service = iso_match.group("service") or "sshd"
        payload = iso_match.group("payload")
        try:
            timestamp = parse_iso_timestamp(iso_match.group("iso_ts"))
        except ValueError as exc:
            return ParsedAuthEvent(
                raw_log=raw_log,
                hostname=hostname,
                service=service,
                is_malformed=True,
                parsing_error=f"Invalid ISO timestamp in syslog header: {exc}",
                line_number=line_number,
            )
    else:
        # Check service prefix fallback (e.g. "sshd[123]: ...")
        service_match = SERVICE_PREFIX_RE.match(working)
        if service_match:
            service = service_match.group("service") or "sshd"
            payload = service_match.group("payload")
        else:
            payload = working

    # 3. Match OpenSSH Authentication Grammar
    event_type = AuthEventType.UNKNOWN
    auth_method: Optional[str] = None
    username: Optional[str] = None
    src_ip_str: Optional[str] = None
    src_port_int: Optional[int] = None
    is_invalid_user = False
    is_malformed = False
    parsing_error: Optional[str] = None

    failed_match = FAILED_RE.search(payload)
    accepted_match = ACCEPTED_RE.search(payload)
    invalid_user_match = INVALID_USER_RE.search(payload)
    disconnect_match = DISCONNECT_RE.search(payload)

    if failed_match:
        event_type = AuthEventType.FAILED_LOGIN
        auth_method = failed_match.group("auth_method")
        username = failed_match.group("username")
        is_invalid_user = bool(failed_match.group("invalid"))
        src_ip_str = failed_match.group("src_ip")
        src_port_int = int(failed_match.group("src_port"))

    elif accepted_match:
        event_type = AuthEventType.ACCEPTED_LOGIN
        auth_method = accepted_match.group("auth_method")
        username = accepted_match.group("username")
        is_invalid_user = False
        src_ip_str = accepted_match.group("src_ip")
        src_port_int = int(accepted_match.group("src_port"))

    elif invalid_user_match:
        event_type = AuthEventType.INVALID_USER
        username = invalid_user_match.group("username")
        is_invalid_user = True
        src_ip_str = invalid_user_match.group("src_ip")
        src_port_str = invalid_user_match.group("src_port")
        src_port_int = int(src_port_str) if src_port_str else None

    elif disconnect_match:
        event_type = AuthEventType.DISCONNECT
        username = disconnect_match.group("username")
        user_type = disconnect_match.group("user_type")
        is_invalid_user = (user_type == "invalid user")
        src_ip_str = disconnect_match.group("src_ip")
        src_port_str = disconnect_match.group("src_port")
        src_port_int = int(src_port_str) if src_port_str else None

    else:
        # Not a recognized auth event pattern
        if has_syslog_header or SERVICE_PREFIX_RE.match(working):
            # Validly structured syslog line with an unrecognized/unsupported SSH or daemon message
            event_type = AuthEventType.UNKNOWN
            is_malformed = False
        else:
            # Lacks both a syslog header and an OpenSSH message pattern: corrupted / unparseable
            event_type = AuthEventType.UNKNOWN
            is_malformed = True
            parsing_error = "Unparseable log line syntax"

    # Clean IP string (strip bracket encapsulation if present, e.g. [2001:db8::1])
    cleaned_ip: Optional[str] = None
    if src_ip_str:
        cleaned_ip = src_ip_str.strip("[]")

    # 4. Construct and Validate ParsedAuthEvent
    try:
        return ParsedAuthEvent(
            raw_log=raw_log,
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=event_type,
            auth_method=auth_method,
            username=username,
            src_ip=cleaned_ip,
            src_port=src_port_int,
            is_malformed=is_malformed,
            parsing_error=parsing_error,
            line_number=line_number,
            is_invalid_user=is_invalid_user,
        )
    except ValidationError as exc:
        # Extract diagnostic message from Pydantic validation failure (e.g. invalid IP or port range)
        error_details = "; ".join(f"{err['loc'][0]}: {err['msg']}" for err in exc.errors())
        return ParsedAuthEvent(
            raw_log=raw_log,
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=AuthEventType.UNKNOWN,
            is_malformed=True,
            parsing_error=f"Validation error: {error_details}",
            line_number=line_number,
            is_invalid_user=is_invalid_user,
        )
