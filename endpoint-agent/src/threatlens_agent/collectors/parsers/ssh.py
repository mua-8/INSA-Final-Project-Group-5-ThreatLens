"""Parser for Linux OpenSSH authentication records."""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from threatlens_agent.models.events import Event, EventSeverity

logger = logging.getLogger(__name__)

# Standard BSD syslog prefix regex: "Oct 26 06:12:34 hostname sshd[12345]: message"
# or RFC 5424 ISO prefix regex: "2026-10-26T06:12:34.123456+00:00 hostname sshd[12345]: message"
# Supports sshd, sshd-session (OpenSSH 9.8+ per-session daemon), and ssh
SYSLOG_LINE_RE = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T[0-9:.]+[\w:+_-]*))\s+"
    r"(?P<host>\S+)\s+"
    r"(?:sshd-session|sshd|ssh)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

# Individual OpenSSH message patterns
FAILED_PWD_INVALID_RE = re.compile(
    r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?",
    re.IGNORECASE,
)
FAILED_PWD_RE = re.compile(
    r"^Failed password for (?:user\s+)?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?",
    re.IGNORECASE,
)
INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
ACCEPTED_PWD_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?",
    re.IGNORECASE,
)
ACCEPTED_PUBKEY_RE = re.compile(
    r"^Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key_info>.*))?",
    re.IGNORECASE,
)
FAILED_PUBKEY_INVALID_RE = re.compile(
    r"^Failed publickey for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key_info>.*))?",
    re.IGNORECASE,
)
FAILED_PUBKEY_RE = re.compile(
    r"^Failed publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?::\s*(?P<key_info>.*))?",
    re.IGNORECASE,
)
FAILED_NONE_RE = re.compile(
    r"^Failed none for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?",
    re.IGNORECASE,
)
MAX_ATTEMPTS_RE = re.compile(
    r"^Maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)
CONNECTION_CLOSED_RE = re.compile(
    r"^Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)",
    re.IGNORECASE,
)


def clean_ip(ip_str: str) -> str | None:
    """Validate and clean IPv4/IPv6 address string."""
    cleaned = ip_str.strip().strip("[]")
    try:
        addr = ipaddress.ip_address(cleaned)
        return str(addr)
    except ValueError:
        return None


def parse_timestamp(ts_str: str, default_year: int | None = None) -> str:
    """Parse BSD syslog or ISO-8601 timestamp string into ISO-8601 UTC string."""
    clean = ts_str.strip()
    if clean.startswith(tuple("0123456789")):
        # ISO-8601 format
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass

    # BSD Syslog format (e.g. "Oct 26 06:12:34" or "Oct  6 06:12:34")
    year = default_year or datetime.now(timezone.utc).year
    # Normalize multiple whitespace between month and day
    parts = clean.split()
    if len(parts) >= 3:
        month, day, time_part = parts[0], parts[1], parts[2]
        date_str = f"{year} {month} {day} {time_part}"
        try:
            dt = datetime.strptime(date_str, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass

    # Fallback to current UTC time if unparseable
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SshParsedEvent:
    """Structured extraction result before conversion to Event model."""

    event_type: str
    severity: EventSeverity
    timestamp: str
    target_host: str
    pid: int
    username: str | None
    source_ip: str | None
    port: int | None
    auth_method: str | None
    failure_reason: str | None
    invalid_user: bool
    raw_message: str


class OpenSshLogParser:
    """Parses raw Linux syslog/journald lines into normalized Event instances."""

    def __init__(self, device_id: str, default_year: int | None = None) -> None:
        self.device_id = device_id
        self.default_year = default_year

    def parse_line(self, line: str) -> Event | None:
        """Parse a single log line. Returns Event if recognized, None otherwise."""
        if not line or not line.strip():
            return None

        # Filter lines that do not mention ssh or sshd early for performance
        if "sshd" not in line and "ssh" not in line:
            return None

        match = SYSLOG_LINE_RE.match(line.strip())
        if not match:
            return None

        ts_raw = match.group("timestamp")
        host = match.group("host")
        pid_raw = match.group("pid")
        message = match.group("message").strip()

        try:
            pid = int(pid_raw)
        except ValueError:
            pid = 0

        timestamp = parse_timestamp(ts_raw, default_year=self.default_year)

        parsed = self._parse_message(message, timestamp, host, pid)
        if not parsed:
            return None

        # Build Event attributes
        attributes: dict[str, Any] = {
            "target_host": parsed.target_host,
            "pid": parsed.pid,
            "invalid_user": parsed.invalid_user,
        }
        if parsed.port is not None:
            attributes["port"] = parsed.port
        if parsed.auth_method is not None:
            attributes["auth_method"] = parsed.auth_method
        if parsed.failure_reason is not None:
            attributes["failure_reason"] = parsed.failure_reason

        return Event(
            event_id=str(uuid.uuid4()),
            device_id=self.device_id,
            timestamp=parsed.timestamp,
            source="linux_auth",
            event_type=parsed.event_type,
            severity=parsed.severity,
            source_ip=parsed.source_ip,
            username=parsed.username,
            raw_event=line.strip(),
            attributes=attributes,
        )

    def parse_journal_entry(self, entry: dict[str, Any]) -> Event | None:
        """Parse a structured systemd journal entry dictionary into an Event."""
        if not entry or not isinstance(entry, dict):
            return None

        raw_message = entry.get("MESSAGE", "")
        if isinstance(raw_message, list):
            message = bytes(raw_message).decode("utf-8", errors="replace").strip()
        else:
            message = str(raw_message).strip()

        if not message:
            return None

        ident = str(entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM") or "sshd").strip()
        unit = str(entry.get("_SYSTEMD_UNIT") or "")

        # Quick reject non-SSH entries
        if ident not in ("sshd", "sshd-session", "ssh"):
            if "ssh" not in unit.lower() and "sshd" not in message and "ssh" not in message:
                return None

        raw_pid = entry.get("SYSLOG_PID") or entry.get("_PID") or 0
        try:
            pid = int(raw_pid)
        except (ValueError, TypeError):
            pid = 0

        host = str(entry.get("_HOSTNAME") or "localhost")

        # Extract timestamp with high precision UTC from __REALTIME_TIMESTAMP or _SOURCE_REALTIME_TIMESTAMP
        ts_us_raw = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")
        timestamp: str | None = None
        if ts_us_raw is not None:
            try:
                ts_us = int(ts_us_raw)
                dt = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)
                timestamp = dt.isoformat()
            except (ValueError, TypeError, OSError):
                timestamp = None

        if timestamp is None:
            syslog_ts = entry.get("SYSLOG_TIMESTAMP")
            if syslog_ts:
                timestamp = parse_timestamp(str(syslog_ts), default_year=self.default_year)
            else:
                timestamp = datetime.now(timezone.utc).isoformat()

        parsed = self._parse_message(message, timestamp, host, pid)
        if not parsed:
            return None

        attributes: dict[str, Any] = {
            "target_host": parsed.target_host,
            "pid": parsed.pid,
            "invalid_user": parsed.invalid_user,
        }
        if parsed.port is not None:
            attributes["port"] = parsed.port
        if parsed.auth_method is not None:
            attributes["auth_method"] = parsed.auth_method
        if parsed.failure_reason is not None:
            attributes["failure_reason"] = parsed.failure_reason

        raw_event = f"{timestamp} {host} {ident}[{pid}]: {message}"

        return Event(
            event_id=str(uuid.uuid4()),
            device_id=self.device_id,
            timestamp=parsed.timestamp,
            source="linux_auth",
            event_type=parsed.event_type,
            severity=parsed.severity,
            source_ip=parsed.source_ip,
            username=parsed.username,
            raw_event=raw_event,
            attributes=attributes,
        )

    def _parse_message(
        self,
        message: str,
        timestamp: str,
        host: str,
        pid: int,
    ) -> SshParsedEvent | None:
        """Analyze OpenSSH message text against known patterns."""
        # 1. Failed password for invalid user
        m = FAILED_PWD_INVALID_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="password",
                failure_reason="invalid_user_password",
                invalid_user=True,
                raw_message=message,
            )

        # 2. Failed password for valid user
        m = FAILED_PWD_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="password",
                failure_reason="bad_password",
                invalid_user=False,
                raw_message=message,
            )

        # 3. Invalid user notice
        m = INVALID_USER_RE.match(message)
        if m:
            port_val = int(m.group("port")) if m.group("port") else None
            return SshParsedEvent(
                event_type="ssh_invalid_user",
                severity=EventSeverity.MEDIUM,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=port_val,
                auth_method=None,
                failure_reason="invalid_user",
                invalid_user=True,
                raw_message=message,
            )

        # 4. Accepted password
        m = ACCEPTED_PWD_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_success",
                severity=EventSeverity.INFORMATIONAL,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="password",
                failure_reason=None,
                invalid_user=False,
                raw_message=message,
            )

        # 5. Accepted publickey
        m = ACCEPTED_PUBKEY_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_success",
                severity=EventSeverity.INFORMATIONAL,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="publickey",
                failure_reason=None,
                invalid_user=False,
                raw_message=message,
            )

        # 6. Failed publickey for invalid user
        m = FAILED_PUBKEY_INVALID_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="publickey",
                failure_reason="invalid_user_publickey",
                invalid_user=True,
                raw_message=message,
            )

        # 7. Failed publickey for valid user
        m = FAILED_PUBKEY_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="publickey",
                failure_reason="bad_publickey",
                invalid_user=False,
                raw_message=message,
            )

        # 8. Failed none
        m = FAILED_NONE_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method="none",
                failure_reason="none_auth_rejected",
                invalid_user=False,
                raw_message=message,
            )

        # 9. Maximum authentication attempts exceeded
        m = MAX_ATTEMPTS_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method=None,
                failure_reason="max_attempts_exceeded",
                invalid_user=False,
                raw_message=message,
            )

        # 10. Connection closed by authenticating user
        m = CONNECTION_CLOSED_RE.match(message)
        if m:
            return SshParsedEvent(
                event_type="ssh_auth_failure",
                severity=EventSeverity.HIGH,
                timestamp=timestamp,
                target_host=host,
                pid=pid,
                username=m.group("user"),
                source_ip=clean_ip(m.group("ip")),
                port=int(m.group("port")),
                auth_method=None,
                failure_reason="preauth_connection_closed",
                invalid_user=False,
                raw_message=message,
            )

        return None
