"""Common event schema and validation for ThreatLens Endpoint Agent."""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from threatlens_agent import __schema_version__

# Patterns for sensitive patterns that should be sanitized
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|private_key|auth_token)",
    re.IGNORECASE,
)
SENSITIVE_VALUE_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)


class EventSeverity(str, Enum):
    """Normalized severity levels for endpoint security events."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, val: str) -> EventSeverity:
        try:
            return cls(val.lower())
        except (ValueError, AttributeError) as exc:
            valid = [s.value for s in cls]
            raise ValueError(f"Invalid event severity '{val}'. Must be one of {valid}") from exc


class EventValidationError(ValueError):
    """Raised when an event fails schema validation."""

    def __init__(self, message: str, field_name: str | None = None) -> None:
        super().__init__(message)
        self.field_name = field_name


def sanitize_raw_text(text: str | None) -> str | None:
    """Mask obvious passwords and credentials in raw log lines."""
    if not text:
        return text
    return SENSITIVE_VALUE_PATTERN.sub(r"\1=[REDACTED]", text)


def sanitize_attributes(attrs: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub sensitive keys in structured metadata."""
    cleaned: dict[str, Any] = {}
    for key, val in attrs.items():
        if SENSITIVE_KEY_PATTERN.search(key):
            cleaned[key] = "[REDACTED]"
        elif isinstance(val, dict):
            cleaned[key] = sanitize_attributes(val)
        elif isinstance(val, str) and SENSITIVE_VALUE_PATTERN.search(val):
            cleaned[key] = sanitize_raw_text(val)
        else:
            cleaned[key] = val
    return cleaned


def validate_iso_timestamp(ts: str) -> datetime:
    """Validate that timestamp is a valid ISO-8601 string and return as UTC datetime."""
    if not isinstance(ts, str) or not ts.strip():
        raise EventValidationError(
            "Event timestamp must be a non-empty ISO-8601 string", "timestamp"
        )

    clean_ts = ts.strip()
    if clean_ts.endswith("Z"):
        clean_ts = clean_ts[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(clean_ts)
    except ValueError as exc:
        raise EventValidationError(
            f"Invalid ISO-8601 timestamp '{ts}': {exc}", "timestamp"
        ) from exc

    if dt.tzinfo is None:
        raise EventValidationError(
            f"Event timestamp must include UTC timezone offset ('Z' or '+00:00'): '{ts}'",
            "timestamp",
        )
    return dt.astimezone(timezone.utc)


@dataclass
class Event:
    """Common normalized event model across all platforms."""

    event_id: str
    device_id: str
    timestamp: str
    source: str
    event_type: str
    severity: EventSeverity
    schema_version: str = __schema_version__
    source_ip: str | None = None
    username: str | None = None
    raw_event: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = EventSeverity.from_str(self.severity)
        if self.raw_event:
            self.raw_event = sanitize_raw_text(self.raw_event)
        if self.attributes:
            self.attributes = sanitize_attributes(self.attributes)

    def validate(self) -> None:
        """Validate required fields, formats, and values."""
        if not self.event_id or not isinstance(self.event_id, str):
            raise EventValidationError("event_id must be a non-empty string", "event_id")

        try:
            uuid.UUID(self.event_id)
        except ValueError as exc:
            raise EventValidationError(
                f"event_id must be a valid UUID string, got: '{self.event_id}'",
                "event_id",
            ) from exc

        if not self.device_id or not isinstance(self.device_id, str):
            raise EventValidationError("device_id must be a non-empty string", "device_id")

        if not self.schema_version or not isinstance(self.schema_version, str):
            raise EventValidationError(
                "schema_version must be a non-empty string", "schema_version"
            )

        if not self.source or not isinstance(self.source, str):
            raise EventValidationError("source must be a non-empty string", "source")

        if not self.event_type or not isinstance(self.event_type, str):
            raise EventValidationError("event_type must be a non-empty string", "event_type")

        if not isinstance(self.severity, EventSeverity):
            raise EventValidationError(
                f"severity must be an EventSeverity instance, got: {type(self.severity).__name__}",
                "severity",
            )

        validate_iso_timestamp(self.timestamp)

        if self.source_ip is not None:
            if not isinstance(self.source_ip, str):
                raise EventValidationError("source_ip must be a string", "source_ip")
            try:
                ipaddress.ip_address(self.source_ip.strip())
            except ValueError as exc:
                raise EventValidationError(
                    f"source_ip must be a valid IP address, got: '{self.source_ip}'",
                    "source_ip",
                ) from exc

        if self.username is not None and not isinstance(self.username, str):
            raise EventValidationError("username must be a string or null", "username")

        if not isinstance(self.attributes, dict):
            raise EventValidationError("attributes must be a dictionary", "attributes")

    def to_dict(self) -> dict[str, Any]:
        """Convert Event to serializable dictionary."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "username": self.username,
            "raw_event": self.raw_event,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        """Create and validate an Event from a dictionary."""
        if not isinstance(data, dict):
            raise EventValidationError("Event data must be a dictionary")

        required = ["event_id", "device_id", "timestamp", "source", "event_type", "severity"]
        for req in required:
            if req not in data:
                raise EventValidationError(f"Missing required event field: '{req}'", req)

        event = cls(
            schema_version=str(data.get("schema_version", __schema_version__)),
            event_id=str(data["event_id"]),
            device_id=str(data["device_id"]),
            timestamp=str(data["timestamp"]),
            source=str(data["source"]),
            event_type=str(data["event_type"]),
            severity=EventSeverity.from_str(str(data["severity"])),
            source_ip=str(data["source_ip"]) if data.get("source_ip") else None,
            username=str(data["username"]) if data.get("username") else None,
            raw_event=str(data["raw_event"]) if data.get("raw_event") else None,
            attributes=dict(data.get("attributes", {})),
        )
        event.validate()
        return event

    @classmethod
    def create_synthetic(
        cls,
        device_id: str,
        source: str = "linux_auth",
        event_type: str = "ssh_auth_failure",
        severity: EventSeverity = EventSeverity.HIGH,
        source_ip: str | None = "192.168.1.50",
        username: str | None = "admin",
        raw_event: str
        | None = "Failed password for invalid user admin from 192.168.1.50 port 44211 ssh2",
        attributes: dict[str, Any] | None = None,
    ) -> Event:
        """Generate a valid synthetic event for testing and verification."""
        now = datetime.now(timezone.utc).isoformat()
        event = cls(
            event_id=str(uuid.uuid4()),
            device_id=device_id,
            timestamp=now,
            source=source,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            username=username,
            raw_event=raw_event,
            attributes=attributes or {"port": 44211, "service": "ssh"},
        )
        event.validate()
        return event
