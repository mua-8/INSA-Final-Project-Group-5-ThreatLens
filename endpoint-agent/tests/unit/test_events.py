"""Unit tests for the common event schema, validation, and redaction."""

import uuid

import pytest

from threatlens_agent.models.events import (
    Event,
    EventSeverity,
    EventValidationError,
)


def test_valid_event_creation(make_event) -> None:
    """Verify standard valid event passes validation."""
    ev = make_event()
    ev.validate()
    assert ev.severity == EventSeverity.HIGH
    assert ev.source == "linux_auth"
    assert ev.username == "root"


def test_reject_invalid_uuid(make_event) -> None:
    """Verify non-UUID event_id is rejected."""
    ev = make_event(event_id="not-a-uuid-1234")
    with pytest.raises(EventValidationError) as exc:
        ev.validate()
    assert "event_id must be a valid UUID string" in str(exc.value)


@pytest.mark.parametrize(
    "invalid_ts",
    [
        "invalid-date",
        "2026-10-26 12:00:00",  # Missing timezone offset
        "2026-10-26T12:00:00",  # Missing offset
        "",
    ],
)
def test_reject_invalid_timestamps(make_event, invalid_ts: str) -> None:
    """Verify invalid or timezone-naive timestamps are rejected."""
    ev = make_event()
    ev.timestamp = invalid_ts
    with pytest.raises(EventValidationError):
        ev.validate()


def test_accept_utc_timestamp_with_z_and_offset(make_event) -> None:
    """Verify ISO timestamps ending in 'Z' or '+00:00' are both accepted."""
    ev1 = make_event()
    ev1.timestamp = "2026-10-26T12:34:56.789Z"
    ev1.validate()

    ev2 = make_event()
    ev2.timestamp = "2026-10-26T12:34:56.789+00:00"
    ev2.validate()


def test_reject_invalid_ip_address(make_event) -> None:
    """Verify malformed source_ip is rejected."""
    ev = make_event(source_ip="999.999.999.999")
    with pytest.raises(EventValidationError) as exc:
        ev.validate()
    assert "source_ip must be a valid IP address" in str(exc.value)


def test_accept_valid_ipv6(make_event) -> None:
    """Verify valid IPv6 source_ip is accepted."""
    ev = make_event(source_ip="2001:db8::1")
    ev.validate()
    assert ev.source_ip == "2001:db8::1"


def test_redaction_in_raw_event() -> None:
    """Verify sensitive password values in raw log strings are redacted."""
    raw = (
        "sshd: Failed password for user admin from 10.0.0.1 password=SuperSecret123 token=abc12345"
    )
    ev = Event(
        event_id=str(uuid.uuid4()),
        device_id="dev-1",
        timestamp="2026-10-26T12:00:00Z",
        source="linux_auth",
        event_type="auth_failure",
        severity=EventSeverity.MEDIUM,
        raw_event=raw,
    )
    assert "SuperSecret123" not in ev.raw_event
    assert "password=[REDACTED]" in ev.raw_event
    assert "token=[REDACTED]" in ev.raw_event


def test_redaction_in_attributes() -> None:
    """Verify sensitive dictionary keys and values are automatically redacted."""
    attrs = {
        "user": "alice",
        "password": "CleartextPassword!",
        "auth_token": "secret-token-xyz",
        "nested": {
            "api_key": "nested-secret-key",
            "safe_detail": "normal-value",
        },
    }
    ev = Event(
        event_id=str(uuid.uuid4()),
        device_id="dev-1",
        timestamp="2026-10-26T12:00:00Z",
        source="app",
        event_type="login",
        severity=EventSeverity.LOW,
        attributes=attrs,
    )
    assert ev.attributes["password"] == "[REDACTED]"
    assert ev.attributes["auth_token"] == "[REDACTED]"
    assert ev.attributes["nested"]["api_key"] == "[REDACTED]"
    assert ev.attributes["nested"]["safe_detail"] == "normal-value"


def test_event_dict_roundtrip(make_event) -> None:
    """Verify event serializes to and deserializes from dictionary losslessly."""
    original = make_event()
    data = original.to_dict()

    restored = Event.from_dict(data)
    assert restored.event_id == original.event_id
    assert restored.device_id == original.device_id
    assert restored.severity == original.severity
    assert restored.attributes == original.attributes


def test_create_synthetic_event() -> None:
    """Verify synthetic event generator produces a valid event."""
    syn = Event.create_synthetic(device_id="synth-dev-1")
    syn.validate()
    assert syn.device_id == "synth-dev-1"
    assert syn.event_type == "ssh_auth_failure"
