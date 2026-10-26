"""Unit tests for ThreatLens data contracts and models."""

from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError

from app.models import (
    AuthEventType,
    IngestionReport,
    ParsedAuthEvent,
    ParsingStatistics,
)


class TestAuthEventType:
    """Test suite for AuthEventType enum values."""

    def test_enum_members_exist(self):
        expected_members = {
            "FAILED_LOGIN",
            "INVALID_USER",
            "ACCEPTED_LOGIN",
            "DISCONNECT",
            "UNKNOWN",
        }
        actual_members = {member.value for member in AuthEventType}
        assert actual_members == expected_members

    def test_string_representation(self):
        assert AuthEventType.FAILED_LOGIN == "FAILED_LOGIN"
        assert AuthEventType.INVALID_USER == "INVALID_USER"
        assert AuthEventType.ACCEPTED_LOGIN == "ACCEPTED_LOGIN"
        assert AuthEventType.DISCONNECT == "DISCONNECT"
        assert AuthEventType.UNKNOWN == "UNKNOWN"


class TestParsedAuthEvent:
    """Test suite for ParsedAuthEvent model validation and normalization."""

    def test_minimal_valid_event(self):
        raw = "Oct 25 10:00:00 server sshd[1234]: Sample message"
        event = ParsedAuthEvent(raw_log=raw)

        assert event.raw_log == raw
        assert event.event_type == AuthEventType.UNKNOWN
        assert event.service == "sshd"
        assert event.is_malformed is False
        assert event.timestamp is None
        assert event.hostname is None
        assert event.username is None
        assert event.src_ip is None
        assert event.src_port is None
        assert event.is_invalid_user is False

    def test_invalid_user_flag(self):
        event = ParsedAuthEvent(
            raw_log="Invalid user test from 1.2.3.4",
            event_type=AuthEventType.INVALID_USER,
            username="test",
            src_ip="1.2.3.4",
            is_invalid_user=True,
        )
        assert event.is_invalid_user is True

    def test_raw_log_exact_preservation(self):
        raw = "Oct 25 10:00:01 host sshd[999]: Failed password for root from 192.168.1.10 port 44322 ssh2"
        event = ParsedAuthEvent(
            raw_log=raw,
            hostname="host",
            service="sshd",
            event_type=AuthEventType.FAILED_LOGIN,
            username="root",
            src_ip="192.168.1.10",
            src_port=44322,
            auth_method="password",
        )
        assert event.raw_log == raw

    def test_valid_ipv4_and_ipv6_addresses(self):
        event_v4 = ParsedAuthEvent(raw_log="log line", src_ip="10.0.0.1")
        assert event_v4.src_ip == "10.0.0.1"

        event_v6 = ParsedAuthEvent(raw_log="log line", src_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert event_v6.src_ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

        event_v6_compressed = ParsedAuthEvent(raw_log="log line", src_ip="::1")
        assert event_v6_compressed.src_ip == "::1"

    def test_invalid_ip_raises_validation_error(self):
        with pytest.raises(ValidationError) as exc_info:
            ParsedAuthEvent(raw_log="log line", src_ip="999.999.999.999")
        assert "Invalid IP address format" in str(exc_info.value)

        with pytest.raises(ValidationError) as exc_info:
            ParsedAuthEvent(raw_log="log line", src_ip="not-an-ip")
        assert "Invalid IP address format" in str(exc_info.value)

    def test_valid_port_ranges(self):
        min_port = ParsedAuthEvent(raw_log="log line", src_port=1)
        assert min_port.src_port == 1

        standard_port = ParsedAuthEvent(raw_log="log line", src_port=22)
        assert standard_port.src_port == 22

        max_port = ParsedAuthEvent(raw_log="log line", src_port=65535)
        assert max_port.src_port == 65535

    def test_invalid_port_raises_validation_error(self):
        with pytest.raises(ValidationError):
            ParsedAuthEvent(raw_log="log line", src_port=0)

        with pytest.raises(ValidationError):
            ParsedAuthEvent(raw_log="log line", src_port=65536)

        with pytest.raises(ValidationError):
            ParsedAuthEvent(raw_log="log line", src_port=-5)

    def test_timestamp_utc_normalization_naive(self):
        naive_dt = datetime(2026, 10, 25, 12, 30, 0)
        event = ParsedAuthEvent(raw_log="log line", timestamp=naive_dt)

        assert event.timestamp is not None
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.hour == 12
        assert event.timestamp.minute == 30

    def test_timestamp_utc_normalization_aware(self):
        # Timezone with +03:00 offset
        tz_plus3 = timezone(timedelta(hours=3))
        aware_dt = datetime(2026, 10, 25, 15, 0, 0, tzinfo=tz_plus3)
        event = ParsedAuthEvent(raw_log="log line", timestamp=aware_dt)

        assert event.timestamp is not None
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.hour == 12  # 15:00 - 3h = 12:00 UTC

    def test_distinguish_unknown_from_malformed(self):
        # A valid SSH daemon line that is not a recognized auth event
        unknown_event = ParsedAuthEvent(
            raw_log="Oct 25 10:00:00 host sshd[123]: Server listening on 0.0.0.0 port 22.",
            event_type=AuthEventType.UNKNOWN,
            is_malformed=False,
        )
        assert unknown_event.event_type == AuthEventType.UNKNOWN
        assert unknown_event.is_malformed is False
        assert unknown_event.parsing_error is None

        # A completely corrupted/garbled line marked as malformed
        malformed_event = ParsedAuthEvent(
            raw_log="\x00\x01\x02 corrupt unparseable data",
            event_type=AuthEventType.UNKNOWN,
            is_malformed=True,
            parsing_error="Unparseable syslog format",
        )
        assert malformed_event.is_malformed is True
        assert malformed_event.parsing_error == "Unparseable syslog format"


class TestParsingStatistics:
    """Test suite for aggregate parsing metrics."""

    def test_default_values(self):
        stats = ParsingStatistics()
        assert stats.total_lines == 0
        assert stats.parsed_count == 0
        assert stats.malformed_count == 0
        assert stats.duplicate_count == 0
        assert stats.processing_time_ms == 0.0

    def test_custom_values(self):
        stats = ParsingStatistics(
            total_lines=150,
            parsed_count=145,
            malformed_count=3,
            duplicate_count=2,
            processing_time_ms=12.45,
        )
        assert stats.total_lines == 150
        assert stats.parsed_count == 145
        assert stats.malformed_count == 3
        assert stats.duplicate_count == 2
        assert stats.processing_time_ms == 12.45

    def test_negative_counts_rejected(self):
        with pytest.raises(ValidationError):
            ParsingStatistics(total_lines=-1)

        with pytest.raises(ValidationError):
            ParsingStatistics(processing_time_ms=-0.5)


class TestIngestionReport:
    """Test suite for IngestionReport response structure."""

    def test_default_report(self):
        report = IngestionReport()
        assert report.status == "success"
        assert report.message == "Log ingestion completed"
        assert report.statistics.total_lines == 0
        assert report.events == []
        assert report.batch_id is None
        assert report.file_hash is None

    def test_populated_report(self):
        raw = "Oct 25 10:00:00 srv sshd[10]: Accepted publickey for muadev from 192.168.1.5 port 55122 ssh2"
        event = ParsedAuthEvent(
            raw_log=raw,
            hostname="srv",
            event_type=AuthEventType.ACCEPTED_LOGIN,
            username="muadev",
            src_ip="192.168.1.5",
            src_port=55122,
            auth_method="publickey",
        )
        stats = ParsingStatistics(
            total_lines=1,
            parsed_count=1,
            malformed_count=0,
            duplicate_count=0,
            processing_time_ms=1.2,
        )
        report = IngestionReport(
            status="success",
            message="Successfully ingested 1 line",
            statistics=stats,
            events=[event],
            batch_id="batch-001",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

        assert report.status == "success"
        assert len(report.events) == 1
        assert report.events[0].username == "muadev"
        assert report.events[0].event_type == AuthEventType.ACCEPTED_LOGIN
        assert report.statistics.parsed_count == 1
        assert report.file_hash is not None
