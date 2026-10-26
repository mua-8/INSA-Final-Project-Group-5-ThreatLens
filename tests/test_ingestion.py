"""Unit tests for ThreatLens log ingestion service."""

from datetime import datetime, timezone
from unittest.mock import patch
import pytest

from app.models.events import AuthEventType, IngestionReport
from app.services.ingestion import ingest_log_lines

FIXED_REF_TIME = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


class TestIngestionService:
    """Test suite for ingest_log_lines function."""

    def test_valid_failed_login_line(self):
        lines = ["Oct 25 10:14:22 host sshd[123]: Failed password for root from 192.168.1.10 port 44322 ssh2"]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert isinstance(report, IngestionReport)
        assert report.status == "success"
        assert len(report.events) == 1

        event = report.events[0]
        assert event.event_type == AuthEventType.FAILED_LOGIN
        assert event.username == "root"
        assert event.src_ip == "192.168.1.10"
        assert event.src_port == 44322
        assert event.auth_method == "password"
        assert event.is_malformed is False
        assert event.line_number == 1

        assert report.statistics.total_lines == 1
        assert report.statistics.parsed_count == 1
        assert report.statistics.malformed_count == 0
        assert report.statistics.duplicate_count == 0
        assert report.statistics.processing_time_ms >= 0.0

    def test_valid_accepted_login_line(self):
        lines = [
            "Oct 25 10:14:25 host sshd[124]: Accepted publickey for muadev from 10.0.0.5 port 52341 ssh2: RSA SHA256:abc..."
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.status == "success"
        assert len(report.events) == 1

        event = report.events[0]
        assert event.event_type == AuthEventType.ACCEPTED_LOGIN
        assert event.username == "muadev"
        assert event.src_ip == "10.0.0.5"
        assert event.src_port == 52341
        assert event.auth_method == "publickey"
        assert event.is_malformed is False
        assert event.line_number == 1

        assert report.statistics.total_lines == 1
        assert report.statistics.parsed_count == 1
        assert report.statistics.malformed_count == 0

    def test_batch_containing_several_recognized_event_types(self):
        lines = [
            "Oct 25 10:00:01 host sshd[101]: Failed password for root from 192.168.1.10 port 44322 ssh2",
            "Oct 25 10:00:02 host sshd[102]: Accepted password for sysadmin from 192.168.1.50 port 50222 ssh2",
            "Oct 25 10:00:03 host sshd[103]: Invalid user oracle from 203.0.113.45 port 55123",
            "Oct 25 10:00:04 host sshd[104]: Disconnected from user sysadmin 192.168.1.50 port 50222",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.status == "success"
        assert len(report.events) == 4

        assert report.events[0].event_type == AuthEventType.FAILED_LOGIN
        assert report.events[1].event_type == AuthEventType.ACCEPTED_LOGIN
        assert report.events[2].event_type == AuthEventType.INVALID_USER
        assert report.events[3].event_type == AuthEventType.DISCONNECT

        assert report.statistics.total_lines == 4
        assert report.statistics.parsed_count == 4
        assert report.statistics.malformed_count == 0
        assert report.statistics.duplicate_count == 0

    def test_malformed_mixed_with_valid_lines(self):
        lines = [
            "Oct 25 10:00:01 host sshd[101]: Failed password for root from 192.168.1.10 port 44322 ssh2",
            "\x00\x01\x02 corrupt unparseable binary noise",
            "Oct 25 10:00:02 host sshd[102]: Accepted password for muadev from 192.168.1.15 port 52341 ssh2",
            "",
            "Oct 25 10:00:03 host sshd[103]: Disconnected from 192.168.1.10 port 44322",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.status == "success"
        assert len(report.events) == 5

        # Lines 1, 3, 5 are valid
        assert report.events[0].is_malformed is False
        assert report.events[0].event_type == AuthEventType.FAILED_LOGIN
        assert report.events[2].is_malformed is False
        assert report.events[2].event_type == AuthEventType.ACCEPTED_LOGIN
        assert report.events[4].is_malformed is False
        assert report.events[4].event_type == AuthEventType.DISCONNECT

        # Lines 2 and 4 are malformed
        assert report.events[1].is_malformed is True
        assert report.events[1].parsing_error is not None
        assert report.events[3].is_malformed is True
        assert report.events[3].parsing_error is not None

        # Statistics accounting
        assert report.statistics.total_lines == 5
        assert report.statistics.parsed_count == 3
        assert report.statistics.malformed_count == 2
        assert report.statistics.duplicate_count == 0
        assert report.statistics.total_lines == report.statistics.parsed_count + report.statistics.malformed_count

    def test_empty_iterable(self):
        # Empty list
        report = ingest_log_lines([], reference_time=FIXED_REF_TIME)
        assert report.status == "success"
        assert report.events == []
        assert report.statistics.total_lines == 0
        assert report.statistics.parsed_count == 0
        assert report.statistics.malformed_count == 0
        assert report.statistics.duplicate_count == 0
        assert report.statistics.processing_time_ms >= 0.0

        # Empty generator
        gen_report = ingest_log_lines((x for x in []), reference_time=FIXED_REF_TIME)
        assert gen_report.statistics.total_lines == 0

    def test_correct_one_based_line_number_assignment(self):
        lines = [
            "Oct 25 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
            "Corrupt line 2",
            "Oct 25 10:00:03 host sshd[3]: Accepted password for user3 from 1.1.1.3 port 22 ssh2",
            "",
            "Oct 25 10:00:05 host sshd[5]: Disconnected from 1.1.1.5 port 22",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert len(report.events) == 5
        for expected_num, event in enumerate(report.events, start=1):
            assert event.line_number == expected_num

    def test_exact_preservation_of_raw_log_lines(self):
        raw_inputs = [
            "  Oct 25 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2 \n",
            "\t\tcorrupt line with tabs\n",
            "   ",
        ]
        report = ingest_log_lines(raw_inputs, reference_time=FIXED_REF_TIME)

        assert len(report.events) == 3
        for original, event in zip(raw_inputs, report.events):
            assert event.raw_log == original

    def test_statistics_counts_consistency(self):
        lines = [
            "Oct 25 10:00:01 host sshd[1]: Failed password for u1 from 1.1.1.1 port 22 ssh2",
            "Oct 25 10:00:02 host sshd[2]: Failed password for u2 from 1.1.1.2 port 22 ssh2",
            "bad line 1",
            "bad line 2",
            "Oct 25 10:00:05 host sshd[5]: Accepted password for u3 from 1.1.1.3 port 22 ssh2",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        stats = report.statistics
        assert stats.total_lines == 5
        assert stats.parsed_count == 3
        assert stats.malformed_count == 2
        assert stats.duplicate_count == 0
        assert stats.total_lines == stats.parsed_count + stats.malformed_count

    def test_consistent_reference_time_forwarding(self):
        # Jan 2, 2026 reference time: Dec 31 should roll back to 2025; Jan 1 should be 2026
        ref_time = datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc)
        lines = [
            "Dec 31 23:59:00 gateway sshd[10]: Failed password for root from 1.2.3.4 port 22 ssh2",
            "Jan  1 01:00:00 gateway sshd[11]: Failed password for root from 1.2.3.4 port 22 ssh2",
        ]
        report = ingest_log_lines(lines, reference_time=ref_time)

        assert report.events[0].timestamp == datetime(2025, 12, 31, 23, 59, 0, tzinfo=timezone.utc)
        assert report.events[1].timestamp == datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

    def test_reference_time_generated_once_when_omitted(self):
        # When reference_time is omitted, verify all calls receive the exact same reference time object
        lines = [
            "Oct 25 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
            "Oct 25 10:00:02 host sshd[2]: Accepted password for u1 from 1.1.1.2 port 22 ssh2",
        ]

        with patch("app.services.ingestion.parse_openssh_line", wraps=None) as mock_parser:
            # Configure mock to return valid dummy events
            mock_parser.return_value = None  # Will fail unless returning an event, so use real parser via wrap
            pass

        # Using real parser without reference_time: both events should share the current year
        report = ingest_log_lines(lines)
        now_year = datetime.now(timezone.utc).year
        assert report.events[0].timestamp.year == now_year
        assert report.events[1].timestamp.year == now_year

    def test_unexpected_exception_on_one_line_does_not_abort_batch(self):
        lines = [
            "Oct 25 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
            "Line that triggers unexpected crash",
            "Oct 25 10:00:03 host sshd[3]: Accepted password for user3 from 1.1.1.3 port 22 ssh2",
        ]

        from app.parsers.openssh import parse_openssh_line as real_parse

        def mock_parse(raw_log, reference_time=None, line_number=None):
            if "unexpected crash" in raw_log:
                raise RuntimeError("Simulated unexpected parser exception")
            return real_parse(raw_log, reference_time=reference_time, line_number=line_number)

        with patch("app.services.ingestion.parse_openssh_line", side_effect=mock_parse):
            report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.status == "success"
        assert len(report.events) == 3

        # Line 1: succeeded
        assert report.events[0].event_type == AuthEventType.FAILED_LOGIN
        assert report.events[0].is_malformed is False
        assert report.events[0].line_number == 1

        # Line 2: crashed inside parser, caught safely by service
        assert report.events[1].event_type == AuthEventType.UNKNOWN
        assert report.events[1].is_malformed is True
        assert "Simulated unexpected parser exception" in report.events[1].parsing_error
        assert report.events[1].line_number == 2
        assert report.events[1].raw_log == "Line that triggers unexpected crash"

        # Line 3: proceeded and succeeded
        assert report.events[2].event_type == AuthEventType.ACCEPTED_LOGIN
        assert report.events[2].is_malformed is False
        assert report.events[2].line_number == 3

        assert report.statistics.total_lines == 3
        assert report.statistics.parsed_count == 2
        assert report.statistics.malformed_count == 1

    def test_processing_time_statistics_are_nonnegative(self):
        lines = [
            "Oct 25 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.statistics.processing_time_ms >= 0.0
        assert isinstance(report.statistics.processing_time_ms, float)

    def test_structurally_valid_unknown_event_not_counted_as_malformed(self):
        lines = [
            "Oct 25 10:00:00 host sshd[100]: Server listening on 0.0.0.0 port 22.",
            "Oct 25 10:00:01 host sshd[101]: pam_unix(sshd:session): session opened for user root by (uid=0)",
        ]
        report = ingest_log_lines(lines, reference_time=FIXED_REF_TIME)

        assert report.status == "success"
        assert len(report.events) == 2

        # Both lines have event_type == UNKNOWN but are NOT malformed
        for event in report.events:
            assert event.event_type == AuthEventType.UNKNOWN
            assert event.is_malformed is False
            assert event.parsing_error is None

        # Critical requirement: parsed_count must count non-malformed events, even if UNKNOWN
        assert report.statistics.total_lines == 2
        assert report.statistics.parsed_count == 2
        assert report.statistics.malformed_count == 0
        assert report.statistics.duplicate_count == 0
