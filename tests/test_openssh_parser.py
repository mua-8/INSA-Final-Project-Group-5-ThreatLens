"""Unit and integration tests for the OpenSSH authentication log parser."""

from datetime import datetime, timezone
import pytest

from app.models.events import AuthEventType
from app.parsers.openssh import (
    infer_syslog_timestamp,
    parse_iso_timestamp,
    parse_openssh_line,
)

FIXED_REF_TIME = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


class TestOpenSSHParser:
    """Comprehensive test suite for OpenSSH log line parsing."""

    def test_failed_password_authentication(self):
        line = "Oct 25 10:14:22 sec-host sshd[5432]: Failed password for root from 192.168.1.105 port 51234 ssh2"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.FAILED_LOGIN
        assert event.auth_method == "password"
        assert event.username == "root"
        assert event.src_ip == "192.168.1.105"
        assert event.src_port == 51234
        assert event.hostname == "sec-host"
        assert event.service == "sshd"
        assert event.is_invalid_user is False
        assert event.is_malformed is False
        assert event.parsing_error is None
        assert event.timestamp == datetime(2026, 10, 25, 10, 14, 22, tzinfo=timezone.utc)

    def test_failed_publickey_authentication(self):
        line = "Oct 25 10:14:23 sec-host sshd[5433]: Failed publickey for devuser from 10.1.2.3 port 49152 ssh2: RSA SHA256:abcd1234efgh5678"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.FAILED_LOGIN
        assert event.auth_method == "publickey"
        assert event.username == "devuser"
        assert event.src_ip == "10.1.2.3"
        assert event.src_port == 49152
        assert event.is_invalid_user is False
        assert event.is_malformed is False

    def test_failed_authentication_for_invalid_user(self):
        line = "Oct 25 10:14:24 sec-host sshd[5434]: Failed password for invalid user admin from 172.16.5.99 port 38291 ssh2"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.FAILED_LOGIN
        assert event.auth_method == "password"
        assert event.username == "admin"
        assert event.src_ip == "172.16.5.99"
        assert event.src_port == 38291
        assert event.is_invalid_user is True
        assert event.is_malformed is False

    def test_explicit_invalid_user_message(self):
        line = "Oct 25 10:14:25 sec-host sshd[5435]: Invalid user oracle from 203.0.113.45 port 55123"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.INVALID_USER
        assert event.username == "oracle"
        assert event.src_ip == "203.0.113.45"
        assert event.src_port == 55123
        assert event.is_invalid_user is True
        assert event.auth_method is None
        assert event.is_malformed is False

    def test_invalid_user_without_port(self):
        line = "Invalid user postgres from 198.51.100.22"
        event = parse_openssh_line(line)

        assert event.event_type == AuthEventType.INVALID_USER
        assert event.username == "postgres"
        assert event.src_ip == "198.51.100.22"
        assert event.src_port is None
        assert event.is_invalid_user is True
        assert event.is_malformed is False

    def test_accepted_password_authentication(self):
        line = "Oct 25 10:14:26 sec-host sshd[5436]: Accepted password for sysadmin from 192.168.1.50 port 50222 ssh2"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.ACCEPTED_LOGIN
        assert event.auth_method == "password"
        assert event.username == "sysadmin"
        assert event.src_ip == "192.168.1.50"
        assert event.src_port == 50222
        assert event.is_invalid_user is False
        assert event.is_malformed is False

    def test_accepted_publickey_authentication(self):
        line = "Oct 25 10:14:27 sec-host sshd[5437]: Accepted publickey for muadev from 192.168.1.50 port 50223 ssh2: ED25519 SHA256:7b9z1x092"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)

        assert event.raw_log == line
        assert event.event_type == AuthEventType.ACCEPTED_LOGIN
        assert event.auth_method == "publickey"
        assert event.username == "muadev"
        assert event.src_ip == "192.168.1.50"
        assert event.src_port == 50223
        assert event.is_invalid_user is False
        assert event.is_malformed is False

    def test_ipv4_and_ipv6_addresses(self):
        # Standard IPv4
        event_v4 = parse_openssh_line(
            "Oct 25 10:00:00 host sshd[1]: Accepted password for u1 from 10.0.0.1 port 22 ssh2",
            reference_time=FIXED_REF_TIME,
        )
        assert event_v4.src_ip == "10.0.0.1"

        # Full IPv6
        event_v6_full = parse_openssh_line(
            "Oct 25 10:00:00 host sshd[1]: Accepted password for u1 from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 22 ssh2",
            reference_time=FIXED_REF_TIME,
        )
        assert event_v6_full.src_ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

        # Compressed IPv6 loopback
        event_v6_loopback = parse_openssh_line(
            "Oct 25 10:00:00 host sshd[1]: Failed password for root from ::1 port 2222 ssh2",
            reference_time=FIXED_REF_TIME,
        )
        assert event_v6_loopback.src_ip == "::1"

        # Bracketed IPv6
        event_v6_bracket = parse_openssh_line(
            "Oct 25 10:00:00 host sshd[1]: Disconnected from [2001:db8::1] port 51111",
            reference_time=FIXED_REF_TIME,
        )
        assert event_v6_bracket.src_ip == "2001:db8::1"

    def test_disconnect_and_connection_closures(self):
        # 1. Disconnected with user
        e1 = parse_openssh_line(
            "Oct 25 10:14:31 sec-host sshd[5441]: Disconnected from user muadev 192.168.1.50 port 50223",
            reference_time=FIXED_REF_TIME,
        )
        assert e1.event_type == AuthEventType.DISCONNECT
        assert e1.username == "muadev"
        assert e1.src_ip == "192.168.1.50"
        assert e1.src_port == 50223
        assert e1.is_invalid_user is False

        # 2. Disconnected authenticating user
        e2 = parse_openssh_line(
            "Oct 25 10:14:32 sec-host sshd[5442]: Disconnected from authenticating user root 192.168.1.200 port 61234 [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e2.event_type == AuthEventType.DISCONNECT
        assert e2.username == "root"
        assert e2.src_ip == "192.168.1.200"
        assert e2.src_port == 61234
        assert e2.is_invalid_user is False

        # 3. Disconnected invalid user
        e3 = parse_openssh_line(
            "Oct 25 10:14:33 sec-host sshd[5443]: Disconnected from invalid user badactor 10.0.0.99 port 59999 [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e3.event_type == AuthEventType.DISCONNECT
        assert e3.username == "badactor"
        assert e3.src_ip == "10.0.0.99"
        assert e3.src_port == 59999
        assert e3.is_invalid_user is True

        # 4. Connection closed by authenticating user
        e4 = parse_openssh_line(
            "Oct 25 10:14:34 sec-host sshd[5444]: Connection closed by authenticating user admin 10.0.0.88 port 48123 [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e4.event_type == AuthEventType.DISCONNECT
        assert e4.username == "admin"
        assert e4.src_ip == "10.0.0.88"
        assert e4.src_port == 48123

        # 5. Connection closed by IP (no user)
        e5 = parse_openssh_line(
            "Oct 25 10:14:35 sec-host sshd[5445]: Connection closed by 192.168.1.200 port 61234 [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e5.event_type == AuthEventType.DISCONNECT
        assert e5.username is None
        assert e5.src_ip == "192.168.1.200"
        assert e5.src_port == 61234

        # 6. Connection reset by
        e6 = parse_openssh_line(
            "Oct 25 10:14:36 sec-host sshd[5446]: Connection reset by 192.168.1.200 port 61234 [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e6.event_type == AuthEventType.DISCONNECT
        assert e6.username is None
        assert e6.src_ip == "192.168.1.200"
        assert e6.src_port == 61234

        # 7. Received disconnect from
        e7 = parse_openssh_line(
            "Oct 25 10:14:37 sec-host sshd[5447]: Received disconnect from 192.168.1.200 port 61234:11: Bye Bye [preauth]",
            reference_time=FIXED_REF_TIME,
        )
        assert e7.event_type == AuthEventType.DISCONNECT
        assert e7.username is None
        assert e7.src_ip == "192.168.1.200"
        assert e7.src_port == 61234

    def test_single_digit_and_double_digit_syslog_days(self):
        # Single digit day with two spaces (standard syslog RFC 3164)
        single_day = "Oct  5 08:30:15 host sshd[10]: Failed password for root from 1.1.1.1 port 22 ssh2"
        event_single = parse_openssh_line(single_day, reference_time=FIXED_REF_TIME)
        assert event_single.timestamp == datetime(2026, 10, 5, 8, 30, 15, tzinfo=timezone.utc)

        # Double digit day with one space
        double_day = "Oct 25 14:45:00 host sshd[10]: Failed password for root from 1.1.1.1 port 22 ssh2"
        event_double = parse_openssh_line(double_day, reference_time=FIXED_REF_TIME)
        assert event_double.timestamp == datetime(2026, 10, 25, 14, 45, 0, tzinfo=timezone.utc)

    def test_iso_8601_timestamps_with_offsets(self):
        # +04:00 offset (14:30 +04:00 -> 10:30 UTC)
        iso_plus4 = "2026-10-25T14:30:00+04:00 host sshd[10]: Accepted password for user1 from 1.1.1.1 port 22 ssh2"
        event_plus4 = parse_openssh_line(iso_plus4)
        assert event_plus4.timestamp == datetime(2026, 10, 25, 10, 30, 0, tzinfo=timezone.utc)

        # -04:00 offset (06:30 -04:00 -> 10:30 UTC)
        iso_minus4 = "2026-10-25T06:30:00-04:00 host sshd[10]: Accepted password for user1 from 1.1.1.1 port 22 ssh2"
        event_minus4 = parse_openssh_line(iso_minus4)
        assert event_minus4.timestamp == datetime(2026, 10, 25, 10, 30, 0, tzinfo=timezone.utc)

        # Z UTC format
        iso_z = "2026-10-25T10:30:00Z host sshd[10]: Accepted password for user1 from 1.1.1.1 port 22 ssh2"
        event_z = parse_openssh_line(iso_z)
        assert event_z.timestamp == datetime(2026, 10, 25, 10, 30, 0, tzinfo=timezone.utc)

    def test_year_end_rollover_with_reference_time(self):
        # Reference time is Jan 2, 2026. A log recorded on Dec 31 belongs to 2025.
        new_year_ref = datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc)

        dec_log = "Dec 31 23:59:00 gateway sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
        dec_event = parse_openssh_line(dec_log, reference_time=new_year_ref)
        assert dec_event.timestamp == datetime(2025, 12, 31, 23, 59, 0, tzinfo=timezone.utc)

        jan_log = "Jan  1 01:00:00 gateway sshd[124]: Failed password for root from 1.2.3.4 port 22 ssh2"
        jan_event = parse_openssh_line(jan_log, reference_time=new_year_ref)
        assert jan_event.timestamp == datetime(2026, 1, 1, 1, 0, 0, tzinfo=timezone.utc)

    def test_empty_malformed_and_unsupported_lines(self):
        # 1. Empty string
        e_empty = parse_openssh_line("")
        assert e_empty.raw_log == ""
        assert e_empty.is_malformed is True
        assert e_empty.event_type == AuthEventType.UNKNOWN
        assert "Empty" in e_empty.parsing_error

        # 2. Whitespace-only string
        e_ws = parse_openssh_line("   \t\n")
        assert e_ws.is_malformed is True
        assert e_ws.event_type == AuthEventType.UNKNOWN

        # 3. Completely corrupt / unparseable binary data
        corrupt = "\x00\x01\x02 corrupt unparseable data"
        e_corrupt = parse_openssh_line(corrupt)
        assert e_corrupt.raw_log == corrupt
        assert e_corrupt.is_malformed is True
        assert e_corrupt.event_type == AuthEventType.UNKNOWN

        # 4. Valid syslog line with unsupported/unrecognized SSH daemon message
        # Should be UNKNOWN, but NOT malformed!
        unsupported = "Oct 25 10:00:00 host sshd[100]: Server listening on 0.0.0.0 port 22."
        e_unsupp = parse_openssh_line(unsupported, reference_time=FIXED_REF_TIME)
        assert e_unsupp.raw_log == unsupported
        assert e_unsupp.event_type == AuthEventType.UNKNOWN
        assert e_unsupp.is_malformed is False
        assert e_unsupp.parsing_error is None
        assert e_unsupp.hostname == "host"
        assert e_unsupp.service == "sshd"
        assert e_unsupp.timestamp == datetime(2026, 10, 25, 10, 0, 0, tzinfo=timezone.utc)

        # 5. Malformed timestamp (invalid calendar date)
        invalid_ts_line = "Oct 35 10:00:00 host sshd[100]: Failed password for root from 1.1.1.1 port 22 ssh2"
        e_bad_ts = parse_openssh_line(invalid_ts_line, reference_time=FIXED_REF_TIME)
        assert e_bad_ts.is_malformed is True
        assert "Invalid timestamp" in e_bad_ts.parsing_error

        # 6. Structurally matching line with invalid IP address
        bad_ip_line = "Oct 25 10:00:00 host sshd[100]: Failed password for root from 999.999.999.999 port 22 ssh2"
        e_bad_ip = parse_openssh_line(bad_ip_line, reference_time=FIXED_REF_TIME)
        assert e_bad_ip.is_malformed is True
        assert "Invalid IP address" in e_bad_ip.parsing_error

        # 7. Structurally matching line with invalid port (out of range)
        bad_port_line = "Oct 25 10:00:00 host sshd[100]: Failed password for root from 1.1.1.1 port 70000 ssh2"
        e_bad_port = parse_openssh_line(bad_port_line, reference_time=FIXED_REF_TIME)
        assert e_bad_port.is_malformed is True
        assert "src_port" in e_bad_port.parsing_error and "65535" in e_bad_port.parsing_error

    def test_exact_preservation_of_raw_log(self):
        line = "  Oct 25 10:00:00 host sshd[123]: Failed password for root from 1.1.1.1 port 22 ssh2 \n"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME)
        # Verify verbatim preservation including leading spaces and trailing newline
        assert event.raw_log == line

    def test_missing_optional_fields(self):
        # Line with no syslog header at all (only OpenSSH payload)
        raw_payload_only = "Failed password for root from 192.168.1.10 port 22 ssh2"
        event = parse_openssh_line(raw_payload_only)

        assert event.raw_log == raw_payload_only
        assert event.event_type == AuthEventType.FAILED_LOGIN
        assert event.username == "root"
        assert event.src_ip == "192.168.1.10"
        assert event.src_port == 22
        assert event.auth_method == "password"
        assert event.timestamp is None
        assert event.hostname is None
        assert event.service == "sshd"
        assert event.is_malformed is False

    def test_no_fabricated_event_data_for_unparseable_input(self):
        unparseable = "Something went completely wrong with this system log entry"
        event = parse_openssh_line(unparseable)

        assert event.is_malformed is True
        assert event.username is None
        assert event.src_ip is None
        assert event.src_port is None
        assert event.auth_method is None
        assert event.timestamp is None
        assert event.hostname is None

    def test_line_number_tracking(self):
        line = "Oct 25 10:00:00 host sshd[123]: Accepted password for user1 from 1.1.1.1 port 22 ssh2"
        event = parse_openssh_line(line, reference_time=FIXED_REF_TIME, line_number=42)
        assert event.line_number == 42
