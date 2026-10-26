"""Unit tests for the OpenSSH log record parser."""

from pathlib import Path

from threatlens_agent.collectors.parsers.ssh import OpenSshLogParser
from threatlens_agent.models.events import EventSeverity

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "ssh_auth_samples.log"


def test_parse_failed_password_valid_user() -> None:
    """Verify parsing of failed password for an existing account."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)
    line = "Oct 26 06:12:31 server01 sshd[1002]: Failed password for root from 192.0.2.10 port 44211 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.device_id == "dev-test"
    assert ev.source == "linux_auth"
    assert ev.event_type == "ssh_auth_failure"
    assert ev.severity == EventSeverity.HIGH
    assert ev.username == "root"
    assert ev.source_ip == "192.0.2.10"
    assert ev.attributes["port"] == 44211
    assert ev.attributes["target_host"] == "server01"
    assert ev.attributes["auth_method"] == "password"
    assert ev.attributes["invalid_user"] is False
    assert ev.timestamp.startswith("2026-10-26T06:12:31")


def test_parse_failed_password_invalid_user() -> None:
    """Verify parsing of failed password for an invalid/nonexistent user."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)
    line = "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_failure"
    assert ev.severity == EventSeverity.HIGH
    assert ev.username == "admin"
    assert ev.source_ip == "192.0.2.10"
    assert ev.attributes["invalid_user"] is True
    assert ev.attributes["failure_reason"] == "invalid_user_password"


def test_parse_invalid_user_notice() -> None:
    """Verify parsing of standalone invalid user record."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)
    line = "Oct 26 06:12:32 server01 sshd[1003]: Invalid user testuser from 203.0.113.50 port 55123"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_invalid_user"
    assert ev.severity == EventSeverity.MEDIUM
    assert ev.username == "testuser"
    assert ev.source_ip == "203.0.113.50"
    assert ev.attributes["port"] == 55123
    assert ev.attributes["invalid_user"] is True


def test_parse_accepted_password() -> None:
    """Verify parsing of successful password authentication."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)
    line = "Oct 26 06:12:33 server01 sshd[1004]: Accepted password for muadev from 192.0.2.10 port 44212 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_success"
    assert ev.severity == EventSeverity.INFORMATIONAL
    assert ev.username == "muadev"
    assert ev.source_ip == "192.0.2.10"
    assert ev.attributes["auth_method"] == "password"
    assert ev.attributes["invalid_user"] is False


def test_parse_accepted_publickey() -> None:
    """Verify parsing of successful publickey authentication."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)
    line = (
        "Oct 26 06:12:34 server01 sshd[1005]: Accepted publickey for muadev "
        "from 192.0.2.10 port 44213 ssh2: RSA SHA256:abc123456789"
    )
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_success"
    assert ev.severity == EventSeverity.INFORMATIONAL
    assert ev.username == "muadev"
    assert ev.source_ip == "192.0.2.10"
    assert ev.attributes["auth_method"] == "publickey"


def test_parse_ipv6_addresses() -> None:
    """Verify correct extraction of standard and bracketed IPv6 addresses."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)

    # Standard IPv6
    line1 = (
        "Oct 26 06:12:35 server01 sshd[1006]: Failed publickey for invalid user ghost "
        "from 2001:db8::1 port 39821 ssh2: RSA SHA256:def"
    )
    ev1 = parser.parse_line(line1)
    assert ev1 is not None
    assert ev1.source_ip == "2001:db8::1"
    assert ev1.username == "ghost"
    assert ev1.attributes["invalid_user"] is True

    # Bracketed IPv6
    line2 = (
        "2026-10-26T06:12:40.123456+00:00 server01 sshd[1011]: Failed password for "
        "invalid user guest from [2001:db8::55] port 44218 ssh2"
    )
    ev2 = parser.parse_line(line2)
    assert ev2 is not None
    assert ev2.source_ip == "2001:db8::55"
    assert ev2.username == "guest"


def test_parse_other_authentication_failures() -> None:
    """Verify parsing of none-auth, max-attempts, and preauth disconnects."""
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)

    # Failed none
    ev_none = parser.parse_line(
        "Oct 26 06:12:37 server01 sshd[1008]: Failed none for root from 192.0.2.10 port 44215 ssh2"
    )
    assert ev_none is not None
    assert ev_none.event_type == "ssh_auth_failure"
    assert ev_none.attributes["auth_method"] == "none"

    # Max attempts exceeded
    ev_max = parser.parse_line(
        "Oct 26 06:12:38 server01 sshd[1009]: Maximum authentication attempts exceeded "
        "for invalid user attacker from 192.0.2.10 port 44216 ssh2 [preauth]"
    )
    assert ev_max is not None
    assert ev_max.event_type == "ssh_auth_failure"
    assert ev_max.attributes["failure_reason"] == "max_attempts_exceeded"

    # Connection closed [preauth]
    ev_closed = parser.parse_line(
        "Oct 26 06:12:39 server01 sshd[1010]: Connection closed by authenticating user root "
        "192.0.2.10 port 44217 [preauth]"
    )
    assert ev_closed is not None
    assert ev_closed.event_type == "ssh_auth_failure"
    assert ev_closed.username == "root"


def test_parse_sshd_session_failed_password_valid_user() -> None:
    """Verify parsing of failed password from OpenSSH 9.8+ sshd-session process (e.g. Kali Linux)."""
    parser = OpenSshLogParser(device_id="diagnostic-test", default_year=2026)
    line = "Oct 26 02:58:32 kali sshd-session[54699]: Failed password for muadev from 127.0.0.1 port 33408 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.device_id == "diagnostic-test"
    assert ev.source == "linux_auth"
    assert ev.event_type == "ssh_auth_failure"
    assert ev.severity == EventSeverity.HIGH
    assert ev.username == "muadev"
    assert ev.source_ip == "127.0.0.1"
    assert ev.attributes["port"] == 33408
    assert ev.attributes["pid"] == 54699
    assert ev.attributes["target_host"] == "kali"
    assert ev.attributes["auth_method"] == "password"
    assert ev.attributes["invalid_user"] is False
    assert ev.timestamp.startswith("2026-10-26T02:58:32")


def test_parse_sshd_session_failed_password_invalid_user() -> None:
    """Verify parsing of failed password for invalid user from sshd-session."""
    parser = OpenSshLogParser(device_id="diagnostic-test", default_year=2026)
    line = "Oct 26 02:58:33 kali sshd-session[54700]: Failed password for invalid user hacker from 192.0.2.77 port 41234 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_failure"
    assert ev.severity == EventSeverity.HIGH
    assert ev.username == "hacker"
    assert ev.source_ip == "192.0.2.77"
    assert ev.attributes["port"] == 41234
    assert ev.attributes["pid"] == 54700
    assert ev.attributes["invalid_user"] is True
    assert ev.attributes["failure_reason"] == "invalid_user_password"


def test_parse_sshd_session_invalid_user_notice() -> None:
    """Verify parsing of invalid user notice from sshd-session."""
    parser = OpenSshLogParser(device_id="diagnostic-test", default_year=2026)
    line = "Oct 26 02:58:34 kali sshd-session[54701]: Invalid user ghost from 192.0.2.77 port 41234"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_invalid_user"
    assert ev.severity == EventSeverity.MEDIUM
    assert ev.username == "ghost"
    assert ev.source_ip == "192.0.2.77"
    assert ev.attributes["port"] == 41234
    assert ev.attributes["pid"] == 54701
    assert ev.attributes["invalid_user"] is True


def test_parse_sshd_session_accepted_authentication() -> None:
    """Verify parsing of successful authentication from sshd-session."""
    parser = OpenSshLogParser(device_id="diagnostic-test", default_year=2026)
    line = "Oct 26 02:58:35 kali sshd-session[54702]: Accepted password for muadev from 127.0.0.1 port 33412 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_success"
    assert ev.severity == EventSeverity.INFORMATIONAL
    assert ev.username == "muadev"
    assert ev.source_ip == "127.0.0.1"
    assert ev.attributes["auth_method"] == "password"


def test_parse_ssh_legacy_process_name() -> None:
    """Verify legacy ssh[PID] process tag continues to parse successfully."""
    parser = OpenSshLogParser(device_id="diagnostic-test", default_year=2026)
    line = "Oct 26 06:12:35 server01 ssh[1006]: Failed password for root from 192.0.2.10 port 44213 ssh2"
    ev = parser.parse_line(line)

    assert ev is not None
    assert ev.event_type == "ssh_auth_failure"
    assert ev.username == "root"
    assert ev.attributes["pid"] == 1006


def test_unrelated_and_malformed_lines_return_none() -> None:
    """Verify non-ssh or malformed lines return None without raising exceptions."""
    parser = OpenSshLogParser(device_id="dev-test")

    unrelated_lines = [
        "",
        "   ",
        "Oct 26 06:12:41 server01 CRON[2001]: (root) CMD (/usr/local/bin/backup.sh)",
        "Oct 26 06:12:42 server01 sudo[2002]: pam_unix(sudo:session): session opened for user root",
        "Oct 26 06:12:43 server01 systemd[1]: Unit disk-check.service failed to reload.",
        "Oct 26 06:12:44 server01 sshd[1012]: Bad line format without colon or message",
        "Oct 26 06:12:45 server01 sshd[1013]: Failed password for user from invalid-ip port invalid-port ssh2",
        "Random chatter on the system",
    ]

    for line in unrelated_lines:
        assert parser.parse_line(line) is None


def test_parse_from_fixture_file() -> None:
    """Verify parsing across all lines of the synthetic fixture file."""
    assert FIXTURE_PATH.is_file()
    parser = OpenSshLogParser(device_id="dev-test", default_year=2026)

    parsed_events = []
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        for line in f:
            ev = parser.parse_line(line)
            if ev is not None:
                parsed_events.append(ev)

    # 11 valid SSH lines out of 16 in the fixture
    assert len(parsed_events) == 11
    # Verify all generated events pass schema validation
    for ev in parsed_events:
        ev.validate()


def test_parse_journal_entry_failed_password() -> None:
    """Verify parsing a structured journald entry dictionary with failed password."""
    parser = OpenSshLogParser(device_id="test-dev")
    entry = {
        "__CURSOR": "s=abc;i=123",
        "__REALTIME_TIMESTAMP": "1793030358729647",
        "_HOSTNAME": "kali-host",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "54699",
        "MESSAGE": "Failed password for invalid user nonexistent-user-for-test from 127.0.0.1 port 52826 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    ev = parser.parse_journal_entry(entry)
    assert ev is not None
    ev.validate()
    assert ev.event_type == "ssh_auth_failure"
    assert ev.severity == EventSeverity.HIGH
    assert ev.username == "nonexistent-user-for-test"
    assert ev.source_ip == "127.0.0.1"
    assert ev.attributes["port"] == 52826
    assert ev.attributes["pid"] == 54699
    assert ev.attributes["invalid_user"] is True
    assert ev.attributes["failure_reason"] == "invalid_user_password"
    assert "2026-10-26" in ev.timestamp


def test_parse_journal_entry_accepted_pubkey() -> None:
    """Verify parsing a structured journald entry for accepted publickey."""
    parser = OpenSshLogParser(device_id="test-dev")
    entry = {
        "__CURSOR": "s=abc;i=124",
        "__REALTIME_TIMESTAMP": "1793030057309862",
        "_HOSTNAME": "kali-host",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "330469",
        "MESSAGE": "Accepted publickey for muadev from 127.0.0.1 port 49546 ssh2: ED25519 SHA256:abc...",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    ev = parser.parse_journal_entry(entry)
    assert ev is not None
    ev.validate()
    assert ev.event_type == "ssh_auth_success"
    assert ev.severity == EventSeverity.INFORMATIONAL
    assert ev.username == "muadev"
    assert ev.source_ip == "127.0.0.1"
    assert ev.attributes["auth_method"] == "publickey"
    assert ev.attributes["invalid_user"] is False


def test_parse_journal_entry_fallback_timestamps_and_binary_message() -> None:
    """Verify fallback to SYSLOG_TIMESTAMP and decoding list[int] message bytes."""
    parser = OpenSshLogParser(device_id="test-dev", default_year=2026)
    msg_bytes = list(b"Failed password for validuser from 192.168.1.100 port 2222 ssh2")
    entry = {
        "SYSLOG_TIMESTAMP": "Oct 26 11:59:18 ",
        "_HOSTNAME": "server01",
        "SYSLOG_IDENTIFIER": "sshd",
        "SYSLOG_PID": "1234",
        "MESSAGE": msg_bytes,
        "_SYSTEMD_UNIT": "sshd.service",
    }
    ev = parser.parse_journal_entry(entry)
    assert ev is not None
    ev.validate()
    assert ev.username == "validuser"
    assert ev.source_ip == "192.168.1.100"
    assert ev.attributes["port"] == 2222
    assert "2026-10-26" in ev.timestamp


def test_parse_journal_entry_reject_unrelated() -> None:
    """Verify non-SSH or malformed journal records return None."""
    parser = OpenSshLogParser(device_id="test-dev")
    assert parser.parse_journal_entry({}) is None
    assert parser.parse_journal_entry({"MESSAGE": ""}) is None
    assert (
        parser.parse_journal_entry(
            {
                "MESSAGE": "gnome-shell: Unable to mount volume",
                "_COMM": "gnome-shell",
                "SYSLOG_IDENTIFIER": "gnome-shell",
            }
        )
        is None
    )
    # SSH record with irrelevant message (session closed)
    assert (
        parser.parse_journal_entry(
            {
                "MESSAGE": "pam_unix(sshd:session): session closed for user muadev",
                "_COMM": "sshd-session",
                "SYSLOG_IDENTIFIER": "sshd-session",
            }
        )
        is None
    )
