"""Unit tests for the Linux authentication telemetry collector."""

from pathlib import Path

from threatlens_agent.collectors.linux_auth import LinuxAuthCollector
from threatlens_agent.storage.checkpoint import CheckpointManager


def test_missing_and_unreadable_sources_handled_gracefully(temp_dir: Path) -> None:
    """Verify collector handles non-existent or inaccessible sources safely."""
    cp_mgr = CheckpointManager(temp_dir)
    missing_file = temp_dir / "does_not_exist.log"

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[missing_file],
        enable_journald=False,
    )
    collector.start()

    events = collector.collect()
    assert events == []

    diag = collector.get_diagnostics()
    assert diag["supported"] is True
    assert diag["active_sources"] == []
    assert str(missing_file) in diag["sources"]["files"]
    assert diag["sources"]["files"][str(missing_file)]["status"] == "missing"


def test_incremental_file_tailing(temp_dir: Path) -> None:
    """Verify collector tails log file incrementally without duplicate reads."""
    cp_mgr = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"

    line1 = "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2\n"
    line2 = "Oct 26 06:12:31 server01 sshd[1002]: Failed password for root from 192.0.2.10 port 44211 ssh2\n"
    line3 = (
        "Oct 26 06:12:32 server01 sshd[1003]: Invalid user testuser from 203.0.113.50 port 55123\n"
    )

    # Step 1: Write initial 2 lines
    log_file.write_text(line1 + line2, encoding="utf-8")

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[log_file],
        enable_journald=False,
        default_year=2026,
    )
    collector.start()

    events1 = collector.collect()
    assert len(events1) == 2
    assert events1[0].username == "admin"
    assert events1[1].username == "root"

    # Step 2: Second collect without file changes must return 0 events
    events2 = collector.collect()
    assert len(events2) == 0

    # Step 3: Append 1 new line to file
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line3)

    # Step 4: Third collect should return only the newly appended line
    events3 = collector.collect()
    assert len(events3) == 1
    assert events3[0].username == "testuser"


def test_checkpoint_persistence_across_restarts(temp_dir: Path) -> None:
    """Verify collector reinitialization respects persisted checkpoints."""
    log_file = temp_dir / "auth.log"
    line1 = "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2\n"
    log_file.write_text(line1, encoding="utf-8")

    # Instance 1 collects line 1
    cp_mgr1 = CheckpointManager(temp_dir)
    c1 = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr1,
        candidate_paths=[log_file],
        enable_journald=False,
    )
    events1 = c1.collect()
    assert len(events1) == 1
    c1.stop()

    # Instance 2 starts pointing to the same directory
    cp_mgr2 = CheckpointManager(temp_dir)
    c2 = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr2,
        candidate_paths=[log_file],
        enable_journald=False,
    )
    events2 = c2.collect()
    # Must NOT reprocess already collected line 1
    assert len(events2) == 0
    c2.stop()


def test_log_rotation_handling(temp_dir: Path) -> None:
    """Verify log rotation is detected and new file is read from beginning."""
    cp_mgr = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"
    line1 = "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2\n"
    line2 = "Oct 26 06:12:31 server01 sshd[1002]: Failed password for root from 192.0.2.10 port 44211 ssh2\n"

    log_file.write_text(line1, encoding="utf-8")
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[log_file],
        enable_journald=False,
    )
    evs1 = collector.collect()
    assert len(evs1) == 1

    # Simulate logrotate: rotate auth.log to auth.log.1 and create new auth.log (new inode)
    rotated = temp_dir / "auth.log.1"
    log_file.rename(rotated)

    log_file.write_text(line2, encoding="utf-8")

    # Collect from newly rotated file
    evs2 = collector.collect()
    assert len(evs2) == 1
    assert evs2[0].username == "root"


def test_log_truncation_handling(temp_dir: Path) -> None:
    """Verify file truncation causes collector to safely reset to offset 0."""
    cp_mgr = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"
    long_content = (
        "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2\n"
        * 10
    )
    log_file.write_text(long_content, encoding="utf-8")

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[log_file],
        enable_journald=False,
    )
    evs1 = collector.collect()
    assert len(evs1) == 10

    # Truncate file to shorter line
    new_line = "Oct 26 06:12:35 server01 sshd[1002]: Failed password for root from 192.0.2.10 port 44211 ssh2\n"
    log_file.write_text(new_line, encoding="utf-8")

    # Collect after truncation
    evs2 = collector.collect()
    assert len(evs2) == 1
    assert evs2[0].username == "root"


def test_unsupported_platform_behavior(monkeypatch, temp_dir: Path) -> None:
    """Verify collector gracefully reports unsupported on non-Linux systems."""
    monkeypatch.setattr("platform.system", lambda: "Windows")
    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(device_id="dev-test", checkpoint_manager=cp_mgr)

    assert collector.is_supported() is False
    assert collector.collect() == []
    diag = collector.get_diagnostics()
    assert diag["supported"] is False


def test_journald_structured_json_collection_and_cursor_advancement(
    monkeypatch, temp_dir: Path
) -> None:
    """Verify structured journald collection parses JSON and advances cursor per processed entry."""
    import json
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    entry1 = {
        "__CURSOR": "cursor-001",
        "__REALTIME_TIMESTAMP": "1793030358000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "1234",
        "MESSAGE": "Failed password for invalid user hacker from 192.0.2.1 port 55555 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    entry2 = {
        "__CURSOR": "cursor-002",
        "__REALTIME_TIMESTAMP": "1793030359000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "1235",
        "MESSAGE": "Accepted publickey for muadev from 127.0.0.1 port 55556 ssh2: ED25519 SHA256:xyz",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    json_stdout = f"{json.dumps(entry1)}\n{json.dumps(entry2)}\n"

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = json_stdout
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()

    assert len(events) == 2
    assert events[0].username == "hacker"
    assert events[0].event_type == "ssh_auth_failure"
    assert events[1].username == "muadev"
    assert events[1].event_type == "ssh_auth_success"

    # Verify cursor advanced to entry 2's cursor
    assert cp_mgr.get_cursor("journald") == "cursor-002"

    diag = collector.get_diagnostics()
    assert diag["active_sources"] == ["journald"]
    assert diag["journald_active"] is True


def test_journald_cursor_not_advanced_on_empty_output(monkeypatch, temp_dir: Path) -> None:
    """Verify cursor is not modified when journalctl produces no new entries."""
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    cp_mgr.update_cursor("journald", "cursor-existing")

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = ""
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()

    assert events == []
    # Cursor must remain unchanged
    assert cp_mgr.get_cursor("journald") == "cursor-existing"


def test_journald_stale_cursor_recovery(monkeypatch, temp_dir: Path) -> None:
    """Verify collector recovers from an invalid or stale cursor by resetting and retrying."""
    import json
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    cp_mgr.update_cursor("journald", "corrupted-or-expired-cursor")

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    entry = {
        "__CURSOR": "cursor-recovered-001",
        "__REALTIME_TIMESTAMP": "1793030360000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "2222",
        "MESSAGE": "Accepted password for root from 192.168.1.50 port 2222 ssh2",
        "_SYSTEMD_UNIT": "sshd.service",
    }

    call_count = 0

    def mock_run(cmd, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        res = MagicMock()
        # First call uses --after-cursor and fails with seek error
        if "--after-cursor" in cmd:
            res.returncode = 1
            res.stdout = ""
            res.stderr = "Failed to seek to cursor: Invalid argument"
            return res
        # Fallback call succeeds without --after-cursor
        res.returncode = 0
        res.stdout = f"{json.dumps(entry)}\n"
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()

    assert len(events) == 1
    assert events[0].username == "root"
    assert cp_mgr.get_cursor("journald") == "cursor-recovered-001"


def test_journald_unprivileged_user_permission_denied_diagnostic(
    monkeypatch, temp_dir: Path
) -> None:
    """Verify notice warning about missing system permissions marks journald as permission_denied."""
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = ""
        res.stderr = (
            "Hint: You are currently not seeing messages from other users and the system.\n"
            "      Users in groups 'systemd-journal' can see all messages."
        )
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    diag = collector.get_diagnostics()

    assert diag["journald_active"] is False
    assert diag["active_sources"] == []
    assert diag["sources"]["journald"]["available"] is False
    assert diag["sources"]["journald"]["status"] == "permission_denied"


def test_journald_standby_precedence_when_files_present(monkeypatch, temp_dir: Path) -> None:
    """Verify that when file sources exist and are readable, journald stays on standby."""
    from unittest.mock import MagicMock

    log_file = temp_dir / "auth.log"
    log_file.write_text(
        "Oct 26 06:12:30 server01 sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 44210 ssh2\n",
        encoding="utf-8",
    )

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[log_file],
        enable_journald=True,
    )

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = ""
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    diag = collector.get_diagnostics()

    assert diag["active_sources"] == [str(log_file)]
    assert diag["journald_active"] is False
    assert diag["sources"]["journald"]["status"] == "standby"

    # Collecting reads from file, not journald
    events = collector.collect()
    assert len(events) == 1
    assert events[0].username == "admin"


def test_journald_corrupt_json_lines_skipped_gracefully(monkeypatch, temp_dir: Path) -> None:
    """Verify corrupt JSON lines are safely skipped while preserving valid entries."""
    import json
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    valid_entry = {
        "__CURSOR": "cursor-valid",
        "__REALTIME_TIMESTAMP": "1793030361000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "3333",
        "MESSAGE": "Accepted publickey for testuser from 10.0.0.1 port 44444 ssh2: RSA SHA256:abc",
        "_SYSTEMD_UNIT": "ssh.service",
    }

    # Line 1: Garbage text, Line 2: Valid JSON
    output_str = f"NOT_JSON_DATA_HERE\n{json.dumps(valid_entry)}\n"

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = output_str
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()

    assert len(events) == 1
    assert events[0].username == "testuser"
    assert cp_mgr.get_cursor("journald") == "cursor-valid"


def test_consecutive_collection_cycles_with_no_new_entries_and_subsequent_event(
    monkeypatch, temp_dir: Path
) -> None:
    """Verify consecutive cycles with no entries produce 0 events, followed by a new event."""
    import json
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    entry1 = {
        "__CURSOR": "cursor-cycle-01",
        "__REALTIME_TIMESTAMP": "1793030361000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "5001",
        "MESSAGE": "Failed password for admin from 192.168.1.100 port 33333 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    entry2 = {
        "__CURSOR": "cursor-cycle-02",
        "__REALTIME_TIMESTAMP": "1793030362000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "5002",
        "MESSAGE": "Accepted publickey for muadev from 127.0.0.1 port 33334 ssh2: ED25519 SHA256:abc",
        "_SYSTEMD_UNIT": "ssh.service",
    }
    entry3 = {
        "__CURSOR": "cursor-cycle-03",
        "__REALTIME_TIMESTAMP": "1793030370000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "5003",
        "MESSAGE": "Failed password for root from 10.0.0.99 port 44444 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }

    current_output = f"{json.dumps(entry1)}\n{json.dumps(entry2)}\n"

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = current_output
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()

    # Cycle 1: 2 entries available
    events_cycle1 = collector.collect()
    assert len(events_cycle1) == 2
    assert cp_mgr.get_cursor("journald") == "cursor-cycle-02"

    # Cycle 2: No new entries (empty output)
    current_output = ""
    events_cycle2 = collector.collect()
    assert len(events_cycle2) == 0
    assert cp_mgr.get_cursor("journald") == "cursor-cycle-02"

    # Cycle 3: Still no new entries (empty output)
    events_cycle3 = collector.collect()
    assert len(events_cycle3) == 0
    assert cp_mgr.get_cursor("journald") == "cursor-cycle-02"

    # Cycle 4: Genuinely new SSH event arrives
    current_output = f"{json.dumps(entry3)}\n"
    events_cycle4 = collector.collect()
    assert len(events_cycle4) == 1
    assert events_cycle4[0].username == "root"
    assert events_cycle4[0].event_type == "ssh_auth_failure"
    assert cp_mgr.get_cursor("journald") == "cursor-cycle-03"


def test_two_phase_checkpoint_commit(monkeypatch, temp_dir: Path) -> None:
    """Verify collector stages checkpoint and does not persist until commit_checkpoints."""
    import json
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
        auto_commit=False,
    )

    entry = {
        "__CURSOR": "staged-cursor-01",
        "__REALTIME_TIMESTAMP": "1793030361000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "6001",
        "MESSAGE": "Failed password for user1 from 192.168.1.10 port 33333 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = f"{json.dumps(entry)}\n"
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()
    assert len(events) == 1

    # Before commit: cursor on disk is NOT updated
    assert cp_mgr.get_cursor("journald") is None

    # After commit: cursor on disk is updated
    collector.commit_checkpoints()
    assert cp_mgr.get_cursor("journald") == "staged-cursor-01"


def test_journald_transient_error_does_not_reset_valid_cursor(monkeypatch, temp_dir: Path) -> None:
    """Verify transient journalctl failures do not reset or wipe a valid cursor."""
    from unittest.mock import MagicMock

    cp_mgr = CheckpointManager(temp_dir)
    cp_mgr.update_cursor("journald", "valid-cursor-abc")

    collector = LinuxAuthCollector(
        device_id="dev-test",
        checkpoint_manager=cp_mgr,
        candidate_paths=[],
        enable_journald=True,
    )

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        # Non-zero returncode but NOT a cursor seek error
        res.returncode = 1
        res.stdout = ""
        res.stderr = "Temporary resource unavailable or timeout"
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    collector.start()
    events = collector.collect()

    assert events == []
    # Valid cursor MUST NOT be reset
    assert cp_mgr.get_cursor("journald") == "valid-cursor-abc"


def test_agent_withholds_checkpoint_commit_on_queue_failure(monkeypatch, temp_dir: Path) -> None:
    """Verify ThreatLensAgent does not commit checkpoints if queue recording fails."""
    import json
    from unittest.mock import MagicMock

    from threatlens_agent.agent import ThreatLensAgent
    from threatlens_agent.config import AgentConfig

    entry = {
        "__CURSOR": "agent-cursor-uncommitted",
        "__REALTIME_TIMESTAMP": "1793030361000000",
        "_HOSTNAME": "kali",
        "_COMM": "sshd-session",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "_PID": "7001",
        "MESSAGE": "Failed password for testuser from 10.0.0.1 port 22 ssh2",
        "_SYSTEMD_UNIT": "ssh.service",
    }

    def mock_run(cmd, *args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        res.stdout = f"{json.dumps(entry)}\n"
        res.stderr = ""
        return res

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/journalctl")
    monkeypatch.setattr("subprocess.run", mock_run)

    cfg = AgentConfig(data_dir=str(temp_dir))
    agent = ThreatLensAgent(cfg)

    # Force queue to fail recording
    monkeypatch.setattr(agent.queue, "enqueue_batch", lambda events: 0)

    collected, detections = agent.collect_and_detect()
    assert collected == 1

    # Checkpoint must NOT be committed to disk because queue enqueue failed
    assert agent.checkpoint_manager.get_cursor("journald") is None

    agent.close()
