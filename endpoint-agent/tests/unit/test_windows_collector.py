"""Unit tests for WindowsEventLogCollector using SyntheticWindowsEventAdapter."""

from pathlib import Path

from threatlens_agent.collectors.windows_adapter import SyntheticWindowsEventAdapter
from threatlens_agent.collectors.windows_event import WindowsEventLogCollector
from threatlens_agent.storage.checkpoint import CheckpointManager

DEVICE_ID = "win-collector-test-01"


def test_incremental_collection_and_checkpoint_persistence(temp_dir: Path) -> None:
    """Verify incremental collection persists highest record ID across collector restarts."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    adapter = SyntheticWindowsEventAdapter(
        records=[
            {
                "Id": 4625,
                "RecordId": 100,
                "TimeCreated": "2026-10-26T06:12:00.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "admin", "IpAddress": "192.0.2.10"},
            },
            {
                "Id": 4624,
                "RecordId": 105,
                "TimeCreated": "2026-10-26T06:12:30.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "alice", "IpAddress": "192.0.2.15"},
            },
        ]
    )

    collector1 = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
    )
    collector1.start()

    events1 = collector1.collect()
    assert len(events1) == 2
    assert events1[0].username == "admin"
    assert events1[1].username == "alice"

    # Verify saved checkpoint
    cp = checkpoint_mgr.get_channel_checkpoint("Security")
    assert cp is not None
    assert cp["last_record_id"] == 105

    # Second collection cycle without new records -> 0 events
    events_empty = collector1.collect()
    assert len(events_empty) == 0

    # Add new record
    adapter.add_record(
        {
            "Id": 4672,
            "RecordId": 110,
            "TimeCreated": "2026-10-26T06:13:00.000000+00:00",
            "Channel": "Security",
            "EventData": {"SubjectUserName": "admin", "PrivilegeList": "SeDebugPrivilege"},
        }
    )

    # Simulate new collector restart using same persisted checkpoint manager
    checkpoint_mgr2 = CheckpointManager(temp_dir)
    collector2 = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr2,
        adapter=adapter,
    )
    collector2.start()

    events2 = collector2.collect()
    assert len(events2) == 1
    assert events2[0].event_type == "windows_special_privilege_assigned"
    assert events2[0].attributes["record_id"] == 110

    # Verify query received after_record_id=105
    last_query = adapter.queries_executed[-1]
    assert last_query["after_record_id"] == 105


def test_duplicate_record_suppression(temp_dir: Path) -> None:
    """Verify collector suppresses duplicate records within memory."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    adapter = SyntheticWindowsEventAdapter(
        records=[
            {
                "Id": 4625,
                "RecordId": 200,
                "TimeCreated": "2026-10-26T06:12:00.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "intruder", "IpAddress": "192.0.2.99"},
            },
            {
                "Id": 4625,
                "RecordId": 200,  # Duplicate record ID
                "TimeCreated": "2026-10-26T06:12:00.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "intruder", "IpAddress": "192.0.2.99"},
            },
        ]
    )

    collector = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
    )
    collector.start()

    events = collector.collect()
    assert len(events) == 1
    assert events[0].attributes["record_id"] == 200


def test_event_log_clearing_discontinuity_detection(temp_dir: Path) -> None:
    """Verify log clearing or wrapping safely resets checkpoint without data loss."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    # Seed checkpoint at high record ID 5000
    checkpoint_mgr.update_channel_checkpoint("Security", last_record_id=5000)

    # Log was cleared: new records start at ID 1, 2
    adapter = SyntheticWindowsEventAdapter(
        records=[
            {
                "Id": 4625,
                "RecordId": 1,
                "TimeCreated": "2026-10-26T06:12:00.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "attacker", "IpAddress": "192.0.2.66"},
            },
            {
                "Id": 4624,
                "RecordId": 2,
                "TimeCreated": "2026-10-26T06:12:10.000000+00:00",
                "Channel": "Security",
                "EventData": {"TargetUserName": "admin", "IpAddress": "192.0.2.66"},
            },
        ]
    )

    collector = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
    )
    collector.start()

    events = collector.collect()
    assert len(events) == 2
    assert events[0].attributes["record_id"] == 1
    assert events[1].attributes["record_id"] == 2

    # Checkpoint should now be reset and updated to 2
    cp = checkpoint_mgr.get_channel_checkpoint("Security")
    assert cp is not None
    assert cp["last_record_id"] == 2


def test_permission_failure_handling(temp_dir: Path) -> None:
    """Verify permission denied error is reported in diagnostics and does not crash agent."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    adapter = SyntheticWindowsEventAdapter(permission_denied_channels={"Security"})

    collector = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
    )
    collector.start()

    # Diagnostics should show permission_denied
    diag = collector.get_diagnostics()
    assert diag["channels"]["Security"]["status"] == "permission_denied"
    assert "Access is denied" in diag["channels"]["Security"]["error"]
    assert "Security" not in diag["active_sources"]

    # Collect should return empty list gracefully without throwing
    events = collector.collect()
    assert events == []


def test_query_error_handling(temp_dir: Path) -> None:
    """Verify unexpected query error is caught and does not crash."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    adapter = SyntheticWindowsEventAdapter()
    adapter.simulate_query_error = RuntimeError("Windows RPC service unavailable")

    collector = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
    )
    collector.start()

    events = collector.collect()
    assert events == []


def test_unsupported_platform_behavior_on_linux(temp_dir: Path) -> None:
    """Verify is_supported() reflects operating system correctly without failing on Linux."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    collector = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
    )

    # On this Linux host, is_supported() must be False
    assert not collector.is_supported()
    assert collector.name == "windows_event_log"


def test_sysmon_availability_and_collection(temp_dir: Path) -> None:
    """Verify optional Sysmon channel collection when enabled."""
    checkpoint_mgr = CheckpointManager(temp_dir)
    adapter = SyntheticWindowsEventAdapter(
        records=[
            {
                "Id": 1,
                "RecordId": 501,
                "TimeCreated": "2026-10-26T06:17:00.000000+00:00",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventData": {
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "User": "CORP\\alice",
                    "Hashes": "SHA256=ABC",
                },
            }
        ],
        available_channels={"Security", "Microsoft-Windows-Sysmon/Operational"},
    )

    # 1. Disabled by default
    collector_disabled = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
        enable_sysmon=False,
    )
    collector_disabled.start()
    events_disabled = collector_disabled.collect()
    # Sysmon record should NOT be collected
    assert len(events_disabled) == 0

    diag_disabled = collector_disabled.get_diagnostics()
    assert not diag_disabled["sysmon"]["enabled"]

    # 2. Enabled
    collector_enabled = WindowsEventLogCollector(
        device_id=DEVICE_ID,
        checkpoint_manager=checkpoint_mgr,
        adapter=adapter,
        enable_sysmon=True,
    )
    collector_enabled.start()
    events_enabled = collector_enabled.collect()
    assert len(events_enabled) == 1
    assert events_enabled[0].event_type == "sysmon_process_creation"
    assert events_enabled[0].source == "windows_sysmon"

    diag_enabled = collector_enabled.get_diagnostics()
    assert diag_enabled["sysmon"]["enabled"]
    assert diag_enabled["sysmon"]["available"]
    assert diag_enabled["sysmon"]["readable"]
