"""Unit tests for LinuxFileMonitorCollector and file event models."""

from __future__ import annotations

import os
import platform
import tempfile
import time
from pathlib import Path

import pytest

from threatlens_agent.collectors.file_monitor import LinuxFileMonitorCollector
from threatlens_agent.config import FileMonitorConfig
from threatlens_agent.models.events import (
    FILE_EVENT_CREATED,
    FILE_EVENT_DELETED,
    FILE_EVENT_MODIFIED,
    FILE_EVENT_RENAMED,
    EventSeverity,
    EventValidationError,
    create_file_event,
)


def test_create_file_event_valid_types():
    """Verify factory creates valid events for each supported file-event type."""
    for ev_type in [FILE_EVENT_CREATED, FILE_EVENT_MODIFIED, FILE_EVENT_RENAMED, FILE_EVENT_DELETED]:
        ev = create_file_event(
            device_id="test-dev",
            event_type=ev_type,
            file_path="/var/log/audit.log",
        )
        assert ev.event_type == ev_type
        assert ev.attributes["file_path"] == "/var/log/audit.log"
        assert ev.attributes["file_extension"] == ".log"
        assert ev.source == "file_monitor"
        assert ev.severity == EventSeverity.INFORMATIONAL


def test_create_file_event_rename_with_and_without_previous_path():
    """Verify rename event handling with and without previous_path."""
    ev_with = create_file_event(
        device_id="test-dev",
        event_type=FILE_EVENT_RENAMED,
        file_path="/opt/data/new_report.pdf",
        previous_path="/opt/data/old_report.pdf",
    )
    assert ev_with.attributes["file_path"] == "/opt/data/new_report.pdf"
    assert ev_with.attributes["previous_path"] == "/opt/data/old_report.pdf"
    assert ev_with.attributes["file_extension"] == ".pdf"

    ev_without = create_file_event(
        device_id="test-dev",
        event_type=FILE_EVENT_RENAMED,
        file_path="/opt/data/standalone.pdf",
        previous_path=None,
    )
    assert ev_without.attributes["file_path"] == "/opt/data/standalone.pdf"
    assert "previous_path" not in ev_without.attributes


def test_create_file_event_process_attribution_optional():
    """Verify process_name and process_id are optional and validated when present."""
    ev = create_file_event(
        device_id="test-dev",
        event_type=FILE_EVENT_MODIFIED,
        file_path="/etc/hosts",
        process_name="nano",
        process_id=1234,
    )
    assert ev.attributes["process_name"] == "nano"
    assert ev.attributes["process_id"] == 1234

    # Invalid process_id
    with pytest.raises(EventValidationError, match="process_id"):
        create_file_event(
            device_id="test-dev",
            event_type=FILE_EVENT_MODIFIED,
            file_path="/etc/hosts",
            process_id=-5,
        )


def test_create_file_event_null_byte_rejected():
    """Verify null bytes in file_path or previous_path are rejected."""
    with pytest.raises(EventValidationError, match="null bytes"):
        create_file_event(
            device_id="test-dev",
            event_type=FILE_EVENT_CREATED,
            file_path="/tmp/evil\x00.sh",
        )

    with pytest.raises(EventValidationError, match="null bytes"):
        create_file_event(
            device_id="test-dev",
            event_type=FILE_EVENT_RENAMED,
            file_path="/tmp/valid.sh",
            previous_path="/tmp/old\x00.sh",
        )


def test_create_file_event_invalid_type_rejected():
    """Verify unsupported event types raise EventValidationError."""
    with pytest.raises(EventValidationError, match="Invalid file event_type"):
        create_file_event(
            device_id="test-dev",
            event_type="file_encrypted_bad",
            file_path="/tmp/test.txt",
        )


def test_file_monitor_collector_opt_in():
    """Verify collector stays inactive when disabled in configuration."""
    cfg = FileMonitorConfig(enabled=False, monitored_paths=["/tmp"])
    collector = LinuxFileMonitorCollector("dev-1", cfg)
    collector.start()
    assert collector._inotify_fd is None
    assert collector.collect() == []
    collector.stop()


def test_file_monitor_collector_lifecycle_in_temp_directory():
    """Verify active file-system monitoring within an isolated temporary directory."""
    if platform.system() != "Linux":
        pytest.skip("Inotify collector runs only on Linux hosts.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = FileMonitorConfig(
            enabled=True,
            monitored_paths=[tmp_dir],
            recursive=False,
            max_events_per_poll=100,
        )
        collector = LinuxFileMonitorCollector("dev-1", cfg, hostname="kali-test")
        collector.start()

        assert collector.is_supported() is True
        assert len(collector._watches) == 1

        # 1. Create file
        test_file = Path(tmp_dir) / "document.txt"
        test_file.write_text("initial contents")

        # Give inotify kernel queue a brief moment to update
        time.sleep(0.05)
        events = collector.collect()
        types = [e.event_type for e in events]
        assert FILE_EVENT_CREATED in types or FILE_EVENT_MODIFIED in types

        # 2. Modify file
        test_file.write_text("updated contents with more data")
        time.sleep(0.05)
        events_mod = collector.collect()
        types_mod = [e.event_type for e in events_mod]
        assert FILE_EVENT_MODIFIED in types_mod

        # 3. Rename file
        renamed_file = Path(tmp_dir) / "renamed_doc.txt"
        test_file.rename(renamed_file)
        time.sleep(0.05)
        events_ren = collector.collect()
        rename_events = [e for e in events_ren if e.event_type == FILE_EVENT_RENAMED]
        assert len(rename_events) >= 1
        assert rename_events[0].attributes["file_path"] == str(renamed_file)
        assert rename_events[0].attributes.get("previous_path") == str(test_file)

        # 4. Delete file
        renamed_file.unlink()
        time.sleep(0.05)
        events_del = collector.collect()
        types_del = [e.event_type for e in events_del]
        assert FILE_EVENT_DELETED in types_del

        collector.stop()
        assert collector._inotify_fd is None


def test_file_monitor_exclusions():
    """Verify excluded paths and extensions are ignored."""
    if platform.system() != "Linux":
        pytest.skip("Inotify collector runs only on Linux hosts.")

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = FileMonitorConfig(
            enabled=True,
            monitored_paths=[tmp_dir],
            excluded_extensions=[".tmp", ".swp"],
            max_events_per_poll=100,
        )
        collector = LinuxFileMonitorCollector("dev-1", cfg)
        collector.start()

        # Create ignored file
        ignored_file = Path(tmp_dir) / "scratch.tmp"
        ignored_file.write_text("temp data")

        # Create monitored file
        valid_file = Path(tmp_dir) / "valid.log"
        valid_file.write_text("log data")

        time.sleep(0.05)
        events = collector.collect()
        paths = [e.attributes["file_path"] for e in events]

        assert str(valid_file) in paths
        assert str(ignored_file) not in paths

        collector.stop()


def test_file_monitor_symlink_protection():
    """Verify collector refuses to follow symlinks to avoid directory escape."""
    if platform.system() != "Linux":
        pytest.skip("Inotify collector runs only on Linux hosts.")

    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as target_dir:
        symlink_dir = Path(tmp_dir) / "symlink_sub"
        try:
            symlink_dir.symlink_to(target_dir)
        except OSError:
            pytest.skip("Symlink creation not supported in this environment.")

        cfg = FileMonitorConfig(
            enabled=True,
            monitored_paths=[str(symlink_dir)],
            follow_symlinks=False,
        )
        collector = LinuxFileMonitorCollector("dev-1", cfg)
        collector.start()

        # Watch should be rejected
        assert len(collector._watches) == 0
        failed = collector.get_diagnostics()["failed_paths"]
        assert any(f["reason"] == "symlink_rejected" for f in failed)

        collector.stop()


def test_file_monitor_graceful_missing_path():
    """Verify nonexistent directories are handled gracefully without raising unhandled errors."""
    cfg = FileMonitorConfig(
        enabled=True,
        monitored_paths=["/nonexistent_test_directory_xyz_12345"],
    )
    collector = LinuxFileMonitorCollector("dev-1", cfg)
    collector.start()
    assert len(collector._watches) == 0
    collector.stop()
