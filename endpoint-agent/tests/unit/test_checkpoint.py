"""Unit tests for the collector checkpoint and log rotation manager."""

import os
from pathlib import Path

import pytest

from threatlens_agent.storage.checkpoint import CheckpointManager, FileCheckpoint


def test_checkpoint_roundtrip_and_persistence(temp_dir: Path) -> None:
    """Verify updating and persisting file checkpoints across manager reinitializations."""
    mgr1 = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"
    log_file.write_text("initial log data\n", encoding="utf-8")

    mgr1.update_file_checkpoint(
        path=log_file,
        offset=17,
        inode=12345,
        size=100,
        mtime=1793000000.0,
    )

    # Reconnect with new manager pointing to same directory
    mgr2 = CheckpointManager(temp_dir)
    cp = mgr2.get_file_checkpoint(log_file)

    assert cp.offset == 17
    assert cp.inode == 12345
    assert cp.size == 100
    assert cp.mtime == 1793000000.0
    assert cp.last_read_at is not None


def test_checkpoint_permissions(temp_dir: Path) -> None:
    """Verify checkpoints.json is created with 0600 permissions on POSIX."""
    if os.name != "posix":
        pytest.skip("POSIX permission bits check only applies to POSIX")

    mgr = CheckpointManager(temp_dir)
    mgr.update_cursor("test_source", "cursor_val_123")

    cp_file = temp_dir / "checkpoints.json"
    assert cp_file.is_file()
    mode = cp_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_rotation_detection(temp_dir: Path) -> None:
    """Verify rotation is detected when the file inode changes."""
    mgr = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"
    log_file.write_text("old file data\n", encoding="utf-8")
    stat1 = log_file.stat()

    old_cp = FileCheckpoint(offset=100, inode=stat1.st_ino + 999, size=200)
    offset, is_rotated, is_truncated = mgr.inspect_file_rotation(log_file, old_cp)

    assert is_rotated is True
    assert is_truncated is False
    assert offset == 0


def test_truncation_detection(temp_dir: Path) -> None:
    """Verify truncation is detected when the file size shrinks below offset."""
    mgr = CheckpointManager(temp_dir)
    log_file = temp_dir / "auth.log"
    log_file.write_text("short\n", encoding="utf-8")
    stat = log_file.stat()

    truncated_cp = FileCheckpoint(offset=5000, inode=stat.st_ino, size=10000)
    offset, is_rotated, is_truncated = mgr.inspect_file_rotation(log_file, truncated_cp)

    assert is_truncated is True
    assert is_rotated is False
    assert offset == 0


def test_cursor_roundtrip(temp_dir: Path) -> None:
    """Verify string cursor storage (e.g. for journald) roundtrips properly."""
    mgr = CheckpointManager(temp_dir)
    mgr.update_cursor("journald", "s=12345;i=6789;b=abc")

    mgr2 = CheckpointManager(temp_dir)
    cursor = mgr2.get_cursor("journald")
    assert cursor == "s=12345;i=6789;b=abc"
