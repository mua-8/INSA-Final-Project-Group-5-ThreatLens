"""Unit tests for device identity generation, stability, and permissions."""

import json
import os
import uuid
from pathlib import Path

import pytest

from threatlens_agent.models.device import DeviceInfo
from threatlens_agent.storage.state import StateManager


def test_device_info_creation() -> None:
    """Verify DeviceInfo.create_new populates required metadata."""
    info = DeviceInfo.create_new()
    assert info.device_id
    uuid.UUID(info.device_id)  # Must be valid UUID
    assert info.hostname
    assert info.os_family in ("linux", "windows", "darwin")
    assert info.os_version
    assert info.architecture
    assert info.agent_version


def test_device_identity_stability(temp_dir: Path) -> None:
    """Verify device identity remains stable across StateManager reinitialization."""
    mgr1 = StateManager(temp_dir)
    dev1 = mgr1.get_or_create_device_info()

    # Second initialization pointing to same directory
    mgr2 = StateManager(temp_dir)
    dev2 = mgr2.get_or_create_device_info()

    assert dev1.device_id == dev2.device_id
    assert dev1.first_seen_at == dev2.first_seen_at
    assert dev1.hostname == dev2.hostname


def test_secure_file_permissions(temp_dir: Path) -> None:
    """Verify state directory and state file have 0700/0600 permissions on POSIX."""
    if os.name != "posix":
        pytest.skip("Permission bit verification only applies to POSIX filesystems")

    data_dir = temp_dir / "secure_data"
    mgr = StateManager(data_dir)
    mgr.get_or_create_device_info()

    # Check directory permissions (0o700)
    dir_stat = data_dir.stat().st_mode & 0o777
    assert dir_stat == 0o700, f"Expected 0700 on dir, got {oct(dir_stat)}"

    # Check file permissions (0o600)
    state_file = data_dir / "device_state.json"
    file_stat = state_file.stat().st_mode & 0o777
    assert file_stat == 0o600, f"Expected 0600 on file, got {oct(file_stat)}"


def test_corrupted_state_file_handling(temp_dir: Path) -> None:
    """Verify corrupted JSON in state file raises exception rather than silent failure."""
    state_file = temp_dir / "device_state.json"
    state_file.write_text("{corrupted-json-data", encoding="utf-8")

    mgr = StateManager(temp_dir)
    with pytest.raises(json.JSONDecodeError):
        mgr.get_or_create_device_info()
