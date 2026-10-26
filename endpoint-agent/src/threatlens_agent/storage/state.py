"""State persistence and device identity management."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from threatlens_agent.models.device import DeviceInfo

logger = logging.getLogger(__name__)


def set_secure_permissions(path: Path, is_dir: bool = False) -> None:
    """Set secure filesystem permissions (POSIX: 0700 for dirs, 0600 for files)."""
    if os.name == "posix":
        try:
            mode = 0o700 if is_dir else 0o600
            os.chmod(path, mode)
        except OSError as exc:
            logger.warning("Failed to set secure permissions on %s: %s", path, exc)


class StateManager:
    """Manages persistent agent state and stable device identity."""

    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.state_file = self.data_dir / "device_state.json"
        self._ensure_data_dir()

    def _ensure_data_dir(self) -> None:
        """Create data directory with restricted permissions if it does not exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        set_secure_permissions(self.data_dir, is_dir=True)

    def get_or_create_device_info(self) -> DeviceInfo:
        """Load existing device info or generate and persist a new stable identity."""
        if self.state_file.is_file():
            try:
                with open(self.state_file, encoding="utf-8") as f:
                    data = json.load(f)
                device_info = DeviceInfo.from_dict(data)
                logger.debug("Loaded existing device identity: %s", device_info.device_id)
                return device_info
            except Exception as exc:
                logger.error("Failed to read device state file at %s: %s", self.state_file, exc)
                raise

        # Generate new stable device identity
        device_info = DeviceInfo.create_new()
        self.save_device_info(device_info)
        logger.info("Generated and saved new device identity: %s", device_info.device_id)
        return device_info

    def save_device_info(self, device_info: DeviceInfo) -> None:
        """Atomically persist device info with secure permissions."""
        self._ensure_data_dir()
        serialized = json.dumps(device_info.to_dict(), indent=2)

        # Atomic write via temporary file in same directory
        temp_fd, temp_path = tempfile.mkstemp(
            prefix="device_state_",
            suffix=".tmp",
            dir=str(self.data_dir),
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                f.write(serialized)
            set_secure_permissions(Path(temp_path), is_dir=False)
            os.replace(temp_path, self.state_file)
            set_secure_permissions(self.state_file, is_dir=False)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
