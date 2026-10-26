"""Device identity and host metadata models."""

from __future__ import annotations

import platform
import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from threatlens_agent import __version__


@dataclass
class DeviceInfo:
    """Represents the host system identity and environment metadata."""

    device_id: str
    hostname: str
    os_family: str
    os_version: str
    architecture: str
    agent_version: str
    first_seen_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert device info to dictionary."""
        return asdict(self)

    @classmethod
    def create_new(cls, device_id: str | None = None) -> DeviceInfo:
        """Create a new DeviceInfo instance by inspecting host environment."""
        resolved_id = device_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            device_id=resolved_id,
            hostname=socket.gethostname(),
            os_family=platform.system().lower(),
            os_version=platform.release(),
            architecture=platform.machine(),
            agent_version=__version__,
            first_seen_at=now,
            metadata={
                "python_version": platform.python_version(),
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceInfo:
        """Instantiate DeviceInfo from dictionary."""
        required = [
            "device_id",
            "hostname",
            "os_family",
            "os_version",
            "architecture",
            "agent_version",
            "first_seen_at",
        ]
        for key in required:
            if key not in data:
                raise ValueError(f"Missing required DeviceInfo field: {key}")
        return cls(
            device_id=str(data["device_id"]),
            hostname=str(data["hostname"]),
            os_family=str(data["os_family"]),
            os_version=str(data["os_version"]),
            architecture=str(data["architecture"]),
            agent_version=str(data["agent_version"]),
            first_seen_at=str(data["first_seen_at"]),
            metadata=dict(data.get("metadata", {})),
        )
