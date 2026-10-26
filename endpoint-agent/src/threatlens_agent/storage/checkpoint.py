"""Persistent checkpoint manager for incremental telemetry log tailing."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatlens_agent.storage.state import set_secure_permissions

logger = logging.getLogger(__name__)


@dataclass
class FileCheckpoint:
    """Offset and metadata tracking an individual log file position."""

    offset: int = 0
    inode: int = 0
    size: int = 0
    mtime: float = 0.0
    last_read_at: str | None = None


class CheckpointManager:
    """Thread-safe manager for persisting collector offsets across agent restarts."""

    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        set_secure_permissions(self.data_dir, is_dir=True)

        self.checkpoint_file = self.data_dir / "checkpoints.json"
        self._checkpoints: dict[str, dict[str, Any]] = self._load()

    def _load(self) -> dict[str, dict[str, Any]]:
        """Load checkpoints from disk."""
        if not self.checkpoint_file.is_file():
            return {}

        try:
            with open(self.checkpoint_file, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as exc:
            logger.warning(
                "Failed to parse checkpoint file at %s: %s. Starting with fresh offsets.",
                self.checkpoint_file,
                exc,
            )
        return {}

    def _save(self) -> None:
        """Atomically persist checkpoints to disk with restricted permissions."""
        content = json.dumps(self._checkpoints, indent=2)

        temp_fd, temp_path = tempfile.mkstemp(
            prefix="checkpoints_",
            suffix=".tmp",
            dir=str(self.data_dir),
        )
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                f.write(content)
            set_secure_permissions(Path(temp_path), is_dir=False)
            os.replace(temp_path, self.checkpoint_file)
            set_secure_permissions(self.checkpoint_file, is_dir=False)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

    def get_file_checkpoint(self, path: Path | str) -> FileCheckpoint:
        """Retrieve stored checkpoint for a given file path."""
        key = str(Path(path).resolve())
        data = self._checkpoints.get(key)
        if not data or not isinstance(data, dict):
            return FileCheckpoint()

        return FileCheckpoint(
            offset=int(data.get("offset", 0)),
            inode=int(data.get("inode", 0)),
            size=int(data.get("size", 0)),
            mtime=float(data.get("mtime", 0.0)),
            last_read_at=data.get("last_read_at"),
        )

    def update_file_checkpoint(
        self,
        path: Path | str,
        offset: int,
        inode: int,
        size: int,
        mtime: float,
    ) -> None:
        """Update and persist checkpoint for a log file."""
        key = str(Path(path).resolve())
        now = datetime.now(timezone.utc).isoformat()
        self._checkpoints[key] = asdict(
            FileCheckpoint(
                offset=offset,
                inode=inode,
                size=size,
                mtime=mtime,
                last_read_at=now,
            )
        )
        self._save()

    def get_cursor(self, source_id: str) -> str | None:
        """Retrieve stored string cursor (e.g. for systemd journald)."""
        data = self._checkpoints.get(source_id)
        if isinstance(data, dict):
            return data.get("cursor")
        return None

    def update_cursor(self, source_id: str, cursor: str) -> None:
        """Update and persist string cursor for a non-file source."""
        now = datetime.now(timezone.utc).isoformat()
        self._checkpoints[source_id] = {
            "cursor": cursor,
            "last_read_at": now,
        }
        self._save()

    def get_channel_checkpoint(self, channel: str) -> dict[str, Any] | None:
        """Retrieve stored checkpoint for a Windows event log channel."""
        key = f"windows_channel:{channel}"
        data = self._checkpoints.get(key)
        if isinstance(data, dict):
            return dict(data)
        return None

    def update_channel_checkpoint(
        self,
        channel: str,
        last_record_id: int,
        last_timestamp: str | None = None,
    ) -> None:
        """Update and persist record checkpoint for a Windows event channel."""
        key = f"windows_channel:{channel}"
        now = datetime.now(timezone.utc).isoformat()
        self._checkpoints[key] = {
            "channel": channel,
            "last_record_id": int(last_record_id),
            "last_timestamp": last_timestamp or now,
            "updated_at": now,
        }
        self._save()

    def clear_channel_checkpoint(self, channel: str) -> None:
        """Clear stored checkpoint for a Windows event channel (e.g. on log reset)."""
        key = f"windows_channel:{channel}"
        if key in self._checkpoints:
            del self._checkpoints[key]
            self._save()

    def inspect_file_rotation(
        self,
        path: Path | str,
        checkpoint: FileCheckpoint,
    ) -> tuple[int, bool, bool]:
        """Determine starting seek offset, detecting rotation and truncation.

        Returns (seek_offset, is_rotated, is_truncated).
        """
        resolved = Path(path).resolve()
        if not resolved.is_file():
            return 0, False, False

        try:
            stat = resolved.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size

            # Inode changed -> Log was rotated
            if checkpoint.inode > 0 and current_inode != checkpoint.inode:
                logger.info(
                    "Detected log rotation for %s (old inode %d -> new inode %d)",
                    resolved,
                    checkpoint.inode,
                    current_inode,
                )
                return 0, True, False

            # File size shrank below saved offset -> Log was truncated
            if current_size < checkpoint.offset:
                logger.warning(
                    "Detected file truncation for %s (size %d < offset %d)",
                    resolved,
                    current_size,
                    checkpoint.offset,
                )
                return 0, False, True

            return checkpoint.offset, False, False
        except OSError as exc:
            logger.warning("Failed to stat %s: %s", resolved, exc)
            return 0, False, False
