"""Linux authentication telemetry collector for auth.log, secure, and journald."""

from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from threatlens_agent.collectors.base import BaseCollector
from threatlens_agent.collectors.parsers.ssh import OpenSshLogParser
from threatlens_agent.models.events import Event
from threatlens_agent.storage.checkpoint import CheckpointManager

logger = logging.getLogger(__name__)

DEFAULT_CANDIDATE_PATHS = [
    Path("/var/log/auth.log"),
    Path("/var/log/secure"),
]

DEFAULT_JOURNAL_FILTERS: list[str] = [
    "_COMM=sshd",
    "+",
    "_COMM=sshd-session",
    "+",
    "SYSLOG_IDENTIFIER=sshd",
    "+",
    "SYSLOG_IDENTIFIER=sshd-session",
    "+",
    "SYSLOG_IDENTIFIER=ssh",
    "+",
    "_SYSTEMD_UNIT=ssh.service",
    "+",
    "_SYSTEMD_UNIT=sshd.service",
]


class LinuxAuthCollector(BaseCollector):
    """Incremental, non-destructive Linux authentication event collector."""

    def __init__(
        self,
        device_id: str,
        checkpoint_manager: CheckpointManager,
        candidate_paths: list[Path | str] | None = None,
        enable_journald: bool = True,
        default_year: int | None = None,
        journal_filters: list[str] | None = None,
        journal_batch_size: int = 100,
        auto_commit: bool = True,
    ) -> None:
        self.device_id = device_id
        self.checkpoint_manager = checkpoint_manager
        self.candidate_paths = [
            Path(p).expanduser().resolve()
            for p in (candidate_paths if candidate_paths is not None else DEFAULT_CANDIDATE_PATHS)
        ]
        self.enable_journald = enable_journald
        self.journal_filters = (
            list(journal_filters) if journal_filters is not None else DEFAULT_JOURNAL_FILTERS
        )
        self.journal_batch_size = max(1, min(journal_batch_size, 1000))
        self.auto_commit = auto_commit
        self.parser = OpenSshLogParser(device_id=device_id, default_year=default_year)

        self._active_sources: list[Path] = []
        self._journald_available: bool = False
        self._lines_read_count: dict[str, int] = {}
        self._diagnostics: dict[str, Any] = {}
        self._is_started: bool = False
        self._pending_journald_cursor: str | None = None
        self._pending_file_checkpoints: dict[Path, dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "linux_auth"

    def is_supported(self) -> bool:
        """Check whether the host operating system is Linux."""
        return platform.system() == "Linux"

    def start(self) -> None:
        """Discover available authentication sources on the host system."""
        self.discover_sources()
        self._is_started = True
        logger.info(
            "LinuxAuthCollector started. Active sources: %s, journald: %s",
            [str(p) for p in self._active_sources],
            self._journald_available,
        )

    def stop(self) -> None:
        """Stop collector."""
        self._is_started = False
        logger.info("LinuxAuthCollector stopped")

    def discover_sources(self) -> None:
        """Probe the host for readable log files and journald availability."""
        self._active_sources = []
        diagnostics: dict[str, Any] = {"files": {}, "journald": {}}

        # 1. Probe candidate log files
        for path in self.candidate_paths:
            path_str = str(path)
            diag_entry: dict[str, Any] = {
                "path": path_str,
                "exists": False,
                "readable": False,
                "status": "unavailable",
            }

            if not path.exists():
                diag_entry["status"] = "missing"
            elif not path.is_file():
                diag_entry["exists"] = True
                diag_entry["status"] = "not_a_regular_file"
            else:
                diag_entry["exists"] = True
                try:
                    with open(path, encoding="utf-8", errors="replace") as test_f:
                        # Try reading 1 byte to verify read permissions
                        test_f.read(1)
                    diag_entry["readable"] = True
                    diag_entry["status"] = "active"
                    self._active_sources.append(path)
                except PermissionError:
                    diag_entry["status"] = "permission_denied"
                    logger.debug("Permission denied opening %s", path)
                except OSError as exc:
                    diag_entry["status"] = f"error: {exc}"
                    logger.debug("OSError accessing %s: %s", path, exc)

            diagnostics["files"][path_str] = diag_entry

        # 2. Probe journalctl
        if self.enable_journald and shutil.which("journalctl") is not None:
            try:
                # Test journalctl execution with limited output using configured filters
                res = subprocess.run(
                    ["journalctl", *self.journal_filters, "-n", "1", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if res.returncode == 0:
                    # Check if user lacks privileges to read system journal
                    if "not seeing messages from other users" in res.stderr.lower():
                        self._journald_available = False
                        diagnostics["journald"] = {
                            "available": False,
                            "status": "permission_denied",
                            "error": "User lacks systemd-journal / adm group membership to access system logs",
                        }
                    else:
                        self._journald_available = True
                        diagnostics["journald"] = {
                            "available": True,
                            "status": "active" if not self._active_sources else "standby",
                        }
                else:
                    self._journald_available = False
                    diagnostics["journald"] = {
                        "available": False,
                        "status": "permission_denied"
                        if "denied" in res.stderr.lower()
                        else "failed",
                        "error": res.stderr.strip(),
                    }
            except Exception as exc:
                self._journald_available = False
                diagnostics["journald"] = {
                    "available": False,
                    "status": "error",
                    "error": str(exc),
                }
        else:
            self._journald_available = False
            diagnostics["journald"] = {
                "available": False,
                "status": "journalctl_not_installed" if self.enable_journald else "disabled",
            }

        self._diagnostics = diagnostics

    def get_diagnostics(self) -> dict[str, Any]:
        """Return operational health and discovery diagnostics for all sources."""
        active: list[str] = [str(p) for p in self._active_sources]
        if not self._active_sources and self._journald_available:
            active.append("journald")
        return {
            "collector": self.name,
            "supported": self.is_supported(),
            "active_sources": active,
            "journald_active": self._journald_available and not self._active_sources,
            "sources": self._diagnostics,
            "lines_read_total": sum(self._lines_read_count.values()),
        }

    def collect(self) -> list[Event]:
        """Read newly appended log lines from active sources and return parsed events."""
        if not self.is_supported():
            logger.debug("LinuxAuthCollector called on unsupported OS; skipping")
            return []

        if not self._is_started:
            self.start()

        # Re-probe sources if none currently active (e.g. log file newly created)
        if not self._active_sources:
            self.discover_sources()

        events: list[Event] = []

        # Read from active file sources
        for path in self._active_sources:
            path_events = self._collect_from_file(path)
            events.extend(path_events)

        # If no active files are readable, fallback to journald if available
        if not self._active_sources and self._journald_available:
            journal_events = self._collect_from_journald()
            events.extend(journal_events)

        if self.auto_commit:
            self.commit_checkpoints()

        return events

    def commit_checkpoints(self) -> None:
        """Persist pending checkpoints after events have been safely enqueued."""
        if self._pending_journald_cursor is not None:
            self.checkpoint_manager.update_cursor("journald", self._pending_journald_cursor)
            self._pending_journald_cursor = None

        for path, data in list(self._pending_file_checkpoints.items()):
            self.checkpoint_manager.update_file_checkpoint(
                path=path,
                offset=data["offset"],
                inode=data["inode"],
                size=data["size"],
                mtime=data["mtime"],
            )
        self._pending_file_checkpoints.clear()

    def _collect_from_file(self, path: Path) -> list[Event]:
        """Read incremental updates from a specific log file using checkpoints."""
        path_str = str(path)
        events: list[Event] = []

        if not path.is_file():
            return events

        checkpoint = self.checkpoint_manager.get_file_checkpoint(path)
        seek_offset, is_rotated, is_truncated = self.checkpoint_manager.inspect_file_rotation(
            path, checkpoint
        )

        try:
            stat = path.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size
            current_mtime = stat.st_mtime

            # If file has not grown and was not rotated, no new data to read
            if current_size == seek_offset and not is_rotated and not is_truncated:
                return events

            with open(path, encoding="utf-8", errors="replace") as f:
                if seek_offset > 0:
                    f.seek(seek_offset)

                lines_read = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    lines_read += 1
                    event = self.parser.parse_line(line)
                    if event is not None:
                        events.append(event)

                final_offset = f.tell()

            # Stage updated offset for two-phase commit
            self._pending_file_checkpoints[path] = {
                "offset": final_offset,
                "inode": current_inode,
                "size": current_size,
                "mtime": current_mtime,
            }
            self._lines_read_count[path_str] = self._lines_read_count.get(path_str, 0) + lines_read
            logger.debug(
                "Read %d lines from %s (offset %d -> %d), parsed %d events",
                lines_read,
                path.name,
                seek_offset,
                final_offset,
                len(events),
            )
        except PermissionError:
            logger.warning("Permission denied reading %s during collection", path)
        except OSError as exc:
            logger.warning("OSError reading %s: %s", path, exc)

        return events

    def _collect_from_journald(self) -> list[Event]:
        """Collect authentication records from systemd-journald."""
        events: list[Event] = []
        cursor = self.checkpoint_manager.get_cursor("journald")

        cmd = [
            "journalctl",
            "--no-pager",
            "-o",
            "json",
            "-n",
            str(self.journal_batch_size),
        ]
        if cursor:
            cmd.extend(["--after-cursor", cursor])
        cmd.extend(self.journal_filters)

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )

            # Check specifically for cursor seek failure (e.g. invalid cursor, corrupted or rotated journal)
            if res.returncode != 0 and cursor and "failed to seek to cursor" in res.stderr.lower():
                logger.warning(
                    "Stored journal cursor '%s' failed seeking (%s); attempting recovery without cursor",
                    cursor,
                    res.stderr.strip(),
                )
                fallback_cmd = [
                    "journalctl",
                    "--no-pager",
                    "-o",
                    "json",
                    "-n",
                    str(self.journal_batch_size),
                    *self.journal_filters,
                ]
                res = subprocess.run(
                    fallback_cmd,
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    check=False,
                )

            if res.returncode != 0:
                logger.debug(
                    "journalctl execution failed (code %d): %s", res.returncode, res.stderr.strip()
                )
                return events

            lines = res.stdout.splitlines()
            last_processed_cursor: str | None = None
            processed_lines_count = 0

            for line in lines:
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.debug("Malformed JSON line from journalctl: %s (err: %s)", line, exc)
                    continue

                processed_lines_count += 1
                entry_cursor = entry.get("__CURSOR")

                try:
                    ev = self.parser.parse_journal_entry(entry)
                    if ev is not None:
                        events.append(ev)
                    # Advance cursor tracking to this successfully processed entry
                    if entry_cursor:
                        last_processed_cursor = entry_cursor
                except Exception as exc:
                    logger.warning("Error parsing journal entry: %s", exc)
                    # Do not advance cursor past failed entry
                    break

            # Stage the checkpoint cursor up to the last successfully processed entry
            if last_processed_cursor:
                self._pending_journald_cursor = last_processed_cursor

            if processed_lines_count > 0:
                self._lines_read_count["journald"] = (
                    self._lines_read_count.get("journald", 0) + processed_lines_count
                )
        except Exception as exc:
            logger.debug("Error collecting from journald: %s", exc)

        return events
