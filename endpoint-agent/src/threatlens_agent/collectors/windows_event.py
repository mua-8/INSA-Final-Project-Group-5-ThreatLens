"""Windows Security Event Log and optional Sysmon telemetry collector."""

from __future__ import annotations

import collections
import logging
import platform
from typing import Any

from threatlens_agent.collectors.base import BaseCollector
from threatlens_agent.collectors.parsers.windows import SysmonEventParser, WindowsEventParser
from threatlens_agent.collectors.windows_adapter import (
    BaseWindowsEventAdapter,
    PowershellWindowsEventAdapter,
    SyntheticWindowsEventAdapter,
)
from threatlens_agent.models.events import Event
from threatlens_agent.storage.checkpoint import CheckpointManager

logger = logging.getLogger(__name__)

DEFAULT_SECURITY_EVENT_IDS = [4625, 4624, 4672, 4688]
DEFAULT_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class WindowsEventLogCollector(BaseCollector):
    """Incremental Windows Security Event Log and optional Sysmon telemetry collector."""

    def __init__(
        self,
        device_id: str,
        checkpoint_manager: CheckpointManager,
        adapter: BaseWindowsEventAdapter | None = None,
        channels: list[str] | None = None,
        enable_sysmon: bool = False,
        sysmon_channel: str = DEFAULT_SYSMON_CHANNEL,
        batch_size: int = 100,
        include_command_line: bool = False,
    ) -> None:
        self.device_id = device_id
        self.checkpoint_manager = checkpoint_manager
        self.adapter: BaseWindowsEventAdapter = adapter or PowershellWindowsEventAdapter()
        self.channels = list(channels if channels is not None else ["Security"])
        self.enable_sysmon = enable_sysmon
        self.sysmon_channel = sysmon_channel
        self.batch_size = max(1, min(batch_size, 1000))
        self.include_command_line = include_command_line

        self.parser = WindowsEventParser(
            device_id=device_id,
            include_command_line=include_command_line,
        )
        self.sysmon_parser = SysmonEventParser(
            device_id=device_id,
            include_command_line=include_command_line,
        )

        self._is_started: bool = False
        self._diagnostics: dict[str, Any] = {}
        self._events_collected_total: int = 0
        # In-memory deduplication cache for recent record identifiers
        self._recent_records: collections.deque[tuple[str, int]] = collections.deque(maxlen=1000)
        self._recent_records_set: set[tuple[str, int]] = set()

    @property
    def name(self) -> str:
        return "windows_event_log"

    def is_supported(self) -> bool:
        """Check whether the collector can run on the host system or with synthetic adapter."""
        if isinstance(self.adapter, SyntheticWindowsEventAdapter):
            return True
        return platform.system() == "Windows"

    def start(self) -> None:
        """Initialize collector and probe channel accessibility and permissions."""
        self._is_started = True
        self.discover_channels()
        logger.info(
            "WindowsEventLogCollector started. Channels: %s, Sysmon enabled: %s",
            self.channels,
            self.enable_sysmon,
        )

    def stop(self) -> None:
        """Stop collector."""
        self._is_started = False
        logger.info("WindowsEventLogCollector stopped")

    def discover_channels(self) -> dict[str, Any]:
        """Probe configured channels and optional Sysmon availability."""
        diag: dict[str, Any] = {
            "supported": self.is_supported(),
            "platform": platform.system(),
            "channels": {},
            "sysmon": {
                "enabled": self.enable_sysmon,
                "channel": self.sysmon_channel,
                "available": False,
                "readable": False,
                "status": "disabled" if not self.enable_sysmon else "probing",
            },
            "active_sources": [],
        }

        # 1. Probe Security and other configured channels
        for chan in self.channels:
            chan_diag: dict[str, Any] = {
                "channel": chan,
                "available": False,
                "readable": False,
                "status": "unavailable",
                "error": None,
                "last_record_id": None,
            }

            cp = self.checkpoint_manager.get_channel_checkpoint(chan)
            if cp:
                chan_diag["last_record_id"] = cp.get("last_record_id")

            if self.adapter.is_channel_available(chan):
                chan_diag["available"] = True
                permitted, reason = self.adapter.check_permissions(chan)
                if permitted:
                    chan_diag["readable"] = True
                    chan_diag["status"] = "active"
                    diag["active_sources"].append(chan)
                else:
                    chan_diag["status"] = "permission_denied"
                    chan_diag["error"] = reason
            else:
                chan_diag["status"] = "channel_not_found"

            diag["channels"][chan] = chan_diag

        # 2. Probe optional Sysmon channel if enabled
        if self.enable_sysmon:
            sysmon_available = self.adapter.is_channel_available(self.sysmon_channel)
            diag["sysmon"]["available"] = sysmon_available
            if sysmon_available:
                permitted, reason = self.adapter.check_permissions(self.sysmon_channel)
                if permitted:
                    diag["sysmon"]["readable"] = True
                    diag["sysmon"]["status"] = "active"
                    diag["active_sources"].append(self.sysmon_channel)
                else:
                    diag["sysmon"]["status"] = "permission_denied"
                    diag["sysmon"]["error"] = reason
            else:
                diag["sysmon"]["status"] = "channel_not_found"

        self._diagnostics = diag
        return diag

    def collect(self) -> list[Event]:
        """Poll and return newly observed normalized Windows events."""
        if not self._is_started:
            self.start()

        events: list[Event] = []

        # 1. Collect from configured Windows channels (Security)
        for channel in self.channels:
            try:
                chan_events = self._collect_channel(
                    channel=channel,
                    event_ids=DEFAULT_SECURITY_EVENT_IDS,
                    parser=self.parser,
                )
                events.extend(chan_events)
            except Exception as exc:
                logger.warning("Error collecting from channel '%s': %s", channel, exc)
                if channel in self._diagnostics.get("channels", {}):
                    self._diagnostics["channels"][channel]["error"] = str(exc)

        # 2. Collect from optional Sysmon channel if enabled and active
        if self.enable_sysmon:
            try:
                sysmon_events = self._collect_channel(
                    channel=self.sysmon_channel,
                    event_ids=[1, 3],
                    parser=self.sysmon_parser,
                )
                events.extend(sysmon_events)
            except Exception as exc:
                logger.warning("Error collecting from Sysmon channel: %s", exc)
                self._diagnostics["sysmon"]["error"] = str(exc)

        self._events_collected_total += len(events)
        return events

    def _collect_channel(
        self,
        channel: str,
        event_ids: list[int],
        parser: WindowsEventParser | SysmonEventParser,
    ) -> list[Event]:
        """Query and normalize incremental events for a specific channel."""
        # Check permissions and availability first
        if not self.adapter.is_channel_available(channel):
            logger.debug("Channel '%s' is not available on host", channel)
            return []

        permitted, reason = self.adapter.check_permissions(channel)
        if not permitted:
            logger.warning(
                "Access denied collecting from Windows channel '%s': %s",
                channel,
                reason,
            )
            return []

        # Retrieve saved checkpoint
        checkpoint = self.checkpoint_manager.get_channel_checkpoint(channel)
        last_record_id: int | None = None
        if checkpoint:
            last_record_id = checkpoint.get("last_record_id")

        # Query batch from adapter
        raw_records = self.adapter.query_events(
            channel=channel,
            event_ids=event_ids,
            after_record_id=last_record_id,
            max_events=self.batch_size,
        )

        # Discontinuity / log clearing detection:
        # If query returned empty but we have a saved checkpoint, check whether current channel
        # records exist with lower IDs (e.g. log was cleared and wrapped to 1).
        if not raw_records and last_record_id is not None:
            probe_records = self.adapter.query_events(
                channel=channel,
                event_ids=event_ids,
                after_record_id=None,
                max_events=self.batch_size,
            )
            if probe_records:
                probe_max = max(
                    int(r.get("RecordId") or r.get("EventRecordID") or 0) for r in probe_records
                )
                if probe_max < last_record_id:
                    logger.warning(
                        "Detected Windows Event Log clearing/discontinuity on '%s' "
                        "(checkpoint was %d, current max is %d). Resetting checkpoint.",
                        channel,
                        last_record_id,
                        probe_max,
                    )
                    self.checkpoint_manager.clear_channel_checkpoint(channel)
                    last_record_id = None
                    raw_records = probe_records

        if not raw_records:
            return []

        # Additional check: If query returned records whose IDs are smaller than checkpoint
        record_ids = [
            int(r.get("RecordId") or r.get("EventRecordID") or 0)
            for r in raw_records
            if (r.get("RecordId") or r.get("EventRecordID")) is not None
        ]

        if last_record_id is not None and record_ids:
            max_observed = max(record_ids)
            if max_observed < last_record_id:
                logger.warning(
                    "Detected Windows Event Log clearing/discontinuity on '%s' "
                    "(checkpoint was %d, current max is %d). Resetting checkpoint.",
                    channel,
                    last_record_id,
                    max_observed,
                )
                self.checkpoint_manager.clear_channel_checkpoint(channel)
                last_record_id = None

        normalized_events: list[Event] = []
        highest_record_id = last_record_id or 0

        for raw_rec in raw_records:
            rec_id = int(raw_rec.get("RecordId") or raw_rec.get("EventRecordID") or 0)

            # In-memory duplicate filter
            dedup_key = (channel, rec_id)
            if rec_id > 0 and dedup_key in self._recent_records_set:
                logger.debug("Skipping already processed record %s:%d", channel, rec_id)
                continue

            event = parser.parse(raw_rec)
            if event is not None:
                normalized_events.append(event)
                if rec_id > 0:
                    if len(self._recent_records) >= self._recent_records.maxlen:
                        oldest = self._recent_records.popleft()
                        self._recent_records_set.discard(oldest)
                    self._recent_records.append(dedup_key)
                    self._recent_records_set.add(dedup_key)

            if rec_id > highest_record_id:
                highest_record_id = rec_id

        # Persist updated checkpoint
        if highest_record_id > (last_record_id or 0):
            self.checkpoint_manager.update_channel_checkpoint(
                channel=channel,
                last_record_id=highest_record_id,
            )
            if channel in self._diagnostics.get("channels", {}):
                self._diagnostics["channels"][channel]["last_record_id"] = highest_record_id

        return normalized_events

    def get_diagnostics(self) -> dict[str, Any]:
        """Return operational diagnostics for CLI and health reporting."""
        if not self._diagnostics:
            self.discover_channels()

        diag = dict(self._diagnostics)
        diag["events_collected_total"] = self._events_collected_total
        return diag
