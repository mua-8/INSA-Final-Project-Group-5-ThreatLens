"""Core ThreatLens Agent lifecycle coordinator and health monitor."""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from threatlens_agent import __version__
from threatlens_agent.collectors.base import BaseCollector
from threatlens_agent.collectors.file_monitor import LinuxFileMonitorCollector
from threatlens_agent.collectors.linux_auth import LinuxAuthCollector
from threatlens_agent.collectors.windows_event import WindowsEventLogCollector
from threatlens_agent.config import AgentConfig
from threatlens_agent.detection.base import BaseDetector
from threatlens_agent.detection.ssh_bruteforce import SshBruteForceDetector
from threatlens_agent.models.device import DeviceInfo
from threatlens_agent.models.events import Event
from threatlens_agent.storage.checkpoint import CheckpointManager
from threatlens_agent.storage.queue import EventQueue, QueueStats
from threatlens_agent.storage.state import StateManager
from threatlens_agent.transport.base import BaseTransport
from threatlens_agent.transport.http import HttpTransport

logger = logging.getLogger(__name__)


def setup_logging(level_name: str = "INFO") -> None:
    """Configure structured, clean standard logging without secret leakage."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%dT%H:%M:%SZ")

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers on re-initialization
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        root.addHandler(handler)


@dataclass
class AgentHealth:
    """Detailed health and status report of the endpoint agent."""

    healthy: bool
    device_id: str
    hostname: str
    agent_version: str
    uptime_seconds: float
    queue_stats: QueueStats
    transport_available: bool
    last_flush_at: str | None = None
    last_transport_error: str | None = None
    collector_diagnostics: dict[str, Any] = field(default_factory=dict)
    total_detections_emitted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "agent_version": self.agent_version,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "queue": self.queue_stats.to_dict(),
            "transport_available": self.transport_available,
            "last_flush_at": self.last_flush_at,
            "last_transport_error": self.last_transport_error,
            "collector_diagnostics": self.collector_diagnostics,
            "total_detections_emitted": self.total_detections_emitted,
        }


class ThreatLensAgent:
    """Central agent coordinator managing storage, transport, and event dispatch."""

    def __init__(
        self,
        config: AgentConfig,
        transport: BaseTransport | None = None,
        collectors: list[BaseCollector] | None = None,
        detectors: list[BaseDetector] | None = None,
    ) -> None:
        self.config = config
        self.config.validate()

        self._start_time = time.time()
        self.last_flush_at: str | None = None
        self.last_transport_error: str | None = None
        self._total_detections_emitted: int = 0

        # 1. Initialize State, Checkpoints, and Device Identity
        self.state_manager = StateManager(self.config.get_data_dir_path())
        self.device_info: DeviceInfo = self.state_manager.get_or_create_device_info()
        self.checkpoint_manager = CheckpointManager(self.config.get_data_dir_path())

        # 2. Initialize Durable Queue
        db_path = self.config.get_data_dir_path() / "events_queue.db"
        self.queue = EventQueue(db_path, config=self.config.queue)

        # 3. Initialize Transport
        if transport is not None:
            self.transport = transport
        else:
            self.transport = HttpTransport(
                self.config.transport,
                device_id=self.device_info.device_id,
            )

        # 4. Initialize Collectors
        if collectors is not None:
            self.collectors: list[BaseCollector] = list(collectors)
        else:
            self.collectors = []
            if self.device_info.os_family == "linux":
                enabled_cols = self.config.monitoring.enabled_collectors
                if not enabled_cols or "linux_auth" in enabled_cols:
                    collector = LinuxAuthCollector(
                        device_id=self.device_info.device_id,
                        checkpoint_manager=self.checkpoint_manager,
                        candidate_paths=self.config.monitoring.linux.candidate_paths,
                        enable_journald=self.config.monitoring.linux.enable_journald,
                        auto_commit=False,
                    )
                    self.collectors.append(collector)
                if self.config.monitoring.file_monitor.enabled:
                    if not enabled_cols or "file_monitor" in enabled_cols:
                        file_collector = LinuxFileMonitorCollector(
                            device_id=self.device_info.device_id,
                            config=self.config.monitoring.file_monitor,
                            hostname=self.device_info.hostname,
                        )
                        self.collectors.append(file_collector)
            elif self.device_info.os_family == "windows":
                enabled_cols = self.config.monitoring.enabled_collectors
                if not enabled_cols or "windows_event_log" in enabled_cols:
                    if self.config.monitoring.windows.enabled:
                        collector = WindowsEventLogCollector(
                            device_id=self.device_info.device_id,
                            checkpoint_manager=self.checkpoint_manager,
                            channels=self.config.monitoring.windows.channels,
                            enable_sysmon=self.config.monitoring.windows.enable_sysmon,
                            sysmon_channel=self.config.monitoring.windows.sysmon_channel,
                            batch_size=self.config.monitoring.windows.batch_size,
                            include_command_line=self.config.monitoring.windows.include_command_line,
                        )
                        self.collectors.append(collector)

        # 5. Initialize Detectors
        if detectors is not None:
            self.detectors: list[BaseDetector] = list(detectors)
        else:
            self.detectors = []
            if self.config.detection.ssh_bruteforce.enabled:
                self.detectors.append(
                    SshBruteForceDetector(
                        threshold=self.config.detection.ssh_bruteforce.threshold,
                        window_seconds=self.config.detection.ssh_bruteforce.window_seconds,
                        coalesce_window_seconds=self.config.detection.ssh_bruteforce.coalesce_window_seconds,
                    )
                )

        # Start supported collectors
        for c in self.collectors:
            if c.is_supported():
                try:
                    c.start()
                except Exception as exc:
                    logger.warning("Failed to start collector %s: %s", c.name, exc)

        logger.info(
            "ThreatLens Agent v%s initialized (device_id: %s, queue_db: %s, collectors: %d)",
            __version__,
            self.device_info.device_id,
            db_path.name,
            len(self.collectors),
        )

    def record_event(self, event: Event) -> bool:
        """Enqueue an event into durable storage."""
        return self.queue.enqueue(event)

    def record_events(self, events: list[Event]) -> int:
        """Enqueue multiple events into durable storage."""
        return self.queue.enqueue_batch(events)

    def flush(self, limit: int | None = None) -> int:
        """Retrieve a pending batch from queue and transmit to backend.

        Returns the number of events successfully transmitted and acknowledged.
        """
        batch_limit = limit or self.config.batch_size
        batch = self.queue.get_pending_batch(limit=batch_limit, mark_in_flight=True)
        if not batch:
            return 0

        logger.debug("Dispatching batch of %d events to transport", len(batch))

        if not self.transport.is_available():
            msg = "Transport is not configured or unavailable"
            self.last_transport_error = msg
            logger.debug(msg)
            self.queue.mark_failed([e.event_id for e in batch], error_message=msg)
            return 0

        result = self.transport.send_batch(batch)

        if result.success:
            self.last_flush_at = datetime.now(timezone.utc).isoformat()
            self.last_transport_error = None

            # Mark acknowledged events as delivered
            acked_set = set(result.acknowledged_event_ids)
            if acked_set:
                self.queue.mark_delivered(list(acked_set))

            # If only some events were acknowledged, return the rest to pending
            unacked = [e.event_id for e in batch if e.event_id not in acked_set]
            if unacked:
                logger.warning(
                    "%d events in batch were not acknowledged by server; returning to pending",
                    len(unacked),
                )
                self.queue.mark_failed(unacked, error_message="Unacknowledged by server")

            return len(acked_set)
        else:
            self.last_transport_error = result.error_message
            logger.warning("Event batch transmission failed: %s", result.error_message)
            self.queue.mark_failed([e.event_id for e in batch], error_message=result.error_message)
            return 0

    def collect_and_detect(self) -> tuple[int, int]:
        """Execute one round of telemetry collection and local threat detection.

        Returns a tuple of (events_collected, detections_triggered).
        """
        all_collected: list[Event] = []
        for collector in self.collectors:
            if not collector.is_supported():
                continue
            try:
                events = collector.collect()
                if events:
                    all_collected.extend(events)
            except Exception as exc:
                logger.error(
                    "Error during collection with %s: %s",
                    collector.name,
                    exc,
                    exc_info=True,
                )

        if all_collected:
            enqueued_count = self.record_events(all_collected)
            if enqueued_count == len(all_collected):
                for collector in self.collectors:
                    if hasattr(collector, "commit_checkpoints") and callable(
                        collector.commit_checkpoints
                    ):
                        collector.commit_checkpoints()
            else:
                logger.warning(
                    "Enqueued %d of %d collected events; withholding checkpoint commit",
                    enqueued_count,
                    len(all_collected),
                )
        else:
            for collector in self.collectors:
                if hasattr(collector, "commit_checkpoints") and callable(
                    collector.commit_checkpoints
                ):
                    collector.commit_checkpoints()

        all_detections: list[Event] = []
        if all_collected and self.detectors:
            for detector in self.detectors:
                try:
                    detections = detector.analyze(all_collected)
                    if detections:
                        all_detections.extend(detections)
                except Exception as exc:
                    logger.error(
                        "Error running detector %s: %s",
                        detector.name,
                        exc,
                        exc_info=True,
                    )

        if all_detections:
            self.record_events(all_detections)
            self._total_detections_emitted += len(all_detections)
            logger.warning("Emitted %d local threat detection events", len(all_detections))

        return len(all_collected), len(all_detections)

    def get_health(self) -> AgentHealth:
        """Compute health snapshot of agent subsystems."""
        stats = self.queue.get_stats()
        uptime = time.time() - self._start_time

        # Gather collector diagnostics
        diagnostics: dict[str, Any] = {}
        for c in self.collectors:
            if hasattr(c, "get_diagnostics") and callable(c.get_diagnostics):
                diagnostics[c.name] = c.get_diagnostics()
            else:
                diagnostics[c.name] = {"supported": c.is_supported()}

        is_healthy = True

        return AgentHealth(
            healthy=is_healthy,
            device_id=self.device_info.device_id,
            hostname=self.device_info.hostname,
            agent_version=__version__,
            uptime_seconds=uptime,
            queue_stats=stats,
            transport_available=self.transport.is_available(),
            last_flush_at=self.last_flush_at,
            last_transport_error=self.last_transport_error,
            collector_diagnostics=diagnostics,
            total_detections_emitted=self._total_detections_emitted,
        )

    def close(self) -> None:
        """Safely close collectors, storage, and transport resources."""
        for c in self.collectors:
            try:
                c.stop()
            except Exception as exc:
                logger.debug("Error stopping collector %s: %s", c.name, exc)
        self.queue.close()
        self.transport.close()
        logger.info("ThreatLens Agent shut down gracefully")
