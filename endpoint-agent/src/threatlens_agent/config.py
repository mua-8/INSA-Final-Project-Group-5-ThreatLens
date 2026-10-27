"""Configuration management and validation for ThreatLens Endpoint Agent."""

from __future__ import annotations

import os
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from threatlens_agent import __version__

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
VALID_RETENTION_POLICIES = {"delete_on_delivery", "retain_delivered"}


class ConfigValidationError(ValueError):
    """Raised when configuration validation fails with actionable error messages."""

    def __init__(self, message: str, field_name: str | None = None) -> None:
        super().__init__(message)
        self.field_name = field_name


@dataclass
class QueueConfig:
    """Queue sizing, retention, and storage limits."""

    max_events: int = 50_000
    max_disk_mb: int = 500
    retention_policy: str = "delete_on_delivery"

    def validate(self) -> None:
        if not isinstance(self.max_events, int) or self.max_events <= 0:
            raise ConfigValidationError(
                f"queue.max_events must be a positive integer, got: {self.max_events}",
                field_name="queue.max_events",
            )
        if not isinstance(self.max_disk_mb, int) or self.max_disk_mb <= 0:
            raise ConfigValidationError(
                f"queue.max_disk_mb must be a positive integer, got: {self.max_disk_mb}",
                field_name="queue.max_disk_mb",
            )
        if self.retention_policy not in VALID_RETENTION_POLICIES:
            raise ConfigValidationError(
                f"queue.retention_policy must be one of {sorted(VALID_RETENTION_POLICIES)}, "
                f"got: '{self.retention_policy}'",
                field_name="queue.retention_policy",
            )


@dataclass
class TransportConfig:
    """Network connection, timeout, and bounded retry settings."""

    backend_url: str | None = None
    events_endpoint: str = "/api/v1/events"
    api_key: str | None = None
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 30.0
    max_retries: int = 5
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 60.0
    jitter_ratio: float = 0.2
    tls_verify: bool = True
    ca_bundle: str | None = None

    def validate(self) -> None:
        if self.backend_url is not None:
            if not isinstance(self.backend_url, str) or not self.backend_url.strip():
                raise ConfigValidationError(
                    "transport.backend_url must be a non-empty string or null",
                    field_name="transport.backend_url",
                )
            parsed = urlparse(self.backend_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ConfigValidationError(
                    f"transport.backend_url must be a valid HTTP/HTTPS URL, got: '{self.backend_url}'",
                    field_name="transport.backend_url",
                )

        if not isinstance(self.events_endpoint, str) or not self.events_endpoint.startswith("/"):
            raise ConfigValidationError(
                f"transport.events_endpoint must start with '/', got: '{self.events_endpoint}'",
                field_name="transport.events_endpoint",
            )

        if (
            not isinstance(self.connect_timeout_seconds, (int, float))
            or self.connect_timeout_seconds <= 0
        ):
            raise ConfigValidationError(
                f"transport.connect_timeout_seconds must be a positive number, got: {self.connect_timeout_seconds}",
                field_name="transport.connect_timeout_seconds",
            )

        if (
            not isinstance(self.read_timeout_seconds, (int, float))
            or self.read_timeout_seconds <= 0
        ):
            raise ConfigValidationError(
                f"transport.read_timeout_seconds must be a positive number, got: {self.read_timeout_seconds}",
                field_name="transport.read_timeout_seconds",
            )

        if not isinstance(self.max_retries, int) or self.max_retries < 0 or self.max_retries > 50:
            raise ConfigValidationError(
                f"transport.max_retries must be an integer between 0 and 50, got: {self.max_retries}",
                field_name="transport.max_retries",
            )

        if (
            not isinstance(self.backoff_base_seconds, (int, float))
            or self.backoff_base_seconds <= 0
        ):
            raise ConfigValidationError(
                f"transport.backoff_base_seconds must be a positive number, got: {self.backoff_base_seconds}",
                field_name="transport.backoff_base_seconds",
            )

        if (
            not isinstance(self.backoff_max_seconds, (int, float))
            or self.backoff_max_seconds < self.backoff_base_seconds
        ):
            raise ConfigValidationError(
                f"transport.backoff_max_seconds must be >= backoff_base_seconds ({self.backoff_base_seconds}), "
                f"got: {self.backoff_max_seconds}",
                field_name="transport.backoff_max_seconds",
            )

        if not isinstance(self.jitter_ratio, (int, float)) or not (0.0 <= self.jitter_ratio <= 1.0):
            raise ConfigValidationError(
                f"transport.jitter_ratio must be between 0.0 and 1.0, got: {self.jitter_ratio}",
                field_name="transport.jitter_ratio",
            )

        if self.ca_bundle is not None:
            ca_path = Path(self.ca_bundle).expanduser()
            if not ca_path.is_file():
                raise ConfigValidationError(
                    f"transport.ca_bundle specified but file does not exist: {self.ca_bundle}",
                    field_name="transport.ca_bundle",
                )


@dataclass
class LinuxCollectorConfig:
    """Settings for Linux authentication log collection."""

    candidate_paths: list[str] = field(
        default_factory=lambda: ["/var/log/auth.log", "/var/log/secure"]
    )
    enable_journald: bool = True

    def validate(self) -> None:
        if not isinstance(self.candidate_paths, list):
            raise ConfigValidationError(
                f"monitoring.linux.candidate_paths must be a list, got: {type(self.candidate_paths).__name__}",
                field_name="monitoring.linux.candidate_paths",
            )
        if not isinstance(self.enable_journald, bool):
            raise ConfigValidationError(
                f"monitoring.linux.enable_journald must be a boolean, got: {self.enable_journald}",
                field_name="monitoring.linux.enable_journald",
            )


@dataclass
class WindowsCollectorConfig:
    """Settings for Windows Security Event Log and optional Sysmon collection."""

    enabled: bool = True
    channels: list[str] = field(default_factory=lambda: ["Security"])
    enable_sysmon: bool = False
    sysmon_channel: str = "Microsoft-Windows-Sysmon/Operational"
    batch_size: int = 100
    poll_interval_seconds: float = 10.0
    include_command_line: bool = False

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigValidationError(
                f"monitoring.windows.enabled must be a boolean, got: {self.enabled}",
                field_name="monitoring.windows.enabled",
            )
        if not isinstance(self.channels, list) or not all(
            isinstance(c, str) for c in self.channels
        ):
            raise ConfigValidationError(
                f"monitoring.windows.channels must be a list of channel strings, got: {self.channels}",
                field_name="monitoring.windows.channels",
            )
        if not isinstance(self.enable_sysmon, bool):
            raise ConfigValidationError(
                f"monitoring.windows.enable_sysmon must be a boolean, got: {self.enable_sysmon}",
                field_name="monitoring.windows.enable_sysmon",
            )
        if not isinstance(self.sysmon_channel, str) or not self.sysmon_channel.strip():
            raise ConfigValidationError(
                f"monitoring.windows.sysmon_channel must be a non-empty string, got: {self.sysmon_channel}",
                field_name="monitoring.windows.sysmon_channel",
            )
        if not isinstance(self.batch_size, int) or not (1 <= self.batch_size <= 1000):
            raise ConfigValidationError(
                f"monitoring.windows.batch_size must be an integer between 1 and 1000, got: {self.batch_size}",
                field_name="monitoring.windows.batch_size",
            )
        if (
            not isinstance(self.poll_interval_seconds, (int, float))
            or self.poll_interval_seconds <= 0
        ):
            raise ConfigValidationError(
                f"monitoring.windows.poll_interval_seconds must be a positive number, got: {self.poll_interval_seconds}",
                field_name="monitoring.windows.poll_interval_seconds",
            )
        if not isinstance(self.include_command_line, bool):
            raise ConfigValidationError(
                f"monitoring.windows.include_command_line must be a boolean, got: {self.include_command_line}",
                field_name="monitoring.windows.include_command_line",
            )


@dataclass
class SshBruteForceConfig:
    """Threshold and sliding window settings for SSH brute-force detection."""

    enabled: bool = True
    threshold: int = 5
    window_seconds: int = 120
    coalesce_window_seconds: float = 2.0

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigValidationError(
                f"detection.ssh_bruteforce.enabled must be a boolean, got: {self.enabled}",
                field_name="detection.ssh_bruteforce.enabled",
            )
        if not isinstance(self.threshold, int) or self.threshold <= 0:
            raise ConfigValidationError(
                f"detection.ssh_bruteforce.threshold must be a positive integer, got: {self.threshold}",
                field_name="detection.ssh_bruteforce.threshold",
            )
        if not isinstance(self.window_seconds, int) or self.window_seconds <= 0:
            raise ConfigValidationError(
                f"detection.ssh_bruteforce.window_seconds must be a positive integer, got: {self.window_seconds}",
                field_name="detection.ssh_bruteforce.window_seconds",
            )
        if (
            not isinstance(self.coalesce_window_seconds, (int, float))
            or self.coalesce_window_seconds < 0
        ):
            raise ConfigValidationError(
                f"detection.ssh_bruteforce.coalesce_window_seconds must be non-negative, got: {self.coalesce_window_seconds}",
                field_name="detection.ssh_bruteforce.coalesce_window_seconds",
            )


@dataclass
class DetectionConfig:
    """Local heuristic and anomaly detection configuration."""

    ssh_bruteforce: SshBruteForceConfig = field(default_factory=SshBruteForceConfig)

    def validate(self) -> None:
        self.ssh_bruteforce.validate()


@dataclass
class FileMonitorConfig:
    """Settings for Linux file-system monitoring collector."""

    enabled: bool = False
    monitored_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    excluded_extensions: list[str] = field(default_factory=list)
    recursive: bool = False
    max_events_per_poll: int = 500
    follow_symlinks: bool = False  # Strictly False per safety policy

    def validate(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigValidationError(
                f"monitoring.file_monitor.enabled must be a boolean, got: {self.enabled}",
                field_name="monitoring.file_monitor.enabled",
            )
        if not isinstance(self.monitored_paths, list):
            raise ConfigValidationError(
                f"monitoring.file_monitor.monitored_paths must be a list of paths, got: {type(self.monitored_paths).__name__}",
                field_name="monitoring.file_monitor.monitored_paths",
            )
        for p in self.monitored_paths:
            if not isinstance(p, str) or not p.strip():
                raise ConfigValidationError(
                    "monitoring.file_monitor.monitored_paths entries must be non-empty strings",
                    field_name="monitoring.file_monitor.monitored_paths",
                )
        if not isinstance(self.excluded_paths, list):
            raise ConfigValidationError(
                f"monitoring.file_monitor.excluded_paths must be a list, got: {type(self.excluded_paths).__name__}",
                field_name="monitoring.file_monitor.excluded_paths",
            )
        if not isinstance(self.excluded_extensions, list):
            raise ConfigValidationError(
                f"monitoring.file_monitor.excluded_extensions must be a list, got: {type(self.excluded_extensions).__name__}",
                field_name="monitoring.file_monitor.excluded_extensions",
            )
        if not isinstance(self.recursive, bool):
            raise ConfigValidationError(
                f"monitoring.file_monitor.recursive must be a boolean, got: {self.recursive}",
                field_name="monitoring.file_monitor.recursive",
            )
        if not isinstance(self.max_events_per_poll, int) or self.max_events_per_poll <= 0:
            raise ConfigValidationError(
                f"monitoring.file_monitor.max_events_per_poll must be a positive integer, got: {self.max_events_per_poll}",
                field_name="monitoring.file_monitor.max_events_per_poll",
            )


@dataclass
class MonitoringConfig:
    """Monitoring and telemetry collection settings."""

    heartbeat_interval_seconds: int = 60
    enabled_collectors: list[str] = field(default_factory=list)
    linux: LinuxCollectorConfig = field(default_factory=LinuxCollectorConfig)
    windows: WindowsCollectorConfig = field(default_factory=WindowsCollectorConfig)
    file_monitor: FileMonitorConfig = field(default_factory=FileMonitorConfig)

    def validate(self) -> None:
        if (
            not isinstance(self.heartbeat_interval_seconds, int)
            or self.heartbeat_interval_seconds <= 0
        ):
            raise ConfigValidationError(
                f"monitoring.heartbeat_interval_seconds must be a positive integer, got: {self.heartbeat_interval_seconds}",
                field_name="monitoring.heartbeat_interval_seconds",
            )
        if not isinstance(self.enabled_collectors, list):
            raise ConfigValidationError(
                f"monitoring.enabled_collectors must be a list of collector names, got: {type(self.enabled_collectors).__name__}",
                field_name="monitoring.enabled_collectors",
            )
        self.linux.validate()
        self.windows.validate()
        self.file_monitor.validate()


@dataclass
class AgentConfig:
    """Top-level agent configuration."""

    display_name: str = field(default_factory=lambda: socket.gethostname())
    version: str = __version__
    data_dir: str = "data"
    log_level: str = "INFO"
    batch_size: int = 100
    queue: QueueConfig = field(default_factory=QueueConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)

    def get_data_dir_path(self) -> Path:
        """Resolve expanded absolute path for local data directory."""
        return Path(self.data_dir).expanduser().resolve()

    def validate(self) -> None:
        """Validate entire configuration tree and raise actionable ConfigValidationError."""
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ConfigValidationError(
                "display_name must be a non-empty string",
                field_name="display_name",
            )

        if not isinstance(self.version, str) or not self.version.strip():
            raise ConfigValidationError(
                "version must be a non-empty string",
                field_name="version",
            )

        if not isinstance(self.data_dir, str) or not self.data_dir.strip():
            raise ConfigValidationError(
                "data_dir must be a non-empty path string",
                field_name="data_dir",
            )

        upper_level = self.log_level.upper() if isinstance(self.log_level, str) else None
        if upper_level not in VALID_LOG_LEVELS:
            raise ConfigValidationError(
                f"log_level must be one of {sorted(VALID_LOG_LEVELS)}, got: '{self.log_level}'",
                field_name="log_level",
            )
        self.log_level = upper_level

        if not isinstance(self.batch_size, int) or not (1 <= self.batch_size <= 1000):
            raise ConfigValidationError(
                f"batch_size must be an integer between 1 and 1000, got: {self.batch_size}",
                field_name="batch_size",
            )

        self.queue.validate()
        self.transport.validate()
        self.monitoring.validate()
        self.detection.validate()

    def to_dict(self, mask_secrets: bool = True) -> dict[str, Any]:
        """Convert configuration to dictionary, optionally masking sensitive fields."""
        data = asdict(self)
        if mask_secrets and self.transport.api_key:
            data["transport"]["api_key"] = "********"
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AgentConfig:
        """Instantiate AgentConfig from raw dictionary, validating nested structures."""
        if not isinstance(raw, dict):
            raise ConfigValidationError("Configuration root must be a mapping/dictionary")

        queue_data = raw.get("queue") or {}
        transport_data = raw.get("transport") or {}
        monitoring_data = raw.get("monitoring") or {}
        detection_data = raw.get("detection") or {}

        if not isinstance(queue_data, dict):
            raise ConfigValidationError(
                f"'queue' must be a dictionary, got: {type(queue_data).__name__}",
                field_name="queue",
            )
        if not isinstance(transport_data, dict):
            raise ConfigValidationError(
                f"'transport' must be a dictionary, got: {type(transport_data).__name__}",
                field_name="transport",
            )
        if not isinstance(monitoring_data, dict):
            raise ConfigValidationError(
                f"'monitoring' must be a dictionary, got: {type(monitoring_data).__name__}",
                field_name="monitoring",
            )
        if not isinstance(detection_data, dict):
            raise ConfigValidationError(
                f"'detection' must be a dictionary, got: {type(detection_data).__name__}",
                field_name="detection",
            )

        # Disallow unknown root keys
        known_root_keys = {
            "display_name",
            "version",
            "data_dir",
            "log_level",
            "batch_size",
            "queue",
            "transport",
            "monitoring",
            "detection",
        }
        unknown_keys = set(raw.keys()) - known_root_keys
        if unknown_keys:
            raise ConfigValidationError(
                f"Unknown configuration key(s): {', '.join(sorted(unknown_keys))}"
            )

        # Parse nested monitoring config
        monitoring_kwargs = dict(monitoring_data)
        if "linux" in monitoring_kwargs and isinstance(monitoring_kwargs["linux"], dict):
            monitoring_kwargs["linux"] = LinuxCollectorConfig(**monitoring_kwargs["linux"])
        if "windows" in monitoring_kwargs and isinstance(monitoring_kwargs["windows"], dict):
            monitoring_kwargs["windows"] = WindowsCollectorConfig(**monitoring_kwargs["windows"])

        # Parse nested detection config
        detection_kwargs = dict(detection_data)
        if "ssh_bruteforce" in detection_kwargs and isinstance(
            detection_kwargs["ssh_bruteforce"], dict
        ):
            detection_kwargs["ssh_bruteforce"] = SshBruteForceConfig(
                **detection_kwargs["ssh_bruteforce"]
            )

        cfg = cls(
            display_name=raw.get("display_name", socket.gethostname()),
            version=raw.get("version", __version__),
            data_dir=raw.get("data_dir", "data"),
            log_level=raw.get("log_level", "INFO"),
            batch_size=raw.get("batch_size", 100),
            queue=QueueConfig(**queue_data),
            transport=TransportConfig(**transport_data),
            monitoring=MonitoringConfig(**monitoring_kwargs),
            detection=DetectionConfig(**detection_kwargs),
        )
        cfg.validate()
        return cfg

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> AgentConfig:
        """Load configuration from YAML file and apply environment variable overrides."""
        raw: dict[str, Any] = {}

        # 1. Resolve path from argument or env var
        resolved_path = config_path or os.getenv("THREATLENS_CONFIG_PATH")
        if resolved_path:
            p = Path(resolved_path).expanduser().resolve()
            if not p.is_file():
                raise ConfigValidationError(f"Configuration file not found: {p}")
            try:
                with open(p, encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if loaded is not None:
                        if not isinstance(loaded, dict):
                            raise ConfigValidationError(
                                f"Configuration file must contain a YAML mapping: {p}"
                            )
                        raw = loaded
            except yaml.YAMLError as exc:
                raise ConfigValidationError(f"Malformed YAML in {p}: {exc}") from exc

        # 2. Merge Environment Overrides
        if "THREATLENS_DATA_DIR" in os.environ:
            raw["data_dir"] = os.environ["THREATLENS_DATA_DIR"]
        if "THREATLENS_LOG_LEVEL" in os.environ:
            raw["log_level"] = os.environ["THREATLENS_LOG_LEVEL"]
        if "THREATLENS_BACKEND_URL" in os.environ:
            raw.setdefault("transport", {})["backend_url"] = os.environ["THREATLENS_BACKEND_URL"]
        if "THREATLENS_API_KEY" in os.environ:
            raw.setdefault("transport", {})["api_key"] = os.environ["THREATLENS_API_KEY"]
        if "THREATLENS_TLS_VERIFY" in os.environ:
            raw.setdefault("transport", {})["tls_verify"] = os.environ[
                "THREATLENS_TLS_VERIFY"
            ].lower() in ("true", "1", "yes")

        return cls.from_dict(raw)
