"""Pytest configuration, fixtures, and helpers for ThreatLens Agent tests."""

from __future__ import annotations

import tempfile
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest

from threatlens_agent.config import AgentConfig, QueueConfig, TransportConfig
from threatlens_agent.models.events import Event, EventSeverity
from threatlens_agent.transport.mock import MockHttpServer


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide an isolated temporary directory for test storage."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def sample_config(temp_dir: Path) -> AgentConfig:
    """Provide a validated default AgentConfig pointing to an isolated directory."""
    return AgentConfig(
        display_name="test-node",
        data_dir=str(temp_dir / "data"),
        log_level="DEBUG",
        batch_size=10,
        queue=QueueConfig(max_events=1000, max_disk_mb=50),
        transport=TransportConfig(
            backend_url=None,
            max_retries=2,
            backoff_base_seconds=0.01,
            backoff_max_seconds=0.05,
            jitter_ratio=0.0,
        ),
    )


@pytest.fixture
def make_event():
    """Factory fixture to create valid synthetic events."""

    def _create(
        device_id: str = "dev-123",
        source: str = "linux_auth",
        event_type: str = "ssh_failure",
        severity: EventSeverity = EventSeverity.HIGH,
        event_id: str | None = None,
        source_ip: str | None = "10.0.0.1",
        username: str | None = "root",
        attributes: dict | None = None,
    ) -> Event:
        return Event(
            event_id=event_id or str(uuid.uuid4()),
            device_id=device_id,
            timestamp="2026-10-26T06:00:00.000000+00:00",
            source=source,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            username=username,
            raw_event=f"Failed login for {username} from {source_ip}",
            attributes=attributes or {"auth_method": "password", "port": 22},
        )

    return _create


@pytest.fixture
def mock_server() -> Generator[MockHttpServer, None, None]:
    """Spawn an ephemeral local HTTP test server on an unused port."""
    server = MockHttpServer("127.0.0.1", 0)
    server.start()
    try:
        yield server
    finally:
        server.stop()
