"""End-to-end integration tests for the ThreatLens Agent lifecycle."""

import importlib
import logging
from pathlib import Path

from threatlens_agent.agent import ThreatLensAgent, setup_logging
from threatlens_agent.config import AgentConfig, QueueConfig, TransportConfig
from threatlens_agent.models.events import Event, EventSeverity
from threatlens_agent.transport.http import HttpTransport
from threatlens_agent.transport.mock import MockHttpServer


def test_end_to_end_agent_restart_and_drain(
    temp_dir: Path,
    mock_server: MockHttpServer,
    make_event,
) -> None:
    """Verify full workflow: enqueue -> restart -> drain -> verify delivery."""
    data_dir = temp_dir / "agent_data"
    cfg = AgentConfig(
        data_dir=str(data_dir),
        batch_size=5,
        queue=QueueConfig(retention_policy="delete_on_delivery"),
        transport=TransportConfig(
            backend_url=mock_server.url,
            max_retries=1,
            backoff_base_seconds=0.01,
        ),
    )

    # 1. First run: Start agent, generate events, shutdown without flushing
    agent1 = ThreatLensAgent(cfg)
    device_id_1 = agent1.device_info.device_id
    assert device_id_1 is not None

    events = [
        make_event(device_id=device_id_1, username=f"user_{i}", severity=EventSeverity.MEDIUM)
        for i in range(12)
    ]
    enqueued = agent1.record_events(events)
    assert enqueued == 12

    # Put some in flight, then simulate sudden shutdown / restart
    agent1.queue.get_pending_batch(limit=3, mark_in_flight=True)
    agent1.close()

    # 2. Second run: Restart agent pointing to the same data directory
    transport2 = HttpTransport(cfg.transport, sleep_fn=lambda _: None)
    agent2 = ThreatLensAgent(cfg, transport=transport2)

    # Verify device ID is identical
    assert agent2.device_info.device_id == device_id_1

    # Verify all 12 events are back to pending status
    stats = agent2.queue.get_stats()
    assert stats.pending_count == 12
    assert stats.in_flight_count == 0

    # Drain all events across multiple batch flushes
    batch1_flushed = agent2.flush(limit=5)
    assert batch1_flushed == 5

    batch2_flushed = agent2.flush(limit=5)
    assert batch2_flushed == 5

    batch3_flushed = agent2.flush(limit=5)
    assert batch3_flushed == 2

    # Queue should be completely drained
    final_stats = agent2.queue.get_stats()
    assert final_stats.pending_count == 0
    assert final_stats.total_count == 0

    health = agent2.get_health()
    assert health.healthy is True
    assert health.queue_stats.pending_count == 0

    agent2.close()


def test_core_package_modules_importable() -> None:
    """Verify that all core modules import cleanly on the host operating system."""
    modules = [
        "threatlens_agent",
        "threatlens_agent.cli",
        "threatlens_agent.agent",
        "threatlens_agent.config",
        "threatlens_agent.models",
        "threatlens_agent.models.device",
        "threatlens_agent.models.events",
        "threatlens_agent.storage",
        "threatlens_agent.storage.state",
        "threatlens_agent.storage.queue",
        "threatlens_agent.transport",
        "threatlens_agent.transport.base",
        "threatlens_agent.transport.http",
        "threatlens_agent.transport.mock",
        "threatlens_agent.collectors",
        "threatlens_agent.collectors.base",
    ]
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None


def test_logs_and_config_do_not_expose_secrets(caplog, temp_dir: Path) -> None:
    """Verify configuration, logs, and representations do not expose tokens or secrets."""
    secret_token = "ultra-secret-token-xyz-12345"
    secret_password = "super-secret-password-xyz"

    cfg = AgentConfig(
        data_dir=str(temp_dir / "data"),
        transport=TransportConfig(
            backend_url="https://siem.test",
            api_key=secret_token,
        ),
    )

    setup_logging("DEBUG")
    caplog.set_level(logging.DEBUG)

    # Log configuration dump
    masked_dict = cfg.to_dict(mask_secrets=True)
    logging.info("Agent config: %s", masked_dict)

    # Create event with password in raw text
    ev = Event.create_synthetic(
        device_id="dev-1",
        raw_event=f"Failed login password={secret_password} token={secret_token}",
    )
    logging.info("Enqueuing synthetic event: %s", ev.event_id)

    log_text = caplog.text
    assert secret_token not in log_text
    assert secret_password not in log_text
