"""Integration tests for Windows telemetry pipeline: Adapter -> Collector -> Queue -> Transport."""

import json
from pathlib import Path

import pytest

from threatlens_agent.agent import ThreatLensAgent
from threatlens_agent.cli import cmd_collect, cmd_status
from threatlens_agent.collectors.windows_adapter import SyntheticWindowsEventAdapter
from threatlens_agent.collectors.windows_event import WindowsEventLogCollector
from threatlens_agent.config import AgentConfig, ConfigValidationError, QueueConfig
from threatlens_agent.transport.mock import MockTransport

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_windows_collector_to_queue_to_transport_workflow(temp_dir: Path) -> None:
    """Verify full pipeline: SyntheticAdapter -> WindowsCollector -> Queue -> Transport."""
    config = AgentConfig(
        data_dir=str(temp_dir),
        batch_size=50,
        queue=QueueConfig(retention_policy="retain_delivered"),
    )

    # 1. Load realistic synthetic records from fixture
    fixture_path = FIXTURES_DIR / "windows_events.json"
    with open(fixture_path, encoding="utf-8") as f:
        records = json.load(f)

    adapter = SyntheticWindowsEventAdapter(
        records=records,
        available_channels={"Security", "Microsoft-Windows-Sysmon/Operational"},
    )

    mock_transport = MockTransport(should_succeed=True)

    # 2. Instantiate agent with injected Windows collector
    agent = ThreatLensAgent(
        config=config,
        transport=mock_transport,
        collectors=[],
    )
    collector = WindowsEventLogCollector(
        device_id=agent.device_info.device_id,
        checkpoint_manager=agent.checkpoint_manager,
        adapter=adapter,
        enable_sysmon=True,
    )
    collector.start()
    agent.collectors = [collector]

    # 3. Collect and detect
    collected_count, detections_count = agent.collect_and_detect()
    # 4 Security + 1 partial + 2 Sysmon = 7 events (9999 is unknown and ignored)
    assert collected_count == 7

    # Queue should now have 7 pending events
    stats = agent.queue.get_stats()
    assert stats.pending_count == 7
    assert stats.delivered_count == 0

    # 4. Flush events to transport
    flushed_count = agent.flush()
    assert flushed_count == 7

    # Queue should reflect 7 delivered
    stats_after = agent.queue.get_stats()
    assert stats_after.pending_count == 0
    assert stats_after.delivered_count == 7

    # Verify transport received batch
    sent_batches = mock_transport.sent_batches
    assert len(sent_batches) == 1
    assert len(sent_batches[0]) == 7

    event_types = {e.event_type for e in sent_batches[0]}
    assert "windows_logon_failure" in event_types
    assert "windows_logon_success" in event_types
    assert "windows_special_privilege_assigned" in event_types
    assert "windows_process_creation" in event_types
    assert "sysmon_process_creation" in event_types
    assert "sysmon_network_connection" in event_types

    # 5. Check health reporting
    health = agent.get_health()
    assert health.healthy
    diag = health.collector_diagnostics["windows_event_log"]
    assert "Security" in diag["active_sources"]
    assert "Microsoft-Windows-Sysmon/Operational" in diag["active_sources"]
    assert diag["events_collected_total"] == 7

    agent.close()


def test_windows_config_validation() -> None:
    """Verify configuration validation for Windows collector settings."""
    # 1. Valid default config
    cfg = AgentConfig()
    cfg.validate()
    assert cfg.monitoring.windows.enabled
    assert cfg.monitoring.windows.channels == ["Security"]
    assert not cfg.monitoring.windows.enable_sysmon

    # 2. Invalid channels
    with pytest.raises(ConfigValidationError) as exc:
        cfg2 = AgentConfig()
        cfg2.monitoring.windows.channels = "NotAList"  # type: ignore[assignment]
        cfg2.validate()
    assert "monitoring.windows.channels must be a list" in str(exc.value)

    # 3. Invalid batch size
    with pytest.raises(ConfigValidationError) as exc:
        cfg3 = AgentConfig()
        cfg3.monitoring.windows.batch_size = 0
        cfg3.validate()
    assert "monitoring.windows.batch_size must be an integer between 1 and 1000" in str(exc.value)

    # 4. Invalid poll interval
    with pytest.raises(ConfigValidationError) as exc:
        cfg4 = AgentConfig()
        cfg4.monitoring.windows.poll_interval_seconds = -1.0
        cfg4.validate()
    assert "monitoring.windows.poll_interval_seconds must be a positive number" in str(exc.value)

    # 5. Invalid sysmon channel
    with pytest.raises(ConfigValidationError) as exc:
        cfg5 = AgentConfig()
        cfg5.monitoring.windows.sysmon_channel = ""
        cfg5.validate()
    assert "monitoring.windows.sysmon_channel must be a non-empty string" in str(exc.value)


def test_cli_diagnostics_windows_collector(
    temp_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify CLI status and collect commands reflect diagnostics cleanly."""
    cfg = AgentConfig(data_dir=str(temp_dir))

    # Test status
    rc_status = cmd_status(cfg, as_json=False)
    assert rc_status == 0
    captured_status = capsys.readouterr().out
    assert "ThreatLens Endpoint Agent Status" in captured_status

    # Test collect
    rc_collect = cmd_collect(cfg, as_json=False)
    assert rc_collect == 0
    captured_collect = capsys.readouterr().out
    assert "ThreatLens Telemetry Collection Completed" in captured_collect
