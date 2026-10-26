"""Integration tests for Linux telemetry collection, detection, and queuing."""

from pathlib import Path

from threatlens_agent.agent import ThreatLensAgent
from threatlens_agent.cli import main
from threatlens_agent.config import (
    AgentConfig,
    DetectionConfig,
    LinuxCollectorConfig,
    MonitoringConfig,
    QueueConfig,
    SshBruteForceConfig,
)
from threatlens_agent.transport.mock import MockTransport


def test_collector_to_detector_to_queue_workflow(temp_dir: Path) -> None:
    """Verify that collected log events pass into queue and trigger local brute-force alerts."""
    log_file = temp_dir / "auth.log"
    data_dir = temp_dir / "agent_data"

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%b %d %H:%M:%S")

    # Write 6 SSH failure lines from same source IP
    lines = [
        f"{ts_str} server01 sshd[{1000 + i}]: Failed password for invalid user "
        f"admin from 192.0.2.10 port {44210 + i} ssh2\n"
        for i in range(6)
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    cfg = AgentConfig(
        data_dir=str(data_dir),
        queue=QueueConfig(retention_policy="delete_on_delivery"),
        monitoring=MonitoringConfig(
            enabled_collectors=["linux_auth"],
            linux=LinuxCollectorConfig(
                candidate_paths=[str(log_file)],
                enable_journald=False,
            ),
        ),
        detection=DetectionConfig(
            ssh_bruteforce=SshBruteForceConfig(
                enabled=True,
                threshold=5,
                window_seconds=120,
            )
        ),
    )

    mock_transport = MockTransport(should_succeed=True)
    agent = ThreatLensAgent(cfg, transport=mock_transport)

    collected_count, detection_count = agent.collect_and_detect()

    # 6 log lines collected
    assert collected_count == 6
    # 1 brute-force alert triggered (threshold was 5)
    assert detection_count == 1

    # Queue should contain 6 auth events + 1 detection event = 7 events total
    stats = agent.queue.get_stats()
    assert stats.pending_count == 7
    assert stats.total_count == 7

    # Check health reporting
    health = agent.get_health()
    assert health.healthy is True
    assert health.total_detections_emitted == 1
    assert "linux_auth" in health.collector_diagnostics
    assert str(log_file.resolve()) in health.collector_diagnostics["linux_auth"]["active_sources"]

    # Drain queue to transport
    flushed = agent.flush(limit=10)
    assert flushed == 7

    # Queue is now empty
    stats_after = agent.queue.get_stats()
    assert stats_after.pending_count == 0

    agent.close()


def test_cli_collect_command(temp_dir: Path, capsys) -> None:
    """Verify CLI 'collect' command executes and reports metrics."""
    log_file = temp_dir / "auth.log"
    log_file.write_text(
        "Oct 26 06:12:30 server01 sshd[1001]: Failed password for root from 192.0.2.10 port 44211 ssh2\n",
        encoding="utf-8",
    )

    cfg_file = temp_dir / "agent.yaml"
    cfg_yaml = f"""
data_dir: "{temp_dir / "data"}"
monitoring:
  enabled_collectors: ["linux_auth"]
  linux:
    candidate_paths: ["{log_file}"]
    enable_journald: false
"""
    cfg_file.write_text(cfg_yaml, encoding="utf-8")

    exit_code = main(["-c", str(cfg_file), "collect"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ThreatLens Telemetry Collection Completed" in out
    assert "Events Collected     : 1" in out
