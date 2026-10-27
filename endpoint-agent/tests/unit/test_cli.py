"""Unit tests for the command-line interface."""

from pathlib import Path

import pytest

from threatlens_agent.cli import main


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify version command exits with 0 and prints version."""
    exit_code = main(["version"])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "ThreatLens Endpoint Agent v0.1.0" in captured
    assert "Schema Version : 1.0.0" in captured


def test_cli_version_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify version command with --json outputs valid JSON."""
    exit_code = main(["--json", "version"])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert '"agent_version": "0.1.0"' in captured


def test_cli_validate_config_success(temp_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify validate-config succeeds for a valid config file."""
    cfg_file = temp_dir / "valid.yaml"
    cfg_file.write_text("display_name: 'test-node'\nbatch_size: 25\n", encoding="utf-8")

    exit_code = main(["validate-config", str(cfg_file)])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "Configuration validation SUCCESS" in captured


def test_cli_validate_config_failure(temp_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify validate-config fails for invalid parameters with actionable error message."""
    cfg_file = temp_dir / "invalid.yaml"
    cfg_file.write_text("batch_size: 99999\n", encoding="utf-8")

    exit_code = main(["validate-config", str(cfg_file)])
    assert exit_code == 1
    captured = capsys.readouterr().err
    assert "Configuration validation FAILED" in captured
    assert "batch_size must be an integer between 1 and 1000" in captured


def test_cli_status_command(temp_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify status command displays agent health and queue status."""
    cfg_file = temp_dir / "agent.yaml"
    cfg_file.write_text(f"data_dir: '{temp_dir / 'data'}'\n", encoding="utf-8")

    exit_code = main(["-c", str(cfg_file), "status"])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "ThreatLens Endpoint Agent Status" in captured
    assert "Overall Health     : HEALTHY" in captured


def test_cli_queue_stats_command(temp_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify queue-stats displays queue statistics."""
    cfg_file = temp_dir / "agent.yaml"
    cfg_file.write_text(f"data_dir: '{temp_dir / 'data'}'\n", encoding="utf-8")

    exit_code = main(["-c", str(cfg_file), "queue-stats"])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "ThreatLens Event Queue Statistics" in captured
    assert "Pending Events     : 0" in captured


def test_cli_invalid_command() -> None:
    """Verify unrecognized commands raise SystemExit / return exit code 2."""
    with pytest.raises(SystemExit) as exc:
        main(["nonexistent-command"])
    assert exc.value.code == 2
