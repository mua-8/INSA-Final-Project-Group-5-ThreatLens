"""Unit tests for configuration validation and loading."""

from pathlib import Path

import pytest

from threatlens_agent.config import (
    AgentConfig,
    ConfigValidationError,
    QueueConfig,
    TransportConfig,
)


def test_valid_default_config() -> None:
    """Verify that default AgentConfig initializes cleanly and passes validation."""
    cfg = AgentConfig()
    cfg.validate()
    assert cfg.log_level == "INFO"
    assert cfg.batch_size == 100
    assert cfg.queue.max_events == 50000


def test_load_from_yaml(temp_dir: Path) -> None:
    """Verify loading from a valid YAML file."""
    yaml_content = """
display_name: "test-node-01"
data_dir: "my_data"
log_level: "debug"
batch_size: 50
queue:
  max_events: 1000
  retention_policy: "retain_delivered"
transport:
  backend_url: "https://siem.example.com"
  max_retries: 3
"""
    config_file = temp_dir / "agent.yaml"
    config_file.write_text(yaml_content, encoding="utf-8")

    cfg = AgentConfig.load(config_file)
    assert cfg.display_name == "test-node-01"
    assert cfg.data_dir == "my_data"
    assert cfg.log_level == "DEBUG"
    assert cfg.batch_size == 50
    assert cfg.queue.max_events == 1000
    assert cfg.queue.retention_policy == "retain_delivered"
    assert cfg.transport.backend_url == "https://siem.example.com"
    assert cfg.transport.max_retries == 3


def test_reject_invalid_log_level() -> None:
    """Verify invalid log level raises ConfigValidationError."""
    with pytest.raises(ConfigValidationError) as exc:
        AgentConfig(log_level="VERBOSE").validate()
    assert "log_level must be one of" in str(exc.value)


@pytest.mark.parametrize("invalid_batch", [0, -5, 1001, "fifty"])
def test_reject_invalid_batch_size(invalid_batch) -> None:
    """Verify batch_size limits are enforced."""
    with pytest.raises(ConfigValidationError) as exc:
        AgentConfig(batch_size=invalid_batch).validate()
    assert "batch_size must be an integer between 1 and 1000" in str(exc.value)


def test_reject_invalid_retention_policy() -> None:
    """Verify invalid retention policy is rejected."""
    with pytest.raises(ConfigValidationError) as exc:
        QueueConfig(retention_policy="archive_to_tape").validate()
    assert "retention_policy must be one of" in str(exc.value)


@pytest.mark.parametrize(
    "invalid_url",
    ["ftp://example.com", "not_a_url", "http://", "://invalid"],
)
def test_reject_invalid_backend_url(invalid_url: str) -> None:
    """Verify malformed backend URLs are rejected."""
    with pytest.raises(ConfigValidationError) as exc:
        TransportConfig(backend_url=invalid_url).validate()
    assert "transport.backend_url must be a valid HTTP/HTTPS URL" in str(exc.value)


def test_reject_invalid_retry_bounds() -> None:
    """Verify backoff_max < backoff_base is rejected."""
    with pytest.raises(ConfigValidationError) as exc:
        TransportConfig(backoff_base_seconds=10.0, backoff_max_seconds=5.0).validate()
    assert "backoff_max_seconds must be >=" in str(exc.value)


def test_reject_nonexistent_ca_bundle(temp_dir: Path) -> None:
    """Verify missing CA bundle file raises actionable error."""
    missing = temp_dir / "missing_ca.pem"
    with pytest.raises(ConfigValidationError) as exc:
        TransportConfig(ca_bundle=str(missing)).validate()
    assert "ca_bundle specified but file does not exist" in str(exc.value)


def test_reject_unknown_configuration_keys() -> None:
    """Verify unexpected root keys are rejected."""
    with pytest.raises(ConfigValidationError) as exc:
        AgentConfig.from_dict({"display_name": "node", "unknown_rogue_key": 123})
    assert "Unknown configuration key" in str(exc.value)


def test_env_var_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variables override configuration settings."""
    monkeypatch.setenv("THREATLENS_DATA_DIR", "/custom/data")
    monkeypatch.setenv("THREATLENS_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("THREATLENS_BACKEND_URL", "https://override.siem.internal")
    monkeypatch.setenv("THREATLENS_API_KEY", "super-secret-token")

    cfg = AgentConfig.load(None)
    assert cfg.data_dir == "/custom/data"
    assert cfg.log_level == "WARNING"
    assert cfg.transport.backend_url == "https://override.siem.internal"
    assert cfg.transport.api_key == "super-secret-token"


def test_mask_secrets_in_to_dict() -> None:
    """Verify secrets are masked when converting configuration to dict."""
    cfg = AgentConfig(
        transport=TransportConfig(
            backend_url="https://siem.test",
            api_key="real-sensitive-token-12345",
        )
    )
    masked = cfg.to_dict(mask_secrets=True)
    assert masked["transport"]["api_key"] == "********"

    unmasked = cfg.to_dict(mask_secrets=False)
    assert unmasked["transport"]["api_key"] == "real-sensitive-token-12345"
