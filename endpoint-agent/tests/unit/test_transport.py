"""Unit tests for transport abstractions, retries, and backoff."""

from urllib.error import HTTPError

from threatlens_agent.config import TransportConfig
from threatlens_agent.transport.http import HttpTransport
from threatlens_agent.transport.mock import MockTransport


def test_unavailable_transport_returns_retryable_error(make_event) -> None:
    """Verify transport without backend_url returns failure without crashing."""
    cfg = TransportConfig(backend_url=None)
    transport = HttpTransport(cfg)
    assert transport.is_available() is False

    result = transport.send_batch([make_event()])
    assert result.success is False
    assert result.retryable is True
    assert "backend_url is not configured" in (result.error_message or "")


def test_bounded_retries_and_no_infinite_loop(monkeypatch, make_event) -> None:
    """Verify transmission retries up to max_retries and stops (bounded)."""
    cfg = TransportConfig(
        backend_url="https://siem.test",
        max_retries=3,
        backoff_base_seconds=0.01,
        backoff_max_seconds=0.05,
        jitter_ratio=0.0,
    )

    sleep_calls = []

    def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    transport = HttpTransport(cfg, sleep_fn=fake_sleep)

    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise HTTPError("https://siem.test", 500, "Internal Server Error", {}, None)

    monkeypatch.setattr("threatlens_agent.transport.http.urlopen", fake_urlopen)

    result = transport.send_batch([make_event()])

    assert result.success is False
    assert result.retryable is True
    # 1 initial attempt + 3 retries = 4 total attempts
    assert call_count == 4
    # 3 sleeps between attempts
    assert len(sleep_calls) == 3
    assert "Exceeded max retries" in (result.error_message or "")


def test_non_retryable_client_error(monkeypatch, make_event) -> None:
    """Verify 400 Bad Request fails immediately without retrying."""
    cfg = TransportConfig(
        backend_url="https://siem.test",
        max_retries=5,
    )
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise HTTPError("https://siem.test", 400, "Bad Request", {}, None)

    monkeypatch.setattr("threatlens_agent.transport.http.urlopen", fake_urlopen)

    transport = HttpTransport(cfg)
    result = transport.send_batch([make_event()])

    assert result.success is False
    assert result.retryable is False
    assert result.status_code == 400
    # Must NOT retry
    assert call_count == 1


def test_rate_limit_429_is_retryable(monkeypatch, make_event) -> None:
    """Verify HTTP 429 triggers retry logic."""
    cfg = TransportConfig(
        backend_url="https://siem.test",
        max_retries=2,
    )
    call_count = 0

    def fake_urlopen(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise HTTPError("https://siem.test", 429, "Too Many Requests", {}, None)

    monkeypatch.setattr("threatlens_agent.transport.http.urlopen", fake_urlopen)

    transport = HttpTransport(cfg, sleep_fn=lambda _: None)
    result = transport.send_batch([make_event()])

    assert result.success is False
    assert result.retryable is True
    # 1 initial + 2 retries = 3 calls
    assert call_count == 3


def test_backoff_calculation() -> None:
    """Verify exponential backoff calculation stays within configured bounds."""
    cfg = TransportConfig(
        backend_url="https://siem.test",
        backoff_base_seconds=1.0,
        backoff_max_seconds=10.0,
        jitter_ratio=0.0,
    )
    transport = HttpTransport(cfg)

    # 1.0 * 2^0 = 1.0
    assert transport._calculate_backoff(0) == 1.0
    # 1.0 * 2^1 = 2.0
    assert transport._calculate_backoff(1) == 2.0
    # 1.0 * 2^2 = 4.0
    assert transport._calculate_backoff(2) == 4.0
    # 1.0 * 2^3 = 8.0
    assert transport._calculate_backoff(3) == 8.0
    # 1.0 * 2^4 = 16.0 -> capped at backoff_max_seconds (10.0)
    assert transport._calculate_backoff(4) == 10.0


def test_mock_transport_behavior(make_event) -> None:
    """Verify MockTransport helper allows simulating success, failure, and partial ack."""
    mock = MockTransport(should_succeed=True, partial_ack_count=1)
    ev1 = make_event()
    ev2 = make_event()

    result = mock.send_batch([ev1, ev2])
    assert result.success is True
    assert result.acknowledged_event_ids == [ev1.event_id]
    assert len(mock.sent_batches) == 1
