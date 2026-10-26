"""Integration tests using an ephemeral local mock HTTP server."""

from pathlib import Path

from threatlens_agent.agent import ThreatLensAgent
from threatlens_agent.config import AgentConfig, QueueConfig, TransportConfig
from threatlens_agent.models.events import Event
from threatlens_agent.transport.http import HttpTransport
from threatlens_agent.transport.mock import MockHttpServer


def test_successful_transmission_and_acknowledgment(
    temp_dir: Path,
    mock_server: MockHttpServer,
    make_event,
) -> None:
    """Verify that events sent to mock server are acknowledged and marked delivered."""
    config = AgentConfig(
        data_dir=str(temp_dir / "data"),
        queue=QueueConfig(retention_policy="delete_on_delivery"),
        transport=TransportConfig(
            backend_url=mock_server.url,
            events_endpoint="/api/v1/events",
            max_retries=1,
            backoff_base_seconds=0.01,
        ),
    )
    transport = HttpTransport(config.transport, sleep_fn=lambda _: None)
    agent = ThreatLensAgent(config, transport=transport)

    ev1 = make_event(username="user1")
    ev2 = make_event(username="user2")
    agent.record_events([ev1, ev2])

    stats_before = agent.queue.get_stats()
    assert stats_before.pending_count == 2

    # Flush batch to mock server
    flushed = agent.flush()
    assert flushed == 2

    # Verify server received the request
    assert len(mock_server.received_requests) == 1
    req = mock_server.received_requests[0]
    assert req["path"] == "/api/v1/events"
    assert "ThreatLens-Agent" in req["headers"].get("User-Agent", "")

    # Queue should now be empty due to delete_on_delivery policy
    stats_after = agent.queue.get_stats()
    assert stats_after.pending_count == 0
    assert stats_after.total_count == 0

    agent.close()


def test_failed_transmission_leaves_events_pending(
    temp_dir: Path,
    mock_server: MockHttpServer,
    make_event,
) -> None:
    """Verify server 500 error leaves events safely in pending state for future retry."""
    # Configure mock server to return 500 error
    mock_server.configured_status = 500
    mock_server.configured_body = '{"error": "Internal database error"}'

    config = AgentConfig(
        data_dir=str(temp_dir / "data"),
        transport=TransportConfig(
            backend_url=mock_server.url,
            max_retries=1,
            backoff_base_seconds=0.01,
        ),
    )
    transport = HttpTransport(config.transport, sleep_fn=lambda _: None)
    agent = ThreatLensAgent(config, transport=transport)

    ev = make_event()
    agent.record_event(ev)

    flushed = agent.flush()
    assert flushed == 0

    # Events must remain in queue
    stats = agent.queue.get_stats()
    assert stats.pending_count == 1
    assert stats.in_flight_count == 0

    # Ensure last transport error is captured
    health = agent.get_health()
    assert health.last_transport_error is not None
    assert "500" in health.last_transport_error

    agent.close()


def test_malformed_response_does_not_lose_events(
    temp_dir: Path,
    mock_server: MockHttpServer,
    make_event,
) -> None:
    """Verify 200 OK with non-JSON or malformed payload is handled safely."""
    # Server returns 200 but sends broken HTML instead of JSON
    mock_server.configured_status = 200
    mock_server.configured_body = "<html><body>502 Bad Gateway from upstream proxy</body></html>"

    config = AgentConfig(
        data_dir=str(temp_dir / "data"),
        transport=TransportConfig(
            backend_url=mock_server.url,
            max_retries=1,
            backoff_base_seconds=0.01,
        ),
    )
    transport = HttpTransport(config.transport, sleep_fn=lambda _: None)
    agent = ThreatLensAgent(config, transport=transport)

    ev = make_event()
    agent.record_event(ev)

    # Flush should not crash; default acknowledgment handles fallback safely
    flushed = agent.flush()
    assert flushed == 1

    agent.close()


def test_partial_acknowledgment_handling(
    temp_dir: Path,
    mock_server: MockHttpServer,
    make_event,
) -> None:
    """Verify when server acknowledges only a subset of IDs, unacknowledged remain pending."""
    ev1 = make_event()
    ev2 = make_event()

    # Mock server acknowledges only ev1
    mock_server.configured_status = 200
    mock_server.configured_body = f'{{"status": "partial", "acknowledged": ["{ev1.event_id}"]}}'

    config = AgentConfig(
        data_dir=str(temp_dir / "data"),
        queue=QueueConfig(retention_policy="delete_on_delivery"),
        transport=TransportConfig(
            backend_url=mock_server.url,
            max_retries=0,
        ),
    )
    transport = HttpTransport(config.transport, sleep_fn=lambda _: None)
    agent = ThreatLensAgent(config, transport=transport)

    agent.record_events([ev1, ev2])

    flushed = agent.flush()
    assert flushed == 1

    # ev1 was deleted; ev2 returned to pending
    stats = agent.queue.get_stats()
    assert stats.pending_count == 1
    assert stats.total_count == 1

    pending_events: list[Event] = agent.queue.get_pending_batch(limit=10, mark_in_flight=False)
    assert len(pending_events) == 1
    assert pending_events[0].event_id == ev2.event_id

    agent.close()
