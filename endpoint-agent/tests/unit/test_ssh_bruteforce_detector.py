"""Unit tests for local SSH brute-force detection rule."""

import uuid
from datetime import datetime, timezone

from threatlens_agent.detection.ssh_bruteforce import RULE_ID, SshBruteForceDetector
from threatlens_agent.models.events import Event, EventSeverity


def create_ssh_failure(
    source_ip: str = "192.0.2.10",
    target_host: str = "server01",
    username: str = "admin",
    epoch_timestamp: float = 1000.0,
    event_type: str = "ssh_auth_failure",
    port: int = 44211,
) -> Event:
    """Helper to generate deterministic SSH failure events with epoch timestamps."""
    iso_ts = datetime.fromtimestamp(epoch_timestamp, tz=timezone.utc).isoformat()
    return Event(
        event_id=str(uuid.uuid4()),
        device_id="dev-test",
        timestamp=iso_ts,
        source="linux_auth",
        event_type=event_type,
        severity=EventSeverity.HIGH,
        source_ip=source_ip,
        username=username,
        raw_event=f"Failed password for user {username} from {source_ip}",
        attributes={
            "target_host": target_host,
            "port": port,
            "auth_method": "password",
            "invalid_user": False,
        },
    )


def test_below_threshold_produces_no_detection() -> None:
    """Verify failure counts strictly below configured threshold do not alert."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=120,
        time_provider=lambda: fake_time,
    )

    # 4 failures (threshold is 5)
    events = [
        create_ssh_failure(epoch_timestamp=fake_time + i, username=f"user_{i}") for i in range(4)
    ]
    detections = detector.analyze(events)
    assert len(detections) == 0


def test_at_threshold_triggers_detection() -> None:
    """Verify reaching configured threshold generates a structured detection event."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=120,
        time_provider=lambda: fake_time + 10,
    )

    # Exactly 5 failures from same IP and host
    events = [
        create_ssh_failure(epoch_timestamp=fake_time + i, username=f"user_{i}") for i in range(5)
    ]
    detections = detector.analyze(events)

    assert len(detections) == 1
    alert = detections[0]
    alert.validate()  # Validates against schema

    assert alert.source == "threatlens_detection"
    assert alert.event_type == "potential_ssh_bruteforce"
    assert alert.severity == EventSeverity.HIGH
    assert alert.source_ip == "192.0.2.10"
    assert alert.attributes["rule_id"] == RULE_ID
    assert alert.attributes["target_host"] == "server01"
    assert alert.attributes["failure_count"] == 5
    assert alert.attributes["threshold"] == 5
    assert len(alert.attributes["supporting_event_ids"]) == 5
    assert "Observed 5 suspected SSH authentication failures" in alert.attributes["explanation"]


def test_above_threshold_escalates_to_critical() -> None:
    """Verify reaching 2x threshold escalates alert severity to CRITICAL."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=120,
        time_provider=lambda: fake_time + 20,
    )

    events = [
        create_ssh_failure(epoch_timestamp=fake_time + i, username=f"user_{i}") for i in range(10)
    ]
    detections = detector.analyze(events)

    assert len(detections) == 1
    alert = detections[0]
    assert alert.severity == EventSeverity.CRITICAL
    assert alert.attributes["failure_count"] == 10


def test_separate_source_ip_and_host_grouping() -> None:
    """Verify events from different IPs or targeting different hosts are grouped separately."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=120,
        time_provider=lambda: fake_time + 10,
    )

    # 4 failures from IP A on host 1
    events_ip_a = [
        create_ssh_failure(
            source_ip="192.0.2.10", target_host="server01", epoch_timestamp=fake_time + i
        )
        for i in range(4)
    ]
    # 4 failures from IP B on host 1
    events_ip_b = [
        create_ssh_failure(
            source_ip="203.0.113.50", target_host="server01", epoch_timestamp=fake_time + i
        )
        for i in range(4)
    ]
    # Neither IP reached threshold 5 alone
    assert len(detector.analyze(events_ip_a + events_ip_b)) == 0

    # 4 failures from IP A on host 2
    events_host_2 = [
        create_ssh_failure(
            source_ip="192.0.2.10", target_host="server02", epoch_timestamp=fake_time + i
        )
        for i in range(4)
    ]
    # Total for IP A is 8, but split across server01 and server02 (4 each) -> 0 alerts
    assert len(detector.analyze(events_host_2)) == 0


def test_time_window_sliding_expiration() -> None:
    """Verify events outside sliding time window are pruned and do not count towards threshold."""
    current_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=100,  # 100s window
        time_provider=lambda: current_time,
    )

    # 4 failures at t = 1000
    events_batch1 = [create_ssh_failure(epoch_timestamp=1000.0 + i) for i in range(4)]
    assert len(detector.analyze(events_batch1)) == 0

    # Advance time to t = 1150 (150s later; older events expired)
    current_time = 1150.0

    # 1 failure at t = 1150
    events_batch2 = [create_ssh_failure(epoch_timestamp=1150.0)]
    # Total in window is only 1 failure (the 4 from t=1000 expired)
    detections = detector.analyze(events_batch2)
    assert len(detections) == 0


def test_duplicate_events_do_not_inflate_count() -> None:
    """Verify that re-submitting identical event IDs does not increase failure count."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=5,
        window_seconds=120,
        time_provider=lambda: fake_time + 10,
    )

    ev = create_ssh_failure(epoch_timestamp=fake_time)
    # Send same event 10 times
    detections = detector.analyze([ev] * 10)
    assert len(detections) == 0


def test_invalid_user_coalescing() -> None:
    """Verify that paired invalid user and failed password lines count as a single attempt."""
    fake_time = 1000.0
    detector = SshBruteForceDetector(
        threshold=3,
        window_seconds=120,
        coalesce_window_seconds=2.0,
        time_provider=lambda: fake_time + 10,
    )

    # Attempt 1: notice + failure for user 'test1' on same port within 0.1s
    ev1_notice = create_ssh_failure(
        username="test1",
        epoch_timestamp=fake_time,
        event_type="ssh_invalid_user",
        port=50001,
    )
    ev1_failure = create_ssh_failure(
        username="test1",
        epoch_timestamp=fake_time + 0.1,
        event_type="ssh_auth_failure",
        port=50001,
    )

    # Attempt 2: notice + failure for user 'test2'
    ev2_notice = create_ssh_failure(
        username="test2",
        epoch_timestamp=fake_time + 1.0,
        event_type="ssh_invalid_user",
        port=50002,
    )
    ev2_failure = create_ssh_failure(
        username="test2",
        epoch_timestamp=fake_time + 1.1,
        event_type="ssh_auth_failure",
        port=50002,
    )

    # 4 log events total, but representing only 2 distinct attempts (threshold is 3)
    detections = detector.analyze([ev1_notice, ev1_failure, ev2_notice, ev2_failure])
    assert len(detections) == 0

    # Attempt 3: adds a third distinct attempt
    ev3 = create_ssh_failure(username="test3", epoch_timestamp=fake_time + 2.0, port=50003)
    detections2 = detector.analyze([ev3])

    # Now reaches threshold 3!
    assert len(detections2) == 1
    alert = detections2[0]
    assert alert.attributes["failure_count"] == 3
    # All 5 event IDs are tracked in supporting events
    assert len(alert.attributes["supporting_event_ids"]) == 5
