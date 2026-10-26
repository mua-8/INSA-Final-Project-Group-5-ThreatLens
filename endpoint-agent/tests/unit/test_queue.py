"""Unit tests for the durable SQLite event queue."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from threatlens_agent.config import QueueConfig
from threatlens_agent.models.events import EventSeverity
from threatlens_agent.storage.queue import EventQueue, QueueFullError


def test_enqueue_and_retrieve_batch(temp_dir: Path, make_event) -> None:
    """Verify events can be enqueued and retrieved in pending batch."""
    db_path = temp_dir / "test_queue.db"
    queue = EventQueue(db_path)

    ev1 = make_event(username="user1")
    ev2 = make_event(username="user2")

    assert queue.enqueue(ev1) is True
    assert queue.enqueue(ev2) is True

    batch = queue.get_pending_batch(limit=10, mark_in_flight=True)
    assert len(batch) == 2
    assert batch[0].event_id == ev1.event_id
    assert batch[1].event_id == ev2.event_id

    stats = queue.get_stats()
    assert stats.pending_count == 0
    assert stats.in_flight_count == 2
    queue.close()


def test_persistence_across_reconnection(temp_dir: Path, make_event) -> None:
    """Verify pending and in-flight events persist across database reconnections."""
    db_path = temp_dir / "persist_queue.db"
    q1 = EventQueue(db_path)
    ev = make_event()
    q1.enqueue(ev)
    # Put it in-flight
    q1.get_pending_batch(limit=5, mark_in_flight=True)
    q1.close()

    # Reconnect
    q2 = EventQueue(db_path)
    # In-flight events should have been reset to pending on restart
    stats = q2.get_stats()
    assert stats.pending_count == 1
    assert stats.in_flight_count == 0

    batch = q2.get_pending_batch(limit=5, mark_in_flight=False)
    assert len(batch) == 1
    assert batch[0].event_id == ev.event_id
    q2.close()


def test_duplicate_event_handling(temp_dir: Path, make_event) -> None:
    """Verify duplicate event IDs are rejected safely without data loss."""
    db_path = temp_dir / "dup_queue.db"
    queue = EventQueue(db_path)

    ev = make_event()
    assert queue.enqueue(ev) is True
    # Second enqueue of identical event_id
    assert queue.enqueue(ev) is False

    stats = queue.get_stats()
    assert stats.total_count == 1
    queue.close()


def test_batch_retrieval_limits(temp_dir: Path, make_event) -> None:
    """Verify get_pending_batch respects the requested limit."""
    db_path = temp_dir / "limit_queue.db"
    queue = EventQueue(db_path)

    for i in range(15):
        queue.enqueue(make_event(username=f"user_{i}"))

    batch = queue.get_pending_batch(limit=5, mark_in_flight=True)
    assert len(batch) == 5

    stats = queue.get_stats()
    assert stats.pending_count == 10
    assert stats.in_flight_count == 5
    queue.close()


def test_mark_delivered_delete_policy(temp_dir: Path, make_event) -> None:
    """Verify delete_on_delivery removes rows upon acknowledgment."""
    db_path = temp_dir / "del_queue.db"
    cfg = QueueConfig(retention_policy="delete_on_delivery")
    queue = EventQueue(db_path, config=cfg)

    ev = make_event()
    queue.enqueue(ev)
    queue.get_pending_batch(limit=1, mark_in_flight=True)

    deleted = queue.mark_delivered([ev.event_id])
    assert deleted == 1

    stats = queue.get_stats()
    assert stats.total_count == 0
    queue.close()


def test_mark_delivered_retain_policy(temp_dir: Path, make_event) -> None:
    """Verify retain_delivered updates status instead of deleting."""
    db_path = temp_dir / "retain_queue.db"
    cfg = QueueConfig(retention_policy="retain_delivered")
    queue = EventQueue(db_path, config=cfg)

    ev = make_event()
    queue.enqueue(ev)
    queue.get_pending_batch(limit=1, mark_in_flight=True)

    updated = queue.mark_delivered([ev.event_id])
    assert updated == 1

    stats = queue.get_stats()
    assert stats.total_count == 1
    assert stats.delivered_count == 1
    assert stats.pending_count == 0
    queue.close()


def test_mark_failed_resets_in_flight(temp_dir: Path, make_event) -> None:
    """Verify mark_failed returns in-flight events to pending for retry."""
    db_path = temp_dir / "fail_queue.db"
    queue = EventQueue(db_path)

    ev = make_event()
    queue.enqueue(ev)
    queue.get_pending_batch(limit=1, mark_in_flight=True)

    reset_count = queue.mark_failed([ev.event_id], error_message="Connection timeout")
    assert reset_count == 1

    stats = queue.get_stats()
    assert stats.pending_count == 1
    assert stats.in_flight_count == 0
    queue.close()


def test_queue_full_limit_enforcement(temp_dir: Path, make_event) -> None:
    """Verify QueueFullError is raised when capacity is exceeded."""
    db_path = temp_dir / "full_queue.db"
    cfg = QueueConfig(max_events=3)
    queue = EventQueue(db_path, config=cfg)

    queue.enqueue(make_event())
    queue.enqueue(make_event())
    queue.enqueue(make_event())

    with pytest.raises(QueueFullError):
        queue.enqueue(make_event())

    queue.close()


def test_concurrent_enqueuing(temp_dir: Path, make_event) -> None:
    """Verify thread-safety when multiple worker threads enqueue events simultaneously."""
    db_path = temp_dir / "concurrent_queue.db"
    queue = EventQueue(db_path, config=QueueConfig(max_events=500))

    def worker(idx: int) -> bool:
        ev = make_event(username=f"worker_{idx}", severity=EventSeverity.LOW)
        return queue.enqueue(ev)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker, range(100)))

    assert all(results)
    stats = queue.get_stats()
    assert stats.total_count == 100
    assert stats.pending_count == 100
    queue.close()
