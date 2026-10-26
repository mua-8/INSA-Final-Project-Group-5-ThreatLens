"""Durable SQLite-backed event queue for reliable telemetry buffering."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatlens_agent.config import QueueConfig
from threatlens_agent.models.events import Event
from threatlens_agent.storage.state import set_secure_permissions

logger = logging.getLogger(__name__)


class QueueError(Exception):
    """Base exception for queue operations."""


class QueueFullError(QueueError):
    """Raised when the event queue exceeds configured size limits."""


@dataclass
class QueueStats:
    """Snapshot of queue metrics and health."""

    pending_count: int
    in_flight_count: int
    delivered_count: int
    total_count: int
    database_size_bytes: int
    oldest_pending_timestamp: str | None = None
    newest_pending_timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pending": self.pending_count,
            "in_flight": self.in_flight_count,
            "delivered": self.delivered_count,
            "total": self.total_count,
            "database_size_bytes": self.database_size_bytes,
            "database_size_mb": round(self.database_size_bytes / (1024 * 1024), 2),
            "oldest_pending_timestamp": self.oldest_pending_timestamp,
            "newest_pending_timestamp": self.newest_pending_timestamp,
        }


class EventQueue:
    """Thread-safe, durable SQLite queue for buffering endpoint events across restarts."""

    def __init__(
        self,
        db_path: Path | str,
        config: QueueConfig | None = None,
    ) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self.config = config or QueueConfig()
        self._lock = threading.Lock()

        # Ensure parent directory exists with secure permissions
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        set_secure_permissions(self.db_path.parent, is_dir=True)

        self._conn = self._init_db()
        self.reset_in_flight()

    def _init_db(self) -> sqlite3.Connection:
        """Initialize SQLite database with WAL mode and resilient schema."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
            isolation_level=None,  # Autocommit mode; transactions managed explicitly
        )
        conn.row_factory = sqlite3.Row

        # Set secure file permissions on the database file
        set_secure_permissions(self.db_path, is_dir=False)

        with conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA busy_timeout = 10000;")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_attempt_at TEXT,
                    delivered_at TEXT
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_status_timestamp
                ON events(status, timestamp);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_event_id
                ON events(event_id);
                """
            )

        return conn

    def _check_and_enforce_limits(self) -> None:
        """Enforce max_events limit, pruning delivered records if necessary."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM events;")
        total_count = cursor.fetchone()[0]

        if total_count >= self.config.max_events:
            # First, purge delivered records to free space
            cursor.execute("DELETE FROM events WHERE status = 'delivered';")
            purged = cursor.rowcount
            if purged > 0:
                logger.info("Purged %d delivered events to enforce queue limits", purged)

            # Re-check count
            cursor.execute("SELECT COUNT(*) FROM events;")
            new_count = cursor.fetchone()[0]
            if new_count >= self.config.max_events:
                raise QueueFullError(
                    f"Queue has reached capacity ({new_count}/{self.config.max_events} events)"
                )

    def enqueue(self, event: Event) -> bool:
        """Enqueue a single event. Returns True if inserted, False if duplicate."""
        event.validate()
        with self._lock:
            self._check_and_enforce_limits()
            now = datetime.now(timezone.utc).isoformat()
            payload = json.dumps(event.to_dict())

            try:
                self._conn.execute(
                    """
                    INSERT INTO events (
                        event_id, device_id, timestamp, source, event_type,
                        severity, payload_json, status, attempts, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?);
                    """,
                    (
                        event.event_id,
                        event.device_id,
                        event.timestamp,
                        event.source,
                        event.event_type,
                        event.severity.value,
                        payload,
                        now,
                    ),
                )
                logger.debug("Enqueued event %s (%s)", event.event_id, event.event_type)
                return True
            except sqlite3.IntegrityError:
                logger.debug("Duplicate event %s ignored", event.event_id)
                return False

    def enqueue_batch(self, events: list[Event]) -> int:
        """Enqueue multiple events in a single transaction. Returns count inserted."""
        if not events:
            return 0

        for ev in events:
            ev.validate()

        now = datetime.now(timezone.utc).isoformat()
        inserted = 0

        with self._lock:
            self._check_and_enforce_limits()
            with self._conn:
                for event in events:
                    payload = json.dumps(event.to_dict())
                    try:
                        self._conn.execute(
                            """
                            INSERT INTO events (
                                event_id, device_id, timestamp, source, event_type,
                                severity, payload_json, status, attempts, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?);
                            """,
                            (
                                event.event_id,
                                event.device_id,
                                event.timestamp,
                                event.source,
                                event.event_type,
                                event.severity.value,
                                payload,
                                now,
                            ),
                        )
                        inserted += 1
                    except sqlite3.IntegrityError:
                        logger.debug("Duplicate event %s skipped during batch", event.event_id)
        return inserted

    def get_pending_batch(self, limit: int, mark_in_flight: bool = True) -> list[Event]:
        """Retrieve up to `limit` pending events ordered by timestamp (FIFO)."""
        if limit <= 0:
            return []

        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT id, event_id, payload_json FROM events
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            if not rows:
                return []

            event_ids = [row["event_id"] for row in rows]
            events: list[Event] = []
            for row in rows:
                try:
                    data = json.loads(row["payload_json"])
                    events.append(Event.from_dict(data))
                except Exception as exc:
                    logger.error("Failed to parse stored event %s: %s", row["event_id"], exc)

            if mark_in_flight and event_ids:
                now = datetime.now(timezone.utc).isoformat()
                placeholders = ",".join("?" for _ in event_ids)
                with self._conn:
                    self._conn.execute(
                        f"""
                        UPDATE events
                        SET status = 'in_flight',
                            attempts = attempts + 1,
                            last_attempt_at = ?
                        WHERE event_id IN ({placeholders});
                        """,
                        [now, *event_ids],
                    )

            return events

    def mark_delivered(self, event_ids: list[str]) -> int:
        """Mark events as delivered or remove them based on retention policy."""
        if not event_ids:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        placeholders = ",".join("?" for _ in event_ids)

        with self._lock:
            with self._conn:
                if self.config.retention_policy == "delete_on_delivery":
                    cursor = self._conn.execute(
                        f"DELETE FROM events WHERE event_id IN ({placeholders});",
                        event_ids,
                    )
                else:
                    cursor = self._conn.execute(
                        f"""
                        UPDATE events
                        SET status = 'delivered', delivered_at = ?
                        WHERE event_id IN ({placeholders});
                        """,
                        [now, *event_ids],
                    )
                count = cursor.rowcount
                logger.debug(
                    "Marked %d events as delivered (%s)", count, self.config.retention_policy
                )
                return count

    def mark_failed(self, event_ids: list[str], error_message: str | None = None) -> int:
        """Reset in_flight events back to pending for retry."""
        if not event_ids:
            return 0

        placeholders = ",".join("?" for _ in event_ids)
        with self._lock:
            with self._conn:
                cursor = self._conn.execute(
                    f"""
                    UPDATE events
                    SET status = 'pending'
                    WHERE event_id IN ({placeholders}) AND status = 'in_flight';
                    """,
                    event_ids,
                )
                count = cursor.rowcount
                logger.warning(
                    "Returned %d in-flight events to pending status due to failure: %s",
                    count,
                    error_message or "transport error",
                )
                return count

    def reset_in_flight(self) -> int:
        """Reset any unacknowledged in-flight events to pending on startup."""
        with self._lock:
            with self._conn:
                cursor = self._conn.execute(
                    "UPDATE events SET status = 'pending' WHERE status = 'in_flight';"
                )
                count = cursor.rowcount
                if count > 0:
                    logger.info("Reset %d in-flight events to pending on initialization", count)
                return count

    def get_stats(self) -> QueueStats:
        """Retrieve real-time queue metrics and file size."""
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN status = 'in_flight' THEN 1 ELSE 0 END) AS in_flight,
                    SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) AS delivered,
                    COUNT(*) AS total,
                    MIN(CASE WHEN status = 'pending' THEN timestamp ELSE NULL END) AS oldest,
                    MAX(CASE WHEN status = 'pending' THEN timestamp ELSE NULL END) AS newest
                FROM events;
                """
            )
            row = cursor.fetchone()

            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
            # Include WAL file size if present
            wal_path = Path(f"{self.db_path}-wal")
            if wal_path.exists():
                db_size += wal_path.stat().st_size

            return QueueStats(
                pending_count=row["pending"] or 0,
                in_flight_count=row["in_flight"] or 0,
                delivered_count=row["delivered"] or 0,
                total_count=row["total"] or 0,
                database_size_bytes=db_size,
                oldest_pending_timestamp=row["oldest"],
                newest_pending_timestamp=row["newest"],
            )

    def close(self) -> None:
        """Safely close database connection."""
        with self._lock:
            try:
                self._conn.close()
            except Exception as exc:
                logger.debug("Error closing queue database: %s", exc)
