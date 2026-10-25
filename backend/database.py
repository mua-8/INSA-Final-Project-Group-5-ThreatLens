"""ThreatLens - Database layer (Module B).

Creates and manages the SQLite database that stores all ThreatLens data.

Six tables
----------
  log_files     - uploaded log file records (prevents duplicate uploads)
  events        - every parsed SSH auth event
  alerts        - one row per correlated detection alert
  alert_evidence - many-to-many: events that triggered an alert
  incidents     - analyst-created incident investigations
  incident_notes - append-only notes on an incident

Design notes
------------
* All inserts use parameterized queries to prevent SQL injection.
* Foreign-key constraints are enforced (PRAGMA foreign_keys = ON).
* Thread-safety: each call acquires the connection from the caller;
  the API layer is responsible for using one connection per request.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Dict, Optional, Tuple


# --------------------------------------------------------------------------
# Schema DDL
# --------------------------------------------------------------------------

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS log_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT    NOT NULL,
    file_hash   TEXT    NOT NULL UNIQUE,        -- SHA-256 of raw content
    uploaded_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    line_count  INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    malformed_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_file_id INTEGER NOT NULL REFERENCES log_files(id) ON DELETE CASCADE,
    timestamp   TEXT    NOT NULL,               -- ISO-8601
    host        TEXT,
    username    TEXT,
    source_ip   TEXT,
    port        INTEGER,
    method      TEXT,
    outcome     TEXT    NOT NULL CHECK(outcome IN ('success','failure','unknown')),
    event_type  TEXT    NOT NULL,
    raw_line    TEXT    NOT NULL,
    line_hash   TEXT    NOT NULL,
    UNIQUE(log_file_id, line_hash)              -- prevents duplicate lines per upload
);

CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_username   ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_ip_time    ON events(source_ip, timestamp); -- Sliding window optimization


CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT    NOT NULL,
    rule_name   TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    status      TEXT    NOT NULL DEFAULT 'new'
                        CHECK(status IN ('new','investigating','resolved','false_positive')),
    source_ip   TEXT    NOT NULL,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    summary     TEXT    NOT NULL,
    explanation TEXT    NOT NULL,
    settings    TEXT    NOT NULL DEFAULT '{}',  -- JSON blob
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip  ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);

CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id    INTEGER NOT NULL REFERENCES alerts(id)  ON DELETE CASCADE,
    event_id    INTEGER NOT NULL REFERENCES events(id)  ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','in_progress','closed')),
    severity    TEXT    NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high','critical')),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id)    ON DELETE CASCADE,
    linked_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_alert (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id)    ON DELETE CASCADE,
    linked_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author      TEXT    NOT NULL DEFAULT 'analyst',
    body        TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id);
"""



# --------------------------------------------------------------------------
# Connection factory
# --------------------------------------------------------------------------

def get_connection(db_path: str = "threatlens.db") -> sqlite3.Connection:
    """Return an open SQLite connection with row factory, WAL mode, and busy timeout."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(db_path: str = "threatlens.db") -> sqlite3.Connection:
    """Create the database and all tables if they do not already exist."""
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


def check_database_integrity(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Perform low-level SQLite integrity and foreign key constraint verification."""
    integrity_row = conn.execute("PRAGMA integrity_check").fetchone()
    integrity_status = integrity_row[0] if integrity_row else "unknown"

    fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    return {
        "integrity": integrity_status,
        "is_healthy": (integrity_status == "ok" and len(fk_violations) == 0),
        "foreign_key_violations": len(fk_violations),
    }


def get_database_metrics(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Retrieve operational telemetry and storage statistics for SOC reporting."""
    table_counts = {}
    for tbl in ["log_files", "events", "alerts", "alert_evidence", "incidents", "incident_notes"]:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()
        table_counts[tbl] = row["n"] if row else 0

    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]

    return {
        "table_counts": table_counts,
        "database_size_bytes": page_count * page_size,
        "page_count": page_count,
        "page_size": page_size,
        "journal_mode": conn.execute("PRAGMA journal_mode").fetchone()[0],
    }


# --------------------------------------------------------------------------
# File-hash helper (duplicate-upload guard)
# --------------------------------------------------------------------------

def sha256_of(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

