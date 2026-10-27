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
    target_host TEXT,                           -- Target host/device under attack
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    summary     TEXT    NOT NULL,
    explanation TEXT    NOT NULL,
    settings    TEXT    NOT NULL DEFAULT '{}',  -- JSON blob
    assignee    TEXT    DEFAULT NULL,           -- Assigned SOC analyst/owner
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

CREATE TABLE IF NOT EXISTS alert_status_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id)  ON DELETE CASCADE,
    old_status  TEXT    NOT NULL,
    new_status  TEXT    NOT NULL CHECK(new_status IN ('new','investigating','resolved','false_positive')),
    changed_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    actor       TEXT    NOT NULL DEFAULT 'SOC Analyst',
    reason      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id ON alert_status_history(alert_id);

CREATE TABLE IF NOT EXISTS alert_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author      TEXT    NOT NULL DEFAULT 'SOC Analyst',
    note        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes(alert_id);

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','in_progress','resolved','closed')),
    severity    TEXT    NOT NULL DEFAULT 'medium'
                        CHECK(severity IN ('low','medium','high','critical')),
    assignee    TEXT    DEFAULT NULL,
    close_reason TEXT   DEFAULT '',
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

CREATE TABLE IF NOT EXISTS detection_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    threshold       INTEGER NOT NULL DEFAULT 5,
    window_minutes  INTEGER NOT NULL DEFAULT 5,
    conditions      TEXT    NOT NULL DEFAULT '{}',  -- JSON blob for rule-specific config
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_rule_id ON detection_rules(rule_id);

CREATE TABLE IF NOT EXISTS rule_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT    NOT NULL,
    action      TEXT    NOT NULL,              -- 'create', 'update', 'enable', 'disable', 'seed'
    changed_by  TEXT    NOT NULL DEFAULT 'SOC Analyst',
    details     TEXT    NOT NULL DEFAULT '',
    changed_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_rule_audit_rule_id ON rule_audit_log(rule_id);

CREATE TABLE IF NOT EXISTS endpoints (
    device_id       TEXT    PRIMARY KEY,
    hostname        TEXT    NOT NULL DEFAULT 'unknown-host',
    os              TEXT    NOT NULL DEFAULT 'linux',
    status          TEXT    NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active', 'disabled', 'offline', 'enrolled')),
    ip_address      TEXT,
    agent_version   TEXT    DEFAULT '1.0.0',
    last_seen       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    registered_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    metadata        TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);

CREATE TABLE IF NOT EXISTS endpoint_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,        -- UUIDv4 string from agent
    device_id       TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,               -- ISO-8601 UTC
    source          TEXT    NOT NULL,               -- e.g. 'linux_auth', 'windows_event', 'sysmon'
    event_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK(severity IN ('informational','low','medium','high','critical')),
    schema_version  TEXT    NOT NULL DEFAULT '1.0.0',
    source_ip       TEXT,
    username        TEXT,
    raw_event       TEXT,
    attributes      TEXT    NOT NULL DEFAULT '{}',  -- JSON blob
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_endpoint_events_event_id  ON endpoint_events(event_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_device_id ON endpoint_events(device_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_timestamp ON endpoint_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_source    ON endpoint_events(source);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_type      ON endpoint_events(event_type);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_source_ip ON endpoint_events(source_ip);
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


def migrate_database(conn: sqlite3.Connection) -> None:
    """Apply safe, backward-compatible incremental schema additions to existing databases."""
    # 1. Add target_host and assignee columns to alerts if missing
    table_info = conn.execute("PRAGMA table_info(alerts)").fetchall()
    columns = {r["name"] for r in table_info}
    if "target_host" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN target_host TEXT")
        # Backfill target_host from evidence events where available
        conn.execute("""
            UPDATE alerts SET target_host = (
                SELECT e.host FROM events e
                JOIN alert_evidence ae ON ae.event_id = e.id
                WHERE ae.alert_id = alerts.id AND e.host IS NOT NULL
                LIMIT 1
            ) WHERE target_host IS NULL
        """)
        conn.commit()

    if "assignee" not in columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN assignee TEXT DEFAULT NULL")
        conn.commit()

    # 2. Ensure alert_status_history table and index exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_status_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            old_status  TEXT    NOT NULL,
            new_status  TEXT    NOT NULL CHECK(new_status IN ('new','investigating','resolved','false_positive')),
            changed_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            actor       TEXT    NOT NULL DEFAULT 'SOC Analyst',
            reason      TEXT    NOT NULL DEFAULT ''
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id ON alert_status_history(alert_id)")
    conn.commit()

    # 3. Ensure alert_notes table and index exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            author      TEXT    NOT NULL DEFAULT 'SOC Analyst',
            note        TEXT    NOT NULL,
            created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_id ON alert_notes(alert_id)")
    conn.commit()

    # 4. Check incidents columns (assignee, close_reason)
    inc_info = conn.execute("PRAGMA table_info(incidents)").fetchall()
    inc_cols = {r["name"] for r in inc_info}
    if "assignee" not in inc_cols:
        conn.execute("ALTER TABLE incidents ADD COLUMN assignee TEXT DEFAULT NULL")
        conn.commit()
    if "close_reason" not in inc_cols:
        conn.execute("ALTER TABLE incidents ADD COLUMN close_reason TEXT DEFAULT ''")
        conn.commit()

    # 5. Ensure detection_rules and rule_audit_log exist and are seeded
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT    NOT NULL UNIQUE,
            name            TEXT    NOT NULL,
            description     TEXT    NOT NULL DEFAULT '',
            severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            enabled         INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
            threshold       INTEGER NOT NULL DEFAULT 5,
            window_minutes  INTEGER NOT NULL DEFAULT 5,
            conditions      TEXT    NOT NULL DEFAULT '{}',
            created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detection_rules_rule_id ON detection_rules(rule_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS rule_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id     TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            changed_by  TEXT    NOT NULL DEFAULT 'SOC Analyst',
            details     TEXT    NOT NULL DEFAULT '',
            changed_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rule_audit_rule_id ON rule_audit_log(rule_id)")
    conn.commit()

    # Seed default rules if table is empty
    rules_count = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
    if rules_count == 0:
        default_rules = [
            ("DR-01", "SSH brute force", "5+ failed logins from one IP in 5 min", "medium", 1, 5, 5, "{}"),
            ("DR-02", "Username enumeration", "3+ distinct invalid usernames from one IP in 5 min", "medium", 1, 3, 5, "{}"),
            ("DR-03", "Password spraying", "Failures against 5+ distinct users from one IP in 10 min", "high", 1, 5, 10, "{}"),
            ("DR-04", "Success after failures", "Accepted login within 10 min of 5+ failures from same IP", "critical", 1, 5, 10, '{"failure_threshold": 5}'),
            ("DR-05", "Root login attempt", "Any root attempt; accepted root escalates to high severity", "medium", 1, 1, 5, '{"usernames": ["root"], "accepted_severity": "high"}'),
        ]
        for r_id, r_name, r_desc, r_sev, r_en, r_thresh, r_win, r_cond in default_rules:
            conn.execute(
                """INSERT INTO detection_rules (rule_id, name, description, severity, enabled, threshold, window_minutes, conditions)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (r_id, r_name, r_desc, r_sev, r_en, r_thresh, r_win, r_cond),
            )
            conn.execute(
                """INSERT INTO rule_audit_log (rule_id, action, changed_by, details)
                   VALUES (?, 'seed', 'System Default', ?)""",
                (r_id, f"Initial system rule seeded: {r_name} (threshold: {r_thresh}, window: {r_win}m)"),
            )
        conn.commit()

    # 6. Ensure endpoints table exists and populate from endpoint_events if needed
    conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            device_id       TEXT    PRIMARY KEY,
            hostname        TEXT    NOT NULL DEFAULT 'unknown-host',
            os              TEXT    NOT NULL DEFAULT 'linux',
            status          TEXT    NOT NULL DEFAULT 'active'
                                    CHECK(status IN ('active', 'disabled', 'offline', 'enrolled')),
            ip_address      TEXT,
            agent_version   TEXT    DEFAULT '1.0.0',
            last_seen       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            registered_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            metadata        TEXT    NOT NULL DEFAULT '{}'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status)")
    conn.commit()

    ep_count = conn.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0]
    if ep_count == 0:
        try:
            conn.execute("""
                INSERT OR IGNORE INTO endpoints (device_id, hostname, os, status, ip_address, last_seen, registered_at)
                SELECT 
                    device_id,
                    'kali-endpoint',
                    'linux',
                    'active',
                    COALESCE(MAX(source_ip), '127.0.0.1'),
                    MAX(timestamp),
                    MIN(timestamp)
                FROM endpoint_events
                GROUP BY device_id
            """)
            conn.commit()
        except Exception:
            pass


def init_db(db_path: str = "threatlens.db") -> sqlite3.Connection:
    """Create the database and all tables if they do not already exist."""
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    migrate_database(conn)
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
    for tbl in [
        "log_files", "events", "alerts", "alert_evidence",
        "alert_status_history", "alert_notes", "incidents", "incident_notes",
        "detection_rules", "rule_audit_log", "endpoints", "endpoint_events"
    ]:
        try:
            row = conn.execute(f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()
            table_counts[tbl] = row["n"] if row else 0
        except sqlite3.OperationalError:
            table_counts[tbl] = 0

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

