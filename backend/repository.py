"""ThreatLens - CRUD repository layer (Module B).

One function per database operation.  Every function accepts an open
sqlite3.Connection so the caller (the API layer) controls transactions.

All queries use parameterized placeholders (?).  No string formatting is
ever used to build SQL, preventing SQL injection.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# log_files
# --------------------------------------------------------------------------

def insert_log_file(conn: sqlite3.Connection, filename: str, file_hash: str,
                    line_count: int, event_count: int, malformed_count: int) -> int:
    """Insert a log-file record.  Returns the new row id."""
    cur = conn.execute(
        """INSERT INTO log_files (filename, file_hash, line_count, event_count, malformed_count)
           VALUES (?, ?, ?, ?, ?)""",
        (filename, file_hash, line_count, event_count, malformed_count),
    )
    return cur.lastrowid


def get_log_file_by_hash(conn: sqlite3.Connection, file_hash: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM log_files WHERE file_hash = ?", (file_hash,)
    ).fetchone()


def list_log_files(conn: sqlite3.Connection) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM log_files ORDER BY uploaded_at DESC"
    ).fetchall()


def get_or_create_endpoint_log_file(conn: sqlite3.Connection, device_id: str) -> int:
    """Retrieve or create a deterministic log_files record for an endpoint device.

    Allows endpoint events to satisfy the foreign key constraint
    events.log_file_id -> log_files(id).
    """
    clean_id = (device_id or "unknown").strip()
    filename = f"endpoint-agent:{clean_id}"
    file_hash = hashlib.sha256(filename.encode("utf-8")).hexdigest()
    row = conn.execute(
        "SELECT id FROM log_files WHERE file_hash = ?", (file_hash,)
    ).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        """INSERT INTO log_files (filename, file_hash, line_count, event_count, malformed_count)
           VALUES (?, ?, 0, 0, 0)""",
        (filename, file_hash),
    )
    return cur.lastrowid


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------

def insert_events_batch(conn: sqlite3.Connection, log_file_id: int,
                        events: List[Dict[str, Any]]) -> List[int]:
    """Bulk-insert parsed events.  Returns list of new row ids (same order).

    Rows that violate the UNIQUE(log_file_id, line_hash) constraint are
    silently skipped (INSERT OR IGNORE) — duplicate line handling.
    """
    ids = []
    for ev in events:
        cur = conn.execute(
            """INSERT OR IGNORE INTO events
               (log_file_id, timestamp, host, username, source_ip, port,
                method, outcome, event_type, raw_line, line_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log_file_id,
                ev["timestamp"],
                ev.get("host"),
                ev.get("username"),
                ev.get("source_ip"),
                ev.get("port"),
                ev.get("method"),
                ev["outcome"],
                ev["event_type"],
                ev["raw_line"],
                ev["line_hash"],
            ),
        )
        ids.append(cur.lastrowid if cur.rowcount > 0 else None)
    return ids


def get_event(conn: sqlite3.Connection, event_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()


def list_events(conn: sqlite3.Connection, source_ip: Optional[str] = None,
                username: Optional[str] = None, outcome: Optional[str] = None,
                event_type: Optional[str] = None,
                since: Optional[str] = None, until: Optional[str] = None,
                limit: int = 100, offset: int = 0) -> List[sqlite3.Row]:
    """Filtered event listing used by the search / filter endpoint."""
    clauses, params = [], []
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if username:
        clauses.append("username = ?")
        params.append(username)
    if outcome:
        clauses.append("outcome = ?")
        params.append(outcome)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp <= ?")
        params.append(until)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    return conn.execute(
        f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def top_source_ips(conn: sqlite3.Connection, limit: int = 10) -> List[sqlite3.Row]:
    """Return source IPs ordered by event count (for the dashboard)."""
    return conn.execute(
        """SELECT source_ip, COUNT(*) AS event_count
           FROM events WHERE source_ip IS NOT NULL
           GROUP BY source_ip ORDER BY event_count DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def auth_statistics(conn: sqlite3.Connection) -> Dict[str, int]:
    """Aggregate counts for the dashboard statistics card."""
    row = conn.execute(
        """SELECT
             COUNT(*)                                          AS total,
             SUM(outcome = 'success')                         AS accepted,
             SUM(outcome = 'failure')                         AS failed,
             COUNT(DISTINCT source_ip)                        AS unique_ips,
             COUNT(DISTINCT username)                         AS unique_users
           FROM events"""
    ).fetchone()
    return dict(row) if row else {}


# --------------------------------------------------------------------------
# alerts
# --------------------------------------------------------------------------

def insert_alert(conn: sqlite3.Connection, alert: Dict[str, Any]) -> int:
    """Insert one alert row.  Returns the new row id."""
    cur = conn.execute(
        """INSERT INTO alerts
           (rule_id, rule_name, severity, status, source_ip,
            first_seen, last_seen, summary, explanation, settings)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["rule_id"],
            alert["rule_name"],
            alert["severity"],
            alert.get("status", "new"),
            alert["source_ip"],
            alert["first_seen"],
            alert["last_seen"],
            alert["summary"],
            alert["explanation"],
            json.dumps(alert.get("settings", {})),
        ),
    )
    return cur.lastrowid


def update_alert(conn: sqlite3.Connection, alert_id: int,
                 severity: str, last_seen: str, summary: str,
                 explanation: str) -> None:
    """Update mutable fields of an existing alert (evidence-driven update)."""
    conn.execute(
        """UPDATE alerts SET severity=?, last_seen=?, summary=?, explanation=?,
           updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
           WHERE id=?""",
        (severity, last_seen, summary, explanation, alert_id),
    )


def update_alert_status(conn: sqlite3.Connection, alert_id: int, status: str) -> bool:
    """Set alert status.  Returns True if a row was found."""
    valid = {"new", "investigating", "resolved", "false_positive"}
    if status not in valid:
        raise ValueError(f"status must be one of {sorted(valid)}")
    cur = conn.execute(
        """UPDATE alerts SET status=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
           WHERE id=?""",
        (status, alert_id),
    )
    return cur.rowcount > 0


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def list_alerts(conn: sqlite3.Connection, status: Optional[str] = None,
                severity: Optional[str] = None, rule_id: Optional[str] = None,
                source_ip: Optional[str] = None,
                limit: int = 100, offset: int = 0) -> List[sqlite3.Row]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id)
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    return conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def count_alerts_by_severity(conn: sqlite3.Connection) -> Dict[str, int]:
    rows = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
    ).fetchall()
    return {r["severity"]: r["n"] for r in rows}


# --------------------------------------------------------------------------
# alert_evidence
# --------------------------------------------------------------------------

def insert_alert_evidence(conn: sqlite3.Connection, alert_id: int,
                          event_ids: List[int]) -> None:
    """Link evidence events to an alert (INSERT OR IGNORE to handle re-runs)."""
    conn.executemany(
        "INSERT OR IGNORE INTO alert_evidence (alert_id, event_id) VALUES (?, ?)",
        [(alert_id, eid) for eid in event_ids if eid],
    )


def get_alert_evidence(conn: sqlite3.Connection, alert_id: int) -> List[sqlite3.Row]:
    """Return full event rows for all evidence linked to an alert."""
    return conn.execute(
        """SELECT e.* FROM events e
           JOIN alert_evidence ae ON ae.event_id = e.id
           WHERE ae.alert_id = ?
           ORDER BY e.timestamp""",
        (alert_id,),
    ).fetchall()


# --------------------------------------------------------------------------
# incidents
# --------------------------------------------------------------------------

def insert_incident(conn: sqlite3.Connection, title: str, description: str = "",
                    severity: str = "medium") -> int:
    valid_sev = {"low", "medium", "high", "critical"}
    if severity not in valid_sev:
        raise ValueError(f"severity must be one of {sorted(valid_sev)}")
    cur = conn.execute(
        "INSERT INTO incidents (title, description, severity) VALUES (?, ?, ?)",
        (title.strip(), description.strip(), severity),
    )
    return cur.lastrowid


def get_incident(conn: sqlite3.Connection, incident_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()


def list_incidents(conn: sqlite3.Connection, status: Optional[str] = None,
                   limit: int = 50, offset: int = 0) -> List[sqlite3.Row]:
    if status:
        return conn.execute(
            "SELECT * FROM incidents WHERE status=? ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            (status, limit, offset),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()


def update_incident_status(conn: sqlite3.Connection, incident_id: int,
                            status: str) -> bool:
    valid = {"open", "in_progress", "closed"}
    if status not in valid:
        raise ValueError(f"status must be one of {sorted(valid)}")
    cur = conn.execute(
        """UPDATE incidents SET status=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
           WHERE id=?""",
        (status, incident_id),
    )
    return cur.rowcount > 0


def link_alert_to_incident(conn: sqlite3.Connection, incident_id: int,
                             alert_id: int) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
        (incident_id, alert_id),
    )
    conn.execute(
        "INSERT OR IGNORE INTO incident_alert (incident_id, alert_id) VALUES (?, ?)",
        (incident_id, alert_id),
    )


def get_incident_alerts(conn: sqlite3.Connection, incident_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        """SELECT a.* FROM alerts a
           JOIN incident_alert ia ON ia.alert_id = a.id
           WHERE ia.incident_id = ?
           ORDER BY a.last_seen DESC""",
        (incident_id,),
    ).fetchall()


# --------------------------------------------------------------------------
# incident_notes
# --------------------------------------------------------------------------

def insert_incident_note(conn: sqlite3.Connection, incident_id: int,
                          note: str, author: str = "analyst") -> int:
    note = note.strip()
    if not note:
        raise ValueError("note must not be empty")
    cur = conn.execute(
        "INSERT INTO incident_notes (incident_id, author, body, note) VALUES (?, ?, ?, ?)",
        (incident_id, author.strip() or "analyst", note, note),
    )
    # bump incident updated_at
    conn.execute(
        "UPDATE incidents SET updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?",
        (incident_id,),
    )
    return cur.lastrowid



def list_incident_notes(conn: sqlite3.Connection,
                         incident_id: int) -> List[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM incident_notes WHERE incident_id=? ORDER BY created_at",
        (incident_id,),
    ).fetchall()


# --------------------------------------------------------------------------
# Active Defense & Auto-Prevention (Quarantine, Actions, Settings)
# --------------------------------------------------------------------------

def block_ip(conn: sqlite3.Connection, ip_address: str, reason: str,
             rule_id: Optional[str] = None, severity: str = "high",
             blocked_by: str = "auto_defense") -> int:
    """Add or re-activate an IP in the quarantine blocklist."""
    ip_clean = ip_address.strip()
    valid_sev = {"low", "medium", "high", "critical"}
    if severity not in valid_sev:
        severity = "high"
    
    cur = conn.execute(
        """INSERT INTO blocked_ips (ip_address, reason, rule_id, severity, blocked_by, status, blocked_at)
           VALUES (?, ?, ?, ?, ?, 'active', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
           ON CONFLICT(ip_address) DO UPDATE SET
             reason = excluded.reason,
             rule_id = COALESCE(excluded.rule_id, blocked_ips.rule_id),
             severity = excluded.severity,
             blocked_by = excluded.blocked_by,
             status = 'active',
             blocked_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')""",
        (ip_clean, reason.strip(), rule_id, severity, blocked_by),
    )
    return cur.lastrowid


def unblock_ip(conn: sqlite3.Connection, ip_address: str) -> bool:
    """Set quarantine status to unblocked for a given IP."""
    cur = conn.execute(
        "UPDATE blocked_ips SET status = 'unblocked' WHERE ip_address = ?",
        (ip_address.strip(),),
    )
    return cur.rowcount > 0


def is_ip_blocked(conn: sqlite3.Connection, ip_address: Optional[str]) -> bool:
    """Check whether an IP is currently actively blocked."""
    if not ip_address:
        return False
    row = conn.execute(
        "SELECT 1 FROM blocked_ips WHERE ip_address = ? AND status = 'active'",
        (ip_address.strip(),),
    ).fetchone()
    return row is not None


def list_blocked_ips(conn: sqlite3.Connection, status: Optional[str] = None) -> List[sqlite3.Row]:
    """Return blocked IPs, optionally filtered by status ('active' or 'unblocked')."""
    if status:
        return conn.execute(
            "SELECT * FROM blocked_ips WHERE status = ? ORDER BY blocked_at DESC",
            (status,),
        ).fetchall()
    return conn.execute(
        "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()


def record_defense_action(conn: sqlite3.Connection, action_type: str,
                          target_ip: str, rule_id: Optional[str],
                          details: str) -> int:
    """Audit log entry for automated or manual defense interventions."""
    cur = conn.execute(
        """INSERT INTO defense_actions (action_type, target_ip, rule_id, details)
           VALUES (?, ?, ?, ?)""",
        (action_type, target_ip.strip(), rule_id, details.strip()),
    )
    return cur.lastrowid


# --------------------------------------------------------------------------
# endpoint_events
# --------------------------------------------------------------------------

def get_endpoint_event(conn: sqlite3.Connection, event_id: str) -> Optional[sqlite3.Row]:
    """Retrieve a single endpoint event by its unique UUID event_id."""
    return conn.execute(
        "SELECT * FROM endpoint_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()


def insert_endpoint_event(
    conn: sqlite3.Connection,
    event_id: str,
    device_id: str,
    timestamp: str,
    source: str,
    event_type: str,
    severity: str,
    schema_version: str = "1.0.0",
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    raw_event: Optional[str] = None,
    attributes: str = "{}",
) -> int:
    """Insert an endpoint event record. Returns the new integer row id."""
    cur = conn.execute(
        """INSERT INTO endpoint_events
           (event_id, device_id, timestamp, source, event_type, severity,
            schema_version, source_ip, username, raw_event, attributes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event_id,
            device_id,
            timestamp,
            source,
            event_type,
            severity,
            schema_version,
            source_ip,
            username,
            raw_event,
            attributes,
        ),
    )
    return cur.lastrowid


def list_defense_actions(conn: sqlite3.Connection, limit: int = 50) -> List[sqlite3.Row]:
    """Return recent defense actions for the admin telemetry feed."""
    return conn.execute(
        "SELECT * FROM defense_actions ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()


def get_defense_setting(conn: sqlite3.Connection, key: str, default: str = "true") -> str:
    row = conn.execute("SELECT value FROM defense_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_defense_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """INSERT INTO defense_settings (key, value) VALUES (?, ?)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
        (key, str(value)),
    )


def get_defense_summary(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Telemetry summary for SOC dashboard defense card."""
    active_blocks = conn.execute(
        "SELECT COUNT(*) FROM blocked_ips WHERE status = 'active'"
    ).fetchone()[0]
    total_actions = conn.execute(
        "SELECT COUNT(*) FROM defense_actions"
    ).fetchone()[0]
    auto_defense_on = get_defense_setting(conn, "auto_defense_enabled", "true").lower() == "true"
    
    return {
        "auto_defense_enabled": auto_defense_on,
        "active_quarantined_ips": active_blocks,
        "total_defense_actions": total_actions,
    }


def list_endpoint_events(
    conn: sqlite3.Connection,
    device_id: Optional[str] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[sqlite3.Row]:
    """Filtered endpoint events query."""
    clauses, params = [], []
    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if source:
        clauses.append("source = ?")
        params.append(source)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source_ip:
        clauses.append("source_ip = ?")
        params.append(source_ip)
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp <= ?")
        params.append(until)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    return conn.execute(
        f"SELECT * FROM endpoint_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def count_endpoint_events(conn: sqlite3.Connection) -> int:
    """Return total number of endpoint events stored."""
    return conn.execute("SELECT COUNT(*) FROM endpoint_events").fetchone()[0]
