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
from datetime import datetime, timezone
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
                event_type: Optional[str] = None, host: Optional[str] = None,
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
    if host:
        clauses.append("(host = ? OR host LIKE ?)")
        params.extend([host, f"{host}.%"])
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
           (rule_id, rule_name, severity, status, source_ip, target_host,
            first_seen, last_seen, summary, explanation, settings)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert["rule_id"],
            alert["rule_name"],
            alert["severity"],
            alert.get("status", "new"),
            alert["source_ip"],
            alert.get("target_host"),
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
                 explanation: str, target_host: Optional[str] = None) -> None:
    """Update mutable fields of an existing alert (evidence-driven update)."""
    if target_host is not None:
        conn.execute(
            """UPDATE alerts SET severity=?, last_seen=?, summary=?, explanation=?, target_host=?,
               updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
               WHERE id=?""",
            (severity, last_seen, summary, explanation, target_host, alert_id),
        )
    else:
        conn.execute(
            """UPDATE alerts SET severity=?, last_seen=?, summary=?, explanation=?,
               updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
               WHERE id=?""",
            (severity, last_seen, summary, explanation, alert_id),
        )


def update_alert_status(conn: sqlite3.Connection, alert_id: int, status: str,
                        actor: str = "SOC Analyst", reason: str = "") -> bool:
    """Set alert status and record status audit trail. Returns True if a row was found."""
    valid = {"new", "investigating", "resolved", "false_positive"}
    if status not in valid:
        raise ValueError(f"status must be one of {sorted(valid)}")

    row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        return False
    old_status = row["status"]

    cur = conn.execute(
        """UPDATE alerts SET status=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
           WHERE id=?""",
        (status, alert_id),
    )
    if cur.rowcount > 0:
        conn.execute(
            """INSERT INTO alert_status_history (alert_id, old_status, new_status, actor, reason)
               VALUES (?, ?, ?, ?, ?)""",
            (alert_id, old_status, status, (actor or "SOC Analyst").strip(), (reason or "").strip()),
        )
        return True
    return False


def get_alert_status_history(conn: sqlite3.Connection, alert_id: int) -> List[sqlite3.Row]:
    """Return chronological status audit history for an alert."""
    return conn.execute(
        """SELECT * FROM alert_status_history
           WHERE alert_id = ?
           ORDER BY changed_at ASC, id ASC""",
        (alert_id,),
    ).fetchall()


def update_alert_assignee(conn: sqlite3.Connection, alert_id: int,
                          assignee: Optional[str], actor: str = "SOC Analyst") -> bool:
    """Assign or reassign an alert to an analyst. Records action in status audit history."""
    clean_assignee = assignee.strip() if assignee else None
    cur = conn.execute(
        """UPDATE alerts SET assignee = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
           WHERE id = ?""",
        (clean_assignee, alert_id),
    )
    if cur.rowcount > 0:
        row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        cur_status = row["status"] if row else "new"
        conn.execute(
            """INSERT INTO alert_status_history (alert_id, old_status, new_status, actor, reason)
               VALUES (?, ?, ?, ?, ?)""",
            (
                alert_id,
                cur_status,
                cur_status,
                (actor or "SOC Analyst").strip(),
                f"Assigned alert ownership to: {clean_assignee or 'Unassigned'}",
            ),
        )
        return True
    return False


def insert_alert_note(conn: sqlite3.Connection, alert_id: int, note: str,
                      author: str = "SOC Analyst") -> int:
    """Add an investigation note to an alert."""
    clean_note = note.strip()
    if not clean_note:
        raise ValueError("note must not be empty")
    cur = conn.execute(
        """INSERT INTO alert_notes (alert_id, author, note)
           VALUES (?, ?, ?)""",
        (alert_id, (author or "SOC Analyst").strip(), clean_note),
    )
    conn.execute(
        "UPDATE alerts SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?",
        (alert_id,),
    )
    return cur.lastrowid


def list_alert_notes(conn: sqlite3.Connection, alert_id: int) -> List[sqlite3.Row]:
    """Return all investigation notes for an alert in chronological order."""
    return conn.execute(
        """SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY created_at ASC, id ASC""",
        (alert_id,),
    ).fetchall()


def get_alert(conn: sqlite3.Connection, alert_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()


def list_alerts(conn: sqlite3.Connection, status: Optional[str] = None,
                severity: Optional[str] = None, rule_id: Optional[str] = None,
                source_ip: Optional[str] = None, target_host: Optional[str] = None,
                assignee: Optional[str] = None,
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
    if target_host:
        clauses.append("target_host = ?")
        params.append(target_host)
    if assignee:
        clauses.append("assignee = ?")
        params.append(assignee)
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


def count_alerts_by_status(conn: sqlite3.Connection) -> Dict[str, int]:
    """Return counts of alerts grouped by operational triage status."""
    rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"
    ).fetchall()
    return {r["status"]: r["n"] for r in rows}


def get_timeseries_buckets(
    conn: sqlite3.Connection,
    table: str = "events",
    target_buckets: int = 24,
) -> List[Dict[str, Any]]:
    """Generate time-series buckets with zero-filled gaps across all records in table."""
    valid_tables = {"events": "timestamp", "alerts": "last_seen"}
    if table not in valid_tables:
        raise ValueError(f"Invalid table for timeseries: {table}")
    col = valid_tables[table]

    rows = conn.execute(
        f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL ORDER BY {col} ASC"
    ).fetchall()
    if not rows:
        return []

    def _parse_ts(val: str) -> Optional[int]:
        try:
            val_clean = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(val_clean)
            return int(dt.timestamp())
        except Exception:
            return None

    epochs = [_parse_ts(r[0]) for r in rows if _parse_ts(r[0]) is not None]
    if not epochs:
        return []

    min_ts, max_ts = min(epochs), max(epochs)
    range_sec = max(max_ts - min_ts, 3600)  # at least 1 hour span

    standard_sizes = [60, 300, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400]
    bucket_sec = 86400
    for s in standard_sizes:
        if range_sec / s <= target_buckets:
            bucket_sec = s
            break

    start_bucket = (min_ts // bucket_sec) * bucket_sec
    end_bucket = (max_ts // bucket_sec) * bucket_sec

    # Zero-fill all buckets in the span
    bucket_counts: Dict[int, int] = {
        b: 0 for b in range(start_bucket, end_bucket + bucket_sec, bucket_sec)
    }
    for t in epochs:
        b = (t // bucket_sec) * bucket_sec
        if b in bucket_counts:
            bucket_counts[b] += 1

    results = []
    use_date = bucket_sec >= 86400 or range_sec > 86400
    for b in sorted(bucket_counts.keys()):
        dt = datetime.fromtimestamp(b, tz=timezone.utc)
        if use_date:
            label = dt.strftime("%b %d, %H:%M UTC")
        else:
            label = dt.strftime("%H:%M UTC")
        results.append({
            "epoch": b,
            "iso": dt.isoformat(),
            "label": label,
            "count": bucket_counts[b],
        })
    return results


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
                    severity: str = "medium", assignee: Optional[str] = None) -> int:
    valid_sev = {"low", "medium", "high", "critical"}
    if severity not in valid_sev:
        raise ValueError(f"severity must be one of {sorted(valid_sev)}")
    cur = conn.execute(
        "INSERT INTO incidents (title, description, severity, assignee) VALUES (?, ?, ?, ?)",
        (title.strip(), description.strip(), severity, (assignee or "").strip() or None),
    )
    return cur.lastrowid


def get_incident(conn: sqlite3.Connection, incident_id: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()


def list_incidents(conn: sqlite3.Connection, status: Optional[str] = None,
                   severity: Optional[str] = None, assignee: Optional[str] = None,
                   search: Optional[str] = None,
                   limit: int = 50, offset: int = 0) -> List[sqlite3.Row]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if assignee:
        clauses.append("assignee = ?")
        params.append(assignee)
    if search:
        clauses.append("(title LIKE ? OR description LIKE ?)")
        term = f"%{search.strip()}%"
        params.extend([term, term])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    return conn.execute(
        f"SELECT * FROM incidents {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()


def update_incident(conn: sqlite3.Connection, incident_id: int,
                    title: Optional[str] = None, description: Optional[str] = None,
                    severity: Optional[str] = None, status: Optional[str] = None,
                    assignee: Optional[str] = None, close_reason: Optional[str] = None) -> bool:
    updates, params = [], []
    if title is not None:
        if not title.strip():
            raise ValueError("title must not be empty")
        updates.append("title = ?")
        params.append(title.strip())
    if description is not None:
        updates.append("description = ?")
        params.append(description.strip())
    if severity is not None:
        valid_sev = {"low", "medium", "high", "critical"}
        if severity.lower() not in valid_sev:
            raise ValueError(f"severity must be one of {sorted(valid_sev)}")
        updates.append("severity = ?")
        params.append(severity.lower())
    if status is not None:
        valid_status = {"open", "in_progress", "resolved", "closed"}
        if status.lower() not in valid_status:
            raise ValueError(f"status must be one of {sorted(valid_status)}")
        updates.append("status = ?")
        params.append(status.lower())
    if assignee is not None:
        updates.append("assignee = ?")
        params.append(assignee.strip() or None)
    if close_reason is not None:
        updates.append("close_reason = ?")
        params.append(close_reason.strip())

    if not updates:
        return False

    updates.append("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
    params.append(incident_id)
    cur = conn.execute(
        f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?",
        params,
    )
    return cur.rowcount > 0


def update_incident_status(conn: sqlite3.Connection, incident_id: int,
                            status: str, close_reason: Optional[str] = None) -> bool:
    valid = {"open", "in_progress", "resolved", "closed"}
    if status not in valid:
        raise ValueError(f"status must be one of {sorted(valid)}")
    if close_reason is not None:
        cur = conn.execute(
            """UPDATE incidents SET status = ?, close_reason = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
               WHERE id = ?""",
            (status, close_reason.strip(), incident_id),
        )
    else:
        cur = conn.execute(
            """UPDATE incidents SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
               WHERE id = ?""",
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


def unlink_alert_from_incident(conn: sqlite3.Connection, incident_id: int,
                               alert_id: int) -> bool:
    cur1 = conn.execute("DELETE FROM incident_alerts WHERE incident_id = ? AND alert_id = ?", (incident_id, alert_id))
    cur2 = conn.execute("DELETE FROM incident_alert WHERE incident_id = ? AND alert_id = ?", (incident_id, alert_id))
    conn.execute("UPDATE incidents SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?", (incident_id,))
    return (cur1.rowcount > 0 or cur2.rowcount > 0)


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


# --------------------------------------------------------------------------
# detection_rules & rule_audit_log
# --------------------------------------------------------------------------

def list_detection_rules(conn: sqlite3.Connection, enabled: Optional[int] = None,
                         severity: Optional[str] = None, search: Optional[str] = None) -> List[sqlite3.Row]:
    """Retrieve all detection rules with optional enabled, severity, or search filter."""
    clauses, params = [], []
    if enabled is not None:
        clauses.append("enabled = ?")
        params.append(1 if enabled else 0)
    if severity:
        clauses.append("severity = ?")
        params.append(severity.lower())
    if search:
        clauses.append("(rule_id LIKE ? OR name LIKE ? OR description LIKE ?)")
        term = f"%{search.strip()}%"
        params.extend([term, term, term])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return conn.execute(
        f"SELECT * FROM detection_rules {where} ORDER BY rule_id ASC",
        params,
    ).fetchall()


def get_detection_rule(conn: sqlite3.Connection, rule_id: str) -> Optional[sqlite3.Row]:
    """Retrieve a single detection rule by ID."""
    return conn.execute(
        "SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id.strip().upper(),)
    ).fetchone()


def insert_detection_rule(conn: sqlite3.Connection, rule_id: str, name: str,
                          description: str = "", severity: str = "medium",
                          enabled: int = 1, threshold: int = 5,
                          window_minutes: int = 5, conditions: str = "{}") -> int:
    """Insert a new detection rule record. Returns new row id."""
    clean_id = rule_id.strip().upper()
    if not clean_id:
        raise ValueError("rule_id must not be empty")
    if not name.strip():
        raise ValueError("name must not be empty")
    valid_sev = {"low", "medium", "high", "critical"}
    if severity.lower() not in valid_sev:
        raise ValueError(f"severity must be one of {sorted(valid_sev)}")
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be >= 1")

    cur = conn.execute(
        """INSERT INTO detection_rules
           (rule_id, name, description, severity, enabled, threshold, window_minutes, conditions)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (clean_id, name.strip(), description.strip(), severity.lower(),
         1 if enabled else 0, threshold, window_minutes, conditions),
    )
    return cur.lastrowid


def update_detection_rule(conn: sqlite3.Connection, rule_id: str,
                          name: Optional[str] = None, description: Optional[str] = None,
                          severity: Optional[str] = None, enabled: Optional[int] = None,
                          threshold: Optional[int] = None, window_minutes: Optional[int] = None,
                          conditions: Optional[str] = None) -> bool:
    """Update detection rule parameters."""
    clean_id = rule_id.strip().upper()
    updates, params = [], []
    if name is not None:
        if not name.strip():
            raise ValueError("name must not be empty")
        updates.append("name = ?")
        params.append(name.strip())
    if description is not None:
        updates.append("description = ?")
        params.append(description.strip())
    if severity is not None:
        valid_sev = {"low", "medium", "high", "critical"}
        if severity.lower() not in valid_sev:
            raise ValueError(f"severity must be one of {sorted(valid_sev)}")
        updates.append("severity = ?")
        params.append(severity.lower())
    if enabled is not None:
        updates.append("enabled = ?")
        params.append(1 if enabled else 0)
    if threshold is not None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        updates.append("threshold = ?")
        params.append(threshold)
    if window_minutes is not None:
        if window_minutes < 1:
            raise ValueError("window_minutes must be >= 1")
        updates.append("window_minutes = ?")
        params.append(window_minutes)
    if conditions is not None:
        updates.append("conditions = ?")
        params.append(conditions)

    if not updates:
        return False

    updates.append("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')")
    params.append(clean_id)
    cur = conn.execute(
        f"UPDATE detection_rules SET {', '.join(updates)} WHERE rule_id = ?",
        params,
    )
    return cur.rowcount > 0


def insert_rule_audit_log(conn: sqlite3.Connection, rule_id: str, action: str,
                          changed_by: str = "SOC Analyst", details: str = "") -> int:
    """Record an audit trail entry for rule creation, update, or status change."""
    cur = conn.execute(
        """INSERT INTO rule_audit_log (rule_id, action, changed_by, details)
           VALUES (?, ?, ?, ?)""",
        (rule_id.strip().upper(), action.strip(), (changed_by or "SOC Analyst").strip(), details.strip()),
    )
    return cur.lastrowid


def list_rule_audit_logs(conn: sqlite3.Connection, rule_id: Optional[str] = None,
                         limit: int = 50) -> List[sqlite3.Row]:
    """Retrieve audit trail logs for rule modifications."""
    if rule_id:
        return conn.execute(
            """SELECT * FROM rule_audit_log WHERE rule_id = ? ORDER BY changed_at DESC, id DESC LIMIT ?""",
            (rule_id.strip().upper(), limit),
        ).fetchall()
    return conn.execute(
        """SELECT * FROM rule_audit_log ORDER BY changed_at DESC, id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


# --------------------------------------------------------------------------
# endpoints fleet management
# --------------------------------------------------------------------------

def list_endpoints(conn: sqlite3.Connection, status: Optional[str] = None,
                   os_type: Optional[str] = None, search: Optional[str] = None,
                   limit: int = 100, offset: int = 0) -> List[sqlite3.Row]:
    """List endpoint devices with telemetry summary and filters."""
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status.lower())
    if os_type:
        clauses.append("os = ?")
        params.append(os_type.lower())
    if search:
        clauses.append("(device_id LIKE ? OR hostname LIKE ? OR ip_address LIKE ?)")
        term = f"%{search.strip()}%"
        params.extend([term, term, term])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]
    return conn.execute(
        f"""SELECT e.*,
                   ((SELECT COUNT(*) FROM endpoint_events ee
                     WHERE ee.device_id = e.device_id) +
                    (SELECT COUNT(*) FROM events ev
                     JOIN log_files lf ON lf.id = ev.log_file_id
                     WHERE (ev.host = e.hostname OR ev.host = e.device_id)
                       AND lf.filename NOT LIKE 'endpoint-agent:%'))
                   AS event_count
            FROM endpoints e
            {where}
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?""",
        params,
    ).fetchall()


def get_endpoint(conn: sqlite3.Connection, device_id: str) -> Optional[sqlite3.Row]:
    """Retrieve a single endpoint record by device_id."""
    return conn.execute(
        """SELECT e.*,
                  ((SELECT COUNT(*) FROM endpoint_events ee
                     WHERE ee.device_id = e.device_id) +
                    (SELECT COUNT(*) FROM events ev
                     JOIN log_files lf ON lf.id = ev.log_file_id
                     WHERE (ev.host = e.hostname OR ev.host = e.device_id)
                       AND lf.filename NOT LIKE 'endpoint-agent:%'))
                   AS event_count
           FROM endpoints e
           WHERE e.device_id = ?""",
        (device_id.strip(),),
    ).fetchone()


def insert_endpoint(conn: sqlite3.Connection, device_id: str, hostname: str,
                    os: str = "linux", status: str = "enrolled",
                    ip_address: Optional[str] = None, agent_version: str = "1.0.0",
                    metadata: str = "{}") -> None:
    """Enroll or register an endpoint record."""
    valid_status = {"active", "disabled", "offline", "enrolled"}
    clean_status = status.lower() if status.lower() in valid_status else "enrolled"
    conn.execute(
        """INSERT INTO endpoints
           (device_id, hostname, os, status, ip_address, agent_version, metadata)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (device_id.strip(), hostname.strip(), os.strip().lower(), clean_status,
         ip_address, agent_version, metadata),
    )


def update_endpoint_status(conn: sqlite3.Connection, device_id: str, status: str) -> bool:
    """Update endpoint operational lifecycle status (e.g. active vs disabled)."""
    valid_status = {"active", "disabled", "offline", "enrolled"}
    if status.lower() not in valid_status:
        raise ValueError(f"status must be one of {sorted(valid_status)}")
    cur = conn.execute(
        "UPDATE endpoints SET status = ? WHERE device_id = ?",
        (status.lower(), device_id.strip()),
    )
    return cur.rowcount > 0


def update_endpoint(conn: sqlite3.Connection, device_id: str,
                    hostname: Optional[str] = None, status: Optional[str] = None,
                    ip_address: Optional[str] = None, metadata: Optional[str] = None) -> bool:
    """Update endpoint hostname, status, or metadata."""
    updates, params = [], []
    if hostname is not None:
        updates.append("hostname = ?")
        params.append(hostname.strip())
    if status is not None:
        valid_status = {"active", "disabled", "offline", "enrolled"}
        if status.lower() not in valid_status:
            raise ValueError(f"status must be one of {sorted(valid_status)}")
        updates.append("status = ?")
        params.append(status.lower())
    if ip_address is not None:
        updates.append("ip_address = ?")
        params.append(ip_address.strip() or None)
    if metadata is not None:
        updates.append("metadata = ?")
        params.append(metadata)

    if not updates:
        return False
    params.append(device_id.strip())
    cur = conn.execute(f"UPDATE endpoints SET {', '.join(updates)} WHERE device_id = ?", params)
    return cur.rowcount > 0


def upsert_endpoint_from_event(conn: sqlite3.Connection, device_id: str,
                               timestamp: str, source: str,
                               source_ip: Optional[str] = None,
                               hostname: Optional[str] = None) -> None:
    """Update or register an endpoint record when an agent reports an event."""
    clean_dev = device_id.strip()
    os_guess = "windows" if "win" in source.lower() else "linux"
    cur = conn.execute(
        """UPDATE endpoints
           SET last_seen = MAX(last_seen, ?),
               ip_address = COALESCE(?, ip_address)
           WHERE device_id = ?""",
        (timestamp, source_ip, clean_dev),
    )
    if cur.rowcount == 0:
        default_host = hostname or f"{clean_dev[:8]}-host"
        conn.execute(
            """INSERT OR IGNORE INTO endpoints
               (device_id, hostname, os, status, ip_address, last_seen, registered_at)
               VALUES (?, ?, ?, 'active', ?, ?, ?)""",
            (clean_dev, default_host, os_guess, source_ip, timestamp, timestamp),
        )
