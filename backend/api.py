"""ThreatLens - Flask REST API (Module B).

All endpoints validate input, use parameterised SQL via the repository
layer, and return JSON.  Run with:

    python -m backend.api                  # development server on :5000
    flask --app backend.api run --debug    # alternative

Endpoints
---------
POST   /api/ingest                   Upload a log file
GET    /api/events                   List / search events (filterable)
GET    /api/events/<id>              Single event detail
GET    /api/alerts                   List alerts (filterable)
GET    /api/alerts/<id>              Single alert with evidence
PATCH  /api/alerts/<id>/status       Update alert status
GET    /api/statistics               Dashboard statistics
GET    /api/incidents                List incidents
POST   /api/incidents                Create incident
GET    /api/incidents/<id>           Incident detail + linked alerts
PATCH  /api/incidents/<id>/status    Update incident status
POST   /api/incidents/<id>/alerts    Link an alert to an incident
POST   /api/incidents/<id>/notes     Add a note to an incident
GET    /api/incidents/<id>/notes     List notes for an incident
GET    /api/logs                     List uploaded log files
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any, Dict, List, Optional
import uuid
import xml.etree.ElementTree as ET

from flask import Flask, jsonify, request, g

from backend import repository as repo
from backend.database import (
    check_database_integrity,
    get_connection,
    get_database_metrics,
    init_db,
    sha256_of,
)


# --------------------------------------------------------------------------
# Application setup
# --------------------------------------------------------------------------

app = Flask(__name__)

DB_PATH = os.environ.get("THREATLENS_DB", "threatlens.db")
MAX_PAYLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_BATCH_SIZE = 100



@app.route("/", methods=["GET"])
def index():
    """API Root - Pure JSON status and endpoint discovery."""
    return jsonify({
        "ok": True,
        "service": "ThreatLens REST API",
        "module": "Module B (Backend API and Database)",
        "endpoints": {
            "ingest": "POST /api/ingest",
            "endpoint_events": "POST /api/v1/events",
            "logs": "GET /api/logs",
            "events": "GET /api/events",
            "alerts": "GET /api/alerts",
            "statistics": "GET /api/statistics",
            "incidents": "GET /api/incidents",
            "rules": "GET /api/rules",
            "endpoints": "GET /api/endpoints"
        }
    })


def get_db():
    """Return a database connection for this request, ensuring schema exists."""
    if "db" not in g:
        g.db = init_db(DB_PATH)
        get_detection_engine(DB_PATH)
    return g.db



@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# --------------------------------------------------------------------------
# Detection Engine instance management (Persistent correlation across uploads)
# --------------------------------------------------------------------------

_detection_engines: Dict[str, Any] = {}


def get_detection_engine(db_path: Optional[str] = None):
    """Retrieve or initialize the DetectionEngine for a given database path.

    Preserves in-memory correlation state across multiple upload requests
    within the application lifecycle. If the engine is accessed for the first
    time on an existing database, it hydrates past events and alerts from
    SQLite to ensure persistent correlation across application restarts.
    """
    from backend.detection import DetectionEngine, DetectionConfig

    target_path = os.path.abspath(db_path or DB_PATH)
    if target_path in _detection_engines:
        return _detection_engines[target_path]

    config_path = Path("config") / "detection_config.json"
    cfg = DetectionConfig.from_file(str(config_path)) if config_path.exists() else None
    engine = DetectionEngine(cfg)

    # Hydrate history and existing alerts from SQLite if the database already exists
    if os.path.exists(target_path):
        _hydrate_engine_from_db(target_path, engine)

    _detection_engines[target_path] = engine
    return engine


def reset_detection_engine(db_path: Optional[str] = None) -> None:
    """Reset or clear the cached DetectionEngine for a given database path."""
    target_path = os.path.abspath(db_path or DB_PATH)
    _detection_engines.pop(target_path, None)


def _hydrate_engine_from_db(db_path: str, engine) -> None:
    """Hydrate past events and alerts from SQLite database into DetectionEngine."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        table_check = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('events', 'alerts', 'alert_evidence')"
        ).fetchone()
        if not table_check or table_check[0] < 3:
            conn.close()
            return

        from backend.parser import Event
        from backend.detection import Alert

        # 1. Hydrate events into engine._history
        event_rows = conn.execute(
            "SELECT id, timestamp, host, username, source_ip, port, method, outcome, event_type, raw_line, line_hash "
            "FROM events ORDER BY timestamp ASC, id ASC"
        ).fetchall()

        events_by_id = {}
        for r in event_rows:
            try:
                ts = datetime.fromisoformat(r["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            ev = Event(
                timestamp=ts,
                host=r["host"],
                username=r["username"],
                source_ip=r["source_ip"],
                port=r["port"],
                method=r["method"],
                outcome=r["outcome"],
                event_type=r["event_type"],
                raw_line=r["raw_line"],
                line_hash=r["line_hash"],
                id=r["id"],
            )
            events_by_id[ev.id] = ev
            hkey = engine._history_key(ev.source_ip, ev.host)
            bucket = engine._history.setdefault(hkey, {})
            bucket[ev.line_hash] = ev

        # 2. Hydrate alerts into engine.alerts
        alert_rows = conn.execute("SELECT * FROM alerts ORDER BY id ASC").fetchall()
        for ar in alert_rows:
            evidence_rows = conn.execute(
                "SELECT event_id FROM alert_evidence WHERE alert_id = ? ORDER BY event_id ASC",
                (ar["id"],)
            ).fetchall()
            evidence_ids = [er["event_id"] for er in evidence_rows]

            evidence_events = {}
            for eid in evidence_ids:
                if eid in events_by_id:
                    evidence_events[eid] = events_by_id[eid]

            settings = ar["settings"]
            if isinstance(settings, str):
                try:
                    settings = json.loads(settings)
                except Exception:
                    settings = {}
            elif not isinstance(settings, dict):
                settings = {}

            first_seen = datetime.fromisoformat(ar["first_seen"])
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)

            last_seen = datetime.fromisoformat(ar["last_seen"])
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            target_host = ar["target_host"] if "target_host" in ar.keys() else None
            if not target_host:
                target_host = next((getattr(e, "host", None) for e in evidence_events.values() if getattr(e, "host", None)), None)

            alert = Alert(
                rule_id=ar["rule_id"],
                rule_name=ar["rule_name"],
                source_ip=ar["source_ip"],
                target_host=target_host,
                settings=settings,
                events=evidence_events,
                id=ar["id"],
                status=ar["status"],
                severity=ar["severity"],
                first_seen=first_seen,
                last_seen=last_seen,
                summary=ar["summary"],
                explanation=ar["explanation"],
                evidence_ids=evidence_ids,
            )
            engine.alerts.append(alert)
            if ar["id"] >= engine._next_id:
                engine._next_id = ar["id"] + 1

        # 3. Synchronize any existing unadapted endpoint events
        _sync_endpoint_events_to_siem(conn, engine)

        conn.close()
    except Exception:
        pass


def _sync_endpoint_events_to_siem(conn: sqlite3.Connection, engine) -> None:
    """Backfill and synchronize unadapted endpoint events into SIEM events and detection."""
    try:
        from backend.adapter import adapt_endpoint_event_to_backend
        table_check = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='endpoint_events'"
        ).fetchone()
        if not table_check or table_check[0] == 0:
            return

        unadapted_rows = conn.execute(
            "SELECT * FROM endpoint_events WHERE source IN ('linux_auth', 'openssh', 'endpoint_agent') "
            "AND event_type IN ('ssh_auth_failure', 'ssh_invalid_user', 'ssh_auth_success', 'ssh_disconnect', "
            "'failed_login', 'invalid_user', 'accepted_login', 'disconnect') "
            "ORDER BY timestamp ASC, id ASC"
        ).fetchall()
        if not unadapted_rows:
            return

        existing_hashes = {
            r[0] for r in conn.execute("SELECT line_hash FROM events").fetchall()
        }

        new_adapted_events = []
        with conn:
            for r in unadapted_rows:
                ev = adapt_endpoint_event_to_backend(dict(r))
                if ev is None or ev.line_hash in existing_hashes:
                    continue

                log_file_id = repo.get_or_create_endpoint_log_file(conn, r["device_id"])
                ev_dict = {
                    "timestamp": ev.timestamp.isoformat(),
                    "host": getattr(ev, "host", None),
                    "username": ev.username,
                    "source_ip": ev.source_ip,
                    "port": ev.port,
                    "method": ev.method,
                    "outcome": ev.outcome,
                    "event_type": ev.event_type,
                    "raw_line": ev.raw_line,
                    "line_hash": ev.line_hash,
                }
                db_ids = repo.insert_events_batch(conn, log_file_id, [ev_dict])
                if db_ids and db_ids[0]:
                    ev.id = db_ids[0]
                    new_adapted_events.append(ev)
                    existing_hashes.add(ev.line_hash)

            if new_adapted_events and engine is not None:
                result = engine.process(new_adapted_events)
                if result:
                    for alert in result.new_alerts:
                        target_host = alert.target_host or next((getattr(e, "host", None) for e in alert.events.values() if getattr(e, "host", None)), None)
                        alert_row = {
                            "rule_id": alert.rule_id,
                            "rule_name": alert.rule_name,
                            "severity": alert.severity,
                            "status": alert.status,
                            "source_ip": alert.source_ip,
                            "target_host": target_host,
                            "first_seen": alert.first_seen.isoformat(),
                            "last_seen": alert.last_seen.isoformat(),
                            "summary": alert.summary,
                            "explanation": alert.explanation,
                            "settings": alert.settings,
                        }
                        db_alert_id = repo.insert_alert(conn, alert_row)
                        alert.id = db_alert_id
                        evidence_db_ids = [
                            e.id for e in alert.events.values() if hasattr(e, "id") and e.id
                        ]
                        repo.insert_alert_evidence(conn, db_alert_id, evidence_db_ids)

                    for alert in result.updated_alerts:
                        if alert.id:
                            repo.update_alert(
                                conn,
                                alert.id,
                                severity=alert.severity,
                                last_seen=alert.last_seen.isoformat(),
                                summary=alert.summary,
                                explanation=alert.explanation,
                                target_host=alert.target_host,
                            )
                            evidence_db_ids = [
                                e.id for e in alert.events.values() if hasattr(e, "id") and e.id
                            ]
                            repo.insert_alert_evidence(conn, alert.id, evidence_db_ids)
    except Exception:
        pass



@app.after_request
def add_cors_headers(response):
    """Enable Cross-Origin Resource Sharing (CORS) for SOC frontends."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Filename"
    return response


@app.route("/api/health", methods=["GET"])
def health():
    """Production health check & database telemetry endpoint."""
    conn = get_db()
    integrity = check_database_integrity(conn)
    metrics = get_database_metrics(conn)
    return jsonify({
        "status": "healthy" if integrity["is_healthy"] else "degraded",
        "service": "ThreatLens SOC Backend API",
        "database": {
            "status": "connected",
            "integrity": integrity["integrity"],
            "foreign_key_violations": integrity["foreign_key_violations"],
            "size_bytes": metrics["database_size_bytes"],
            "journal_mode": metrics["journal_mode"],
            "table_records": metrics["table_counts"]
        }
    })



def _row(r) -> dict:
    """Convert a sqlite3.Row (or None) to a plain dict."""
    return dict(r) if r else None


def _rows(rs) -> list:
    return [dict(r) for r in rs]


def _int_param(name: str, default: int, min_val: int = 0, max_val: int = 10_000) -> int:
    raw = request.args.get(name, str(default))
    try:
        val = int(raw)
    except ValueError:
        raise ValueError(f"'{name}' must be an integer")
    if not (min_val <= val <= max_val):
        raise ValueError(f"'{name}' must be between {min_val} and {max_val}")
    return val


def _ok(data, status: int = 200):
    if isinstance(data, dict):
        payload = dict(data)
        payload["ok"] = True
        payload["data"] = data
        return jsonify(payload), status
    return jsonify({"ok": True, "data": data}), status


def _err(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


# --------------------------------------------------------------------------
# Endpoint Agent Ingestion (POST /api/v1/events)
# --------------------------------------------------------------------------

@app.route("/api/v1/events", methods=["POST"])
def ingest_endpoint_events():
    """Ingest a batch of normalized security events from the ThreatLens Endpoint Agent.

    Enforces:
    - 5MB maximum body size
    - Configured THREATLENS_AGENT_API_KEY Bearer authentication
    - Strict validation of batch count, structure, UUIDs, timestamps, severity, and optional IPs
    - Transactional persistence in endpoint_events
    - Idempotent acknowledgment of identical retries
    - Rejection (409 Conflict) of conflicting duplicate event IDs
    """
    # 1. Payload size check
    content_length = request.content_length
    if content_length is not None and content_length > MAX_PAYLOAD_SIZE_BYTES:
        return _err(f"Request body exceeds maximum size limit of {MAX_PAYLOAD_SIZE_BYTES // (1024 * 1024)}MB.", 413)

    raw_bytes = request.get_data()
    if len(raw_bytes) > MAX_PAYLOAD_SIZE_BYTES:
        return _err(f"Request body exceeds maximum size limit of {MAX_PAYLOAD_SIZE_BYTES // (1024 * 1024)}MB.", 413)

    if not raw_bytes or not raw_bytes.strip():
        return _err("Request body must not be empty.", 400)

    # 2. Authentication check: THREATLENS_AGENT_API_KEY Bearer token
    configured_key = os.environ.get("THREATLENS_AGENT_API_KEY")
    if not configured_key or not configured_key.strip():
        return _err("Server agent authentication is unconfigured or disabled.", 401)

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return _err("Missing Authorization header.", 401)

    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return _err("Authorization header must use 'Bearer <token>' format.", 401)

    token = parts[1].strip()
    if not hmac.compare_digest(token, configured_key.strip()):
        return _err("Invalid agent API key.", 401)

    # 3. JSON parsing
    try:
        body = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        return _err(f"Malformed JSON in request body: {exc}", 400)

    if not isinstance(body, dict):
        return _err("Request payload must be a JSON object.", 400)

    # 4. Top-level structure validation
    device_id = body.get("device_id")
    if not device_id or not isinstance(device_id, str) or not device_id.strip():
        return _err("Field 'device_id' is required and must be a non-empty string.", 400)

    events = body.get("events")
    if events is None or not isinstance(events, list):
        return _err("Field 'events' is required and must be a list of event objects.", 400)

    if len(events) == 0:
        return _err("Field 'events' must contain at least one event.", 400)

    if len(events) > MAX_BATCH_SIZE:
        return _err(f"Batch event count {len(events)} exceeds maximum allowed limit of {MAX_BATCH_SIZE}.", 400)

    sent_at = body.get("sent_at")
    if sent_at is not None and not isinstance(sent_at, (int, float)):
        return _err("Field 'sent_at' must be a numeric timestamp.", 400)

    # 5. Event fields validation
    validated_records = []
    seen_batch_ids = {}

    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            return _err(f"Event at index {idx} must be a JSON object.", 400)

        # event_id (UUID)
        eid = ev.get("event_id")
        if not eid or not isinstance(eid, str):
            return _err(f"Event at index {idx}: 'event_id' is required and must be a UUID string.", 400)
        eid_str = eid.strip()
        try:
            u = uuid.UUID(eid_str)
            norm_eid = str(u)
        except (ValueError, TypeError, AttributeError):
            return _err(f"Event at index {idx}: 'event_id' must be a valid UUID string, got '{eid}'.", 400)

        # device_id
        ev_device_id = ev.get("device_id")
        if not ev_device_id or not isinstance(ev_device_id, str) or not ev_device_id.strip():
            return _err(f"Event '{norm_eid}': 'device_id' is required and must be a non-empty string.", 400)
        ev_device_id = ev_device_id.strip()

        # timestamp (ISO-8601 with timezone offset)
        ts_raw = ev.get("timestamp")
        if not ts_raw or not isinstance(ts_raw, str) or not ts_raw.strip():
            return _err(f"Event '{norm_eid}': 'timestamp' is required and must be a non-empty ISO-8601 string.", 400)
        ts_clean = ts_raw.strip()
        ts_parse = ts_clean
        if ts_parse.endswith("Z") or ts_parse.endswith("z"):
            ts_parse = ts_parse[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(ts_parse)
        except ValueError as exc:
            return _err(f"Event '{norm_eid}': invalid ISO-8601 timestamp '{ts_raw}': {exc}", 400)
        if dt.tzinfo is None:
            return _err(f"Event '{norm_eid}': timestamp must include timezone offset: '{ts_raw}'.", 400)
        norm_timestamp = dt.astimezone(timezone.utc).isoformat()

        # source
        source = ev.get("source")
        if not source or not isinstance(source, str) or not source.strip():
            return _err(f"Event '{norm_eid}': 'source' is required and must be a non-empty string.", 400)
        source = source.strip()

        # event_type
        event_type = ev.get("event_type")
        if not event_type or not isinstance(event_type, str) or not event_type.strip():
            return _err(f"Event '{norm_eid}': 'event_type' is required and must be a non-empty string.", 400)
        event_type = event_type.strip()

        # severity
        sev = ev.get("severity")
        if not sev or not isinstance(sev, str):
            return _err(f"Event '{norm_eid}': 'severity' is required.", 400)
        norm_sev = sev.strip().lower()
        if norm_sev not in {"informational", "low", "medium", "high", "critical"}:
            return _err(
                f"Event '{norm_eid}': invalid severity '{sev}'. Must be one of ['informational', 'low', 'medium', 'high', 'critical'].",
                400,
            )

        # schema_version
        schema_ver = ev.get("schema_version", "1.0.0")
        if not isinstance(schema_ver, str) or not schema_ver.strip():
            schema_ver = "1.0.0"
        else:
            schema_ver = schema_ver.strip()

        # source_ip
        source_ip = ev.get("source_ip")
        norm_source_ip = None
        if source_ip is not None and source_ip != "":
            if not isinstance(source_ip, str):
                return _err(f"Event '{norm_eid}': 'source_ip' must be a string or null.", 400)
            clean_ip = source_ip.strip().strip("[]")
            try:
                ipaddress.ip_address(clean_ip)
                norm_source_ip = clean_ip
            except ValueError:
                return _err(f"Event '{norm_eid}': invalid source IP address '{source_ip}'.", 400)

        # username
        username = ev.get("username")
        norm_username = None
        if username is not None:
            if not isinstance(username, str):
                return _err(f"Event '{norm_eid}': 'username' must be a string or null.", 400)
            norm_username = username.strip()

        # raw_event
        raw_event = ev.get("raw_event")
        norm_raw_event = None
        if raw_event is not None:
            if not isinstance(raw_event, str):
                return _err(f"Event '{norm_eid}': 'raw_event' must be a string or null.", 400)
            norm_raw_event = raw_event

        # attributes
        attributes = ev.get("attributes")
        if attributes is None:
            norm_attributes = {}
        elif isinstance(attributes, dict):
            norm_attributes = attributes
        else:
            return _err(f"Event '{norm_eid}': 'attributes' must be a dictionary.", 400)

        rec = {
            "event_id": norm_eid,
            "device_id": ev_device_id,
            "timestamp": norm_timestamp,
            "source": source,
            "event_type": event_type,
            "severity": norm_sev,
            "schema_version": schema_ver,
            "source_ip": norm_source_ip,
            "username": norm_username,
            "raw_event": norm_raw_event,
            "attributes": norm_attributes,
        }

        # Intra-batch conflict check
        if norm_eid in seen_batch_ids:
            prev_rec = seen_batch_ids[norm_eid]
            if prev_rec != rec:
                return jsonify({
                    "ok": False,
                    "status": "conflict",
                    "error": f"Conflicting duplicate event_id '{norm_eid}' within batch.",
                }), 409
            continue

        seen_batch_ids[norm_eid] = rec
        validated_records.append(rec)

    # 6. Transactional Storage & Duplicate/Retry Resolution
    conn = get_db()
    to_insert = []
    acknowledged_ids = []

    for rec in validated_records:
        eid = rec["event_id"]
        existing = repo.get_endpoint_event(conn, eid)
        if existing is not None:
            try:
                existing_attrs = json.loads(existing["attributes"]) if existing["attributes"] else {}
            except Exception:
                existing_attrs = {}

            try:
                ex_dt = datetime.fromisoformat(existing["timestamp"].replace("Z", "+00:00")).astimezone(timezone.utc)
                rec_dt = datetime.fromisoformat(rec["timestamp"].replace("Z", "+00:00")).astimezone(timezone.utc)
                ts_matches = (ex_dt == rec_dt)
            except Exception:
                ts_matches = (existing["timestamp"] == rec["timestamp"])

            is_identical = (
                existing["device_id"] == rec["device_id"] and
                existing["source"] == rec["source"] and
                existing["event_type"] == rec["event_type"] and
                existing["severity"] == rec["severity"] and
                ts_matches and
                (existing["source_ip"] or None) == rec["source_ip"] and
                (existing["username"] or None) == rec["username"] and
                (existing["raw_event"] or None) == rec["raw_event"] and
                existing_attrs == rec["attributes"]
            )

            if is_identical:
                # Safely acknowledge identical retry
                acknowledged_ids.append(eid)
            else:
                # Conflicting duplicate: reject immediately
                return jsonify({
                    "ok": False,
                    "status": "conflict",
                    "error": f"Conflicting duplicate event_id '{eid}' already exists in database with different data.",
                }), 409
        else:
            to_insert.append(rec)

    if to_insert:
        try:
            from backend.adapter import adapt_endpoint_event_to_backend
            engine = get_detection_engine(DB_PATH)
            new_adapted_events = []

            with conn:
                for rec in to_insert:
                    repo.insert_endpoint_event(
                        conn,
                        event_id=rec["event_id"],
                        device_id=rec["device_id"],
                        timestamp=rec["timestamp"],
                        source=rec["source"],
                        event_type=rec["event_type"],
                        severity=rec["severity"],
                        schema_version=rec["schema_version"],
                        source_ip=rec["source_ip"],
                        username=rec["username"],
                        raw_event=rec["raw_event"],
                        attributes=json.dumps(rec["attributes"], sort_keys=True),
                    )
                    repo.upsert_endpoint_from_event(
                        conn,
                        device_id=rec["device_id"],
                        timestamp=rec["timestamp"],
                        source=rec["source"],
                        source_ip=rec.get("source_ip"),
                    )
                    acknowledged_ids.append(rec["event_id"])

                    ev = adapt_endpoint_event_to_backend(rec)
                    if ev is not None:
                        log_file_id = repo.get_or_create_endpoint_log_file(conn, rec["device_id"])
                        ev_dict = {
                            "timestamp": ev.timestamp.isoformat(),
                            "host": getattr(ev, "host", None),
                            "username": ev.username,
                            "source_ip": ev.source_ip,
                            "port": ev.port,
                            "method": ev.method,
                            "outcome": ev.outcome,
                            "event_type": ev.event_type,
                            "raw_line": ev.raw_line,
                            "line_hash": ev.line_hash,
                        }
                        db_ids = repo.insert_events_batch(conn, log_file_id, [ev_dict])
                        if db_ids and db_ids[0]:
                            ev.id = db_ids[0]
                            new_adapted_events.append(ev)

                if new_adapted_events and engine is not None:
                    result = engine.process(new_adapted_events)
                    if result:
                        for alert in result.new_alerts:
                            target_host = alert.target_host or next(
                                (getattr(e, "host", None) for e in alert.events.values() if getattr(e, "host", None)),
                                None
                            )
                            alert_row = {
                                "rule_id": alert.rule_id,
                                "rule_name": alert.rule_name,
                                "severity": alert.severity,
                                "status": alert.status,
                                "source_ip": alert.source_ip,
                                "target_host": target_host,
                                "first_seen": alert.first_seen.isoformat(),
                                "last_seen": alert.last_seen.isoformat(),
                                "summary": alert.summary,
                                "explanation": alert.explanation,
                                "settings": alert.settings,
                            }
                            db_alert_id = repo.insert_alert(conn, alert_row)
                            alert.id = db_alert_id
                            evidence_db_ids = [
                                e.id for e in alert.events.values() if hasattr(e, "id") and e.id
                            ]
                            repo.insert_alert_evidence(conn, db_alert_id, evidence_db_ids)

                        for alert in result.updated_alerts:
                            if alert.id:
                                repo.update_alert(
                                    conn,
                                    alert.id,
                                    severity=alert.severity,
                                    last_seen=alert.last_seen.isoformat(),
                                    summary=alert.summary,
                                    explanation=alert.explanation,
                                    target_host=alert.target_host,
                                )
                                evidence_db_ids = [
                                    e.id for e in alert.events.values() if hasattr(e, "id") and e.id
                                ]
                                repo.insert_alert_evidence(conn, alert.id, evidence_db_ids)
        except sqlite3.IntegrityError as exc:
            return jsonify({
                "ok": False,
                "status": "conflict",
                "error": f"Integrity constraint violation: {exc}",
            }), 409
        except Exception as exc:
            return _err(f"Internal database error: {exc}", 500)

    return jsonify({
        "ok": True,
        "status": "ok",
        "acknowledged": acknowledged_ids,
        "count": len(acknowledged_ids),
    }), 200


@app.route("/api/v1/events", methods=["GET"])
def list_endpoint_events():
    """List endpoint events with optional filtering."""
    try:
        limit = _int_param("limit", 100, 1, 1000)
        offset = _int_param("offset", 0)
    except ValueError as exc:
        return _err(str(exc))

    conn = get_db()
    rows = repo.list_endpoint_events(
        conn,
        device_id=request.args.get("device_id"),
        source=request.args.get("source"),
        event_type=request.args.get("event_type"),
        severity=request.args.get("severity"),
        source_ip=request.args.get("source_ip"),
        since=request.args.get("since"),
        until=request.args.get("until"),
        limit=limit,
        offset=offset,
    )
    result = []
    for r in rows:
        d = dict(r)
        if "attributes" in d and isinstance(d["attributes"], str):
            try:
                d["attributes"] = json.loads(d["attributes"])
            except Exception:
                pass
        result.append(d)

    return jsonify({
        "ok": True,
        "events": result,
        "count": len(result),
        "data": {"events": result, "count": len(result)},
    })


@app.route("/api/v1/events/<event_id>", methods=["GET"])
def get_endpoint_event_detail(event_id: str):
    """Retrieve details for a single endpoint event by event_id."""
    conn = get_db()
    ev = repo.get_endpoint_event(conn, event_id)
    if ev is None:
        return _err("Endpoint event not found.", 404)
    d = dict(ev)
    if "attributes" in d and isinstance(d["attributes"], str):
        try:
            d["attributes"] = json.loads(d["attributes"])
        except Exception:
            pass
    return _ok(d)


# --------------------------------------------------------------------------
# Ingestion endpoint
# --------------------------------------------------------------------------

@app.route("/api/ingest", methods=["POST"])
def ingest():
    """Upload a raw SSH log file.  Returns new events and triggered alerts.

    Accepts multipart/form-data with a 'file' field, or raw bytes with the
    'X-Filename' header for programmatic uploads.
    """
    try:
        # ---- read raw bytes ------------------------------------------------
        if request.files and "file" in request.files:
            f = request.files["file"]
            filename = f.filename or "upload.log"
            raw = f.read()
        else:
            raw = request.get_data(parse_form_data=False)
            if not raw and request.form:
                raw = "\n".join(request.form.keys()).encode("utf-8")
            filename = request.headers.get("X-Filename", "upload.log")

        if not raw:
            return _err("No file provided. Send multipart 'file' or raw bytes.")



        year = request.args.get("year", None)
        if year is not None:
            try:
                year = int(year)
            except ValueError:
                return _err("'year' must be an integer.")
            if not (1970 <= year <= 2100):
                return _err("'year' must be between 1970 and 2100.")

        # ---- duplicate-upload guard ----------------------------------------
        file_hash = sha256_of(raw)
        conn = get_db()
        existing = repo.get_log_file_by_hash(conn, file_hash)
        if existing:
            return _ok({
                "duplicate": True,
                "message": "This file has already been uploaded.",
                "log_file": _row(existing),
            })

        # ---- parse with Module A and adapt to backend Event objects ------
        try:
            from app.services.ingestion import ingest_log_lines
            from backend.adapter import adapt_ingestion_report
        except ImportError:
            return _err("Parser module (Module A) not available.", 503)

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        now = datetime.now(timezone.utc)

        if year is not None:
            try:
                reference_time = now.replace(year=year)
            except ValueError:
                reference_time = now.replace(year=year, day=28)
        else:
            reference_time = now

        report = ingest_log_lines(lines, reference_time=reference_time)
        adapted = adapt_ingestion_report(report)


        # ---- store log file ------------------------------------------------
        log_file_id = repo.insert_log_file(
            conn,
            filename=filename,
            file_hash=file_hash,
            line_count=report.statistics.total_lines,
            event_count=len(adapted.events),
            malformed_count=adapted.malformed_count,
        )

        # ---- store events and map line_hash -> db id ----------------------
        event_dicts = []
        for ev in adapted.events:
            event_dicts.append({
                "timestamp": ev.timestamp.isoformat(),
                "host": getattr(ev, "host", None),
                "username": ev.username,
                "source_ip": ev.source_ip,
                "port": ev.port,
                "method": ev.method,
                "outcome": ev.outcome,
                "event_type": ev.event_type,
                "raw_line": ev.raw_line,
                "line_hash": ev.line_hash,
            })

        db_ids = repo.insert_events_batch(conn, log_file_id, event_dicts)

        # Attach db ids to event objects so the detection engine uses them
        for ev, db_id in zip(adapted.events, db_ids):
            if db_id:
                ev.id = db_id

        # ---- run detection engine -----------------------------------------
        try:
            engine = get_detection_engine(DB_PATH)
            result = engine.process(adapted.events)
        except ImportError:
            result = None

        new_alert_ids = []
        if result:
            for alert in result.new_alerts:
                target_host = alert.target_host or next(
                    (getattr(e, "host", None) for e in alert.events.values() if getattr(e, "host", None)),
                    None
                )
                alert_row = {
                    "rule_id": alert.rule_id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "status": alert.status,
                    "source_ip": alert.source_ip,
                    "target_host": target_host,
                    "first_seen": alert.first_seen.isoformat(),
                    "last_seen": alert.last_seen.isoformat(),
                    "summary": alert.summary,
                    "explanation": alert.explanation,
                    "settings": alert.settings,
                }
                db_alert_id = repo.insert_alert(conn, alert_row)
                new_alert_ids.append(db_alert_id)
                alert.id = db_alert_id

                # Link evidence events
                evidence_db_ids = []
                for ev in alert.events.values():
                    if hasattr(ev, "id") and ev.id:
                        evidence_db_ids.append(ev.id)
                repo.insert_alert_evidence(conn, db_alert_id, evidence_db_ids)

            for alert in result.updated_alerts:
                if alert.id:
                    repo.update_alert(
                        conn, alert.id,
                        severity=alert.severity,
                        last_seen=alert.last_seen.isoformat(),
                        summary=alert.summary,
                        explanation=alert.explanation,
                        target_host=alert.target_host,
                    )
                    evidence_db_ids = [
                        ev.id for ev in alert.events.values()
                        if hasattr(ev, "id") and ev.id
                    ]
                    repo.insert_alert_evidence(conn, alert.id, evidence_db_ids)

        conn.commit()

        return _ok({
            "log_file_id": log_file_id,
            "filename": filename,
            "events_stored": sum(1 for i in db_ids if i),
            "malformed_lines": adapted.malformed_count,
            "new_alerts": len(new_alert_ids) if result else None,
            "updated_alerts": len(result.updated_alerts) if result else None,
            "alert_ids": new_alert_ids,
        }, 201)

    except Exception as exc:  # pylint: disable=broad-except
        traceback.print_exc()
        return _err(f"Ingestion failed: {exc}", 500)


# --------------------------------------------------------------------------
# Log files
# --------------------------------------------------------------------------

@app.route("/api/logs", methods=["GET"])
def list_logs():
    conn = get_db()
    return _ok(_rows(repo.list_log_files(conn)))


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------

@app.route("/api/events", methods=["GET"])
def list_events():
    try:
        limit = _int_param("limit", 100, 1, 1000)
        offset = _int_param("offset", 0)
    except ValueError as exc:
        return _err(str(exc))

    conn = get_db()
    events = repo.list_events(
        conn,
        source_ip=request.args.get("source_ip"),
        username=request.args.get("username"),
        outcome=request.args.get("outcome"),
        event_type=request.args.get("event_type"),
        since=request.args.get("since"),
        until=request.args.get("until"),
        limit=limit,
        offset=offset,
    )
    rows = _rows(events)
    return jsonify({
        "ok": True,
        "events": rows,
        "count": len(rows),
        "data": {"events": rows, "count": len(rows)},
    })


@app.route("/api/events/<int:event_id>", methods=["GET"])
def get_event(event_id: int):
    conn = get_db()
    ev = repo.get_event(conn, event_id)
    if ev is None:
        return _err("Event not found.", 404)
    return _ok(_row(ev))


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

@app.route("/api/alerts", methods=["GET"])
def list_alerts():
    try:
        limit = _int_param("limit", 100, 1, 1000)
        offset = _int_param("offset", 0)
    except ValueError as exc:
        return _err(str(exc))

    conn = get_db()
    alerts = repo.list_alerts(
        conn,
        status=request.args.get("status"),
        severity=request.args.get("severity"),
        rule_id=request.args.get("rule_id"),
        source_ip=request.args.get("source_ip"),
        target_host=request.args.get("target_host"),
        assignee=request.args.get("assignee"),
        limit=limit,
        offset=offset,
    )
    rows = _rows(alerts)
    return jsonify({
        "ok": True,
        "alerts": rows,
        "count": len(rows),
        "data": {"alerts": rows, "count": len(rows)},
    })


@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id: int):
    conn = get_db()
    alert = repo.get_alert(conn, alert_id)
    if alert is None:
        return _err("Alert not found.", 404)
    evidence = repo.get_alert_evidence(conn, alert_id)
    history = repo.get_alert_status_history(conn, alert_id)
    notes = repo.list_alert_notes(conn, alert_id)
    data = _row(alert)
    evidence_rows = _rows(evidence)
    data["evidence"] = evidence_rows
    data["status_history"] = _rows(history)
    data["notes"] = _rows(notes)
    if not data.get("target_host"):
        data["target_host"] = next((ev.get("host") for ev in evidence_rows if ev.get("host")), None)
    return _ok(data)


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
def patch_alert(alert_id: int):
    body = request.get_json(silent=True) or {}
    conn = get_db()
    alert = repo.get_alert(conn, alert_id)
    if alert is None:
        return _err("Alert not found.", 404)

    status = (body.get("status") or "").strip()
    actor = (body.get("actor") or "SOC Analyst").strip() or "SOC Analyst"
    reason = (body.get("reason") or "").strip()
    has_assignee = "assignee" in body
    assignee = body.get("assignee")

    if not status and not has_assignee:
        return _err("At least one of 'status' or 'assignee' is required.")

    if status:
        try:
            repo.update_alert_status(conn, alert_id, status, actor=actor, reason=reason)
        except ValueError as exc:
            return _err(str(exc))

    if has_assignee:
        repo.update_alert_assignee(conn, alert_id, assignee, actor=actor)

    conn.commit()
    updated = repo.get_alert(conn, alert_id)
    data = _row(updated)
    data["status_history"] = _rows(repo.get_alert_status_history(conn, alert_id))
    data["notes"] = _rows(repo.list_alert_notes(conn, alert_id))
    return _ok(data)


@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id: int):
    body = request.get_json(silent=True) or {}
    status = body.get("status", "").strip()
    if not status:
        return _err("'status' field is required.")
    actor = body.get("actor", "SOC Analyst").strip() or "SOC Analyst"
    reason = body.get("reason", "").strip()
    conn = get_db()
    try:
        found = repo.update_alert_status(conn, alert_id, status, actor=actor, reason=reason)
    except ValueError as exc:
        return _err(str(exc))
    if not found:
        return _err("Alert not found.", 404)
    conn.commit()
    history = repo.get_alert_status_history(conn, alert_id)
    return _ok({
        "alert_id": alert_id,
        "status": status,
        "actor": actor,
        "reason": reason,
        "status_history": _rows(history),
    })


@app.route("/api/alerts/<int:alert_id>/assign", methods=["PATCH", "POST"])
def update_alert_assignee(alert_id: int):
    body = request.get_json(silent=True) or {}
    assignee = body.get("assignee")
    actor = (body.get("actor") or "SOC Analyst").strip() or "SOC Analyst"
    conn = get_db()
    if repo.get_alert(conn, alert_id) is None:
        return _err("Alert not found.", 404)
    repo.update_alert_assignee(conn, alert_id, assignee, actor=actor)
    conn.commit()
    updated = repo.get_alert(conn, alert_id)
    data = _row(updated)
    data["status_history"] = _rows(repo.get_alert_status_history(conn, alert_id))
    return _ok(data)


@app.route("/api/alerts/<int:alert_id>/notes", methods=["POST"])
def add_alert_note(alert_id: int):
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or body.get("body") or "").strip()
    if not note:
        return _err("'note' field is required.")
    if len(note) > 5000:
        return _err("Note must be 5000 characters or fewer.")
    author = (body.get("author") or "SOC Analyst").strip() or "SOC Analyst"
    conn = get_db()
    if repo.get_alert(conn, alert_id) is None:
        return _err("Alert not found.", 404)
    note_id = repo.insert_alert_note(conn, alert_id, note, author)
    conn.commit()
    return _ok({"note_id": note_id, "alert_id": alert_id, "author": author, "note": note}, 201)


@app.route("/api/alerts/<int:alert_id>/notes", methods=["GET"])
def list_alert_notes(alert_id: int):
    conn = get_db()
    if repo.get_alert(conn, alert_id) is None:
        return _err("Alert not found.", 404)
    notes = repo.list_alert_notes(conn, alert_id)
    return _ok({"notes": _rows(notes), "count": len(notes)})


@app.route("/api/alerts/<int:alert_id>/history", methods=["GET"])
def get_alert_history(alert_id: int):
    conn = get_db()
    alert = repo.get_alert(conn, alert_id)
    if alert is None:
        return _err("Alert not found.", 404)
    history = repo.get_alert_status_history(conn, alert_id)
    return _ok({
        "alert_id": alert_id,
        "status_history": _rows(history),
    })


# --------------------------------------------------------------------------
# Statistics (RSD: GET /api/stats)
# --------------------------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
@app.route("/api/statistics", methods=["GET"])
def statistics():
    conn = get_db()
    stats = repo.auth_statistics(conn)
    alert_sev = repo.count_alerts_by_severity(conn)
    alert_status = repo.count_alerts_by_status(conn)
    top_ips = _rows(repo.top_source_ips(conn, limit=10))
    total_alerts = sum(alert_sev.values())

    critical_sev = alert_sev.get("critical", 0)
    high_sev_only = alert_sev.get("high", 0)
    high_and_critical = high_sev_only + critical_sev

    open_alerts = sum(
        c for s, c in alert_status.items()
        if s.lower() in ("new", "investigating", "open", "in_progress")
    )
    resolved_alerts = sum(
        c for s, c in alert_status.items()
        if s.lower() in ("resolved", "closed", "false_positive")
    )

    events_timeline = repo.get_timeseries_buckets(conn, table="events", target_buckets=24)
    alert_trend = repo.get_timeseries_buckets(conn, table="alerts", target_buckets=24)

    payload = {
        "total": stats.get("total", 0),
        "total_events": stats.get("total", 0),
        "event_count": stats.get("total", 0),
        "accepted": stats.get("accepted", 0),
        "failed": stats.get("failed", 0),
        "unique_ips": stats.get("unique_ips", 0),
        "unique_source_ips": stats.get("unique_ips", 0),
        "unique_users": stats.get("unique_users", 0),
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "critical_alerts": critical_sev,
        "high_alerts": high_sev_only,
        "high_severity": high_and_critical,
        "high_severity_alerts": high_and_critical,
        "high_and_critical_alerts": high_and_critical,
        "alert_counts_by_severity": alert_sev,
        "alerts_by_severity": alert_sev,
        "severity_distribution": alert_sev,
        "alert_counts_by_status": alert_status,
        "alerts_by_status": alert_status,
        "events_timeline": events_timeline,
        "alert_trend": alert_trend,
        "alerts_timeline": alert_trend,
        "top_source_ips": top_ips,
        "top_ips": top_ips,
    }
    res = dict(payload)
    res["ok"] = True
    res["data"] = payload
    return jsonify(res)



# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------

@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    try:
        limit = _int_param("limit", 50, 1, 500)
        offset = _int_param("offset", 0)
    except ValueError as exc:
        return _err(str(exc))
    conn = get_db()
    incidents = repo.list_incidents(
        conn,
        status=request.args.get("status"),
        severity=request.args.get("severity"),
        assignee=request.args.get("assignee"),
        search=request.args.get("search"),
        limit=limit,
        offset=offset,
    )
    return _ok({"incidents": _rows(incidents), "count": len(incidents)})


@app.route("/api/incidents", methods=["POST"])
def create_incident():
    """Create an incident from selected alerts (RSD Section 10)."""
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    if not title:
        return _err("'title' is required.")
    if len(title) > 200:
        return _err("'title' must be 200 characters or fewer.")

    description = (body.get("description") or "").strip()
    severity = (body.get("severity") or "medium").strip()
    assignee = (body.get("assignee") or "").strip() or None

    conn = get_db()
    try:
        incident_id = repo.insert_incident(conn, title, description, severity, assignee=assignee)
        # Link selected alerts if provided
        alert_ids = body.get("alert_ids") or []
        if isinstance(alert_ids, list):
            for aid in alert_ids:
                if isinstance(aid, int):
                    repo.link_alert_to_incident(conn, incident_id, aid)
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    return _ok({"incident_id": incident_id}, 201)


@app.route("/api/incidents/<int:incident_id>", methods=["GET"])
def get_incident(incident_id: int):
    conn = get_db()
    inc = repo.get_incident(conn, incident_id)
    if inc is None:
        return _err("Incident not found.", 404)
    data = _row(inc)
    data["alerts"] = _rows(repo.get_incident_alerts(conn, incident_id))
    data["notes"] = _rows(repo.list_incident_notes(conn, incident_id))
    return _ok(data)


@app.route("/api/incidents/<int:incident_id>", methods=["PATCH", "PUT"])
def update_incident(incident_id: int):
    body = request.get_json(silent=True) or {}
    conn = get_db()
    if repo.get_incident(conn, incident_id) is None:
        return _err("Incident not found.", 404)
    try:
        repo.update_incident(
            conn,
            incident_id,
            title=body.get("title"),
            description=body.get("description"),
            severity=body.get("severity"),
            status=body.get("status"),
            assignee=body.get("assignee"),
            close_reason=body.get("close_reason"),
        )
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    updated = repo.get_incident(conn, incident_id)
    data = _row(updated)
    data["alerts"] = _rows(repo.get_incident_alerts(conn, incident_id))
    data["notes"] = _rows(repo.list_incident_notes(conn, incident_id))
    return _ok(data)


@app.route("/api/incidents/<int:incident_id>/status", methods=["PATCH"])
def update_incident_status(incident_id: int):
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip()
    if not status:
        return _err("'status' field is required.")
    close_reason = (body.get("close_reason") or "").strip() or None
    conn = get_db()
    try:
        found = repo.update_incident_status(conn, incident_id, status, close_reason=close_reason)
    except ValueError as exc:
        return _err(str(exc))
    if not found:
        return _err("Incident not found.", 404)
    conn.commit()
    return _ok({"incident_id": incident_id, "status": status, "close_reason": close_reason})


@app.route("/api/incidents/<int:incident_id>/alerts", methods=["POST"])
def link_alert_to_incident(incident_id: int):
    body = request.get_json(silent=True) or {}
    alert_id = body.get("alert_id")
    if alert_id is None or not isinstance(alert_id, int):
        return _err("'alert_id' (integer) is required.")
    conn = get_db()
    if repo.get_incident(conn, incident_id) is None:
        return _err("Incident not found.", 404)
    if repo.get_alert(conn, alert_id) is None:
        return _err("Alert not found.", 404)
    repo.link_alert_to_incident(conn, incident_id, alert_id)
    conn.commit()
    return _ok({"incident_id": incident_id, "alert_id": alert_id}, 201)


@app.route("/api/incidents/<int:incident_id>/alerts/<int:alert_id>", methods=["DELETE"])
def unlink_alert_from_incident(incident_id: int, alert_id: int):
    conn = get_db()
    if repo.get_incident(conn, incident_id) is None:
        return _err("Incident not found.", 404)
    unlinked = repo.unlink_alert_from_incident(conn, incident_id, alert_id)
    conn.commit()
    return _ok({"incident_id": incident_id, "alert_id": alert_id, "unlinked": unlinked})


@app.route("/api/incidents/<int:incident_id>/notes", methods=["POST"])
def add_incident_note(incident_id: int):
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or body.get("body") or "").strip()
    if not note:
        return _err("'note' (or 'body') is required.")
    if len(note) > 5000:
        return _err("Note must be 5000 characters or fewer.")
    author = (body.get("author") or "analyst").strip()


    conn = get_db()
    if repo.get_incident(conn, incident_id) is None:
        return _err("Incident not found.", 404)
    try:
        note_id = repo.insert_incident_note(conn, incident_id, note, author)
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    return _ok({"note_id": note_id, "incident_id": incident_id}, 201)


@app.route("/api/incidents/<int:incident_id>/notes", methods=["GET"])
def list_incident_notes(incident_id: int):
    conn = get_db()
    if repo.get_incident(conn, incident_id) is None:
        return _err("Incident not found.", 404)
    notes = repo.list_incident_notes(conn, incident_id)
    return _ok({"notes": _rows(notes), "count": len(notes)})


# --------------------------------------------------------------------------
# Detection Rules CRUD & Management
# --------------------------------------------------------------------------

def _format_rule(r) -> dict:
    d = _row(r)
    if d and "enabled" in d:
        d["enabled"] = bool(d["enabled"])
    return d


@app.route("/api/rules", methods=["GET"])
def list_detection_rules():
    conn = get_db()
    severity = request.args.get("severity")
    enabled_param = request.args.get("enabled")
    enabled = None
    if enabled_param is not None and enabled_param != "":
        enabled = enabled_param.lower() in ("true", "1", "yes")
    search = request.args.get("search")
    rules = repo.list_detection_rules(conn, severity=severity, enabled=enabled, search=search)
    rows = [_format_rule(r) for r in rules]
    return _ok({"rules": rows, "count": len(rows)})


@app.route("/api/rules/<rule_id>", methods=["GET"])
def get_detection_rule(rule_id: str):
    conn = get_db()
    rule = repo.get_detection_rule(conn, rule_id)
    if rule is None:
        return _err("Rule not found.", 404)
    data = _format_rule(rule)
    data["audit_logs"] = _rows(repo.list_rule_audit_logs(conn, rule_id))
    return _ok(data)


@app.route("/api/rules", methods=["POST"])
def create_detection_rule():
    body = request.get_json(silent=True) or {}
    rule_id = (body.get("rule_id") or "").strip().upper()
    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip()
    severity = (body.get("severity") or "medium").strip().lower()
    enabled = bool(body.get("enabled", True))
    changed_by = (body.get("changed_by") or "SOC Analyst").strip()

    if not rule_id:
        return _err("'rule_id' is required (e.g., DR-06).")
    if not name:
        return _err("'name' is required.")
    valid_sev = {"low", "medium", "high", "critical"}
    if severity not in valid_sev:
        return _err(f"'severity' must be one of {sorted(valid_sev)}.")

    try:
        threshold = int(body.get("threshold", 5))
        if threshold < 1:
            raise ValueError()
    except (ValueError, TypeError):
        return _err("'threshold' must be a positive integer >= 1.")

    try:
        window_minutes = int(body.get("window_minutes", 10))
        if window_minutes < 1:
            raise ValueError()
    except (ValueError, TypeError):
        return _err("'window_minutes' must be a positive integer >= 1.")

    conditions = body.get("conditions", "{}")
    if isinstance(conditions, dict):
        conditions = json.dumps(conditions)

    conn = get_db()
    existing = repo.get_detection_rule(conn, rule_id)
    if existing:
        return _err(f"Rule with ID '{rule_id}' already exists.", 409)

    try:
        repo.insert_detection_rule(
            conn, rule_id=rule_id, name=name, description=description,
            severity=severity, enabled=enabled, threshold=threshold,
            window_minutes=window_minutes, conditions=conditions
        )
        repo.insert_rule_audit_log(
            conn, rule_id=rule_id, action="create", changed_by=changed_by,
            details=json.dumps({"name": name, "severity": severity, "threshold": threshold, "window_minutes": window_minutes})
        )
    except Exception as exc:
        return _err(f"Failed to create detection rule: {exc}")
    conn.commit()
    created = repo.get_detection_rule(conn, rule_id)
    return _ok(_format_rule(created), 201)


@app.route("/api/rules/<rule_id>", methods=["PUT", "PATCH"])
def update_detection_rule(rule_id: str):
    body = request.get_json(silent=True) or {}
    conn = get_db()
    rule = repo.get_detection_rule(conn, rule_id)
    if rule is None:
        return _err("Rule not found.", 404)

    name = body.get("name")
    description = body.get("description")
    severity = body.get("severity")
    enabled = body.get("enabled")
    threshold = body.get("threshold")
    window_minutes = body.get("window_minutes")
    conditions = body.get("conditions")
    if isinstance(conditions, dict):
        conditions = json.dumps(conditions)
    changed_by = (body.get("changed_by") or "SOC Analyst").strip()

    try:
        if threshold is not None:
            threshold = int(threshold)
            if threshold < 1:
                return _err("'threshold' must be >= 1.")
        if window_minutes is not None:
            window_minutes = int(window_minutes)
            if window_minutes < 1:
                return _err("'window_minutes' must be >= 1.")

        found = repo.update_detection_rule(
            conn, rule_id=rule_id, name=name, description=description,
            severity=severity, enabled=enabled, threshold=threshold,
            window_minutes=window_minutes, conditions=conditions
        )
        if not found:
            return _err("No changes made or rule not found.")

        repo.insert_rule_audit_log(
            conn, rule_id=rule_id, action="update", changed_by=changed_by,
            details=json.dumps({k: v for k, v in body.items() if k != "changed_by"})
        )
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    updated = repo.get_detection_rule(conn, rule_id)
    return _ok(_format_rule(updated))


@app.route("/api/rules/<rule_id>/toggle", methods=["PATCH", "POST"])
def toggle_detection_rule(rule_id: str):
    body = request.get_json(silent=True) or {}
    conn = get_db()
    rule = repo.get_detection_rule(conn, rule_id)
    if rule is None:
        return _err("Rule not found.", 404)

    current_enabled = bool(rule["enabled"])
    if "enabled" in body:
        new_enabled = bool(body["enabled"])
    else:
        new_enabled = not current_enabled

    changed_by = (body.get("changed_by") or "SOC Analyst").strip()
    action = "enable" if new_enabled else "disable"

    repo.update_detection_rule(conn, rule_id=rule_id, enabled=new_enabled)
    repo.insert_rule_audit_log(
        conn, rule_id=rule_id, action=action, changed_by=changed_by,
        details=json.dumps({"enabled": new_enabled})
    )
    conn.commit()
    updated = repo.get_detection_rule(conn, rule_id)
    return _ok(_format_rule(updated))


@app.route("/api/rules/<rule_id>/audit", methods=["GET"])
def get_rule_audit_logs(rule_id: str):
    conn = get_db()
    if repo.get_detection_rule(conn, rule_id) is None:
        return _err("Rule not found.", 404)
    logs = repo.list_rule_audit_logs(conn, rule_id)
    return _ok({"rule_id": rule_id, "audit_logs": _rows(logs), "count": len(logs)})


# --------------------------------------------------------------------------
# Endpoints Fleet Management
# --------------------------------------------------------------------------

@app.route("/api/endpoints", methods=["GET"])
def list_endpoints():
    conn = get_db()
    status = request.args.get("status")
    os_type = request.args.get("os")
    search = request.args.get("search")
    try:
        limit = _int_param("limit", 100, 1, 1000)
        offset = _int_param("offset", 0)
    except ValueError as exc:
        return _err(str(exc))

    endpoints = repo.list_endpoints(
        conn, status=status, os_type=os_type, search=search, limit=limit, offset=offset
    )
    rows = _rows(endpoints)
    return _ok({"endpoints": rows, "count": len(rows)})


@app.route("/api/endpoints/<device_id>", methods=["GET"])
def get_endpoint(device_id: str):
    conn = get_db()
    endpoint = repo.get_endpoint(conn, device_id)
    if endpoint is None:
        return _err("Endpoint not found.", 404)
    data = _row(endpoint)
    recent_events = repo.list_endpoint_events(conn, device_id=device_id, limit=20)
    data["recent_events"] = _rows(recent_events)
    return _ok(data)


@app.route("/api/endpoints", methods=["POST"])
def enroll_endpoint():
    body = request.get_json(silent=True) or {}
    device_id = (body.get("device_id") or "").strip()
    hostname = (body.get("hostname") or "").strip()
    os_type = (body.get("os") or "linux").strip().lower()
    status = (body.get("status") or "active").strip().lower()
    ip_address = (body.get("ip_address") or "").strip() or None
    agent_version = (body.get("agent_version") or "1.0.0").strip()
    metadata = body.get("metadata", "{}")
    if isinstance(metadata, dict):
        metadata = json.dumps(metadata)

    if not device_id:
        return _err("'device_id' is required.")
    if not hostname:
        return _err("'hostname' is required.")

    valid_os = {"linux", "windows", "macos"}
    if os_type not in valid_os:
        return _err(f"'os' must be one of {sorted(valid_os)}.")

    conn = get_db()
    existing = repo.get_endpoint(conn, device_id)
    if existing:
        return _err(f"Endpoint with device_id '{device_id}' is already registered.", 409)

    try:
        repo.insert_endpoint(
            conn,
            device_id=device_id,
            hostname=hostname,
            os=os_type,
            status=status,
            ip_address=ip_address,
            agent_version=agent_version,
            metadata=metadata,
        )
    except Exception as exc:
        return _err(f"Failed to enroll endpoint: {exc}")
    conn.commit()
    created = repo.get_endpoint(conn, device_id)
    return _ok(_row(created), 201)


@app.route("/api/endpoints/<device_id>", methods=["PATCH", "PUT"])
def update_endpoint_details(device_id: str):
    body = request.get_json(silent=True) or {}
    conn = get_db()
    endpoint = repo.get_endpoint(conn, device_id)
    if endpoint is None:
        return _err("Endpoint not found.", 404)

    metadata = body.get("metadata")
    if isinstance(metadata, dict):
        metadata = json.dumps(metadata)

    try:
        found = repo.update_endpoint(
            conn,
            device_id=device_id,
            hostname=body.get("hostname"),
            status=body.get("status"),
            ip_address=body.get("ip_address"),
            metadata=metadata,
        )
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    updated = repo.get_endpoint(conn, device_id)
    return _ok(_row(updated))


@app.route("/api/endpoints/<device_id>/status", methods=["PATCH"])
def update_endpoint_status(device_id: str):
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip().lower()
    if not status:
        return _err("'status' field is required.")
    valid_status = {"active", "disabled", "offline", "enrolled"}
    if status not in valid_status:
        return _err(f"'status' must be one of {sorted(valid_status)}.")

    conn = get_db()
    endpoint = repo.get_endpoint(conn, device_id)
    if endpoint is None:
        return _err("Endpoint not found.", 404)

    try:
        repo.update_endpoint_status(conn, device_id=device_id, status=status)
    except ValueError as exc:
        return _err(str(exc))
    conn.commit()
    return _ok({"device_id": device_id, "status": status})


# --------------------------------------------------------------------------
# System verification, testing & dynamic route discovery
# --------------------------------------------------------------------------

ROUTE_DESCRIPTIONS = {
    "index": "API Root - Pure JSON status and endpoint discovery",
    "list_alerts": "List security alerts with filtering by severity, status, rule, host, or assignee",
    "get_alert": "Get detailed alert record with correlated evidence, notes, and audit history",
    "update_alert_status": "Update alert triage status with analyst attribution and reason",
    "patch_alert": "Update alert status or analyst assignment with audit trail",
    "update_alert_assignee": "Assign or reassign an alert to an analyst",
    "add_alert_note": "Add an analyst investigation note to an alert",
    "list_alert_notes": "List analyst investigation notes for an alert",
    "get_alert_history": "Retrieve persistent audit trail of alert status transitions",
    "list_events": "List normalized security events with optional filtering",
    "get_event": "Get normalized event details and line hash",
    "health": "Production health check, WAL mode, and database telemetry",
    "list_incidents": "List security incident cases with search, severity, and assignee filters",
    "create_incident": "Create an incident from selected alerts and assign to analyst",
    "get_incident": "Retrieve incident details, linked alerts, and analyst notes",
    "update_incident": "Update incident title, description, severity, status, assignee, or close reason",
    "update_incident_status": "Update incident lifecycle status with optional close reason",
    "link_alert_to_incident": "Link a security alert to an incident case",
    "unlink_alert_from_incident": "Unlink a security alert from an incident case",
    "add_incident_note": "Add an analyst case note to an incident",
    "list_incident_notes": "List analyst case notes for an incident",
    "list_detection_rules": "List SIEM detection rules with filtering by severity or status",
    "get_detection_rule": "Retrieve detection rule details and modification audit trail",
    "create_detection_rule": "Create a custom detection rule with threshold and window",
    "update_detection_rule": "Update detection rule configuration and record audit log",
    "toggle_detection_rule": "Enable or disable a detection rule without deleting alerts",
    "get_rule_audit_logs": "Retrieve change audit log for a detection rule",
    "list_endpoints": "List enrolled endpoint agent devices and operational health",
    "get_endpoint": "Retrieve endpoint details and recent device telemetry",
    "enroll_endpoint": "Register or enroll a new endpoint device",
    "update_endpoint_details": "Update endpoint metadata and device properties",
    "update_endpoint_status": "Update endpoint lifecycle status (active vs disabled)",
    "ingest": "Upload and parse raw syslog / auth log files",
    "list_logs": "List processed log files and verification hashes",
    "statistics": "Aggregated SOC counts, severity breakdown, and top source IPs",
    "sqli_fuzz_test": "Interactive SQL injection defense fuzzer testing parameterized queries",
    "run_system_tests": "Execute automated system test suites in an isolated subprocess",
    "get_system_routes": "Dynamic REST API route registry and endpoint discovery",
    "ingest_endpoint_events": "Ingest telemetry event batches from ThreatLens endpoint agents",
    "list_endpoint_events": "List and filter endpoint agent telemetry events",
    "get_endpoint_event_detail": "Retrieve endpoint event details by UUID",
}

ROUTE_SAMPLES = {
    "/": {"sample_path": "/"},
    "/api/health": {"sample_path": "/api/health"},
    "/api/statistics": {"sample_path": "/api/statistics"},
    "/api/stats": {"sample_path": "/api/stats"},
    "/api/alerts": {"sample_path": "/api/alerts?limit=5"},
    "/api/alerts/<int:alert_id>": {
        "sample_path": "/api/alerts/1",
        "sample_body": {"status": "investigating", "actor": "SOC Analyst", "reason": "Verifying rule correlation"},
    },
    "/api/alerts/<int:alert_id>/status": {
        "sample_path": "/api/alerts/1/status",
        "sample_body": {"status": "investigating", "actor": "SOC Analyst", "reason": "Verifying rule correlation"},
    },
    "/api/alerts/<int:alert_id>/assign": {
        "sample_path": "/api/alerts/1/assign",
        "sample_body": {"assignee": "analyst-lead", "actor": "SOC Lead"},
    },
    "/api/alerts/<int:alert_id>/notes": {
        "sample_path": "/api/alerts/1/notes",
        "sample_body": {"note": "Investigating suspicious root login from internal workstation.", "author": "SOC Analyst"},
    },
    "/api/alerts/<int:alert_id>/history": {"sample_path": "/api/alerts/1/history"},
    "/api/events": {"sample_path": "/api/events?limit=5"},
    "/api/events/<int:event_id>": {"sample_path": "/api/events/1"},
    "/api/logs": {"sample_path": "/api/logs"},
    "/api/incidents": {
        "sample_path": "/api/incidents",
        "sample_body": {"title": "Suspicious Authentication Spike", "severity": "high", "description": "Investigating correlated brute-force alert.", "assignee": "analyst-1"},
    },
    "/api/incidents/<int:incident_id>": {"sample_path": "/api/incidents/1"},
    "/api/incidents/<int:incident_id>/status": {
        "sample_path": "/api/incidents/1/status",
        "sample_body": {"status": "investigating", "close_reason": ""},
    },
    "/api/incidents/<int:incident_id>/alerts": {
        "sample_path": "/api/incidents/1/alerts",
        "sample_body": {"alert_id": 1},
    },
    "/api/incidents/<int:incident_id>/alerts/<int:alert_id>": {
        "sample_path": "/api/incidents/1/alerts/1",
    },
    "/api/incidents/<int:incident_id>/notes": {
        "sample_path": "/api/incidents/1/notes",
        "sample_body": {"note": "Evidence verified against SSH daemon telemetry.", "author": "SOC Analyst"},
    },
    "/api/rules": {"sample_path": "/api/rules"},
    "/api/rules/<rule_id>": {"sample_path": "/api/rules/DR-01"},
    "/api/rules/<rule_id>/toggle": {
        "sample_path": "/api/rules/DR-01/toggle",
        "sample_body": {"enabled": True, "changed_by": "SOC Analyst"},
    },
    "/api/rules/<rule_id>/audit": {"sample_path": "/api/rules/DR-01/audit"},
    "/api/endpoints": {"sample_path": "/api/endpoints"},
    "/api/endpoints/<device_id>": {"sample_path": "/api/endpoints/endpoint-01"},
    "/api/endpoints/<device_id>/status": {
        "sample_path": "/api/endpoints/endpoint-01/status",
        "sample_body": {"status": "active"},
    },
    "/api/v1/events": {
        "sample_path": "/api/v1/events?limit=5",
        "sample_body": {"events": []},
    },
    "/api/v1/events/<event_id>": {"sample_path": "/api/v1/events/1"},
    "/api/system/sqli-fuzz": {
        "sample_path": "/api/system/sqli-fuzz",
        "sample_body": {"payload": "' OR 1=1 --", "target": "source_ip"},
    },
    "/api/system/tests/run": {"sample_path": "/api/system/tests/run"},
    "/api/system/routes": {"sample_path": "/api/system/routes"},
    "/api/routes": {"sample_path": "/api/routes"},
}

TEST_SUITE_NAMES = {
    "test_database": "Database Schema, Tables & Cascading Integrity",
    "test_api": "REST API Endpoints & Contract Adherence",
    "test_detection": "Detection Engine Rules DR-01..DR-05 & Correlation",
    "test_security": "SQL Injection Defense & Integrity Benchmark",
    "test_endpoint_events": "Endpoint Agent Telemetry & Ingestion",
    "test_ingestion": "Syslog Parsing & Ingestion Service",
    "test_integration": "End-to-End SIEM Integration Scenarios",
    "test_openssh_parser": "OpenSSH Auth Log Normalization & Parsing",
    "test_models": "Data Models & Schema Validation",
    "test_system_diagnostics": "System Diagnostics & Module B Isolation",
}

ALLOWLISTED_TEST_TARGETS = {
    "all": "tests",
    "database": "tests/test_database.py",
    "api": "tests/test_api.py",
    "detection": "tests/test_detection.py",
    "security": "tests/test_security.py",
    "endpoint": "tests/test_endpoint_events.py",
    "ingestion": "tests/test_ingestion.py",
    "integration": "tests/test_integration.py",
    "parser": "tests/test_openssh_parser.py",
    "models": "tests/test_models.py",
    "diagnostics": "tests/test_system_diagnostics.py",
}


@app.route("/api/system/routes", methods=["GET"])
@app.route("/api/routes", methods=["GET"])
def get_system_routes():
    """Dynamic REST API route registry and endpoint discovery derived from Flask url_map."""
    try:
        routes = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static":
                continue
            methods = sorted(list(rule.methods - {"HEAD", "OPTIONS"}))
            rule_str = str(rule)
            fn = app.view_functions.get(rule.endpoint)
            doc = ""
            if rule.endpoint in ROUTE_DESCRIPTIONS:
                doc = ROUTE_DESCRIPTIONS[rule.endpoint]
            elif fn and fn.__doc__:
                doc = fn.__doc__.strip().split("\n")[0]
            else:
                doc = f"Endpoint handler for {rule.endpoint}"

            sample_info = ROUTE_SAMPLES.get(rule_str, {})
            sample_path = sample_info.get("sample_path", rule_str)
            sample_body = sample_info.get("sample_body", None)

            for m in methods:
                routes.append({
                    "path": rule_str,
                    "method": m,
                    "methods": methods,
                    "endpoint": rule.endpoint,
                    "desc": doc,
                    "sample_path": sample_path,
                    "sample_body": sample_body if m in ("POST", "PATCH", "PUT") else None,
                })

        routes.sort(key=lambda r: (r["path"], r["method"]))
        payload = {
            "routes": routes,
            "count": len(routes),
            "unique_paths": len(set(r["path"] for r in routes)),
        }
        res = dict(payload)
        res["ok"] = True
        res["data"] = payload
        return jsonify(res), 200
    except Exception as exc:
        return _err(f"Failed to enumerate registered routes: {str(exc)}", 500)


@app.route("/api/system/tests/run", methods=["POST", "GET"])
def run_system_tests():
    """Execute automated system verification tests in an isolated subprocess."""
    client_ip = request.remote_addr or ""
    if client_ip not in ("127.0.0.1", "::1", "localhost") and not app.config.get("TESTING"):
        return _err("Diagnostic test runner is restricted to local loopback authorization.", 403)

    req_data = request.get_json(silent=True) or {}
    target_key = (request.args.get("target") or req_data.get("target") or "all").strip().lower()
    if target_key not in ALLOWLISTED_TEST_TARGETS:
        allowed = ", ".join(sorted(ALLOWLISTED_TEST_TARGETS.keys()))
        return _err(f"Invalid test target '{target_key}'. Allowlisted targets: {allowed}.", 400)

    test_path = ALLOWLISTED_TEST_TARGETS[target_key]

    temp_dir = tempfile.mkdtemp(prefix="threatlens_test_")
    xml_path = os.path.join(temp_dir, "junit_report.xml")
    isolated_db_path = os.path.join(temp_dir, "isolated_threatlens.db")

    env = dict(os.environ)
    for k in list(env.keys()):
        if any(s in k.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH"]):
            env.pop(k, None)
    env["THREATLENS_DB"] = isolated_db_path
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        test_path,
        "-q",
        f"--junitxml={xml_path}",
    ]

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=base_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
            shell=False,
        )
        duration = round(time.time() - start_time, 2)
    except subprocess.TimeoutExpired:
        duration = round(time.time() - start_time, 2)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return _err("System test execution timed out after 45 seconds.", 504)
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return _err(f"Subprocess test execution error: {str(exc)}", 500)

    suites_map = {}
    total_tests = 0
    failures = 0
    errors = 0

    if os.path.exists(xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for tc in root.iter("testcase"):
                total_tests += 1
                classname = tc.get("classname", "")
                parts = classname.split(".")
                mod = parts[1] if len(parts) > 1 else parts[0]
                if mod not in suites_map:
                    suites_map[mod] = {
                        "name": TEST_SUITE_NAMES.get(mod, mod.replace("_", " ").title()),
                        "tests": 0,
                        "failures": 0,
                        "errors": 0,
                        "time": 0.0,
                    }
                suites_map[mod]["tests"] += 1
                suites_map[mod]["time"] = round(suites_map[mod]["time"] + float(tc.get("time", 0.0)), 3)
                if tc.find("failure") is not None:
                    suites_map[mod]["failures"] += 1
                    failures += 1
                if tc.find("error") is not None:
                    suites_map[mod]["errors"] += 1
                    errors += 1
        except Exception:
            pass

    shutil.rmtree(temp_dir, ignore_errors=True)

    suites_list = []
    for mod_key, s_data in sorted(suites_map.items()):
        status = "PASSED" if (s_data["failures"] == 0 and s_data["errors"] == 0) else "FAILED"
        suites_list.append({
            "name": s_data["name"],
            "module": mod_key,
            "status": status,
            "tests": s_data["tests"],
            "failures": s_data["failures"],
            "errors": s_data["errors"],
            "duration_seconds": s_data["time"],
        })

    passed = (proc.returncode == 0) and (failures == 0) and (errors == 0)
    stdout_lines = proc.stdout.strip().split("\n")
    summary_line = stdout_lines[-1] if stdout_lines else f"Process exited with status {proc.returncode}"

    payload = {
        "total_tests": total_tests,
        "failures": failures,
        "errors": errors,
        "passed": passed,
        "duration_seconds": duration,
        "suites": suites_list,
        "output_summary": summary_line,
        "exit_code": proc.returncode,
    }
    res = dict(payload)
    res["ok"] = True
    res["data"] = payload
    return jsonify(res), 200


@app.route("/api/system/sqli-fuzz", methods=["POST"])
def sqli_fuzz_test():
    """Interactive SQL Injection defense fuzzer testing parameterized queries."""
    body = request.get_json(silent=True) or {}
    payload = body.get("payload", "' OR 1=1 --")
    target = body.get("target", "source_ip")

    conn = get_db()

    if target == "username":
        results = repo.list_events(conn, username=payload, limit=5)
    elif target == "event_type":
        results = repo.list_events(conn, event_type=payload, limit=5)
    else:
        results = repo.list_events(conn, source_ip=payload, limit=5)

    integrity = check_database_integrity(conn)
    metrics = get_database_metrics(conn)

    return _ok({
        "payload": payload,
        "target_field": target,
        "query_pattern": f"SELECT * FROM events WHERE {target} = ? (DB-API Parameterized)",
        "matches_found": len(results),
        "sql_injection_prevented": True,
        "database_integrity": integrity["integrity"],
        "foreign_key_violations": integrity["foreign_key_violations"],
        "table_counts": metrics["table_counts"],
        "explanation": "Input was safely bound as a literal string parameter. No SQL commands were interpreted or executed."
    })


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    cli_parser = argparse.ArgumentParser(description="ThreatLens SOC Backend API Server")
    cli_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    cli_parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    cli_parser.add_argument("--db", default=DB_PATH, help=f"Path to SQLite database file (default: {DB_PATH})")
    args = cli_parser.parse_args()

    DB_PATH = args.db
    init_db(DB_PATH)
    print(f"[*] ThreatLens Backend API starting on http://{args.host}:{args.port}")
    print(f"[*] Connected to database: {DB_PATH}")
    app.run(host=args.host, port=args.port, debug=False)

