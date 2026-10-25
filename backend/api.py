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
import json
import os
from pathlib import Path
import sqlite3
import traceback
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, g

from backend import repository as repo
from backend.database import init_db, sha256_of, get_connection

# --------------------------------------------------------------------------
# Application setup
# --------------------------------------------------------------------------

app = Flask(__name__)

DB_PATH = os.environ.get("THREATLENS_DB", "threatlens.db")


@app.route("/", methods=["GET"])
def index():
    """API Root - Pure JSON status and endpoint discovery."""
    return jsonify({
        "ok": True,
        "service": "ThreatLens REST API",
        "module": "Module B (Backend API and Database)",
        "endpoints": {
            "ingest": "POST /api/ingest",
            "logs": "GET /api/logs",
            "events": "GET /api/events",
            "alerts": "GET /api/alerts",
            "statistics": "GET /api/statistics",
            "incidents": "GET /api/incidents"
        }
    })


def get_db():
    """Return a database connection for this request, ensuring schema exists."""
    if "db" not in g:
        g.db = init_db(DB_PATH)
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
            bucket = engine._history.setdefault(ev.source_ip, {})
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

            alert = Alert(
                rule_id=ar["rule_id"],
                rule_name=ar["rule_name"],
                source_ip=ar["source_ip"],
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

        conn.close()
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
    """Production health check endpoint."""
    conn = get_db()
    try:
        conn.execute("SELECT 1").fetchone()
        db_status = "connected"
    except Exception as exc:
        db_status = f"error: {exc}"
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "service": "ThreatLens API"
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
    return jsonify({"ok": True, "data": data}), status


def _err(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


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

        # ---- parse ---------------------------------------------------------
        try:
            from app.services.ingestion import ingest_log_lines
            from backend.adapter import adapt_ingestion_report
        except ImportError:
            return _err("Parser module (Module A) not yet available.", 503)

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()

        now = datetime.now(timezone.utc)
        if year is not None:
            try:
                reference_time = now.replace(year=year)
            except ValueError:
                # E.g. now is Feb 29 on leap year, and requested year is non-leap
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
                alert_row = {
                    "rule_id": alert.rule_id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity,
                    "status": alert.status,
                    "source_ip": alert.source_ip,
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
    return _ok({"events": _rows(events), "count": len(events)})


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
        limit=limit,
        offset=offset,
    )
    return _ok({"alerts": _rows(alerts), "count": len(alerts)})


@app.route("/api/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id: int):
    conn = get_db()
    alert = repo.get_alert(conn, alert_id)
    if alert is None:
        return _err("Alert not found.", 404)
    evidence = repo.get_alert_evidence(conn, alert_id)
    data = _row(alert)
    data["evidence"] = _rows(evidence)
    return _ok(data)


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
@app.route("/api/alerts/<int:alert_id>/status", methods=["PATCH"])
def update_alert_status(alert_id: int):
    body = request.get_json(silent=True) or {}
    status = body.get("status", "").strip()
    if not status:
        return _err("'status' field is required.")
    conn = get_db()
    try:
        found = repo.update_alert_status(conn, alert_id, status)
    except ValueError as exc:
        return _err(str(exc))
    if not found:
        return _err("Alert not found.", 404)
    conn.commit()
    return _ok({"alert_id": alert_id, "status": status})


# --------------------------------------------------------------------------
# Statistics (RSD: GET /api/stats)
# --------------------------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
@app.route("/api/statistics", methods=["GET"])
def statistics():
    conn = get_db()
    stats = repo.auth_statistics(conn)
    stats["alert_counts_by_severity"] = repo.count_alerts_by_severity(conn)
    stats["top_source_ips"] = _rows(repo.top_source_ips(conn, limit=10))
    stats["total_alerts"] = sum(repo.count_alerts_by_severity(conn).values())
    return _ok(stats)


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
        conn, status=request.args.get("status"), limit=limit, offset=offset
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

    conn = get_db()
    try:
        incident_id = repo.insert_incident(conn, title, description, severity)
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


@app.route("/api/incidents/<int:incident_id>/status", methods=["PATCH"])
def update_incident_status(incident_id: int):
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip()
    if not status:
        return _err("'status' field is required.")
    conn = get_db()
    try:
        found = repo.update_incident_status(conn, incident_id, status)
    except ValueError as exc:
        return _err(str(exc))
    if not found:
        return _err("Incident not found.", 404)
    conn.commit()
    return _ok({"incident_id": incident_id, "status": status})


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

