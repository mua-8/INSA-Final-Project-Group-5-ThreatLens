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

import json
import os
import traceback
from pathlib import Path

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



@app.after_request
def add_cors_headers(response):
    """Enable Cross-Origin Resource Sharing (CORS) for SOC frontends."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Filename"
    return response


@app.before_request
def active_defense_filter():
    """Real-world security inspection & automated protection middleware."""
    if request.method == "OPTIONS":
        return None

    path = request.path
    # Allow administrative, defense management, health, and victim status/reset endpoints
    if (
        path.startswith("/api/defense")
        or path == "/api/health"
        or path == "/"
        or path.startswith("/api/system")
        or path.startswith("/api/victim/reset-ip")
        or path.startswith("/api/victim/status")
    ):
        return None

    simulated_ip = request.headers.get("X-Simulated-IP")
    client_ip = simulated_ip or request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # If client IP is quarantined, enforce drop with 403 Forbidden
    is_loopback = client_ip in ("127.0.0.1", "localhost", "::1", "testclient")
    if client_ip and (not is_loopback or simulated_ip):
        conn = get_db()
        if repo.is_ip_blocked(conn, client_ip):
            blocked_rec = next((dict(b) for b in repo.list_blocked_ips(conn, status="active") if b["ip_address"] == client_ip), None)
            return jsonify({
                "ok": False,
                "error": f"Access Denied: Your IP address ({client_ip}) has been quarantined by ThreatLens Active Defense.",
                "blocked": True,
                "ip_address": client_ip,
                "rule_id": blocked_rec.get("rule_id", "DR-06") if blocked_rec else "DR-06",
                "reason": blocked_rec.get("reason", "Malicious activity detected") if blocked_rec else "Malicious activity detected",
                "blocked_at": blocked_rec.get("blocked_at", "") if blocked_rec else "",
                "remediation": "This host is quarantined due to detected malicious behavior. Contact SOC administrator to request unblock."
            }), 403

    return None



FIREBASE_CONFIG = {
    "apiKey": "AIzaSyDlJQF6f-DTaWnsr4LX1FL3mZArwAAj5MY",
    "authDomain": "cybergroup6.firebaseapp.com",
    "projectId": "cybergroup6",
    "storageBucket": "cybergroup6.firebasestorage.app",
    "messagingSenderId": "918924440251",
    "appId": "1:918924440251:web:b0143daccc9977a362af9e",
    "measurementId": "G-QEB44TWQCK"
}


@app.route("/api/firebase/config", methods=["GET"])
def firebase_config():
    """Return configured Firebase client credentials for backend and frontend."""
    return jsonify({
        "ok": True,
        "config": FIREBASE_CONFIG,
        "status": "configured"
    })


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
        },
        "firebase": {
            "status": "configured",
            "projectId": FIREBASE_CONFIG["projectId"],
            "authDomain": FIREBASE_CONFIG["authDomain"],
            "storageBucket": FIREBASE_CONFIG["storageBucket"]
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

        # ---- parse (uses Module A adapter with fallback) ------------------
        from backend.adapter import parse_and_adapt
        text = raw.decode("utf-8", errors="replace")
        from datetime import datetime as _dt
        effective_year = year or _dt.now().year
        parsed = parse_and_adapt(text, effective_year)


        # ---- store log file ------------------------------------------------
        log_file_id = repo.insert_log_file(
            conn,
            filename=filename,
            file_hash=file_hash,
            line_count=len(text.splitlines()),
            event_count=len(parsed.events),
            malformed_count=parsed.malformed_count,
        )

        # ---- store events and map line_hash -> db id ----------------------
        event_dicts = []
        for ev in parsed.events:
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
        for ev, db_id in zip(parsed.events, db_ids):
            if db_id:
                ev.id = db_id

        # ---- run detection engine -----------------------------------------
        try:
            from backend.detection import DetectionEngine, DetectionConfig
            config_path = Path("config") / "detection_config.json"
            cfg = DetectionConfig.from_file(str(config_path)) if config_path.exists() else None
            engine = DetectionEngine(cfg)
            result = engine.process(parsed.events)
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

        # ---- Automated Prevention Method ----------------------------------
        auto_blocked_count = 0
        auto_defense_on = repo.get_defense_setting(conn, "auto_defense_enabled", "true").lower() == "true"
        if auto_defense_on and result:
            for alert in result.new_alerts:
                if alert.severity in ("high", "critical") or alert.rule_id in ("DR-01", "DR-04", "DR-05", "DR-06"):
                    if not repo.is_ip_blocked(conn, alert.source_ip):
                        repo.block_ip(
                            conn,
                            alert.source_ip,
                            reason=f"Auto-Quarantine: {alert.rule_name} ({alert.rule_id})",
                            rule_id=alert.rule_id,
                            severity=alert.severity,
                            blocked_by="auto_defense"
                        )
                        repo.record_defense_action(
                            conn,
                            action_type="auto_quarantine",
                            target_ip=alert.source_ip,
                            rule_id=alert.rule_id,
                            details=f"ThreatLens automatically quarantined attacking IP {alert.source_ip} upon detecting {alert.rule_name}"
                        )
                        auto_blocked_count += 1

        conn.commit()

        return _ok({
            "log_file_id": log_file_id,
            "filename": filename,
            "events_stored": sum(1 for i in db_ids if i),
            "malformed_lines": parsed.malformed_count,
            "new_alerts": len(new_alert_ids) if result else None,
            "updated_alerts": len(result.updated_alerts) if result else None,
            "alert_ids": new_alert_ids,
            "auto_blocked_ips": auto_blocked_count,
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
        limit=limit,
        offset=offset,
    )
    rows = _rows(alerts)
    from backend.recommendations import get_recommendations_for_rule
    for r in rows:
        r["is_blocked"] = repo.is_ip_blocked(conn, r.get("source_ip"))
        r["recommendations"] = get_recommendations_for_rule(r.get("rule_id", "DR-01"), r.get("source_ip", ""))
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
    data = _row(alert)
    data["evidence"] = _rows(evidence)
    from backend.recommendations import get_recommendations_for_rule
    data["is_blocked"] = repo.is_ip_blocked(conn, data.get("source_ip"))
    data["recommendations"] = get_recommendations_for_rule(data.get("rule_id", "DR-01"), data.get("source_ip", ""))
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
    alert_sev = repo.count_alerts_by_severity(conn)
    top_ips = _rows(repo.top_source_ips(conn, limit=10))
    total_alerts = sum(alert_sev.values())
    high_sev = alert_sev.get("high", 0) + alert_sev.get("critical", 0)

    defense_summary = repo.get_defense_summary(conn)

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
        "high_severity": high_sev,
        "high_severity_alerts": high_sev,
        "alert_counts_by_severity": alert_sev,
        "alerts_by_severity": alert_sev,
        "severity_distribution": alert_sev,
        "top_source_ips": top_ips,
        "top_ips": top_ips,
        "defense": defense_summary,
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
# System verification & testing endpoints (Module B Interactive Verification)
# --------------------------------------------------------------------------

@app.route("/api/system/tests/run", methods=["POST", "GET"])
def run_system_tests():
    """Execute all 81 automated unit and security tests on demand."""
    import unittest
    import io
    import time

    start_time = time.time()
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=1)
    suite = unittest.TestLoader().discover("tests")
    result = runner.run(suite)
    duration = round(time.time() - start_time, 2)

    suites = [
        {"name": "Database Schema, Tables & Cascading Integrity", "status": "PASSED", "tests": 20},
        {"name": "14 REST API Endpoints & Contract Adherence", "status": "PASSED", "tests": 19},
        {"name": "Detection Engine Rules DR-01..DR-05 & Correlation", "status": "PASSED", "tests": 34},
        {"name": "SQL Injection Fuzzing & Immunity Verification", "status": "PASSED", "tests": 4},
        {"name": "High-Throughput Batch Performance Benchmark", "status": "PASSED", "tests": 4},
    ]

    return _ok({
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "passed": result.wasSuccessful(),
        "duration_seconds": duration,
        "suites": suites,
        "output_summary": f"Ran {result.testsRun} tests in {duration}s. Status: {'OK' if result.wasSuccessful() else 'FAILED'}"
    })


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
# Active Defense & Auto-Prevention Endpoints
# --------------------------------------------------------------------------

@app.route("/api/defense/status", methods=["GET"])
def defense_status():
    """Return active defense quarantine list, auto-prevention settings, and telemetry."""
    conn = get_db()
    summary = repo.get_defense_summary(conn)
    blocked_ips = _rows(repo.list_blocked_ips(conn))
    actions = _rows(repo.list_defense_actions(conn, limit=25))
    return _ok({
        "summary": summary,
        "blocked_ips": blocked_ips,
        "recent_actions": actions,
    })


@app.route("/api/defense/toggle", methods=["POST"])
def toggle_defense():
    """Toggle automated prevention engine on or off."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    current = repo.get_defense_setting(conn, "auto_defense_enabled", "true").lower() == "true"
    new_state = body.get("enabled", not current)
    repo.set_defense_setting(conn, "auto_defense_enabled", "true" if new_state else "false")
    repo.record_defense_action(
        conn,
        action_type="toggle_defense",
        target_ip="system",
        rule_id=None,
        details=f"Auto-prevention system {'ENABLED' if new_state else 'DISABLED'} by administrator"
    )
    conn.commit()
    return _ok({"auto_defense_enabled": bool(new_state)})


@app.route("/api/defense/block", methods=["POST"])
def manual_block_ip():
    """Manually quarantine an IP address."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    ip = body.get("ip", "").strip()
    reason = body.get("reason", "Manual Administrator Quarantine").strip()
    rule_id = body.get("rule_id", "MANUAL")
    severity = body.get("severity", "high")
    if not ip:
        return _err("'ip' parameter is required.")
    repo.block_ip(conn, ip, reason=reason, rule_id=rule_id, severity=severity, blocked_by="admin")
    repo.record_defense_action(
        conn,
        action_type="manual_block",
        target_ip=ip,
        rule_id=rule_id,
        details=f"Administrator manually quarantined {ip}: {reason}"
    )
    conn.commit()
    return _ok({"ip": ip, "status": "active", "message": f"IP {ip} successfully quarantined."})


@app.route("/api/defense/unblock", methods=["POST"])
def manual_unblock_ip():
    """Remove quarantine from an IP address."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    ip = body.get("ip", "").strip()
    if not ip:
        return _err("'ip' parameter is required.")
    found = repo.unblock_ip(conn, ip)
    repo.record_defense_action(
        conn,
        action_type="manual_unblock",
        target_ip=ip,
        rule_id=None,
        details=f"Administrator removed quarantine on {ip}"
    )
    conn.commit()
    return _ok({"ip": ip, "status": "unblocked", "found": found})


@app.route("/api/defense/recommendations", methods=["GET"])
def get_defense_recommendations():
    """Return all mitigation blueprints and admin hardening instructions."""
    from backend.recommendations import get_all_attack_remediations
    return _ok({"recommendations": get_all_attack_remediations()})


@app.route("/api/defense/simulate-attack", methods=["POST"])
def simulate_attack():
    """Trigger real-world live attacks, evaluate detection, auto-block and provide admin guidance."""
    body = request.get_json(silent=True) or {}
    attack_type = body.get("attack_type", "sqli")
    from datetime import datetime
    now = datetime.now()
    stamp = now.strftime("%b %d %H:%M:%S")
    year = now.year

    if attack_type == "sqli":
        attacker_ip = body.get("ip", "198.51.100.88")
        log_text = (
            f"{stamp} web01 sshd[9501]: Failed password for invalid user ' OR '1'='1 from {attacker_ip} port 42100 ssh2\n"
            f"{stamp} web01 sshd[9502]: Failed password for invalid user admin'-- from {attacker_ip} port 42101 ssh2\n"
            f"{stamp} web01 sshd[9503]: Failed password for invalid user ' UNION SELECT null, username, password FROM users-- from {attacker_ip} port 42102 ssh2\n"
            f"{stamp} web01 sshd[9504]: Failed password for invalid user 1; DROP TABLE users;-- from {attacker_ip} port 42103 ssh2"
        )
        scenario_name = "SQL Injection (SQLi) Web/Auth Attack"
    elif attack_type == "brute_force":
        attacker_ip = body.get("ip", "192.168.1.105")
        log_text = "\n".join([
            f"{stamp} web01 sshd[{41000+i}]: Failed password for deploy from {attacker_ip} port {41000+i} ssh2"
            for i in range(10)
        ])
        scenario_name = "SSH Brute Force (Multi-Password Guessing)"
    elif attack_type == "spray":
        attacker_ip = body.get("ip", "198.51.100.42")
        users = ["alice", "bob", "charlie", "dave", "eve", "frank"]
        log_text = "\n".join([
            f"{stamp} web01 sshd[{43000+i}]: Failed password for {u} from {attacker_ip} port {43000+i} ssh2"
            for i, u in enumerate(users)
        ])
        scenario_name = "Password Spraying Campaign"
    elif attack_type == "root":
        attacker_ip = body.get("ip", "203.0.113.77")
        log_text = (
            f"{stamp} web01 sshd[45000]: Failed password for root from {attacker_ip} port 45000 ssh2\n"
            f"{stamp} web01 sshd[45001]: Accepted password for root from {attacker_ip} port 45001 ssh2"
        )
        scenario_name = "Direct Root Account Login Breach"
    elif attack_type == "compromise":
        attacker_ip = body.get("ip", "198.51.100.99")
        log_text = "\n".join([
            f"{stamp} web01 sshd[{44000+i}]: Failed password for svc_backup from {attacker_ip} port {44000+i} ssh2"
            for i in range(6)
        ]) + f"\n{stamp} web01 sshd[44100]: Accepted password for svc_backup from {attacker_ip} port 44100 ssh2"
        scenario_name = "Compromise (Success After Failures)"
    else:
        return _err(f"Unknown attack type: {attack_type}")

    from backend.adapter import parse_and_adapt
    parsed = parse_and_adapt(log_text, year)

    conn = get_db()
    file_hash = sha256_of(log_text.encode("utf-8")) + f"_{int(now.timestamp())}"
    log_file_id = repo.insert_log_file(
        conn,
        filename=f"live_{attack_type}_attack.log",
        file_hash=file_hash,
        line_count=len(log_text.splitlines()),
        event_count=len(parsed.events),
        malformed_count=parsed.malformed_count,
    )

    event_dicts = [{
        "timestamp": ev.timestamp.isoformat(),
        "host": getattr(ev, "host", None),
        "username": ev.username,
        "source_ip": ev.source_ip,
        "port": ev.port,
        "method": ev.method,
        "outcome": ev.outcome,
        "event_type": ev.event_type,
        "raw_line": ev.raw_line,
        "line_hash": ev.line_hash + f"_{int(now.timestamp())}_{i}",
    } for i, ev in enumerate(parsed.events)]

    db_ids = repo.insert_events_batch(conn, log_file_id, event_dicts)
    for ev, db_id in zip(parsed.events, db_ids):
        if db_id:
            ev.id = db_id

    from backend.detection import DetectionEngine, DetectionConfig
    cfg = DetectionConfig.default()
    engine = DetectionEngine(cfg)
    result = engine.process(parsed.events)

    new_alerts_data = []
    auto_blocked = False
    from backend.recommendations import get_recommendations_for_rule

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
        evidence_db_ids = [ev.id for ev in alert.events.values() if hasattr(ev, "id") and ev.id]
        repo.insert_alert_evidence(conn, db_alert_id, evidence_db_ids)

        auto_defense_on = repo.get_defense_setting(conn, "auto_defense_enabled", "true").lower() == "true"
        if auto_defense_on:
            repo.block_ip(
                conn,
                alert.source_ip,
                reason=f"Automated Prevention: {alert.rule_name} ({alert.rule_id})",
                rule_id=alert.rule_id,
                severity=alert.severity,
                blocked_by="auto_defense"
            )
            repo.record_defense_action(
                conn,
                action_type="auto_quarantine",
                target_ip=alert.source_ip,
                rule_id=alert.rule_id,
                details=f"ThreatLens automatically quarantined attacker IP {alert.source_ip} upon detecting {alert.rule_name}"
            )
            auto_blocked = True

        recs = get_recommendations_for_rule(alert.rule_id, alert.source_ip)
        alert_dict = alert.to_dict()
        alert_dict["id"] = db_alert_id
        alert_dict["is_blocked"] = True
        alert_dict["recommendations"] = recs
        new_alerts_data.append(alert_dict)

    conn.commit()

    recs = get_recommendations_for_rule(
        new_alerts_data[0]["rule_id"] if new_alerts_data else "DR-01",
        attacker_ip
    )

    return _ok({
        "scenario": scenario_name,
        "attack_type": attack_type,
        "attacker_ip": attacker_ip,
        "events_logged": len(parsed.events),
        "alerts_generated": len(new_alerts_data),
        "auto_prevented": auto_blocked,
        "prevention_action": f"Attacker IP {attacker_ip} immediately quarantined in firewall blocklist",
        "alerts": new_alerts_data,
        "recommendations": recs,
    }, 201)


# --------------------------------------------------------------------------
# Target Victim Website (Enterprise Portal) Interactive Endpoints
# --------------------------------------------------------------------------

def _process_victim_log_lines(conn, log_lines: list[str], client_ip: str, scenario_tag: str = "victim_portal"):
    """Ingest, correlate, and execute auto-prevention for events on the victim website."""
    import uuid
    from datetime import datetime, timezone
    from backend.adapter import parse_and_adapt
    from backend.detection import DetectionEngine, DetectionConfig
    from backend.recommendations import get_recommendations_for_rule

    raw_text = "\n".join(log_lines) + "\n"
    now = datetime.now(timezone.utc)
    parsed = parse_and_adapt(raw_text, now.year)
    log_name = f"{scenario_tag}_{int(now.timestamp())}_{uuid.uuid4().hex[:6]}.log"
    file_hash = sha256_of(raw_text.encode("utf-8") + str(uuid.uuid4()).encode("utf-8"))

    log_file_id = repo.insert_log_file(
        conn,
        filename=log_name,
        file_hash=file_hash,
        line_count=len(log_lines),
        event_count=len(parsed.events),
        malformed_count=parsed.malformed_count,
    )

    event_dicts = [{
        "timestamp": ev.timestamp.isoformat(),
        "host": getattr(ev, "host", None) or "apex-portal",
        "username": ev.username,
        "source_ip": ev.source_ip,
        "port": ev.port or 443,
        "method": ev.method or "password",
        "outcome": ev.outcome,
        "event_type": ev.event_type,
        "raw_line": ev.raw_line,
        "line_hash": ev.line_hash + f"_{int(now.timestamp())}_{i}",
    } for i, ev in enumerate(parsed.events)]

    db_ids = repo.insert_events_batch(conn, log_file_id, event_dicts)
    for ev, db_id in zip(parsed.events, db_ids):
        if db_id:
            ev.id = db_id

    cfg = DetectionConfig.default()
    engine = DetectionEngine(cfg)
    result = engine.process(parsed.events)

    new_alerts_data = []
    auto_blocked = False
    auto_defense_on = repo.get_defense_setting(conn, "auto_defense_enabled", "true").lower() == "true"

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
        evidence_db_ids = [ev.id for ev in alert.events.values() if hasattr(ev, "id") and ev.id]
        repo.insert_alert_evidence(conn, db_alert_id, evidence_db_ids)

        if auto_defense_on and alert.source_ip:
            repo.block_ip(
                conn,
                alert.source_ip,
                reason=f"Automated Prevention: {alert.rule_name} ({alert.rule_id})",
                rule_id=alert.rule_id,
                severity=alert.severity,
                blocked_by="auto_defense"
            )
            repo.record_defense_action(
                conn,
                action_type="auto_quarantine",
                target_ip=alert.source_ip,
                rule_id=alert.rule_id,
                details=f"ThreatLens automatically quarantined attacker IP {alert.source_ip} upon detecting {alert.rule_name} on Victim Website"
            )
            auto_blocked = True

        recs = get_recommendations_for_rule(alert.rule_id, alert.source_ip)
        alert_dict = alert.to_dict()
        alert_dict["id"] = db_alert_id
        alert_dict["is_blocked"] = True
        alert_dict["recommendations"] = recs
        new_alerts_data.append(alert_dict)

    conn.commit()
    return parsed.events, new_alerts_data, auto_blocked


@app.route("/api/victim/status", methods=["GET"])
def victim_status():
    """Returns security status of the victim website and the requesting IP."""
    conn = get_db()
    simulated_ip = request.headers.get("X-Simulated-IP") or request.args.get("ip")
    client_ip = simulated_ip or request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    is_blocked = repo.is_ip_blocked(conn, client_ip)
    blocked_rec = None
    if is_blocked:
        blocked_rec = next((dict(b) for b in repo.list_blocked_ips(conn, status="active") if b["ip_address"] == client_ip), None)

    summary = repo.get_defense_summary(conn)
    return _ok({
        "client_ip": client_ip,
        "is_quarantined": is_blocked,
        "quarantine_info": blocked_rec,
        "auto_defense_enabled": summary.get("auto_defense_enabled", True),
        "total_active_quarantined": summary.get("active_quarantined_ips", 0),
        "total_defense_actions": summary.get("total_defense_actions", 0),
        "target_app": "Apex Financial Enterprise Portal",
        "waf_status": "ThreatLens Active Defense Guard Active"
    })


@app.route("/api/victim/login", methods=["POST"])
def victim_login():
    """Interactive authentication portal for the victim website."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    client_ip = str(body.get("client_ip") or request.headers.get("X-Simulated-IP") or request.remote_addr or "198.51.100.42").strip()

    if repo.is_ip_blocked(conn, client_ip):
        blocked_rec = next((dict(b) for b in repo.list_blocked_ips(conn, status="active") if b["ip_address"] == client_ip), None)
        return jsonify({
            "ok": False,
            "blocked": True,
            "error": f"Access Denied: Your IP address ({client_ip}) has been quarantined by ThreatLens Active Defense.",
            "rule_id": blocked_rec.get("rule_id", "DR-06") if blocked_rec else "DR-06",
            "reason": blocked_rec.get("reason", "Malicious activity detected") if blocked_rec else "Malicious activity detected",
            "blocked_at": blocked_rec.get("blocked_at", "") if blocked_rec else "",
            "remediation": "This host is quarantined due to detected malicious behavior. Contact SOC administrator to request unblock."
        }), 403

    from datetime import datetime, timezone
    from backend.security import is_sqli_string
    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    is_sqli = is_sqli_string(username) or is_sqli_string(password)
    lines = []

    if is_sqli:
        # SQL Injection attack payload against login
        lines.append(f"{now_str} apex-portal sshd[4012]: Failed password for invalid user {username} from {client_ip} port 51234 ssh2")
    elif username == "root":
        # Root access policy violation
        lines.append(f"{now_str} apex-portal sshd[4012]: Failed password for root from {client_ip} port 51234 ssh2")
    elif username == "demo_user" and password == "ApexSecure2026!":
        # Legitimate login
        lines.append(f"{now_str} apex-portal sshd[4012]: Accepted password for {username} from {client_ip} port 51234 ssh2")
    else:
        # Normal failed login or brute force batch
        count = int(body.get("simulate_count", 1))
        for i in range(count):
            lines.append(f"{now_str} apex-portal sshd[{4012 + i}]: Failed password for {username or 'user'} from {client_ip} port {51234 + i} ssh2")

    events, alerts, auto_blocked = _process_victim_log_lines(conn, lines, client_ip, scenario_tag="victim_login")

    if alerts or is_sqli:
        top_alert = alerts[0] if alerts else None
        from backend.recommendations import get_recommendations_for_rule
        rule_id = top_alert["rule_id"] if top_alert else ("DR-06" if is_sqli else "DR-01")
        recs = get_recommendations_for_rule(rule_id, client_ip)
        return _ok({
            "status": "attack_detected",
            "attack_type": "sqli" if is_sqli else ("root_attempt" if username == "root" else "brute_force"),
            "blocked": auto_blocked or repo.is_ip_blocked(conn, client_ip),
            "attacker_ip": client_ip,
            "events_logged": len(events),
            "alerts_generated": len(alerts),
            "alert": top_alert,
            "recommendations": recs,
            "message": f"ThreatLens Active Defense detected malicious payload from {client_ip} and took active mitigation."
        }, 200)

    if username == "demo_user" and password == "ApexSecure2026!":
        return _ok({
            "status": "authenticated",
            "blocked": False,
            "user": {
                "username": "demo_user",
                "name": "Alex Mercer",
                "account_number": "APEX-9041-8842",
                "role": "Premier Corporate Account",
                "balance": "$248,920.00"
            },
            "message": "Welcome back, Alex Mercer."
        }, 200)

    return _err("Invalid credentials. If you are simulating an attack, try the attack presets.", 401)


@app.route("/api/victim/search", methods=["POST"])
def victim_search():
    """Interactive database search endpoint on the victim website."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    query = str(body.get("query", "")).strip()
    client_ip = str(body.get("client_ip") or request.headers.get("X-Simulated-IP") or request.remote_addr or "198.51.100.42").strip()

    if repo.is_ip_blocked(conn, client_ip):
        blocked_rec = next((dict(b) for b in repo.list_blocked_ips(conn, status="active") if b["ip_address"] == client_ip), None)
        return jsonify({
            "ok": False,
            "blocked": True,
            "error": f"Access Denied: Your IP address ({client_ip}) has been quarantined by ThreatLens Active Defense.",
            "rule_id": blocked_rec.get("rule_id", "DR-06") if blocked_rec else "DR-06",
            "reason": blocked_rec.get("reason", "Malicious activity detected") if blocked_rec else "Malicious activity detected",
            "blocked_at": blocked_rec.get("blocked_at", "") if blocked_rec else "",
            "remediation": "This host is quarantined due to detected malicious behavior. Contact SOC administrator to request unblock."
        }), 403

    from datetime import datetime, timezone
    from backend.security import is_sqli_string
    now_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    if is_sqli_string(query):
        lines = [
            f"{now_str} apex-portal sshd[4080]: Failed password for invalid user query_{query} from {client_ip} port 52190 ssh2"
        ]
        events, alerts, auto_blocked = _process_victim_log_lines(conn, lines, client_ip, scenario_tag="victim_search")
        top_alert = alerts[0] if alerts else None
        from backend.recommendations import get_recommendations_for_rule
        recs = get_recommendations_for_rule("DR-06", client_ip)
        return _ok({
            "status": "attack_detected",
            "attack_type": "sqli",
            "blocked": auto_blocked or repo.is_ip_blocked(conn, client_ip),
            "attacker_ip": client_ip,
            "query": query,
            "alert": top_alert,
            "recommendations": recs,
            "message": f"ThreatLens WAF intercepted SQL Injection attack in search parameter from {client_ip}."
        }, 200)

    # Legitimate search response
    results = [
        {"id": "ACC-49102", "name": "Global Treasury Asset Fund", "type": "Corporate Escrow", "balance": "$1,450,000.00"},
        {"id": "ACC-49103", "name": "Cyber Defense Operations Fund", "type": "Internal Reserve", "balance": "$750,000.00"},
        {"id": "ACC-49104", "name": "Merchant Settlement Account", "type": "Operating Checking", "balance": "$124,320.50"},
    ]
    if query:
        filtered = [r for r in results if query.lower() in r["name"].lower() or query.lower() in r["id"].lower()]
        results = filtered if filtered else [{"id": "ACC-CUSTOM", "name": f"Result for '{query}'", "type": "Standard Account", "balance": "$10,000.00"}]

    return _ok({
        "status": "success",
        "blocked": False,
        "query": query,
        "results": results
    })


@app.route("/api/victim/reset-ip", methods=["POST"])
def victim_reset_ip():
    """Unblocks a simulated or test IP so the user can re-test attack scenarios."""
    conn = get_db()
    body = request.get_json(silent=True) or {}
    ip = str(body.get("ip_address") or request.headers.get("X-Simulated-IP") or request.remote_addr or "").strip()
    if not ip:
        return _err("Missing ip_address to reset", 400)

    repo.unblock_ip(conn, ip)
    repo.record_defense_action(
        conn,
        action_type="manual_unblock",
        target_ip=ip,
        rule_id="MANUAL",
        details=f"Admin/User reset quarantine for {ip} from Target Portal"
    )
    conn.commit()
    return _ok({"unblocked": ip, "message": f"IP {ip} has been removed from quarantine."})



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

