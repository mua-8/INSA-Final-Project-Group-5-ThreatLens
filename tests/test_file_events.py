"""Tests for ThreatLens Phase 1: File-System Telemetry Foundation.

Validates the complete file-system telemetry integration:
1. Supported file-event types (file_created, file_modified, file_renamed, file_deleted).
2. Event serialization, deserialization, and agent model validation.
3. Ingestion via POST /api/v1/events and POST /api/v1/file-events with dual persistence.
4. Rejection of invalid event types and malformed payloads (400).
5. Missing or invalid endpoint identity (device_id) handling (400).
6. Idempotent retries (200) vs conflicting duplicate event handling (409).
7. Strict timestamp validation (ISO-8601 with timezone offset required).
8. Rename events with and without previous_path.
9. Querying and filtering via GET /api/v1/file-events (device, path, extension, type, pagination).
10. Single file event detail query via GET /api/v1/file-events/<event_id> (200 and 404).
11. Optional process attribution (process_id, process_name) and validation of invalid values.
12. Security validation: rejection of null bytes and path traversal in file_path and previous_path.
13. Backward compatibility: existing SSH parsing and ingestion via POST /api/ingest.
14. Detection rule isolation: built-in rules DR-01 through DR-05 generate zero alerts from file events.
15. Custom rule engine isolation: custom detection rules are never evaluated against file events.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
import unittest
import uuid
import sys

# Ensure repository root and endpoint-agent are on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
AGENT_SRC = os.path.join(REPO_ROOT, "endpoint-agent", "src")
if AGENT_SRC not in sys.path:
    sys.path.insert(0, AGENT_SRC)

from backend import api, repository as repo
from backend.database import init_db
from threatlens_agent.models.events import (
    create_file_event,
    EventValidationError,
    FILE_EVENT_CREATED,
    FILE_EVENT_MODIFIED,
    FILE_EVENT_RENAMED,
    FILE_EVENT_DELETED,
    FILE_EVENT_TYPES,
)


class TestFileSystemTelemetryIntegration(unittest.TestCase):
    """Test suite verifying file-system telemetry ingestion, validation, and isolation."""

    TEST_API_KEY = "test-file-telemetry-secret-key-9999"

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        # Direct backend API to isolated temporary test database
        api.DB_PATH = self.db_path
        api.reset_detection_engine(self.db_path)
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

        # Set API key for endpoint agent requests
        self.original_api_key = os.environ.get("THREATLENS_AGENT_API_KEY")
        os.environ["THREATLENS_AGENT_API_KEY"] = self.TEST_API_KEY

    def tearDown(self):
        if self.original_api_key is not None:
            os.environ["THREATLENS_AGENT_API_KEY"] = self.original_api_key
        else:
            os.environ.pop("THREATLENS_AGENT_API_KEY", None)

        api.reset_detection_engine(self.db_path)
        self.conn.close()

        import gc
        gc.collect()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass

    def _auth_headers(self, key: str | None = None) -> dict[str, str]:
        token = key if key is not None else self.TEST_API_KEY
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ThreatLens-Agent/0.1.0",
        }

    def _sample_file_event(
        self,
        event_id: str | None = None,
        device_id: str = "endpoint-srv-01",
        timestamp: str | None = None,
        event_type: str = "file_created",
        file_path: str = "/var/www/html/index.php",
        file_extension: str | None = None,
        previous_path: str | None = None,
        process_name: str | None = None,
        process_id: int | None = None,
        source: str = "file_monitor",
        severity: str = "informational",
        raw_event: str | None = None,
        attributes: dict | None = None,
    ) -> dict:
        eid = event_id or str(uuid.uuid4())
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        attrs = attributes.copy() if attributes else {}
        attrs["file_path"] = file_path
        if file_extension is not None:
            attrs["file_extension"] = file_extension
        if previous_path is not None:
            attrs["previous_path"] = previous_path
        if process_name is not None:
            attrs["process_name"] = process_name
        if process_id is not None:
            attrs["process_id"] = process_id

        return {
            "schema_version": "1.0.0",
            "event_id": eid,
            "device_id": device_id,
            "timestamp": ts,
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "source_ip": None,
            "username": None,
            "raw_event": raw_event or f"[{ts}] device={device_id} type={event_type} path={file_path}",
            "attributes": attrs,
        }

    # =========================================================================
    # 1. Supported File-Event Types & Model Serialization
    # =========================================================================

    def test_supported_file_event_types_persistence(self):
        """Verify all 4 supported event types (created, modified, renamed, deleted) persist in dual tables."""
        types_and_paths = [
            ("file_created", "/home/user/docs/report.docx", None),
            ("file_modified", "/home/user/docs/report.docx", None),
            ("file_renamed", "/home/user/docs/report_final.docx", "/home/user/docs/report.docx"),
            ("file_deleted", "/home/user/docs/report_final.docx", None),
        ]

        events = []
        for ev_type, path, prev in types_and_paths:
            ev = self._sample_file_event(
                event_type=ev_type,
                file_path=path,
                previous_path=prev,
            )
            events.append(ev)

        payload = {"device_id": "endpoint-srv-01", "events": events}
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["count"], 4)

        # Verify endpoint_events table has all 4
        ee_rows = self.conn.execute("SELECT * FROM endpoint_events ORDER BY id ASC").fetchall()
        self.assertEqual(len(ee_rows), 4)

        # Verify file_events table has all 4 with proper field projections
        fe_rows = self.conn.execute("SELECT * FROM file_events ORDER BY id ASC").fetchall()
        self.assertEqual(len(fe_rows), 4)

        for i, (ev_type, path, prev) in enumerate(types_and_paths):
            fe = fe_rows[i]
            self.assertEqual(fe["event_type"], ev_type)
            self.assertEqual(fe["file_path"], path)
            self.assertEqual(fe["file_extension"], ".docx")
            self.assertEqual(fe["previous_path"], prev)
            self.assertEqual(fe["device_id"], "endpoint-srv-01")

    def test_agent_model_create_file_event_and_serialization(self):
        """Verify endpoint-agent create_file_event factory and serialization contract."""
        event = create_file_event(
            device_id="dev-node-01",
            event_type="file_created",
            file_path="/data/finance/q4.xlsx",
            process_name="excel.exe",
            process_id=2048,
        )
        self.assertEqual(event.event_type, FILE_EVENT_CREATED)
        self.assertEqual(event.attributes["file_path"], "/data/finance/q4.xlsx")
        self.assertEqual(event.attributes["file_extension"], ".xlsx")
        self.assertEqual(event.attributes["process_name"], "excel.exe")
        self.assertEqual(event.attributes["process_id"], 2048)

        # Serialization to dictionary
        d = event.to_dict()
        self.assertEqual(d["device_id"], "dev-node-01")
        self.assertEqual(d["source"], "file_monitor")
        self.assertIn("file_path", d["attributes"])

        # JSON round-trip
        json_str = json.dumps(d)
        deserialized = json.loads(json_str)
        self.assertEqual(deserialized["event_id"], event.event_id)
        self.assertEqual(deserialized["attributes"]["file_extension"], ".xlsx")

    # =========================================================================
    # 2. Ingestion Routes: POST /api/v1/events and POST /api/v1/file-events
    # =========================================================================

    def test_ingestion_via_api_v1_events(self):
        """POST /api/v1/events accepts batch of file events and updates endpoint status."""
        ev = self._sample_file_event(
            device_id="linux-workstation-01",
            event_type="file_created",
            file_path="/tmp/test.sh",
        )
        payload = {"device_id": "linux-workstation-01", "events": [ev]}
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 200)

        # Check endpoint table auto-enrollment
        ep = self.conn.execute("SELECT * FROM endpoints WHERE device_id = ?", ("linux-workstation-01",)).fetchone()
        self.assertIsNotNone(ep)
        self.assertEqual(ep["device_id"], "linux-workstation-01")

        # Check file_events table
        fe = self.conn.execute("SELECT * FROM file_events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        self.assertIsNotNone(fe)
        self.assertEqual(fe["file_path"], "/tmp/test.sh")
        self.assertEqual(fe["file_extension"], ".sh")

    def test_ingestion_via_api_v1_file_events_batch(self):
        """POST /api/v1/file-events accepts standard batch payload."""
        ev = self._sample_file_event(
            device_id="db-srv-02",
            event_type="file_modified",
            file_path="/etc/mysql/my.cnf",
        )
        payload = {"device_id": "db-srv-02", "events": [ev]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertIn(ev["event_id"], data["acknowledged"])

        fe = repo.get_file_event(self.conn, ev["event_id"])
        self.assertIsNotNone(fe)
        self.assertEqual(fe["file_path"], "/etc/mysql/my.cnf")

    def test_ingestion_via_api_v1_file_events_single(self):
        """POST /api/v1/file-events accepts single event JSON object directly."""
        ev = self._sample_file_event(
            device_id="app-srv-03",
            event_type="file_deleted",
            file_path="/var/log/old.log",
        )
        # Post single event object without outer {"device_id": ..., "events": [...]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=ev)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertIn(ev["event_id"], data["acknowledged"])

        fe = repo.get_file_event(self.conn, ev["event_id"])
        self.assertIsNotNone(fe)
        self.assertEqual(fe["event_type"], "file_deleted")

    # =========================================================================
    # 3. Invalid Event Types and Malformed Payloads
    # =========================================================================

    def test_invalid_event_type_rejected_400(self):
        """Unsupported file event_type is rejected with HTTP 400."""
        ev = self._sample_file_event(event_type="file_encrypted_ransomware")
        payload = {"device_id": "srv-01", "events": [ev]}
        # Unsupported file event_type rejected
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid file event_type", resp.get_json()["error"])

        resp2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Invalid file event_type", resp2.get_json()["error"])

        # Non-file event sent to file-events endpoint rejected
        non_file_ev = {
            "event_id": str(uuid.uuid4()),
            "device_id": "srv-01",
            "source": "linux_auth",
            "event_type": "ssh_auth_failure",
            "severity": "high",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        resp3 = self.client.post(
            "/api/v1/file-events",
            headers=self._auth_headers(),
            json={"device_id": "srv-01", "events": [non_file_ev]}
        )
        self.assertEqual(resp3.status_code, 400)
        self.assertIn("not a supported file-system event type", resp3.get_json()["error"])

    def test_malformed_json_and_payloads_rejected_400(self):
        """Non-JSON text, empty body, and empty events list are rejected with 400."""
        # Empty body
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), data="")
        self.assertEqual(resp.status_code, 400)

        # Invalid JSON syntax
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), data="{bad: json,}")
        self.assertEqual(resp.status_code, 400)

        # Empty events list
        payload = {"device_id": "srv-01", "events": []}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("at least one event", resp.get_json()["error"])

        # Non-dict event item
        payload = {"device_id": "srv-01", "events": ["not-a-dict"]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("must be a JSON object", resp.get_json()["error"])

    def test_missing_file_path_rejected_400(self):
        """File event missing file_path is rejected with 400."""
        ev = self._sample_file_event()
        del ev["attributes"]["file_path"]
        payload = {"device_id": "srv-01", "events": [ev]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("requires a non-empty 'file_path'", resp.get_json()["error"])

    # =========================================================================
    # 4. Missing or Invalid Endpoint Identity
    # =========================================================================

    def test_missing_or_blank_device_id_rejected_400(self):
        """Missing or whitespace-only device_id is rejected with 400."""
        ev = self._sample_file_event()
        # Missing root device_id in batch
        payload = {"events": [ev]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("device_id", resp.get_json()["error"])

        # Blank root device_id
        payload = {"device_id": "   ", "events": [ev]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)

        # Blank event-level device_id
        ev_blank = self._sample_file_event(device_id=" ")
        payload2 = {"device_id": "valid-dev", "events": [ev_blank]}
        resp2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload2)
        self.assertEqual(resp2.status_code, 400)

    def test_invalid_event_id_uuid_rejected_400(self):
        """Non-UUID event_id is rejected with 400."""
        ev = self._sample_file_event(event_id="not-a-valid-uuid")
        payload = {"device_id": "srv-01", "events": [ev]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("must be a valid UUID string", resp.get_json()["error"])

    # =========================================================================
    # 5. Duplicate Event Handling & Idempotency
    # =========================================================================

    def test_idempotent_duplicate_retry_200(self):
        """Resending an identical event batch succeeds idempotently without duplicate rows."""
        ev = self._sample_file_event()
        payload = {"device_id": "srv-01", "events": [ev]}

        # First ingestion
        r1 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(r1.status_code, 200)

        # Retry exact same batch
        r2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()["acknowledged"], [ev["event_id"]])

        # Confirm count in database is still 1
        count = self.conn.execute("SELECT COUNT(*) FROM file_events WHERE event_id = ?", (ev["event_id"],)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_conflicting_duplicate_in_same_batch_409(self):
        """Batch containing duplicate event_id with different data returns 409 conflict."""
        eid = str(uuid.uuid4())
        ev1 = self._sample_file_event(event_id=eid, file_path="/path/one.txt")
        ev2 = self._sample_file_event(event_id=eid, file_path="/path/two.txt")

        payload = {"device_id": "srv-01", "events": [ev1, ev2]}
        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 409)
        self.assertIn("Conflicting duplicate event_id", resp.get_json()["error"])

    def test_conflicting_duplicate_against_db_409(self):
        """Sending an event with an existing event_id but different data returns 409 conflict."""
        eid = str(uuid.uuid4())
        ev1 = self._sample_file_event(event_id=eid, file_path="/original/file.txt")
        r1 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev1]})
        self.assertEqual(r1.status_code, 200)

        # Send same event_id with different file path
        ev2 = self._sample_file_event(event_id=eid, file_path="/modified/different.txt")
        r2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev2]})
        self.assertEqual(r2.status_code, 409)
        self.assertIn("Conflicting duplicate event_id", r2.get_json()["error"])

    # =========================================================================
    # 6. Timestamp Validation
    # =========================================================================

    def test_timestamp_validation_rules(self):
        """Timestamps must be valid ISO-8601 with explicit timezone offsets."""
        # Non-ISO string
        ev_bad_iso = self._sample_file_event(timestamp="yesterday morning")
        r1 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_bad_iso]})
        self.assertEqual(r1.status_code, 400)
        self.assertIn("invalid ISO-8601 timestamp", r1.get_json()["error"])

        # Naive timestamp without timezone
        ev_naive = self._sample_file_event(timestamp="2026-10-27T10:15:30")
        r2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_naive]})
        self.assertEqual(r2.status_code, 400)
        self.assertIn("timezone offset", r2.get_json()["error"])

        # Valid with 'Z' suffix
        ev_z = self._sample_file_event(timestamp="2026-10-27T10:15:30Z")
        r3 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_z]})
        self.assertEqual(r3.status_code, 200)

        # Valid with numeric offset
        ev_offset = self._sample_file_event(timestamp="2026-10-27T12:15:30+02:00")
        r4 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_offset]})
        self.assertEqual(r4.status_code, 200)

    # =========================================================================
    # 7. Rename Events (With and Without Previous Path)
    # =========================================================================

    def test_rename_events_with_and_without_previous_path(self):
        """file_renamed events support both paired renames and moves with unobservable origin."""
        # Rename with previous_path
        ev_with_prev = self._sample_file_event(
            event_type="file_renamed",
            file_path="/etc/nginx/sites-available/app.conf",
            previous_path="/etc/nginx/sites-available/app.conf.bak",
        )
        r1 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_with_prev]})
        self.assertEqual(r1.status_code, 200)

        fe1 = repo.get_file_event(self.conn, ev_with_prev["event_id"])
        self.assertEqual(fe1["previous_path"], "/etc/nginx/sites-available/app.conf.bak")

        # Rename without previous_path (e.g. moved in from outside watch directory)
        ev_no_prev = self._sample_file_event(
            event_type="file_renamed",
            file_path="/etc/nginx/sites-enabled/app.conf",
            previous_path=None,
        )
        r2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_no_prev]})
        self.assertEqual(r2.status_code, 200)

        fe2 = repo.get_file_event(self.conn, ev_no_prev["event_id"])
        self.assertIsNone(fe2["previous_path"])

    # =========================================================================
    # 8. Querying File Events & Filtering (GET /api/v1/file-events)
    # =========================================================================

    def test_querying_file_events_with_filters_and_pagination(self):
        """Verify GET /api/v1/file-events supports device, path, extension, type filters, and pagination."""
        test_events = [
            self._sample_file_event(device_id="dev-alpha", event_type="file_created", file_path="/var/www/script1.py"),
            self._sample_file_event(device_id="dev-alpha", event_type="file_modified", file_path="/var/www/script2.py"),
            self._sample_file_event(device_id="dev-beta", event_type="file_created", file_path="/opt/data/archive.tar.gz"),
            self._sample_file_event(device_id="dev-beta", event_type="file_deleted", file_path="/opt/data/temp.log"),
            self._sample_file_event(device_id="dev-gamma", event_type="file_modified", file_path="/etc/config.json"),
        ]

        resp = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "dev-batch", "events": test_events})
        self.assertEqual(resp.status_code, 200)

        # Filter by device_id
        r_dev = self.client.get("/api/v1/file-events?device_id=dev-alpha")
        self.assertEqual(r_dev.status_code, 200)
        data_dev = r_dev.get_json()
        self.assertEqual(data_dev["count"], 2)
        self.assertTrue(all(e["device_id"] == "dev-alpha" for e in data_dev["events"]))

        # Filter by event_type
        r_type = self.client.get("/api/v1/file-events?event_type=file_created")
        self.assertEqual(r_type.status_code, 200)
        data_type = r_type.get_json()
        self.assertEqual(data_type["count"], 2)

        # Filter by file_extension (with leading dot)
        r_ext1 = self.client.get("/api/v1/file-events?file_extension=.py")
        self.assertEqual(r_ext1.status_code, 200)
        self.assertEqual(r_ext1.get_json()["count"], 2)

        # Filter by file_extension (without leading dot)
        r_ext2 = self.client.get("/api/v1/file-events?file_extension=py")
        self.assertEqual(r_ext2.status_code, 200)
        self.assertEqual(r_ext2.get_json()["count"], 2)

        # Filter by file_path substring
        r_path = self.client.get("/api/v1/file-events?file_path=archive")
        self.assertEqual(r_path.status_code, 200)
        data_path = r_path.get_json()
        self.assertEqual(data_path["count"], 1)
        self.assertEqual(data_path["events"][0]["file_path"], "/opt/data/archive.tar.gz")

        # Pagination: limit & offset
        r_page1 = self.client.get("/api/v1/file-events?limit=2&offset=0")
        self.assertEqual(r_page1.status_code, 200)
        data_p1 = r_page1.get_json()
        self.assertEqual(data_p1["count"], 2)
        self.assertEqual(data_p1["total"], 5)

        r_page2 = self.client.get("/api/v1/file-events?limit=2&offset=2")
        self.assertEqual(r_page2.status_code, 200)
        data_p2 = r_page2.get_json()
        self.assertEqual(data_p2["count"], 2)

        # Distinct events between page 1 and page 2
        p1_ids = {e["event_id"] for e in data_p1["events"]}
        p2_ids = {e["event_id"] for e in data_p2["events"]}
        self.assertTrue(p1_ids.isdisjoint(p2_ids))

    def test_get_single_file_event_detail(self):
        """GET /api/v1/file-events/<event_id> returns 200 for existing and 404 for missing."""
        ev = self._sample_file_event(file_path="/var/secret/keys.pem")
        self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev]})

        # Existing event
        resp_found = self.client.get(f"/api/v1/file-events/{ev['event_id']}")
        self.assertEqual(resp_found.status_code, 200)
        data = resp_found.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["event_id"], ev["event_id"])
        self.assertEqual(data["data"]["file_path"], "/var/secret/keys.pem")

        # Missing event UUID
        missing_uuid = str(uuid.uuid4())
        resp_missing = self.client.get(f"/api/v1/file-events/{missing_uuid}")
        self.assertEqual(resp_missing.status_code, 404)
        self.assertIn("File event not found", resp_missing.get_json()["error"])

    # =========================================================================
    # 9. Process Attribution Handling
    # =========================================================================

    def test_process_attribution_valid_and_invalid(self):
        """Process attribution is optional; valid values are persisted and invalid values rejected."""
        # Valid process attribution
        ev_valid = self._sample_file_event(
            process_name="ransom_test_proc",
            process_id=9876,
        )
        r_valid = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_valid]})
        self.assertEqual(r_valid.status_code, 200)

        fe = repo.get_file_event(self.conn, ev_valid["event_id"])
        self.assertEqual(fe["process_name"], "ransom_test_proc")
        self.assertEqual(fe["process_id"], 9876)

        # Invalid process_id <= 0
        ev_neg_pid = self._sample_file_event(process_id=-1)
        r_neg = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_neg_pid]})
        self.assertEqual(r_neg.status_code, 400)
        self.assertIn("positive integer", r_neg.get_json()["error"])

        ev_zero_pid = self._sample_file_event(process_id=0)
        r_zero = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_zero_pid]})
        self.assertEqual(r_zero.status_code, 400)
        self.assertIn("positive integer", r_zero.get_json()["error"])

        # Invalid empty process_name
        ev_empty_pname = self._sample_file_event(process_name="   ")
        r_empty = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_empty_pname]})
        self.assertEqual(r_empty.status_code, 400)
        self.assertIn("non-empty string", r_empty.get_json()["error"])

    # =========================================================================
    # 10. Rejection of Null Bytes and Path Traversal
    # =========================================================================

    def test_null_bytes_and_path_traversal_rejected(self):
        """file_path and previous_path containing null bytes or path traversal are rejected with 400."""
        # Null byte in file_path
        ev_null_path = self._sample_file_event(file_path="/tmp/evil\x00.exe")
        r1 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_null_path]})
        self.assertEqual(r1.status_code, 400)
        self.assertIn("null bytes", r1.get_json()["error"])

        # Null byte in previous_path
        ev_null_prev = self._sample_file_event(
            event_type="file_renamed",
            file_path="/tmp/normal.txt",
            previous_path="/tmp/evil\x00.txt",
        )
        r2 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_null_prev]})
        self.assertEqual(r2.status_code, 400)
        self.assertIn("null bytes", r2.get_json()["error"])

        # Path traversal in file_path
        ev_traversal_path = self._sample_file_event(file_path="../../etc/shadow")
        r3 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_traversal_path]})
        self.assertEqual(r3.status_code, 400)
        self.assertIn("path traversal", r3.get_json()["error"])

        # Internal path traversal in file_path
        ev_internal_traversal = self._sample_file_event(file_path="/var/www/../../etc/passwd")
        r4 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_internal_traversal]})
        self.assertEqual(r4.status_code, 400)
        self.assertIn("path traversal", r4.get_json()["error"])

        # Path traversal in previous_path
        ev_traversal_prev = self._sample_file_event(
            event_type="file_renamed",
            file_path="/var/data/good.txt",
            previous_path="/var/data/../../root/flag.txt",
        )
        r5 = self.client.post("/api/v1/file-events", headers=self._auth_headers(), json={"device_id": "srv-01", "events": [ev_traversal_prev]})
        self.assertEqual(r5.status_code, 400)
        self.assertIn("path traversal", r5.get_json()["error"])

    # =========================================================================
    # 11. Existing SSH Ingestion & Compatibility (POST /api/ingest)
    # =========================================================================

    def test_existing_ssh_ingest_via_api_ingest_intact(self):
        """POST /api/ingest continues to parse SSH auth syslog lines and write to events table."""
        sample_syslog = (
            "Oct 27 10:00:01 web01 sshd[12345]: Failed password for invalid user hacker from 198.51.100.22 port 42100 ssh2\n"
            "Oct 27 10:00:02 web01 sshd[12346]: Accepted password for deploy from 198.51.100.22 port 42102 ssh2\n"
        )
        resp = self.client.post("/api/ingest", data=sample_syslog, headers={"Content-Type": "text/plain", "X-Filename": "auth.log"})
        self.assertIn(resp.status_code, (200, 201))
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["data"]["events_stored"], 2)

        # Verify parsed events in events table
        events = self.conn.execute("SELECT * FROM events").fetchall()
        self.assertGreaterEqual(len(events), 2)
        users = {e["username"] for e in events}
        self.assertIn("hacker", users)
        self.assertIn("deploy", users)

    def test_existing_ssh_endpoint_events_via_api_v1_events(self):
        """SSH authentication events via POST /api/v1/events continue to adapt into events table."""
        ssh_event = {
            "schema_version": "1.0.0",
            "event_id": str(uuid.uuid4()),
            "device_id": "server-ssh-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "linux_auth",
            "event_type": "ssh_auth_failure",
            "severity": "high",
            "source_ip": "203.0.113.88",
            "username": "root",
            "raw_event": "Failed password for root from 203.0.113.88 port 55432 ssh2",
            "attributes": {"port": 55432, "auth_method": "password"},
        }
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json={"device_id": "server-ssh-01", "events": [ssh_event]})
        self.assertEqual(resp.status_code, 200)

        # Verify in endpoint_events
        ee = repo.get_endpoint_event(self.conn, ssh_event["event_id"])
        self.assertIsNotNone(ee)
        self.assertEqual(ee["source"], "linux_auth")

        # Verify adapted and stored in SSH events table
        ssh_rows = self.conn.execute("SELECT * FROM events WHERE username = 'root'").fetchall()
        self.assertEqual(len(ssh_rows), 1)
        self.assertEqual(ssh_rows[0]["source_ip"], "203.0.113.88")

    # =========================================================================
    # 12. Detection Rule Isolation: DR-01 through DR-05 Unaffected
    # =========================================================================

    def test_file_events_do_not_generate_ssh_alerts(self):
        """File-system telemetry never pollutes the SSH events table and generates zero alerts for DR-01..DR-05."""
        # Send 25 file-system events in rapid succession
        events = []
        for i in range(25):
            ev = self._sample_file_event(
                event_type="file_modified" if i % 2 == 0 else "file_deleted",
                file_path=f"/var/www/site/file_{i}.html",
            )
            events.append(ev)

        payload = {"device_id": "victim-srv-01", "events": events}
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json=payload)
        self.assertEqual(resp.status_code, 200)

        # 0 rows in SSH events table
        ssh_events_count = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(ssh_events_count, 0)

        # 0 alerts in alerts table
        alerts_count = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        self.assertEqual(alerts_count, 0)

    # =========================================================================
    # 13. Custom Rule Engine Isolation
    # =========================================================================

    def test_file_events_never_trigger_custom_rules(self):
        """Custom detection rules evaluate only SSH authentication events; file events are strictly isolated."""
        # Create an aggressive custom detection rule that triggers on threshold 1
        rule_sql = """
        INSERT INTO detection_rules
        (rule_id, name, description, severity, enabled, threshold, window_minutes, conditions, created_at, updated_at)
        VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """
        conditions_json = json.dumps({
            "version": 1,
            "filters": [
                {"field": "outcome", "op": "in", "value": ["failure", "success", "unknown"]}
            ],
            "aggregation": {"type": "count", "target": "*"},
            "group_by": ["source_ip"]
        })
        self.conn.execute(
            rule_sql,
            ("CR-99", "Any Event Rule", "Triggers on any processed event", "high", 1, 1, 5, conditions_json)
        )
        self.conn.commit()

        # Ingest 10 file events
        file_events = [
            self._sample_file_event(event_type="file_created", file_path=f"/etc/cron.d/job_{i}")
            for i in range(10)
        ]
        resp = self.client.post("/api/v1/events", headers=self._auth_headers(), json={"device_id": "cron-srv", "events": file_events})
        self.assertEqual(resp.status_code, 200)

        # Custom rule must produce ZERO alerts because file events never adapt to backend Events
        custom_alerts = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE rule_id = 'CR-99'").fetchone()[0]
        self.assertEqual(custom_alerts, 0)


if __name__ == "__main__":
    unittest.main()
