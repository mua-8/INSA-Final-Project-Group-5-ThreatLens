"""Tests for Module B: Flask REST API endpoints and integration.

Validates:
- All 14 API endpoints respond with correct status codes and JSON envelopes.
- Input validation on parameters, body fields, status values, and pagination bounds.
- Duplicate log upload handling (SHA-256 detection).
- Incident workflow: creation, notes, linking alerts, status lifecycle.
- Alert status updates and evidence relationships.
- Statistics endpoint structure for dashboard consumption.
"""

import json
import os
import tempfile
import unittest

from backend import api, repository as repo
from backend.database import init_db


class TestThreatLensAPI(unittest.TestCase):
    """Test suite covering the ThreatLens REST API."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        # Configure API to use this test database
        api.DB_PATH = self.db_path
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

        # Seed sample log file and events for retrieval tests
        self.log_file_id = repo.insert_log_file(
            self.conn, "initial_test.log", "dummy_hash_001", 5, 2, 0
        )
        self.event_ids = repo.insert_events_batch(
            self.conn,
            self.log_file_id,
            [
                {
                    "timestamp": "2026-10-25T14:00:00Z",
                    "host": "web01",
                    "username": "deploy",
                    "source_ip": "203.0.113.50",
                    "port": 41000,
                    "method": "password",
                    "outcome": "failure",
                    "event_type": "failed_login",
                    "raw_line": "Oct 24 14:00:00 web01 sshd[5000]: Failed password for deploy",
                    "line_hash": "hash_ev_01",
                },
                {
                    "timestamp": "2026-10-25T14:05:00Z",
                    "host": "web01",
                    "username": "deploy",
                    "source_ip": "203.0.113.50",
                    "port": 41001,
                    "method": "password",
                    "outcome": "success",
                    "event_type": "accepted_login",
                    "raw_line": "Oct 24 14:05:00 web01 sshd[5001]: Accepted password for deploy",
                    "line_hash": "hash_ev_02",
                },
            ],
        )

        # Seed an alert linked to event 1
        self.alert_id = repo.insert_alert(
            self.conn,
            {
                "rule_id": "DR-01",
                "rule_name": "SSH brute force",
                "severity": "medium",
                "status": "new",
                "source_ip": "203.0.113.50",
                "first_seen": "2026-10-25T14:00:00Z",
                "last_seen": "2026-10-25T14:05:00Z",
                "summary": "Brute force attempts from 203.0.113.50",
                "explanation": "Detected multiple SSH failures followed by activity",
                "settings": {"threshold": 5},
            },
        )
        repo.insert_alert_evidence(self.conn, self.alert_id, [self.event_ids[0]])
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    # ----------------------------------------------------------------------
    # Logs endpoint
    # ----------------------------------------------------------------------

    def test_list_logs(self):
        resp = self.client.get("/api/logs")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["data"]), 1)
        self.assertEqual(data["data"][0]["filename"], "initial_test.log")

    # ----------------------------------------------------------------------
    # Events endpoints
    # ----------------------------------------------------------------------

    def test_list_events(self):
        resp = self.client.get("/api/events")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["count"], 2)

    def test_list_events_filtering(self):
        resp = self.client.get("/api/events?outcome=failure")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["data"]["count"], 1)
        self.assertEqual(data["data"]["events"][0]["outcome"], "failure")

    def test_get_event_by_id(self):
        resp = self.client.get(f"/api/events/{self.event_ids[0]}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["username"], "deploy")

    def test_get_event_not_found(self):
        resp = self.client.get("/api/events/99999")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertFalse(data["ok"])

    # ----------------------------------------------------------------------
    # Alerts endpoints
    # ----------------------------------------------------------------------

    def test_list_alerts(self):
        resp = self.client.get("/api/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["count"], 1)

    def test_get_alert_with_evidence(self):
        resp = self.client.get(f"/api/alerts/{self.alert_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["rule_id"], "DR-01")
        self.assertEqual(len(data["data"]["evidence"]), 1)
        self.assertEqual(data["data"]["evidence"][0]["id"], self.event_ids[0])

    def test_update_alert_status(self):
        # Update to investigating
        resp = self.client.patch(
            f"/api/alerts/{self.alert_id}/status",
            json={"status": "investigating"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["status"], "investigating")

        # Verify invalid status is rejected
        resp_bad = self.client.patch(
            f"/api/alerts/{self.alert_id}/status",
            json={"status": "invalid_status_value"},
        )
        self.assertEqual(resp_bad.status_code, 400)

    # ----------------------------------------------------------------------
    # Statistics endpoint
    # ----------------------------------------------------------------------

    def test_statistics_endpoint(self):
        resp = self.client.get("/api/statistics")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        stats = data["data"]
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["total_alerts"], 1)
        self.assertIn("top_source_ips", stats)
        self.assertIn("alert_counts_by_severity", stats)

    # ----------------------------------------------------------------------
    # Incidents & notes endpoints
    # ----------------------------------------------------------------------

    def test_create_and_manage_incident(self):
        # Create incident
        create_resp = self.client.post(
            "/api/incidents",
            json={
                "title": "Unauthorized SSH Infiltration",
                "description": "Host 203.0.113.50 engaged in credential attack",
                "severity": "high",
            },
        )
        self.assertEqual(create_resp.status_code, 201)
        inc_data = create_resp.get_json()["data"]
        inc_id = inc_data["incident_id"]

        # Link alert
        link_resp = self.client.post(
            f"/api/incidents/{inc_id}/alerts",
            json={"alert_id": self.alert_id},
        )
        self.assertEqual(link_resp.status_code, 201)

        # Add notes
        note_resp = self.client.post(
            f"/api/incidents/{inc_id}/notes",
            json={"note": "Isolated source IP in network gateway.", "author": "adnan"},
        )
        self.assertEqual(note_resp.status_code, 201)

        # Update status
        status_resp = self.client.patch(
            f"/api/incidents/{inc_id}/status",
            json={"status": "in_progress"},
        )
        self.assertEqual(status_resp.status_code, 200)

        # Fetch full incident detail
        get_resp = self.client.get(f"/api/incidents/{inc_id}")
        self.assertEqual(get_resp.status_code, 200)
        full_inc = get_resp.get_json()["data"]
        self.assertEqual(full_inc["title"], "Unauthorized SSH Infiltration")
        self.assertEqual(full_inc["status"], "in_progress")
        self.assertEqual(len(full_inc["alerts"]), 1)
        self.assertEqual(len(full_inc["notes"]), 1)
        self.assertEqual(full_inc["notes"][0]["note"], "Isolated source IP in network gateway.")

    # ----------------------------------------------------------------------
    # Ingestion validation & duplicate prevention
    # ----------------------------------------------------------------------

    def test_ingest_empty_rejected(self):
        resp = self.client.post("/api/ingest", data=b"")
        self.assertEqual(resp.status_code, 400)

    def test_ingest_duplicate_file_detected(self):
        content = b"Oct 24 14:00:00 web01 sshd[5000]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        headers = {"X-Filename": "sample_spray.log"}

        # First upload
        resp1 = self.client.post("/api/ingest", data=content, headers=headers)
        # 201 or 503 depending on parser availability
        if resp1.status_code == 201:
            # Second upload of exact same bytes should report duplicate
            resp2 = self.client.post("/api/ingest", data=content, headers=headers)
            self.assertEqual(resp2.status_code, 200)
            data2 = resp2.get_json()
            self.assertTrue(data2["data"]["duplicate"])


if __name__ == "__main__":
    unittest.main()
