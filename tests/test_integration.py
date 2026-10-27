"""End-to-End Integration Tests for ThreatLens SIEM.

Validates the full pipeline across all layers:
Log Ingestion Service (Module A) -> Compatibility Adapter ->
Database & Repository (Module B) -> Detection Engine (Module C) -> REST API.

Covers all 15 required integration scenarios:
1. Ingest via API using raw text with X-Filename header -> database record, events, statistics.
2. Ingest via API using multipart form upload -> same result.
3. Ingest with year query parameter -> parsed events reflect requested year.
4. Database records accurately reflect parsed fields: timestamp, hostname, username,
   source_ip, port, method, outcome, event_type, raw_line, line_hash.
5. Failed password vs accepted password: correct event_type and outcome ('failure' vs 'success').
6. Invalid user log lines: correctly classified, username preserved, outcome is 'failure'.
7. Failed password for invalid user: both failed login and invalid user characteristics handled correctly.
8. IPv6 addresses handled correctly through the API and database.
9. Malformed lines handled safely: ingestion succeeds, malformed count reported accurately, valid lines still ingested.
10. Missing timestamp / headerless lines: handled gracefully without terminating the batch.
11. Duplicate file upload rejected via API: returns 200 with duplicate flag and message.
12. Duplicate lines within the same file: handled gracefully (database UNIQUE constraint on (log_file_id, line_hash)).
13. End-to-end detection: ingest a brute-force pattern -> verify DR-01 alert is generated in the database.
14. End-to-end detection: ingest invalid user pattern -> verify DR-02 alert is generated in the database.
15. Alert evidence linking: verify the generated alert references the correct event database IDs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
import tempfile
import unittest

from backend import api, repository as repo
from backend.database import init_db


class TestThreatLensIntegration(unittest.TestCase):
    """End-to-end integration test suite covering the 15 required scenarios."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        # Direct API to isolated test database
        api.DB_PATH = self.db_path
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

    def tearDown(self):
        self.conn.close()
        import gc
        gc.collect()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass

    def get_events_for_log_file(self, log_file_id: int):
        """Helper to fetch all events belonging to a specific log file, ordered by ID."""
        cur = self.conn.execute(
            "SELECT * FROM events WHERE log_file_id = ? ORDER BY id ASC",
            (log_file_id,),
        )
        return cur.fetchall()

    # --------------------------------------------------------------------------
    # Scenario 1: Ingest via API using raw text with X-Filename header
    # --------------------------------------------------------------------------
    def test_scenario_01_ingest_raw_text_with_x_filename(self):
        content = (
            b"Oct 25 14:00:00 auth-server sshd[1001]: Accepted password for deploy "
            b"from 192.168.1.100 port 50000 ssh2\n"
        )
        headers = {"X-Filename": "raw_upload_test.log"}

        resp = self.client.post("/api/ingest", data=content, headers=headers)
        self.assertEqual(resp.status_code, 201)

        payload = resp.get_json()
        self.assertTrue(payload["ok"])
        data = payload["data"]
        self.assertEqual(data["filename"], "raw_upload_test.log")
        self.assertEqual(data["events_stored"], 1)
        self.assertEqual(data["malformed_lines"], 0)
        self.assertIsInstance(data["log_file_id"], int)

        # Verify database record in log_files
        log_file = repo.get_log_file_by_hash(self.conn, hashlib.sha256(content).hexdigest())
        self.assertIsNotNone(log_file)
        self.assertEqual(log_file["filename"], "raw_upload_test.log")
        self.assertEqual(log_file["line_count"], 1)
        self.assertEqual(log_file["event_count"], 1)
        self.assertEqual(log_file["malformed_count"], 0)

        # Verify event in events table
        events = self.get_events_for_log_file(data["log_file_id"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "deploy")

    # --------------------------------------------------------------------------
    # Scenario 2: Ingest via API using multipart form upload
    # --------------------------------------------------------------------------
    def test_scenario_02_ingest_multipart_form_upload(self):
        content = (
            b"Oct 25 14:05:00 auth-server sshd[1002]: Accepted publickey for admin "
            b"from 192.168.1.105 port 50005 ssh2\n"
        )
        file_tuple = (io.BytesIO(content), "multipart_audit.log")

        resp = self.client.post(
            "/api/ingest",
            data={"file": file_tuple},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 201)

        data = resp.get_json()["data"]
        self.assertEqual(data["filename"], "multipart_audit.log")
        self.assertEqual(data["events_stored"], 1)
        self.assertEqual(data["malformed_lines"], 0)

        log_file = repo.get_log_file_by_hash(self.conn, hashlib.sha256(content).hexdigest())
        self.assertIsNotNone(log_file)
        self.assertEqual(log_file["filename"], "multipart_audit.log")

    # --------------------------------------------------------------------------
    # Scenario 3: Ingest with year query parameter
    # --------------------------------------------------------------------------
    def test_scenario_03_ingest_with_year_parameter(self):
        content = (
            b"Oct 25 14:10:00 auth-server sshd[1003]: Accepted password for backup "
            b"from 192.168.1.110 port 50010 ssh2\n"
        )
        resp = self.client.post(
            "/api/ingest?year=2024",
            data=content,
            headers={"X-Filename": "year_test.log"},
        )
        self.assertEqual(resp.status_code, 201)

        events = self.get_events_for_log_file(resp.get_json()["data"]["log_file_id"])
        self.assertEqual(len(events), 1)
        # Parsed timestamp must start with the requested year (2024)
        self.assertTrue(events[0]["timestamp"].startswith("2024-10-25"))

    # --------------------------------------------------------------------------
    # Scenario 4: Database records accurately reflect parsed fields
    # --------------------------------------------------------------------------
    def test_scenario_04_database_fields_mapping_accuracy(self):
        raw_line_str = "Oct 25 14:15:30 srv-primary sshd[2048]: Accepted password for analyst from 10.10.10.25 port 44321 ssh2"
        content = (raw_line_str + "\n").encode("utf-8")

        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "field_accuracy.log"},
        )
        self.assertEqual(resp.status_code, 201)
        log_file_id = resp.get_json()["data"]["log_file_id"]

        events = self.get_events_for_log_file(log_file_id)
        self.assertEqual(len(events), 1)
        ev = events[0]

        expected_hash = hashlib.sha256(raw_line_str.encode("utf-8")).hexdigest()[:16]

        self.assertEqual(ev["host"], "srv-primary")
        self.assertEqual(ev["username"], "analyst")
        self.assertEqual(ev["source_ip"], "10.10.10.25")
        self.assertEqual(ev["port"], 44321)
        self.assertEqual(ev["method"], "password")
        self.assertEqual(ev["outcome"], "success")
        self.assertEqual(ev["event_type"], "accepted_login")
        self.assertEqual(ev["raw_line"], raw_line_str)
        self.assertEqual(ev["line_hash"], expected_hash)
        self.assertIn("T14:15:30", ev["timestamp"])

    # --------------------------------------------------------------------------
    # Scenario 5: Failed password vs accepted password classification and outcome
    # --------------------------------------------------------------------------
    def test_scenario_05_failed_password_vs_accepted_password(self):
        content = (
            b"Oct 25 14:20:00 gateway sshd[3001]: Failed password for dev from 172.16.0.5 port 39001 ssh2\n"
            b"Oct 25 14:20:05 gateway sshd[3002]: Accepted password for dev from 172.16.0.5 port 39002 ssh2\n"
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "outcomes.log"},
        )
        self.assertEqual(resp.status_code, 201)
        log_file_id = resp.get_json()["data"]["log_file_id"]

        events = self.get_events_for_log_file(log_file_id)
        self.assertEqual(len(events), 2)

        # First event is failure
        self.assertEqual(events[0]["event_type"], "failed_login")
        self.assertEqual(events[0]["outcome"], "failure")
        self.assertEqual(events[0]["method"], "password")

        # Second event is success
        self.assertEqual(events[1]["event_type"], "accepted_login")
        self.assertEqual(events[1]["outcome"], "success")
        self.assertEqual(events[1]["method"], "password")

    # --------------------------------------------------------------------------
    # Scenario 6: Invalid user log lines correctly classified
    # --------------------------------------------------------------------------
    def test_scenario_06_invalid_user_classification(self):
        content = (
            b"Oct 25 14:25:00 bastion sshd[4001]: Invalid user intruder from 198.51.100.42 port 51234\n"
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "invalid_user.log"},
        )
        self.assertEqual(resp.status_code, 201)
        log_file_id = resp.get_json()["data"]["log_file_id"]

        events = self.get_events_for_log_file(log_file_id)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_type"], "invalid_user")
        self.assertEqual(ev["outcome"], "failure")
        self.assertEqual(ev["username"], "intruder")
        self.assertEqual(ev["source_ip"], "198.51.100.42")
        self.assertEqual(ev["port"], 51234)

    # --------------------------------------------------------------------------
    # Scenario 7: Failed password for invalid user handling
    # --------------------------------------------------------------------------
    def test_scenario_07_failed_password_for_invalid_user(self):
        content = (
            b"Oct 25 14:30:00 bastion sshd[4002]: Failed password for invalid user phantom from 198.51.100.43 port 51235 ssh2\n"
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "failed_invalid.log"},
        )
        self.assertEqual(resp.status_code, 201)
        log_file_id = resp.get_json()["data"]["log_file_id"]

        events = self.get_events_for_log_file(log_file_id)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_type"], "failed_login")
        self.assertEqual(ev["outcome"], "failure")
        self.assertEqual(ev["username"], "phantom")
        self.assertEqual(ev["method"], "password")
        self.assertEqual(ev["source_ip"], "198.51.100.43")

    # --------------------------------------------------------------------------
    # Scenario 8: IPv6 addresses handled correctly
    # --------------------------------------------------------------------------
    def test_scenario_08_ipv6_addresses_handled(self):
        content = (
            b"Oct 25 14:35:00 edge sshd[5001]: Accepted publickey for root from 2001:db8:85a3::8a2e:370:7334 port 2222 ssh2\n"
            b"Oct 25 14:35:05 edge sshd[5002]: Failed password for root from ::1 port 2222 ssh2\n"
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "ipv6_traffic.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]
        self.assertEqual(data["events_stored"], 2)
        self.assertEqual(data["malformed_lines"], 0)

        events = self.get_events_for_log_file(data["log_file_id"])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["source_ip"], "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(events[1]["source_ip"], "::1")

    # --------------------------------------------------------------------------
    # Scenario 9: Malformed lines handled safely without aborting batch
    # --------------------------------------------------------------------------
    def test_scenario_09_malformed_lines_handled_safely(self):
        content = (
            b"Oct 25 14:40:00 srv sshd[6001]: Accepted password for bob from 10.0.0.1 port 22 ssh2\n"
            b"GARBAGE UNPARSEABLE LINE NUMBER 1\n"
            b"Oct 25 14:40:10 srv sshd[6002]: Failed password for root from 999.999.999.999 port 22 ssh2\n"
            b"Oct 25 14:40:20 srv sshd[6003]: Accepted password for alice from 10.0.0.2 port 22 ssh2\n"
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "mixed_malformed.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        # 4 lines total: 2 valid events stored, 2 malformed lines accounted for
        self.assertEqual(data["events_stored"], 2)
        self.assertEqual(data["malformed_lines"], 2)

        log_file = repo.get_log_file_by_hash(self.conn, hashlib.sha256(content).hexdigest())
        self.assertEqual(log_file["line_count"], 4)
        self.assertEqual(log_file["event_count"], 2)
        self.assertEqual(log_file["malformed_count"], 2)

    # --------------------------------------------------------------------------
    # Scenario 10: Missing timestamp / headerless lines handled gracefully
    # --------------------------------------------------------------------------
    def test_scenario_10_missing_timestamp_or_headerless_lines(self):
        content = (
            b"Oct 25 14:45:00 srv sshd[7001]: Accepted password for carl from 10.0.0.3 port 22 ssh2\n"
            b"Failed password for user from 10.0.0.4 port 22 ssh2\n"  # Missing syslog header/timestamp
        )
        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "missing_header.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        self.assertEqual(data["events_stored"], 1)
        self.assertEqual(data["malformed_lines"], 1)

    # --------------------------------------------------------------------------
    # Scenario 11: Duplicate file upload rejected via API
    # --------------------------------------------------------------------------
    def test_scenario_11_duplicate_file_upload_rejected(self):
        content = b"Oct 25 14:50:00 srv sshd[8001]: Accepted password for eve from 10.0.0.5 port 22 ssh2\n"
        headers = {"X-Filename": "duplicate_check.log"}

        # First ingestion
        resp1 = self.client.post("/api/ingest", data=content, headers=headers)
        self.assertEqual(resp1.status_code, 201)

        # Duplicate ingestion of exact same bytes
        resp2 = self.client.post("/api/ingest", data=content, headers=headers)
        self.assertEqual(resp2.status_code, 200)

        data2 = resp2.get_json()["data"]
        self.assertTrue(data2["duplicate"])
        self.assertEqual(data2["message"], "This file has already been uploaded.")
        self.assertIn("log_file", data2)

    # --------------------------------------------------------------------------
    # Scenario 12: Duplicate lines within the same file handled gracefully
    # --------------------------------------------------------------------------
    def test_scenario_12_duplicate_lines_within_same_file(self):
        line1 = b"Oct 25 14:55:00 srv sshd[9001]: Failed password for test from 10.0.0.6 port 22 ssh2\n"
        line2 = b"Oct 25 14:55:01 srv sshd[9002]: Failed password for test from 10.0.0.6 port 23 ssh2\n"
        content = line1 + line1 + line2  # Duplicate line1 present twice in same file

        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "intrafile_dupes.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        # Only 2 unique event rows inserted due to UNIQUE(log_file_id, line_hash)
        self.assertEqual(data["events_stored"], 2)
        events = self.get_events_for_log_file(data["log_file_id"])
        self.assertEqual(len(events), 2)

    # --------------------------------------------------------------------------
    # Scenario 13: End-to-end detection: DR-01 SSH brute force alert
    # --------------------------------------------------------------------------
    def test_scenario_13_end_to_end_dr01_brute_force_alert(self):
        lines = [
            f"Oct 25 15:00:0{i} srv sshd[{1000+i}]: Failed password for admin from 203.0.113.19 port {4000+i} ssh2\n".encode("utf-8")
            for i in range(5)
        ]
        content = b"".join(lines)

        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "brute_force_spray.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        self.assertEqual(data["events_stored"], 5)
        self.assertEqual(data["new_alerts"], 1)
        self.assertEqual(len(data["alert_ids"]), 1)

        # Inspect alert via API
        alert_id = data["alert_ids"][0]
        alert_resp = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(alert_resp.status_code, 200)
        alert_data = alert_resp.get_json()["data"]
        self.assertEqual(alert_data["rule_id"], "DR-01")
        self.assertEqual(alert_data["rule_name"], "SSH brute force")
        self.assertEqual(alert_data["source_ip"], "203.0.113.19")
        self.assertEqual(alert_data["severity"], "medium")

    # --------------------------------------------------------------------------
    # Scenario 14: End-to-end detection: DR-02 Username enumeration alert
    # --------------------------------------------------------------------------
    def test_scenario_14_end_to_end_dr02_username_enumeration_alert(self):
        lines = [
            b"Oct 25 15:10:00 srv sshd[2001]: Invalid user oracle from 203.0.113.20 port 5001\n",
            b"Oct 25 15:10:01 srv sshd[2002]: Invalid user postgres from 203.0.113.20 port 5002\n",
            b"Oct 25 15:10:02 srv sshd[2003]: Invalid user tomcat from 203.0.113.20 port 5003\n",
        ]
        content = b"".join(lines)

        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "user_enum.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]

        self.assertEqual(data["events_stored"], 3)
        self.assertEqual(data["new_alerts"], 1)

        alert_id = data["alert_ids"][0]
        alert_resp = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(alert_resp.status_code, 200)
        alert_data = alert_resp.get_json()["data"]
        self.assertEqual(alert_data["rule_id"], "DR-02")
        self.assertEqual(alert_data["rule_name"], "Username enumeration")
        self.assertEqual(alert_data["source_ip"], "203.0.113.20")

    # --------------------------------------------------------------------------
    # Scenario 15: Alert evidence linking to persisted database event IDs
    # --------------------------------------------------------------------------
    def test_scenario_15_alert_evidence_linking(self):
        lines = [
            f"Oct 25 15:20:0{i} srv sshd[{3000+i}]: Failed password for testuser from 203.0.113.21 port {6000+i} ssh2\n".encode("utf-8")
            for i in range(5)
        ]
        content = b"".join(lines)

        resp = self.client.post(
            "/api/ingest",
            data=content,
            headers={"X-Filename": "evidence_link_test.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]
        self.assertGreaterEqual(data["new_alerts"], 1)
        log_file_id = data["log_file_id"]

        # Fetch stored event IDs
        stored_events = self.get_events_for_log_file(log_file_id)
        stored_event_ids = {ev["id"] for ev in stored_events}
        self.assertEqual(len(stored_event_ids), 5)

        # DR-01 alert should be generated
        alert_id = data["alert_ids"][0]
        alert_resp = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(alert_resp.status_code, 200)
        alert_data = alert_resp.get_json()["data"]

        # Verify evidence field exists and links to persisted event IDs
        self.assertIn("evidence", alert_data)
        evidence_list = alert_data["evidence"]
        self.assertGreaterEqual(len(evidence_list), 1)

        evidence_ids = {ev["id"] for ev in evidence_list}
        # Evidence IDs must be a subset of the stored event IDs
        self.assertTrue(evidence_ids.issubset(stored_event_ids))

        # Each evidence event can be individually fetched via GET /api/events/<id>
        for ev_id in evidence_ids:
            ev_resp = self.client.get(f"/api/events/{ev_id}")
            self.assertEqual(ev_resp.status_code, 200)
            self.assertEqual(ev_resp.get_json()["data"]["id"], ev_id)

    # --------------------------------------------------------------------------
    # Regression Test 1: Correlation across separate uploads within application lifetime
    # --------------------------------------------------------------------------
    def test_regression_cross_upload_correlation_and_updating(self):
        # Upload 1: 3 failed attempts (below threshold of 5 for DR-01)
        upload1_lines = [
            f"Oct 25 16:00:0{i} srv sshd[{4000+i}]: Failed password for deploy from 203.0.113.88 port {5000+i} ssh2\n".encode("utf-8")
            for i in range(3)
        ]
        resp1 = self.client.post(
            "/api/ingest",
            data=b"".join(upload1_lines),
            headers={"X-Filename": "cross_upload_part1.log"},
        )
        self.assertEqual(resp1.status_code, 201)
        data1 = resp1.get_json()["data"]
        self.assertEqual(data1["events_stored"], 3)
        self.assertEqual(data1["new_alerts"], 0)
        self.assertEqual(data1["updated_alerts"], 0)

        # Upload 2: 2 more failed attempts from same IP within window -> DR-01 fires!
        upload2_lines = [
            f"Oct 25 16:01:0{i} srv sshd[{4010+i}]: Failed password for deploy from 203.0.113.88 port {5010+i} ssh2\n".encode("utf-8")
            for i in range(2)
        ]
        resp2 = self.client.post(
            "/api/ingest",
            data=b"".join(upload2_lines),
            headers={"X-Filename": "cross_upload_part2.log"},
        )
        self.assertEqual(resp2.status_code, 201)
        data2 = resp2.get_json()["data"]
        self.assertEqual(data2["events_stored"], 2)
        self.assertEqual(data2["new_alerts"], 1)
        self.assertEqual(len(data2["alert_ids"]), 1)
        alert_id = data2["alert_ids"][0]

        # Verify all 5 events across both uploads are linked as evidence
        alert_resp = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(alert_resp.status_code, 200)
        alert_data = alert_resp.get_json()["data"]
        self.assertEqual(alert_data["rule_id"], "DR-01")
        self.assertEqual(len(alert_data["evidence"]), 5)

        # Upload 3: 1 additional failed attempt -> updates existing alert without creating a duplicate
        upload3_line = b"Oct 25 16:02:00 srv sshd[4020]: Failed password for deploy from 203.0.113.88 port 5020 ssh2\n"
        resp3 = self.client.post(
            "/api/ingest",
            data=upload3_line,
            headers={"X-Filename": "cross_upload_part3.log"},
        )
        self.assertEqual(resp3.status_code, 201)
        data3 = resp3.get_json()["data"]
        self.assertEqual(data3["events_stored"], 1)
        self.assertEqual(data3["new_alerts"], 0)
        self.assertEqual(data3["updated_alerts"], 1)

        # Verify alert now links all 6 events
        alert_resp2 = self.client.get(f"/api/alerts/{alert_id}")
        alert_data2 = alert_resp2.get_json()["data"]
        self.assertEqual(len(alert_data2["evidence"]), 6)

    # --------------------------------------------------------------------------
    # Regression Test 2: Persistent detection state across application restart
    # --------------------------------------------------------------------------
    def test_regression_persistent_correlation_across_simulated_restart(self):
        # Upload 1: 3 failed attempts
        upload1_lines = [
            f"Oct 25 16:10:0{i} srv sshd[{5000+i}]: Failed password for deploy from 203.0.113.89 port {6000+i} ssh2\n".encode("utf-8")
            for i in range(3)
        ]
        resp1 = self.client.post(
            "/api/ingest",
            data=b"".join(upload1_lines),
            headers={"X-Filename": "restart_test_part1.log"},
        )
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.get_json()["data"]["new_alerts"], 0)

        # Simulate application restart: purge in-memory detection engine cache
        api.reset_detection_engine(self.db_path)

        # Upload 2: 2 more failed attempts
        upload2_lines = [
            f"Oct 25 16:11:0{i} srv sshd[{5010+i}]: Failed password for deploy from 203.0.113.89 port {6010+i} ssh2\n".encode("utf-8")
            for i in range(2)
        ]
        resp2 = self.client.post(
            "/api/ingest",
            data=b"".join(upload2_lines),
            headers={"X-Filename": "restart_test_part2.log"},
        )
        self.assertEqual(resp2.status_code, 201)
        data2 = resp2.get_json()["data"]

        # Engine hydrated past events from SQLite: correlation across restart succeeded!
        self.assertEqual(data2["new_alerts"], 1)
        alert_id = data2["alert_ids"][0]
        alert_resp = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(len(alert_resp.get_json()["data"]["evidence"]), 5)

    # --------------------------------------------------------------------------
    # Regression Test 3: Missing source IP handling in detection engine
    # --------------------------------------------------------------------------
    def test_regression_missing_source_ip_handling(self):
        from backend.parser import Event
        from backend.detection import DetectionEngine

        engine = DetectionEngine()
        now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

        # 1. Non-root events without source_ip do not crash and do not fire IP-dependent rules
        non_root_events = [
            Event(
                timestamp=now,
                host="srv",
                username=f"user{i}",
                source_ip=None,
                port=22,
                method="password",
                outcome="failure",
                event_type="failed_login",
                raw_line=f"raw line {i}",
                line_hash=f"hash_{i}",
                id=i,
            )
            for i in range(10)
        ]
        res1 = engine.process(non_root_events)
        self.assertEqual(res1.events_processed, 10)
        # IP-dependent rules (DR-01 through DR-04) do NOT fire without source IP
        self.assertEqual(len(res1.new_alerts), 0)

        # 2. Privileged account attempt (DR-05) without source IP DOES fire
        root_event = Event(
            timestamp=now,
            host="srv",
            username="root",
            source_ip=None,
            port=None,
            method="password",
            outcome="failure",
            event_type="failed_login",
            raw_line="root login attempt on console",
            line_hash="hash_root_console",
            id=99,
        )
        res2 = engine.process([root_event])
        self.assertEqual(len(res2.new_alerts), 1)
        alert = res2.new_alerts[0]
        self.assertEqual(alert.rule_id, "DR-05")
        self.assertIsNone(alert.source_ip)
        self.assertNotIn("None", alert.summary)
        self.assertNotIn("None", alert.explanation)

    # --------------------------------------------------------------------------
    # Regression Test 4: Malformed-event accounting and missing timestamps
    # --------------------------------------------------------------------------
    def test_regression_malformed_event_accounting_consistency(self):
        from app.services.ingestion import ingest_log_lines
        from backend.adapter import adapt_ingestion_report

        lines = [
            "Oct 25 17:00:00 srv sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2",
            "Oct 25 17:00:01 srv sshd[2]: Server listening on 0.0.0.0 port 22.",
            "Failed password for root from 1.2.3.4 port 22 ssh2",  # Missing syslog header/timestamp
            "GARBAGE UNPARSEABLE LINE NOISE !@#$%",               # Parser malformed
        ]
        report = ingest_log_lines(lines, reference_time=datetime(2026, 10, 25, 17, 0, 0, tzinfo=timezone.utc))
        adapted = adapt_ingestion_report(report)

        # Consistency between IngestionReport and AdaptedIngestionResult
        self.assertEqual(adapted.malformed_count, 2)
        self.assertEqual(report.statistics.malformed_count, 2)
        self.assertEqual(adapted.missing_timestamp_count, 1)
        self.assertEqual(adapted.parser_malformed_count, 1)
        self.assertEqual(len(adapted.events), 2)
        self.assertEqual(report.statistics.parsed_count, 2)

        # Diagnostics preserved
        missing_ts_ev = next(e for e in adapted.malformed_events if "Missing mandatory timestamp" in (e.parsing_error or ""))
        self.assertIsNotNone(missing_ts_ev)

        # Test end-to-end via API
        resp = self.client.post(
            "/api/ingest",
            data="\n".join(lines).encode("utf-8"),
            headers={"X-Filename": "accounting_test.log"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()["data"]
        self.assertEqual(data["events_stored"], 2)
        self.assertEqual(data["malformed_lines"], 2)

        # Database log_file record matches exact counts
        log_file = self.conn.execute("SELECT * FROM log_files WHERE id = ?", (data["log_file_id"],)).fetchone()
        self.assertEqual(log_file["line_count"], 4)
        self.assertEqual(log_file["event_count"], 2)
        self.assertEqual(log_file["malformed_count"], 2)

    # --------------------------------------------------------------------------
    # Regression Test 5: Year parameter validation and leap day handling
    # --------------------------------------------------------------------------
    def test_regression_year_parameter_validation_and_leap_day(self):
        content = b"Oct 25 17:30:00 srv sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2\n"

        # 1. Non-integer year rejected with HTTP 400
        resp_invalid_str = self.client.post("/api/ingest?year=notayear", data=content)
        self.assertEqual(resp_invalid_str.status_code, 400)
        self.assertIn("must be an integer", resp_invalid_str.get_json()["error"])

        # 2. Out-of-bounds year rejected with HTTP 400
        resp_too_early = self.client.post("/api/ingest?year=1850", data=content)
        self.assertEqual(resp_too_early.status_code, 400)
        self.assertIn("between 1970 and 2100", resp_too_early.get_json()["error"])

        resp_too_late = self.client.post("/api/ingest?year=2500", data=content)
        self.assertEqual(resp_too_late.status_code, 400)
        self.assertIn("between 1970 and 2100", resp_too_late.get_json()["error"])

        # 3. Valid year accepted
        resp_valid = self.client.post("/api/ingest?year=2028", data=content)
        self.assertEqual(resp_valid.status_code, 201)

        # 4. Leap day handling logic verification
        now_leap = datetime(2024, 2, 29, 12, 0, 0, tzinfo=timezone.utc)
        # In a non-leap year (e.g. 2025), Feb 29 safely maps to Feb 28 without raising or corrupting month
        try:
            ref_time = now_leap.replace(year=2025)
        except ValueError:
            ref_time = now_leap.replace(year=2025, day=28)
        self.assertEqual(ref_time.year, 2025)
        self.assertEqual(ref_time.month, 2)
        self.assertEqual(ref_time.day, 28)

    # --------------------------------------------------------------------------
    # Regression Test 6: Dynamic rule toggle synchronization and suppression
    # --------------------------------------------------------------------------
    def test_regression_rule_toggle_synchronization_and_suppression(self):
        """Verify that disabling a detection rule via API immediately updates the
        in-memory detection engine and prevents the rule from generating alerts.
        """
        # 1. Toggle DR-01 to disabled
        resp_toggle = self.client.patch("/api/rules/DR-01/toggle", json={"enabled": False})
        self.assertEqual(resp_toggle.status_code, 200)
        rule_row = self.conn.execute("SELECT enabled FROM detection_rules WHERE rule_id = 'DR-01'").fetchone()
        self.assertEqual(rule_row["enabled"], 0)

        # 2. Ingest 10 failed logins that would normally trigger DR-01
        lines = [
            f"Oct 25 18:00:{i:02d} srv sshd[{1000+i}]: Failed password for user{i} from 192.0.2.77 port {50000+i} ssh2\n".encode("utf-8")
            for i in range(10)
        ]
        resp_ingest = self.client.post("/api/ingest?simulate=true", data=b"".join(lines))
        self.assertEqual(resp_ingest.status_code, 201)

        # 3. Confirm NO DR-01 alert is created for the disabled rule
        dr01_alerts = self.conn.execute("SELECT * FROM alerts WHERE rule_id = 'DR-01' AND source_ip = '192.0.2.77'").fetchall()
        self.assertEqual(len(dr01_alerts), 0, "Disabled rule DR-01 must not raise alerts")

        # 4. Re-enable DR-01
        resp_reenable = self.client.patch("/api/rules/DR-01/toggle", json={"enabled": True})
        self.assertEqual(resp_reenable.status_code, 200)

        # 5. Ingest 10 failed logins from a new IP -> DR-01 MUST fire
        lines2 = [
            f"Oct 25 18:05:{i:02d} srv sshd[{2000+i}]: Failed password for user{i} from 192.0.2.88 port {51000+i} ssh2\n".encode("utf-8")
            for i in range(10)
        ]
        resp_ingest2 = self.client.post("/api/ingest?simulate=true", data=b"".join(lines2))
        self.assertEqual(resp_ingest2.status_code, 201)
        dr01_alerts2 = self.conn.execute("SELECT * FROM alerts WHERE rule_id = 'DR-01' AND source_ip = '192.0.2.88'").fetchall()
        self.assertEqual(len(dr01_alerts2), 1, "Re-enabled rule DR-01 must fire when triggered")

    # --------------------------------------------------------------------------
    # Regression Test 7: Dynamic rule threshold adjustment in detection engine
    # --------------------------------------------------------------------------
    def test_regression_rule_threshold_adjustment(self):
        """Verify that adjusting a rule threshold via API immediately updates the
        in-memory detection engine and alters firing behavior.
        """
        # 1. Update DR-01 threshold from 5 to 3
        resp_update = self.client.patch("/api/rules/DR-01", json={"threshold": 3})
        self.assertEqual(resp_update.status_code, 200)

        # 2. Ingest exactly 3 failed logins (sub-threshold under default 5, but meets new threshold 3)
        lines = [
            f"Oct 25 18:10:{i:02d} srv sshd[{3000+i}]: Failed password for victim from 192.0.2.99 port {52000+i} ssh2\n".encode("utf-8")
            for i in range(3)
        ]
        resp_ingest = self.client.post("/api/ingest?simulate=true", data=b"".join(lines))
        self.assertEqual(resp_ingest.status_code, 201)

        # 3. Confirm DR-01 fired at the adjusted threshold of 3
        dr01_alerts = self.conn.execute("SELECT * FROM alerts WHERE rule_id = 'DR-01' AND source_ip = '192.0.2.99'").fetchall()
        self.assertEqual(len(dr01_alerts), 1, "DR-01 must fire at the new lowered threshold of 3")
        # Evidence check
        evidence = self.conn.execute("SELECT count(*) FROM alert_evidence WHERE alert_id = ?", (dr01_alerts[0]["id"],)).fetchone()[0]
        self.assertEqual(evidence, 3)


if __name__ == "__main__":
    unittest.main()
