"""Focused test suite for ThreatLens Endpoint Agent Integration.

Validates:
1. Authentication: configured THREATLENS_AGENT_API_KEY Bearer token enforcement.
2. Validation: request structure, batch size limits, body size limits, UUIDs, timestamps,
   severity enum, optional IP addresses, and attributes.
3. Transactional storage: atomic inserts, schema adherence, queryability.
4. Idempotency & Conflict: safe acknowledgment of identical retries, rejection of conflicting duplicate IDs.
5. Isolation & Backward Compatibility: POST /api/ingest and SSH detection pipeline remain
   operational and unaffected; Windows/Sysmon telemetry is never misclassified as SSH events.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
import unittest
import uuid

from backend import api, repository as repo
from backend.database import init_db


class TestEndpointAgentIntegration(unittest.TestCase):
    """Comprehensive test suite for endpoint agent integration."""

    TEST_API_KEY = "test-agent-secret-key-12345"

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        # Direct API to isolated test database
        api.DB_PATH = self.db_path
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

        # Configure environment variable for agent API key
        self.original_api_key = os.environ.get("THREATLENS_AGENT_API_KEY")
        os.environ["THREATLENS_AGENT_API_KEY"] = self.TEST_API_KEY

    def tearDown(self):
        if self.original_api_key is not None:
            os.environ["THREATLENS_AGENT_API_KEY"] = self.original_api_key
        else:
            os.environ.pop("THREATLENS_AGENT_API_KEY", None)

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

    def _sample_event(
        self,
        event_id: str | None = None,
        device_id: str = "dev-node-001",
        timestamp: str | None = None,
        source: str = "linux_auth",
        event_type: str = "ssh_auth_failure",
        severity: str = "high",
        source_ip: str | None = "192.168.1.50",
        username: str | None = "admin",
        raw_event: str | None = "Failed password for admin from 192.168.1.50 port 44211 ssh2",
        attributes: dict | None = None,
    ) -> dict:
        return {
            "schema_version": "1.0.0",
            "event_id": event_id or str(uuid.uuid4()),
            "device_id": device_id,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "source_ip": source_ip,
            "username": username,
            "raw_event": raw_event,
            "attributes": attributes if attributes is not None else {"port": 44211, "service": "ssh"},
        }

    # =========================================================================
    # 1. Authentication Tests
    # =========================================================================

    def test_unconfigured_server_api_key_rejects_401(self):
        """When THREATLENS_AGENT_API_KEY is not set on the server, requests are rejected with 401."""
        os.environ.pop("THREATLENS_AGENT_API_KEY", None)
        payload = {
            "device_id": "node-1",
            "events": [self._sample_event()],
        }
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers={"Authorization": "Bearer some-key", "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("unconfigured", data["error"].lower())

    def test_missing_authorization_header_rejects_401(self):
        """Request lacking an Authorization header must be rejected with 401."""
        payload = {
            "device_id": "node-1",
            "events": [self._sample_event()],
        }
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("Missing Authorization header", data["error"])

    def test_malformed_authorization_header_rejects_401(self):
        """Headers not adhering to 'Bearer <token>' must be rejected with 401."""
        payload = {"device_id": "node-1", "events": [self._sample_event()]}
        for bad_header in ["Basic dXNlcjpwYXNz", "Token secret123", "Bearer", "Bearer "]:
            resp = self.client.post(
                "/api/v1/events",
                data=json.dumps(payload),
                headers={"Authorization": bad_header, "Content-Type": "application/json"},
            )
            self.assertEqual(resp.status_code, 401, f"Expected 401 for header '{bad_header}'")

    def test_invalid_bearer_token_rejects_401(self):
        """An incorrect Bearer token must be rejected with 401."""
        payload = {"device_id": "node-1", "events": [self._sample_event()]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers("wrong-key-value"),
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("Invalid", data["error"])

    def test_valid_bearer_token_accepted_200(self):
        """A valid Bearer token matching THREATLENS_AGENT_API_KEY must be accepted."""
        payload = {"device_id": "node-1", "events": [self._sample_event()]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["count"], 1)

    # =========================================================================
    # 2. Validation Tests
    # =========================================================================

    def test_empty_body_rejected_400(self):
        """Empty request body must return 400 Bad Request."""
        resp = self.client.post(
            "/api/v1/events",
            data=b"",
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_json_body_rejected_400(self):
        """Non-JSON payload must return 400 Bad Request."""
        resp = self.client.post(
            "/api/v1/events",
            data=b"not-json-content-here",
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Malformed JSON", resp.get_json()["error"])

    def test_non_dict_json_rejected_400(self):
        """JSON list or primitive at root level must return 400 Bad Request."""
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(["not", "an", "object"]),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)

    def test_body_exceeding_max_size_rejected_413(self):
        """Payload exceeding 5MB must return 413 Payload Too Large."""
        large_padding = "A" * (5 * 1024 * 1024 + 1024)
        payload = {
            "device_id": "dev-1",
            "events": [self._sample_event(raw_event=large_padding)],
        }
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 413)

    def test_missing_device_id_rejected_400(self):
        """Missing or whitespace device_id at root must return 400."""
        payload = {"events": [self._sample_event()]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("device_id", resp.get_json()["error"])

    def test_missing_or_empty_events_list_rejected_400(self):
        """Missing 'events' field or empty list must return 400."""
        # Missing events
        resp1 = self.client.post(
            "/api/v1/events",
            data=json.dumps({"device_id": "dev-1"}),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp1.status_code, 400)

        # Empty events
        resp2 = self.client.post(
            "/api/v1/events",
            data=json.dumps({"device_id": "dev-1", "events": []}),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp2.status_code, 400)

    def test_batch_count_exceeding_limit_rejected_400(self):
        """Batch containing more than 100 events must return 400."""
        events = [self._sample_event() for _ in range(101)]
        payload = {"device_id": "dev-1", "events": events}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("exceeds maximum allowed limit of 100", resp.get_json()["error"])

    def test_invalid_event_id_uuid_rejected_400(self):
        """Non-UUID event_id must return 400."""
        event = self._sample_event(event_id="not-a-valid-uuid-string")
        payload = {"device_id": "dev-1", "events": [event]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("valid UUID", resp.get_json()["error"])

    def test_missing_required_event_field_rejected_400(self):
        """Events missing required fields must return 400."""
        for field in ["timestamp", "source", "event_type", "severity"]:
            event = self._sample_event()
            del event[field]
            payload = {"device_id": "dev-1", "events": [event]}
            resp = self.client.post(
                "/api/v1/events",
                data=json.dumps(payload),
                headers=self._auth_headers(),
            )
            self.assertEqual(resp.status_code, 400, f"Expected 400 for missing '{field}'")
            self.assertIn(field, resp.get_json()["error"])

    def test_invalid_timestamp_rejected_400(self):
        """Invalid or timezone-lacking ISO timestamps must return 400."""
        bad_timestamps = [
            "2026-10-26 12:00:00",  # Lacks timezone offset
            "2026-13-45T99:99:99Z",  # Invalid date components
            "invalid-date-string",
        ]
        for bad_ts in bad_timestamps:
            event = self._sample_event(timestamp=bad_ts)
            payload = {"device_id": "dev-1", "events": [event]}
            resp = self.client.post(
                "/api/v1/events",
                data=json.dumps(payload),
                headers=self._auth_headers(),
            )
            self.assertEqual(resp.status_code, 400, f"Expected 400 for timestamp '{bad_ts}'")

    def test_invalid_severity_rejected_400(self):
        """Severity outside of standard enum must return 400."""
        event = self._sample_event(severity="catastrophic")
        payload = {"device_id": "dev-1", "events": [event]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("severity", resp.get_json()["error"])

    def test_invalid_source_ip_rejected_400(self):
        """Syntactically invalid IP string must return 400."""
        event = self._sample_event(source_ip="999.999.999.999")
        payload = {"device_id": "dev-1", "events": [event]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("source IP address", resp.get_json()["error"])

    def test_valid_optional_ips_accepted(self):
        """IPv4, IPv6, and null source_ip addresses must all be accepted."""
        cases = ["192.168.1.1", "2001:db8::1", "[2001:db8::2]", None]
        events = [self._sample_event(source_ip=ip) for ip in cases]
        payload = {"device_id": "dev-1", "events": events}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 4)

    def test_invalid_attributes_rejected_400(self):
        """Non-dictionary attributes field must return 400."""
        event = self._sample_event(attributes="invalid-not-dict")
        payload = {"device_id": "dev-1", "events": [event]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("attributes", resp.get_json()["error"])

    # =========================================================================
    # 3. Successful Ingestion & Storage Tests
    # =========================================================================

    def test_single_event_ingestion_and_sqlite_persistence(self):
        """Verify single event is stored correctly in endpoint_events table."""
        eid = str(uuid.uuid4())
        event = self._sample_event(
            event_id=eid,
            device_id="host-alpha",
            source="linux_auth",
            event_type="ssh_auth_failure",
            severity="high",
            source_ip="10.0.0.1",
            username="analyst",
            raw_event="Failed password for analyst from 10.0.0.1 port 2222 ssh2",
            attributes={"service": "sshd", "port": 2222},
        )
        payload = {"device_id": "host-alpha", "events": [event]}

        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["acknowledged"], [eid])

        # Verify in SQLite database
        stored = repo.get_endpoint_event(self.conn, eid)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["event_id"], eid)
        self.assertEqual(stored["device_id"], "host-alpha")
        self.assertEqual(stored["source"], "linux_auth")
        self.assertEqual(stored["event_type"], "ssh_auth_failure")
        self.assertEqual(stored["severity"], "high")
        self.assertEqual(stored["source_ip"], "10.0.0.1")
        self.assertEqual(stored["username"], "analyst")
        self.assertEqual(json.loads(stored["attributes"]), {"port": 2222, "service": "sshd"})
        self.assertIsNotNone(stored["received_at"])

    def test_multi_event_batch_with_windows_and_sysmon_telemetry(self):
        """Verify batch with Linux, Windows Security, and Sysmon telemetry is stored."""
        ev_linux = self._sample_event(
            source="linux_auth",
            event_type="ssh_auth_failure",
            severity="high",
        )
        ev_windows = self._sample_event(
            source="windows_event",
            event_type="windows_logon_failure",
            severity="high",
            source_ip="192.168.10.5",
            username="Administrator",
            raw_event="An account failed to log on. Event ID: 4625",
            attributes={"event_id": 4625, "channel": "Security", "logon_type": 3},
        )
        ev_sysmon = self._sample_event(
            source="sysmon",
            event_type="sysmon_process_creation",
            severity="informational",
            source_ip=None,
            username="SYSTEM",
            raw_event="Process Create: C:\\Windows\\System32\\cmd.exe",
            attributes={"event_id": 1, "image": "cmd.exe", "process_id": 1234},
        )

        payload = {
            "device_id": "multi-os-fleet",
            "events": [ev_linux, ev_windows, ev_sysmon],
        }

        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["acknowledged"]), 3)
        self.assertEqual(repo.count_endpoint_events(self.conn), 3)

    def test_query_endpoint_events_api(self):
        """Verify GET /api/v1/events and GET /api/v1/events/<id> retrieve stored events."""
        ev = self._sample_event(source="windows_event", event_type="windows_logon_failure")
        self.client.post(
            "/api/v1/events",
            data=json.dumps({"device_id": "host-1", "events": [ev]}),
            headers=self._auth_headers(),
        )

        # Query all
        resp = self.client.get("/api/v1/events")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["count"], 1)

        # Query with filter
        resp_filtered = self.client.get("/api/v1/events?source=windows_event")
        self.assertEqual(resp_filtered.status_code, 200)
        self.assertEqual(resp_filtered.get_json()["count"], 1)

        resp_miss = self.client.get("/api/v1/events?source=nonexistent")
        self.assertEqual(resp_miss.status_code, 200)
        self.assertEqual(resp_miss.get_json()["count"], 0)

        # Detail endpoint
        resp_detail = self.client.get(f"/api/v1/events/{ev['event_id']}")
        self.assertEqual(resp_detail.status_code, 200)
        self.assertEqual(resp_detail.get_json()["data"]["event_id"], ev["event_id"])

    # =========================================================================
    # 4. Duplicate & Conflict Resolution Tests
    # =========================================================================

    def test_identical_retry_safely_acknowledged(self):
        """Re-transmitting the exact same batch must return 200 and acknowledge all IDs."""
        ev1 = self._sample_event()
        ev2 = self._sample_event()
        payload = {"device_id": "dev-retry", "events": [ev1, ev2]}

        # Initial ingestion
        resp1 = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(len(resp1.get_json()["acknowledged"]), 2)
        self.assertEqual(repo.count_endpoint_events(self.conn), 2)

        # Identical retry
        resp2 = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        self.assertTrue(data2["ok"])
        self.assertEqual(set(data2["acknowledged"]), {ev1["event_id"], ev2["event_id"]})
        # Database count remains exactly 2 (no duplicate rows created)
        self.assertEqual(repo.count_endpoint_events(self.conn), 2)

    def test_conflicting_duplicate_event_id_rejected_409(self):
        """Sending an existing event_id with modified payload must return 409 Conflict."""
        eid = str(uuid.uuid4())
        ev_original = self._sample_event(event_id=eid, severity="low", username="user1")
        payload1 = {"device_id": "dev-conflict", "events": [ev_original]}

        # Ingest original
        resp1 = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload1),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp1.status_code, 200)

        # Conflicting second event: same event_id, different severity and username
        ev_conflict = self._sample_event(event_id=eid, severity="critical", username="different_user")
        payload2 = {"device_id": "dev-conflict", "events": [ev_conflict]}

        resp2 = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload2),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp2.status_code, 409)
        data2 = resp2.get_json()
        self.assertFalse(data2["ok"])
        self.assertEqual(data2["status"], "conflict")
        self.assertIn("Conflicting duplicate event_id", data2["error"])

        # Database remains untouched with original data
        stored = repo.get_endpoint_event(self.conn, eid)
        self.assertEqual(stored["severity"], "low")
        self.assertEqual(stored["username"], "user1")

    def test_intra_batch_conflicting_duplicates_rejected_409(self):
        """A single batch containing two conflicting events with identical event_id must return 409."""
        eid = str(uuid.uuid4())
        ev1 = self._sample_event(event_id=eid, username="alice")
        ev2 = self._sample_event(event_id=eid, username="bob")  # conflict!
        payload = {"device_id": "dev-intra", "events": [ev1, ev2]}

        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(repo.count_endpoint_events(self.conn), 0)

    def test_transactional_rollback_on_conflict(self):
        """If any event in a batch is conflicting, no new events from that batch are persisted."""
        # Pre-seed one event
        pre_eid = str(uuid.uuid4())
        self.client.post(
            "/api/v1/events",
            data=json.dumps({"device_id": "dev-tx", "events": [self._sample_event(event_id=pre_eid, severity="low")]}),
            headers=self._auth_headers(),
        )
        self.assertEqual(repo.count_endpoint_events(self.conn), 1)

        # Send batch: ev_new1 (new), ev_conf (conflicting), ev_new2 (new)
        ev_new1 = self._sample_event(event_id=str(uuid.uuid4()))
        ev_conf = self._sample_event(event_id=pre_eid, severity="critical")  # conflict
        ev_new2 = self._sample_event(event_id=str(uuid.uuid4()))

        payload = {"device_id": "dev-tx", "events": [ev_new1, ev_conf, ev_new2]}
        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 409)

        # Neither ev_new1 nor ev_new2 was committed
        self.assertEqual(repo.count_endpoint_events(self.conn), 1)
        self.assertIsNone(repo.get_endpoint_event(self.conn, ev_new1["event_id"]))
        self.assertIsNone(repo.get_endpoint_event(self.conn, ev_new2["event_id"]))

    # =========================================================================
    # 5. Pipeline Preservation & Non-SSH Isolation Tests
    # =========================================================================

    def test_post_api_ingest_ssh_pipeline_unaffected(self):
        """Verify POST /api/ingest continues to ingest SSH logs and trigger alerts."""
        raw_ssh_log = (
            "Oct 24 14:00:01 srv1 sshd[100]: Failed password for root from 198.51.100.1 port 40001 ssh2\n"
            "Oct 24 14:00:02 srv1 sshd[101]: Failed password for root from 198.51.100.1 port 40002 ssh2\n"
            "Oct 24 14:00:03 srv1 sshd[102]: Failed password for root from 198.51.100.1 port 40003 ssh2\n"
            "Oct 24 14:00:04 srv1 sshd[103]: Failed password for root from 198.51.100.1 port 40004 ssh2\n"
            "Oct 24 14:00:05 srv1 sshd[104]: Failed password for root from 198.51.100.1 port 40005 ssh2\n"
        ).encode("utf-8")

        headers = {"X-Filename": "ssh_spray_test.log"}
        resp = self.client.post("/api/ingest", data=raw_ssh_log, headers=headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["data"]["events_stored"], 5)
        # Verify DR-01 SSH brute force alert was generated
        self.assertGreaterEqual(data["data"]["new_alerts"], 1)
        alerts = repo.list_alerts(self.conn)
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "DR-01")

        # Second upload of same file detected as duplicate
        resp_dup = self.client.post("/api/ingest", data=raw_ssh_log, headers=headers)
        self.assertEqual(resp_dup.status_code, 200)
        self.assertTrue(resp_dup.get_json()["data"]["duplicate"])

    def test_windows_sysmon_telemetry_not_classified_as_ssh(self):
        """Endpoint events for Windows/Sysmon telemetry must NOT populate SSH tables or alerts."""
        ev_win = self._sample_event(
            source="windows_event",
            event_type="windows_logon_failure",
            severity="high",
            source_ip="192.168.10.99",
            username="Alice",
            raw_event="Event 4625 An account failed to log on",
        )
        ev_sys = self._sample_event(
            source="sysmon",
            event_type="sysmon_process_creation",
            severity="informational",
            source_ip="192.168.10.99",
            username="SYSTEM",
            raw_event="Event 1 Process creation",
        )

        resp = self.client.post(
            "/api/v1/events",
            data=json.dumps({"device_id": "win-fleet", "events": [ev_win, ev_sys]}),
            headers=self._auth_headers(),
        )
        self.assertEqual(resp.status_code, 200)

        # Verify events table (SSH events) is completely empty
        self.assertEqual(repo.count_events(self.conn), 0)

        # Verify alerts table (SSH detection alerts) has no alerts
        alerts = repo.list_alerts(self.conn)
        self.assertEqual(len(alerts), 0)

        # Verify endpoint_events has the 2 events
        self.assertEqual(repo.count_endpoint_events(self.conn), 2)


if __name__ == "__main__":
    unittest.main()
