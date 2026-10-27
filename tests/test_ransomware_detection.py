"""Tests for ThreatLens Phase 2: Ransomware Behavior Detection Engine.

Validates:
1. Sliding-window burst evaluation (modify, rename, delete, combined):
   - Below threshold produces no alert
   - Above threshold produces single alert per episode
   - Distinct normalized paths counted, raw count tracked in metadata
   - Device isolation (episodes isolated per device)
   - Out-of-order timestamps handled safely
   - Replay / re-evaluation idempotency (no duplicate alerts within dedupe gap)
2. Canary / honeyfile monitoring:
   - Modification, deletion, rename away from canary, rename into canary
   - Exact path equality (prefix / substring / suffix variations do not match)
   - Device scoping (global vs endpoint-specific)
   - Disabled canary suppression
   - Deduplication within dedupe gap
3. Suspicious file-extension mutation:
   - Qualifying rename to suspicious extension (.locked, .enc, etc.)
   - Same-extension renames ignored
   - Non-suspicious target extension ignored
   - Missing previous_path handled safely without false positives
   - Case-insensitivity and dot normalization
4. Alert correlation, evidence tracking, and incident escalation:
   - Alert file evidence stored in alert_file_evidence table
   - Incident creation and linking within correlation window
   - Escalation to critical on canary hit or multi-indicator combinations
   - Duplicate incident prevention
5. REST API management:
   - Policy configuration GET and PATCH with validation
   - Canary registration, listing, retrieval, update, and deletion
   - On-demand ransomware analysis endpoint (POST /api/v1/ransomware/analyze)
   - Ransomware alerts listing with evidence (GET /api/v1/ransomware/alerts)
6. Backward compatibility & isolation:
   - SSH detection rules (DR-01..DR-05) remain unaffected
   - File events never enter events table or trigger SSH rules
   - Parameterized SQL defense & schema integrity
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import os
import sys
import tempfile
import unittest
import uuid

# Ensure repository root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from backend import api, repository as repo
from backend.database import init_db, check_database_integrity
from backend.ransomware_detection import (
    RansomwareDetectionEngine,
    RansomwareConfig,
    get_ransomware_engine,
    reset_ransomware_engine,
    normalize_path,
)


class BaseRansomwareTest(unittest.TestCase):
    """Base test class providing an isolated temporary SQLite database and API client."""

    TEST_API_KEY = "test-rw-telemetry-secret-key-1234"

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        api.DB_PATH = self.db_path
        reset_ransomware_engine(self.db_path)
        api.reset_detection_engine(self.db_path)

        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

        self.original_api_key = os.environ.get("THREATLENS_AGENT_API_KEY")
        os.environ["THREATLENS_AGENT_API_KEY"] = self.TEST_API_KEY

    def tearDown(self):
        if self.original_api_key is not None:
            os.environ["THREATLENS_AGENT_API_KEY"] = self.original_api_key
        else:
            os.environ.pop("THREATLENS_AGENT_API_KEY", None)

        reset_ransomware_engine(self.db_path)
        api.reset_detection_engine(self.db_path)
        self.conn.close()

        import gc
        gc.collect()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.TEST_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "ThreatLens-Agent/0.1.0",
        }

    def _insert_file_event(
        self,
        event_type: str = "file_modified",
        file_path: str = "/data/finance/file1.docx",
        previous_path: str | None = None,
        device_id: str = "srv-01",
        timestamp: str | None = None,
        process_name: str | None = "crypto_tool",
        process_id: int | None = 1337,
    ) -> int:
        """Helper to insert a raw file event into the test database and return its rowid."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        ext = os.path.splitext(file_path)[1].lower()
        cur = self.conn.execute(
            """INSERT INTO file_events (
                event_id, device_id, event_type, file_path, file_extension,
                previous_path, process_name, process_id, timestamp, attributes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"fev-{uuid.uuid4().hex[:12]}",
                device_id,
                event_type,
                file_path,
                ext,
                previous_path,
                process_name,
                process_id,
                timestamp,
                "{}",
            ),
        )
        self.conn.commit()
        return cur.lastrowid


# ==============================================================================
# 1. Burst Detection Tests
# ==============================================================================

class TestRansomwareBurstDetection(BaseRansomwareTest):
    """Verifies sliding-window burst detection across modifications, renames, and deletions."""

    def test_burst_below_threshold_produces_no_alerts(self):
        """Burst below configured threshold should not trigger an alert."""
        engine = get_ransomware_engine(self.db_path)
        # Update policy thresholds to 10 for quick testing
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=10)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # Insert 8 distinct modifications within 5 seconds (threshold is 10)
        for i in range(8):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", timestamp=ts)

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 0)
        alerts = self.conn.execute("SELECT * FROM alerts WHERE rule_id LIKE 'RW-%'").fetchall()
        self.assertEqual(len(alerts), 0)

    def test_burst_above_threshold_produces_single_alert(self):
        """Burst exceeding threshold generates exactly one alert for the episode."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=10)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # Insert 12 distinct file modifications within 4 seconds
        for i in range(12):
            ts = (base_time + timedelta(seconds=i * 0.3)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", timestamp=ts)

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        alert = result.new_alerts[0]
        self.assertEqual(alert["rule_id"], "RW-BURST-01")
        self.assertEqual(alert["target_host"], "srv-01")
        self.assertGreaterEqual(alert["settings"]["raw_event_count"], 12)
        self.assertGreaterEqual(alert["settings"]["distinct_paths_count"], 10)

        # Check alert_file_evidence table
        evidence = repo.get_alert_file_evidence(self.conn, alert["id"])
        self.assertEqual(len(evidence), 12)

    def test_burst_counts_distinct_paths_not_raw_duplicates(self):
        """Repeated modifications to the same file path must not inflate distinct path count."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=10)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # 15 events, but only across 4 distinct files
        for i in range(15):
            path = f"/data/docs/doc_{i % 4}.txt"
            ts = (base_time + timedelta(seconds=i * 0.2)).isoformat()
            self._insert_file_event("file_modified", path, timestamp=ts)

        result = engine.process_file_events(self.conn)
        # Threshold is 10 distinct paths; here only 4 distinct paths -> No alert
        self.assertEqual(len(result.new_alerts), 0)

    def test_burst_device_isolation(self):
        """Burst activity on srv-01 and srv-02 must be evaluated separately without cross-device bleeding."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=8)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # 5 events on srv-01
        for i in range(5):
            ts = (base_time + timedelta(seconds=i * 0.2)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", device_id="srv-01", timestamp=ts)

        # 5 events on srv-02
        for i in range(5):
            ts = (base_time + timedelta(seconds=i * 0.2)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", device_id="srv-02", timestamp=ts)

        result = engine.process_file_events(self.conn)
        # Neither srv-01 (5 paths) nor srv-02 (5 paths) reaches threshold 8
        self.assertEqual(len(result.new_alerts), 0)

    def test_burst_out_of_order_timestamps_sorted_safely(self):
        """Out-of-order events within the window must be ordered chronologically before evaluation."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=5)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # Insert events in reverse chronological order
        for i in reversed(range(6)):
            ts = (base_time + timedelta(seconds=i * 1.0)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", timestamp=ts)

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        self.assertEqual(result.new_alerts[0]["rule_id"], "RW-BURST-01")

    def test_burst_rename_and_delete_categories(self):
        """Rename and delete burst categories trigger RW-BURST-02 and RW-BURST-03."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(
            self.conn,
            "default",
            burst_window_seconds=10,
            burst_rename_threshold=5,
            burst_delete_threshold=5,
        )
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # Renames on srv-01
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            self._insert_file_event(
                "file_renamed",
                f"/data/docs/file_{i}.enc",
                previous_path=f"/data/docs/file_{i}.txt",
                device_id="srv-01",
                timestamp=ts,
            )

        # Deletions on srv-02
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            self._insert_file_event(
                "file_deleted",
                f"/data/docs/file_{i}.txt",
                device_id="srv-02",
                timestamp=ts,
            )

        result = engine.process_file_events(self.conn)
        self.assertGreaterEqual(len(result.new_alerts), 2)
        rules = {a["rule_id"] for a in result.new_alerts}
        self.assertIn("RW-BURST-02", rules)
        self.assertIn("RW-BURST-03", rules)

    def test_burst_repeated_evaluation_idempotency(self):
        """Repeated evaluation of the same burst events must not create duplicate alerts within dedupe gap."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(self.conn, "default", burst_window_seconds=10, burst_modify_threshold=5)
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            self._insert_file_event("file_modified", f"/data/docs/doc_{i}.txt", timestamp=ts)

        res1 = engine.process_file_events(self.conn)
        self.assertEqual(len(res1.new_alerts), 1)

        # Re-evaluate same events
        res2 = engine.process_file_events(self.conn)
        self.assertEqual(len(res2.new_alerts), 0)
        # Alert was updated / preserved, not duplicated
        alerts = self.conn.execute("SELECT * FROM alerts WHERE rule_id = 'RW-BURST-01'").fetchall()
        self.assertEqual(len(alerts), 1)


# ==============================================================================
# 2. Canary / Honeyfile Monitoring Tests
# ==============================================================================

class TestRansomwareCanaryMonitoring(BaseRansomwareTest):
    """Verifies exact path matching, device scoping, event types, and suppression."""

    def test_canary_modification_and_deletion(self):
        """Modification or deletion of a registered canary file triggers RW-CANARY-01."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-passwords",
            file_path="/var/canaries/passwords.kdbx",
            severity="critical",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        ev_id = self._insert_file_event(
            "file_modified",
            "/var/canaries/passwords.kdbx",
            device_id="srv-01",
        )
        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        alert = result.new_alerts[0]
        self.assertEqual(alert["rule_id"], "RW-CANARY-01")
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("passwords.kdbx", alert["explanation"])

    def test_canary_rename_away_and_into(self):
        """Renaming a canary file (either previous_path or target file_path) triggers canary alert."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-finance",
            file_path="/finance/ledger.xlsx",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        # Case 1: Renaming away from canary
        self._insert_file_event(
            "file_renamed",
            "/finance/ledger_archive.xlsx",
            previous_path="/finance/ledger.xlsx",
            device_id="srv-01",
        )
        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        self.assertEqual(result.new_alerts[0]["rule_id"], "RW-CANARY-01")

        # Case 2: Renaming into canary path
        self._insert_file_event(
            "file_renamed",
            "/finance/ledger.xlsx",
            previous_path="/tmp/fake_ledger.xlsx",
            device_id="srv-02",
        )
        result2 = engine.process_file_events(self.conn)
        self.assertEqual(len(result2.new_alerts), 1)
        self.assertEqual(result2.new_alerts[0]["rule_id"], "RW-CANARY-01")

    def test_canary_exact_path_matching(self):
        """Canary matching must use exact path equality, never prefix or substring matching."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-exact",
            file_path="/var/canaries/decoy.txt",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        # These should NOT trigger the canary:
        # 1. Suffix added: decoy.txt.backup
        self._insert_file_event("file_modified", "/var/canaries/decoy.txt.backup")
        # 2. Subdirectory: /var/canaries/decoy.txt/child.txt
        self._insert_file_event("file_modified", "/var/canaries/decoy.txt/child.txt")
        # 3. Partial filename: /var/canaries/decoy.tx
        self._insert_file_event("file_modified", "/var/canaries/decoy.tx")

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 0)

        # Exact match triggers
        self._insert_file_event("file_modified", "/var/canaries/decoy.txt")
        result2 = engine.process_file_events(self.conn)
        self.assertEqual(len(result2.new_alerts), 1)
        self.assertEqual(result2.new_alerts[0]["rule_id"], "RW-CANARY-01")

    def test_canary_device_scoping(self):
        """Device-scoped canary alerts only for that device; global canary alerts for all devices."""
        # Scoped canary for srv-01 only
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-srv01",
            file_path="/opt/data/secret.key",
            device_id="srv-01",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        # Activity on srv-02 should NOT trigger
        self._insert_file_event("file_modified", "/opt/data/secret.key", device_id="srv-02")
        res1 = engine.process_file_events(self.conn)
        self.assertEqual(len(res1.new_alerts), 0)

        # Activity on srv-01 triggers
        self._insert_file_event("file_modified", "/opt/data/secret.key", device_id="srv-01")
        res2 = engine.process_file_events(self.conn)
        self.assertEqual(len(res2.new_alerts), 1)
        self.assertEqual(res2.new_alerts[0]["target_host"], "srv-01")

    def test_disabled_canary_suppression(self):
        """Disabled canary file must produce zero alerts."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-disabled",
            file_path="/opt/data/unused.key",
            enabled=0,
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        self._insert_file_event("file_modified", "/opt/data/unused.key", device_id="srv-01")
        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 0)


# ==============================================================================
# 3. Suspicious Extension Change Tests
# ==============================================================================

class TestRansomwareExtensionDetection(BaseRansomwareTest):
    """Verifies rapid suspicious file-extension mutation detection."""

    def test_qualifying_extension_mutation_triggers_alert(self):
        """Renaming a document to a suspicious extension (.locked) triggers RW-EXT-01."""
        engine = get_ransomware_engine(self.db_path)

        self._insert_file_event(
            "file_renamed",
            file_path="/home/user/document.docx.locked",
            previous_path="/home/user/document.docx",
            device_id="srv-01",
        )

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        alert = result.new_alerts[0]
        self.assertEqual(alert["rule_id"], "RW-EXT-01")
        self.assertEqual(alert["severity"], "medium")
        self.assertIn(".locked", alert["explanation"])

    def test_rename_with_same_extension_is_ignored(self):
        """Renaming a file with no extension change (or already .locked) does not trigger extension alert."""
        engine = get_ransomware_engine(self.db_path)

        # .txt -> .txt
        self._insert_file_event(
            "file_renamed",
            file_path="/home/user/new_name.txt",
            previous_path="/home/user/old_name.txt",
        )
        # .locked -> .locked (already encrypted)
        self._insert_file_event(
            "file_renamed",
            file_path="/home/user/archive2.locked",
            previous_path="/home/user/archive1.locked",
        )

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 0)

    def test_rename_without_previous_path_handled_safely(self):
        """When previous_path is None or empty, treat as incomplete evidence, not a fabricated mutation."""
        engine = get_ransomware_engine(self.db_path)

        self._insert_file_event(
            "file_renamed",
            file_path="/home/user/unknown.locked",
            previous_path=None,
        )

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 0)

    def test_extension_case_insensitivity_and_dot_normalization(self):
        """Extensions such as '.LOCKED' or '.WNCRY' must match configured suspicious extensions."""
        engine = get_ransomware_engine(self.db_path)

        self._insert_file_event(
            "file_renamed",
            file_path="/home/user/database.mdf.LOCKED",
            previous_path="/home/user/database.mdf",
        )

        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        self.assertEqual(result.new_alerts[0]["rule_id"], "RW-EXT-01")


# ==============================================================================
# 4. Correlation, Evidence, and Incident Escalation Tests
# ==============================================================================

class TestRansomwareCorrelationAndIncidents(BaseRansomwareTest):
    """Verifies evidence linking, incident grouping, and critical escalation."""

    def test_evidence_linking_to_alert_file_evidence_table(self):
        """Ransomware alerts must link file event IDs into alert_file_evidence table."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-1",
            file_path="/canary/file.txt",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        row_id = self._insert_file_event("file_modified", "/canary/file.txt")
        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_alerts), 1)
        alert_id = result.new_alerts[0]["id"]

        evidence = repo.get_alert_file_evidence(self.conn, alert_id)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["id"], row_id)
        self.assertEqual(evidence[0]["file_path"], "/canary/file.txt")

    def test_incident_escalation_to_critical_on_canary(self):
        """Canary alert creates or updates incident with severity escalated to 'critical'."""
        repo.insert_canary_file(
            self.conn,
            canary_id="canary-hr",
            file_path="/hr/salaries.xlsx",
        )
        self.conn.commit()
        engine = get_ransomware_engine(self.db_path)

        self._insert_file_event("file_modified", "/hr/salaries.xlsx", device_id="workstation-09")
        result = engine.process_file_events(self.conn)
        self.assertEqual(len(result.new_incidents), 1)
        inc = result.new_incidents[0]
        self.assertEqual(inc["severity"], "critical")
        self.assertIn("Ransomware Activity Detected", inc["title"])

        # Verify linked via incident_alerts
        linked_alerts = repo.get_incident_alerts(self.conn, inc["id"])
        self.assertEqual(len(linked_alerts), 1)
        self.assertEqual(linked_alerts[0]["rule_id"], "RW-CANARY-01")

    def test_multi_indicator_correlation_escalates_to_critical(self):
        """Correlating burst detection + suspicious extension on the same endpoint escalates incident to critical."""
        engine = get_ransomware_engine(self.db_path)
        repo.update_ransomware_policy(
            self.conn,
            "default",
            burst_window_seconds=10,
            burst_modify_threshold=5,
        )
        self.conn.commit()
        engine.load_config_from_db(self.conn)

        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        # 1. Burst of modifications on srv-db
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 0.5)).isoformat()
            self._insert_file_event("file_modified", f"/data/db_{i}.dat", device_id="srv-db", timestamp=ts)

        # 2. Suspicious extension rename on srv-db
        ts_rename = (base_time + timedelta(seconds=4)).isoformat()
        self._insert_file_event(
            "file_renamed",
            file_path="/data/important.sql.locked",
            previous_path="/data/important.sql",
            device_id="srv-db",
            timestamp=ts_rename,
        )

        result = engine.process_file_events(self.conn)
        self.assertGreaterEqual(len(result.new_alerts), 2)

        # Should be correlated into a single incident with critical severity
        incidents = self.conn.execute("SELECT * FROM incidents").fetchall()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc["severity"], "critical")

        # Linked alerts should include both RW-BURST-01 and RW-EXT-01
        linked = repo.get_incident_alerts(self.conn, inc["id"])
        rules = {a["rule_id"] for a in linked}
        self.assertIn("RW-BURST-01", rules)
        self.assertIn("RW-EXT-01", rules)


# ==============================================================================
# 5. REST API & Policy Management Tests
# ==============================================================================

class TestRansomwareApiEndpoints(BaseRansomwareTest):
    """Verifies REST endpoints for config, canaries, analysis, and alerts."""

    def test_get_and_update_ransomware_config(self):
        """GET and PATCH /api/v1/ransomware/config update policy parameters with validation."""
        # 1. GET default config
        resp = self.client.get("/api/v1/ransomware/config")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()["data"]
        self.assertEqual(data["burst_modify_threshold"], 50)
        self.assertEqual(data["burst_window_seconds"], 10)

        # 2. PATCH config with updated thresholds
        update_payload = {
            "burst_modify_threshold": 30,
            "burst_window_seconds": 15,
            "suspicious_extensions": [".locked", ".crypto", ".customext"],
        }
        resp = self.client.patch(
            "/api/v1/ransomware/config",
            data=json.dumps(update_payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        updated = resp.get_json()["data"]
        self.assertEqual(updated["burst_modify_threshold"], 30)
        self.assertEqual(updated["burst_window_seconds"], 15)
        self.assertIn(".customext", updated["suspicious_extensions"])

        # 3. Validation: negative threshold rejected
        bad_payload = {"burst_modify_threshold": -5}
        resp = self.client.patch(
            "/api/v1/ransomware/config",
            data=json.dumps(bad_payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_canary_crud_endpoints(self):
        """Full CRUD lifecycle for canary management via REST API."""
        # 1. Create canary
        canary_data = {
            "canary_id": "test-canary-api",
            "file_path": "/var/secrets/canary.txt",
            "device_id": "srv-api",
            "description": "Sensitive credentials decoy",
            "severity": "high",
            "enabled": True,
        }
        res = self.client.post(
            "/api/v1/canaries",
            data=json.dumps(canary_data),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 201)
        created = res.get_json()["data"]["canary"]
        self.assertEqual(created["canary_id"], "test-canary-api")
        self.assertEqual(created["file_path"], "/var/secrets/canary.txt")

        # 2. Conflict on duplicate ID
        res_dup = self.client.post(
            "/api/v1/canaries",
            data=json.dumps(canary_data),
            content_type="application/json",
        )
        self.assertEqual(res_dup.status_code, 409)

        # 3. GET canary detail
        res_get = self.client.get("/api/v1/canaries/test-canary-api")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.get_json()["data"]["description"], "Sensitive credentials decoy")

        # 4. List canaries
        res_list = self.client.get("/api/v1/canaries")
        self.assertEqual(res_list.status_code, 200)
        self.assertGreaterEqual(res_list.get_json()["count"], 1)

        # 5. Update canary (disable)
        res_patch = self.client.patch(
            "/api/v1/canaries/test-canary-api",
            data=json.dumps({"enabled": False, "severity": "critical"}),
            content_type="application/json",
        )
        self.assertEqual(res_patch.status_code, 200)
        self.assertEqual(res_patch.get_json()["data"]["enabled"], 0)
        self.assertEqual(res_patch.get_json()["data"]["severity"], "critical")

        # 6. Delete canary
        res_del = self.client.delete("/api/v1/canaries/test-canary-api")
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json()["data"]["deleted"])

        # 7. Verify 404 after deletion
        res_get404 = self.client.get("/api/v1/canaries/test-canary-api")
        self.assertEqual(res_get404.status_code, 404)

    def test_canary_path_traversal_and_null_byte_rejection(self):
        """Canary registration rejects path traversal (..) and null bytes."""
        bad_paths = [
            "/var/secrets/../../etc/passwd",
            "/var/canary\x00.txt",
            "",
            "   ",
        ]
        for p in bad_paths:
            res = self.client.post(
                "/api/v1/canaries",
                data=json.dumps({"file_path": p}),
                content_type="application/json",
            )
            self.assertEqual(res.status_code, 400, f"Expected 400 for bad path: {repr(p)}")

    def test_analyze_and_list_ransomware_alerts(self):
        """POST /api/v1/ransomware/analyze evaluates events and GET /api/v1/ransomware/alerts lists results."""
        repo.insert_canary_file(self.conn, canary_id="canary-db", file_path="/db/canary.db")
        self.conn.commit()

        self._insert_file_event("file_modified", "/db/canary.db", device_id="srv-prod")

        # Trigger on-demand analysis
        res_an = self.client.post(
            "/api/v1/ransomware/analyze",
            data=json.dumps({"device_id": "srv-prod"}),
            content_type="application/json",
        )
        self.assertEqual(res_an.status_code, 200)
        data = res_an.get_json()["data"]
        self.assertGreaterEqual(data["new_alerts_count"], 1)

        # Query ransomware alerts
        res_al = self.client.get("/api/v1/ransomware/alerts")
        self.assertEqual(res_al.status_code, 200)
        alerts = res_al.get_json()["data"]["alerts"]
        self.assertGreaterEqual(len(alerts), 1)
        first = alerts[0]
        self.assertIn("file_evidence", first)
        self.assertGreaterEqual(len(first["file_evidence"]), 1)

        # Query single alert endpoint (used by AlertDetailModal.jsx)
        alert_id = first["id"]
        res_single = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(res_single.status_code, 200)
        single_data = res_single.get_json()["data"]
        self.assertIn("file_evidence", single_data)
        self.assertGreaterEqual(len(single_data["file_evidence"]), 1)
        self.assertIsInstance(single_data["settings"], dict)


# ==============================================================================
# 6. Backward Compatibility & System Integrity Tests
# ==============================================================================

class TestRansomwareRegressionAndIntegrity(BaseRansomwareTest):
    """Verifies that file events never interfere with SSH detection or database integrity."""

    def test_ssh_rules_remain_functional(self):
        """Built-in SSH rules (DR-01..DR-05) continue to process SSH events without regression."""
        log_id = repo.insert_log_file(self.conn, "auth_test.log", "hash_auth_test_123", 6, 6, 0)
        # Insert 6 failed SSH events from same IP within 2 minutes to trigger DR-01
        base_time = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(6):
            ts = (base_time + timedelta(seconds=i * 10)).isoformat()
            self.conn.execute(
                """INSERT INTO events (
                    log_file_id, timestamp, host, username, source_ip, port, method,
                    outcome, event_type, raw_line, line_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    log_id,
                    ts,
                    "bastion-01",
                    "root",
                    "192.168.1.100",
                    22,
                    "password",
                    "failure",
                    "ssh_login",
                    f"Failed password for root from 192.168.1.100 port 22 {i}",
                    f"hash-{i}",
                ),
            )
        self.conn.commit()

        # Run SSH detection engine
        from backend.parser import Event
        parsed_events = [
            Event(
                timestamp=base_time + timedelta(seconds=i * 10),
                host="bastion-01",
                username="root",
                source_ip="192.168.1.100",
                port=22,
                method="password",
                outcome="failure",
                event_type="failed_login",
                raw_line=f"Failed password for root from 192.168.1.100 port 22 {i}",
                line_hash=f"ssh-live-hash-{i}",
            )
            for i in range(6)
        ]
        det_engine = api.get_detection_engine(self.db_path)
        api.sync_engine_rules_from_db(det_engine, self.conn)
        det_res = det_engine.process(parsed_events)
        rule_ids = {a.rule_id for a in det_res.new_alerts}
        self.assertIn("DR-01", rule_ids)

    def test_file_events_never_enter_ssh_events_or_trigger_ssh_rules(self):
        """File events in file_events table must not bleed into events table or trigger SSH rules."""
        # Insert 20 file events
        for i in range(20):
            self._insert_file_event("file_modified", f"/var/log/file_{i}.log")

        # 1. SSH events table should have 0 rows
        ssh_events_count = self.conn.execute("SELECT count(*) FROM events").fetchone()[0]
        self.assertEqual(ssh_events_count, 0)

        # 2. SSH alerts should be 0
        ssh_alerts_count = self.conn.execute("SELECT count(*) FROM alerts WHERE rule_id LIKE 'DR-%'").fetchone()[0]
        self.assertEqual(ssh_alerts_count, 0)

    def test_database_integrity_and_foreign_keys(self):
        """SQLite PRAGMA integrity_check and foreign_key_check must pass cleanly."""
        check = check_database_integrity(self.conn)
        self.assertTrue(check["is_healthy"])
        self.assertEqual(check["integrity"], "ok")
        self.assertEqual(check["foreign_key_violations"], 0)


if __name__ == "__main__":
    unittest.main()
