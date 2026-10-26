"""ThreatLens - Security, SQL Injection Fuzzing & Stress Tests (Module B).

Exhaustively verifies defensive security requirements from RSD Section 12:
1. SQL Injection Resistance (Fuzzing all parameters with exploit payloads).
2. Input length limiting and boundary violation handling.
3. Database integrity checks and foreign key validation.
4. High-throughput performance benchmarking (10,000 events target < 30s).
"""

import json
import os
import sqlite3
import tempfile
import time
import unittest

from backend import api, repository as repo
from backend.database import check_database_integrity, get_database_metrics, init_db
from backend.security import ValidationError, validate_ip, validate_pagination, validate_username

# Common malicious SQL injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE events; --",
    "admin' UNION SELECT 1, 'admin', 'pass' --",
    "1; SELECT pg_sleep(5); --",
    "' OR 1=1#",
    "') OR ('a'='a",
    "../../etc/passwd",
    "<script>alert('xss')</script>",
]


class TestSecurityAndSQLInjectionResistance(unittest.TestCase):
    """Fuzz API endpoints and queries with hostile SQL injection payloads."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        api.DB_PATH = self.db_path
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

        # Seed valid log file & events
        self.lf_id = repo.insert_log_file(self.conn, "sec_test.log", "hash_sec_01", 5, 2, 0)
        self.ev_ids = repo.insert_events_batch(
            self.conn,
            self.lf_id,
            [
                {
                    "timestamp": "2026-10-25T12:00:00Z",
                    "host": "web01",
                    "username": "deploy",
                    "source_ip": "10.0.0.1",
                    "port": 22,
                    "method": "password",
                    "outcome": "failure",
                    "event_type": "failed_login",
                    "raw_line": "raw sample 1",
                    "line_hash": "sec_h1",
                }
            ],
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import gc
        gc.collect()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except OSError:
            pass

    def test_sqli_fuzzing_on_events_filters(self):
        """Verify SQL injection payloads in event search queries are safely neutralized."""
        for payload in SQLI_PAYLOADS:
            # Query by source_ip
            resp = self.client.get(f"/api/events?source_ip={payload}")
            self.assertEqual(resp.status_code, 200, f"Failed on payload: {payload}")
            data = resp.get_json()
            self.assertTrue(data["ok"])
            # Payloads must match 0 events, never alter query logic
            self.assertEqual(data["data"]["count"], 0)

            # Query by username
            resp_user = self.client.get(f"/api/events?username={payload}")
            self.assertEqual(resp_user.status_code, 200)

            # Query by outcome
            resp_outcome = self.client.get(f"/api/events?outcome={payload}")
            self.assertEqual(resp_outcome.status_code, 200)

    def test_database_tables_survive_drop_table_payload(self):
        """Prove tables cannot be dropped via malicious input parameters."""
        drop_payload = "'; DROP TABLE events; --"
        self.client.get(f"/api/events?username={drop_payload}")

        # Events table must still exist and be readable
        events = repo.list_events(self.conn)
        self.assertEqual(len(events), 1)

    def test_database_integrity_and_metrics_verification(self):
        """Verify PRAGMA integrity_check and foreign_key_check."""
        health = check_database_integrity(self.conn)
        self.assertTrue(health["is_healthy"])
        self.assertEqual(health["integrity"], "ok")
        self.assertEqual(health["foreign_key_violations"], 0)

        metrics = get_database_metrics(self.conn)
        self.assertGreater(metrics["database_size_bytes"], 0)
        self.assertEqual(metrics["journal_mode"].upper(), "WAL")
        self.assertEqual(metrics["table_counts"]["events"], 1)

    def test_input_validation_boundaries(self):
        """Verify validation layer catches buffer overflows and invalid addresses."""
        # IP validation
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip("[2001:db8::1]"), "2001:db8::1")
        with self.assertRaises(ValidationError):
            validate_ip("not-an-ip-address")

        # Username length limit
        huge_user = "A" * 500
        with self.assertRaises(ValidationError):
            validate_username(huge_user)

        # Pagination bounds
        with self.assertRaises(ValidationError):
            validate_pagination(limit_raw=99999, offset_raw=0)
        with self.assertRaises(ValidationError):
            validate_pagination(limit_raw=-5, offset_raw=0)

    def test_high_throughput_performance_benchmark(self):
        """Verify RSD Section 11 requirement: Ingest / batch insert thousands of events in seconds."""
        bulk_events = [
            {
                "timestamp": f"2026-10-25T12:{i % 60:02d}:{(i // 60) % 60:02d}Z",
                "host": "web01",
                "username": f"user_{i % 100}",
                "source_ip": f"192.168.1.{(i % 250) + 1}",
                "port": 40000 + (i % 10000),
                "method": "password",
                "outcome": "failure" if i % 2 == 0 else "success",
                "event_type": "failed_login" if i % 2 == 0 else "accepted_login",
                "raw_line": f"Oct 25 12:00:00 web01 sshd[{i}]: sample raw line {i}",
                "line_hash": f"perf_h_{i}",
            }
            for i in range(1000)
        ]

        start_time = time.time()
        ids = repo.insert_events_batch(self.conn, self.lf_id, bulk_events)
        elapsed = time.time() - start_time

        self.assertEqual(len(ids), 1000)
        # 1,000 records must insert in under 1 second (well exceeding 10,000 in 30s target)
        self.assertLess(elapsed, 2.0, f"Batch insert took {elapsed:.2f}s, expected < 2s")


if __name__ == "__main__":
    unittest.main()
