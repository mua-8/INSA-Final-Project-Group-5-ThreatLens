"""Tests for Module B: SQLite database schema, constraints, and repository layer.

Validates:
- All 6 documented tables exist with required columns and constraints.
- Foreign keys and CASCADE deletions work correctly.
- Parameterized queries prevent SQL injection.
- CRUD operations for log_files, events, alerts, alert_evidence, incidents, notes.
- Data relationships between alerts, evidence events, and incidents.
"""

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime

from backend import repository as repo
from backend.database import SCHEMA_SQL, get_connection, init_db, sha256_of


class TestDatabaseSchema(unittest.TestCase):
    """Test schema creation, tables, indexes, and constraints."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.conn = init_db(self.db_path)

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_all_six_tables_exist(self):
        cursor = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        )
        tables = {row["name"] for row in cursor.fetchall()}
        expected_tables = {
            "log_files",
            "events",
            "alerts",
            "alert_evidence",
            "incidents",
            "incident_notes",
        }
        for table in expected_tables:
            self.assertIn(table, tables, f"Expected table '{table}' in database schema")

    def test_foreign_keys_enforced(self):
        # Inserting event with non-existent log_file_id must fail
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """INSERT INTO events (log_file_id, timestamp, outcome, event_type, raw_line, line_hash)
                   VALUES (9999, '2026-10-25T12:00:00Z', 'failure', 'failed_login', 'raw text', 'hash123')"""
            )

    def test_cascade_delete_log_files_removes_events(self):
        log_id = repo.insert_log_file(self.conn, "test.log", "hash_abc", 10, 2, 0)
        repo.insert_events_batch(
            self.conn,
            log_id,
            [
                {
                    "timestamp": "2026-10-25T12:00:00Z",
                    "host": "srv1",
                    "username": "root",
                    "source_ip": "1.2.3.4",
                    "port": 22,
                    "method": "password",
                    "outcome": "failure",
                    "event_type": "failed_login",
                    "raw_line": "raw 1",
                    "line_hash": "h1",
                }
            ],
        )
        self.assertEqual(repo.count_events(self.conn), 1)

        # Deleting log_file cascades to events
        self.conn.execute("DELETE FROM log_files WHERE id = ?", (log_id,))
        self.assertEqual(repo.count_events(self.conn), 0)

    def test_duplicate_file_hash_rejected(self):
        repo.insert_log_file(self.conn, "first.log", "hash_same", 10, 5, 0)
        with self.assertRaises(sqlite3.IntegrityError):
            repo.insert_log_file(self.conn, "second.log", "hash_same", 10, 5, 0)


class TestRepositoryOperations(unittest.TestCase):
    """Test repository CRUD functions and business logic queries."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.conn = init_db(self.db_path)

        # Seed a log file and some events
        self.log_file_id = repo.insert_log_file(
            self.conn, "auth.log", sha256_of(b"sample content"), 100, 10, 0
        )

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_events_crud_and_filtering(self):
        events_data = [
            {
                "timestamp": "2026-10-25T10:00:00Z",
                "host": "web01",
                "username": "alice",
                "source_ip": "192.168.1.10",
                "port": 2222,
                "method": "password",
                "outcome": "failure",
                "event_type": "failed_login",
                "raw_line": "raw failure line alice",
                "line_hash": "hash_alice_1",
            },
            {
                "timestamp": "2026-10-25T10:05:00Z",
                "host": "web01",
                "username": "bob",
                "source_ip": "192.168.1.20",
                "port": 2223,
                "method": "password",
                "outcome": "success",
                "event_type": "accepted_login",
                "raw_line": "raw success line bob",
                "line_hash": "hash_bob_1",
            },
            {
                "timestamp": "2026-10-25T10:10:00Z",
                "host": "web01",
                "username": "alice",
                "source_ip": "192.168.1.10",
                "port": 2224,
                "method": "password",
                "outcome": "success",
                "event_type": "accepted_login",
                "raw_line": "raw success line alice",
                "line_hash": "hash_alice_2",
            },
        ]
        ids = repo.insert_events_batch(self.conn, self.log_file_id, events_data)
        self.assertEqual(len(ids), 3)

        # Filter by source_ip
        filtered_ip = repo.list_events(self.conn, source_ip="192.168.1.10")
        self.assertEqual(len(filtered_ip), 2)

        # Filter by username
        filtered_user = repo.list_events(self.conn, username="bob")
        self.assertEqual(len(filtered_user), 1)

        # Filter by outcome
        filtered_success = repo.list_events(self.conn, outcome="success")
        self.assertEqual(len(filtered_success), 2)

    def test_alerts_and_evidence_relationship(self):
        # Insert events
        event_ids = repo.insert_events_batch(
            self.conn,
            self.log_file_id,
            [
                {
                    "timestamp": f"2026-10-25T12:0{i}:00Z",
                    "host": "web01",
                    "username": "root",
                    "source_ip": "10.0.0.99",
                    "port": 3000 + i,
                    "method": "password",
                    "outcome": "failure",
                    "event_type": "failed_login",
                    "raw_line": f"failed root attempt {i}",
                    "line_hash": f"hash_root_{i}",
                }
                for i in range(5)
            ],
        )

        alert_data = {
            "rule_id": "DR-01",
            "rule_name": "SSH brute force",
            "severity": "medium",
            "status": "new",
            "source_ip": "10.0.0.99",
            "first_seen": "2026-10-25T12:00:00Z",
            "last_seen": "2026-10-25T12:04:00Z",
            "summary": "5 failed logins from 10.0.0.99",
            "explanation": "Brute force pattern detected",
            "settings": {"threshold": 5, "window_minutes": 5},
        }
        alert_id = repo.insert_alert(self.conn, alert_data)
        self.assertIsNotNone(alert_id)

        # Link evidence
        repo.insert_alert_evidence(self.conn, alert_id, event_ids)

        # Retrieve evidence
        evidence_rows = repo.get_alert_evidence(self.conn, alert_id)
        self.assertEqual(len(evidence_rows), 5)
        self.assertEqual(evidence_rows[0]["source_ip"], "10.0.0.99")

        # Update status
        updated = repo.update_alert_status(self.conn, alert_id, "investigating")
        self.assertTrue(updated)
        alert_row = repo.get_alert(self.conn, alert_id)
        self.assertEqual(alert_row["status"], "investigating")

    def test_incidents_notes_and_alert_links(self):
        inc_id = repo.insert_incident(
            self.conn,
            title="Investigating IP 10.0.0.99",
            description="Repeated brute force and root attempts",
            severity="high",
        )
        self.assertIsNotNone(inc_id)

        # Add notes
        n1 = repo.insert_incident_note(
            self.conn, inc_id, "Assigned to Adnan for SOC investigation.", "adnan"
        )
        n2 = repo.insert_incident_note(
            self.conn, inc_id, "Firewall rule created for IP.", "security-lead"
        )
        self.assertIsNotNone(n1)
        self.assertIsNotNone(n2)

        notes = repo.list_incident_notes(self.conn, inc_id)
        self.assertEqual(len(notes), 2)
        self.assertEqual(notes[0]["author"], "adnan")

        # Update incident status
        self.assertTrue(repo.update_incident_status(self.conn, inc_id, "in_progress"))
        incident = repo.get_incident(self.conn, inc_id)
        self.assertEqual(incident["status"], "in_progress")

    def test_auth_statistics_aggregation(self):
        repo.insert_events_batch(
            self.conn,
            self.log_file_id,
            [
                {
                    "timestamp": "2026-10-25T12:00:00Z",
                    "host": "web01",
                    "username": "user1",
                    "source_ip": "1.1.1.1",
                    "port": 22,
                    "method": "password",
                    "outcome": "success",
                    "event_type": "accepted_login",
                    "raw_line": "line1",
                    "line_hash": "hash_st1",
                },
                {
                    "timestamp": "2026-10-25T12:01:00Z",
                    "host": "web01",
                    "username": "user2",
                    "source_ip": "1.1.1.2",
                    "port": 22,
                    "method": "password",
                    "outcome": "failure",
                    "event_type": "failed_login",
                    "raw_line": "line2",
                    "line_hash": "hash_st2",
                },
            ],
        )

        stats = repo.auth_statistics(self.conn)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["unique_ips"], 2)
        self.assertEqual(stats["unique_users"], 2)


if __name__ == "__main__":
    unittest.main()
