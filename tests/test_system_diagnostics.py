"""Tests for Module B: Dynamic Route Discovery and Isolated Subprocess Test Runner.

Verifies:
1. GET /api/system/routes and GET /api/routes dynamically derive from Flask url_map.
2. Static built-in endpoints are excluded.
3. All registered application routes expose methods, path, endpoint name, and description.
4. POST /api/system/tests/run executes in an isolated subprocess.
5. Command injection and hostile parameters are strictly rejected (HTTP 400).
6. Execution does not alter or pollute the active database.
7. External client requests are restricted (HTTP 403) unless authenticated.
8. Subprocess timeouts are handled cleanly (HTTP 504).
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from backend import api
from backend.database import init_db


class TestSystemDiagnostics(unittest.TestCase):
    """Test suite for system verification, route discovery, and isolated test runner."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()

        api.DB_PATH = self.db_path
        self.conn = init_db(self.db_path)
        self.client = api.app.test_client()

    def tearDown(self):
        if hasattr(self, "conn") and self.conn:
            self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_get_system_routes_returns_dynamic_registry(self):
        """GET /api/system/routes must return all registered routes derived from url_map."""
        res = self.client.get("/api/system/routes")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))

        routes = data.get("routes") or data.get("data", {}).get("routes")
        self.assertIsInstance(routes, list)
        self.assertGreater(len(routes), 15)

        # Confirm static route is excluded
        endpoints = [r.get("endpoint") for r in routes]
        self.assertNotIn("static", endpoints)

        # Confirm core application endpoints are present
        self.assertIn("health", endpoints)
        self.assertIn("list_alerts", endpoints)
        self.assertIn("list_events", endpoints)
        self.assertIn("statistics", endpoints)
        self.assertIn("create_incident", endpoints)
        self.assertIn("run_system_tests", endpoints)
        self.assertIn("get_system_routes", endpoints)

        # Confirm contract fields on each route
        for r in routes:
            self.assertIn("path", r)
            self.assertIn("method", r)
            self.assertIn("endpoint", r)
            self.assertIn("desc", r)
            self.assertIsInstance(r["desc"], str)
            self.assertGreater(len(r["desc"]), 0)

    def test_get_routes_alias(self):
        """GET /api/routes should serve as an alias for /api/system/routes."""
        res = self.client.get("/api/routes")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))

    def test_isolated_test_runner_single_suite_execution(self):
        """POST /api/system/tests/run with allowlisted target executes successfully."""
        res = self.client.post("/api/system/tests/run", json={"target": "database"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))

        payload = data.get("data", data)
        self.assertTrue(payload.get("passed"))
        self.assertGreater(payload.get("total_tests", 0), 5)
        self.assertEqual(payload.get("failures"), 0)
        self.assertEqual(payload.get("errors"), 0)
        self.assertIn("suites", payload)
        self.assertGreaterEqual(len(payload["suites"]), 1)

    def test_isolated_test_runner_rejects_command_injection(self):
        """POST /api/system/tests/run must reject shell injection and invalid targets."""
        hostile_payloads = [
            "database; rm -rf /",
            "api && echo hacked",
            "| cat /etc/passwd",
            "--help",
            "../api.py",
            "../../../etc/shadow",
            "invalid_suite_name",
        ]
        for payload in hostile_payloads:
            res = self.client.post("/api/system/tests/run", json={"target": payload})
            self.assertEqual(res.status_code, 400, f"Expected 400 for payload: {payload}")
            data = res.get_json()
            self.assertFalse(data.get("ok"))
            self.assertIn("Invalid test target", data.get("error", ""))

    def test_isolated_test_runner_does_not_mutate_active_database(self):
        """The test runner must run in isolated DB and never alter active database."""
        # Record pre-execution state
        stat_before = os.stat(self.db_path)

        res = self.client.post("/api/system/tests/run", json={"target": "database"})
        self.assertEqual(res.status_code, 200)

        # Check post-execution state
        stat_after = os.stat(self.db_path)
        self.assertEqual(stat_before.st_size, stat_after.st_size)
        self.assertEqual(stat_before.st_mtime, stat_after.st_mtime)

    def test_isolated_test_runner_remote_ip_restriction(self):
        """Diagnostic test runner must reject non-loopback external clients."""
        was_testing = api.app.config.get("TESTING")
        try:
            api.app.config["TESTING"] = False
            # Simulate external caller
            res = self.client.post(
                "/api/system/tests/run",
                json={"target": "database"},
                environ_base={"REMOTE_ADDR": "198.51.100.99"},
            )
            self.assertEqual(res.status_code, 403)
            data = res.get_json()
            self.assertFalse(data.get("ok"))
            self.assertIn("restricted", data.get("error", "").lower())
        finally:
            api.app.config["TESTING"] = was_testing

    @patch("subprocess.run")
    def test_isolated_test_runner_timeout_handling(self, mock_run):
        """Subprocess timeout must be caught cleanly and return HTTP 504."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["pytest"], timeout=45)

        res = self.client.post("/api/system/tests/run", json={"target": "database"})
        self.assertEqual(res.status_code, 504)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertIn("timed out", data.get("error", "").lower())


if __name__ == "__main__":
    unittest.main()
