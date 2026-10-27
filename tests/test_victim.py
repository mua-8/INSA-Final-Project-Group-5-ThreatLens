import unittest
import json
from backend.api import app
from backend.database import init_db
import tempfile
import os

class TestVictimEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.tmp.close()
        self.db_path = self.tmp.name
        self.db = init_db(self.db_path)
        app.config["TESTING"] = True
        self.client = app.test_client()

        import backend.api as api_mod
        self.orig_db = api_mod.DB_PATH
        api_mod.DB_PATH = self.db_path

    def tearDown(self):
        self.db.close()
        import backend.api as api_mod
        api_mod.DB_PATH = self.orig_db
        try:
            os.remove(self.db_path)
        except OSError:
            pass

    def test_victim_status(self):
        res = self.client.get("/api/victim/status?ip=198.51.100.42")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertEqual(data["client_ip"], "198.51.100.42")
        self.assertFalse(data["is_quarantined"])

    def test_victim_login_sqli_attack_auto_quarantined(self):
        payload = {
            "username": "admin' OR '1'='1",
            "password": "any",
            "client_ip": "198.51.100.42"
        }
        res = self.client.post("/api/victim/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertEqual(data["status"], "attack_detected")
        self.assertEqual(data["attack_type"], "sqli")
        self.assertTrue(data["blocked"])

        # Second request from same IP should get 403 Forbidden!
        res2 = self.client.post("/api/victim/login", json=payload)
        self.assertEqual(res2.status_code, 403)
        self.assertTrue(res2.get_json()["blocked"])

    def test_victim_search_sqli(self):
        payload = {
            "query": "1001' UNION SELECT username, password FROM users --",
            "client_ip": "203.0.113.88"
        }
        res = self.client.post("/api/victim/search", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertEqual(data["status"], "attack_detected")
        self.assertTrue(data["blocked"])

    def test_victim_reset_ip(self):
        # First block it
        self.client.post("/api/victim/login", json={
            "username": "admin' OR '1'='1",
            "client_ip": "198.51.100.99"
        })
        # Reset IP
        res = self.client.post("/api/victim/reset-ip", json={"ip_address": "198.51.100.99"})
        self.assertEqual(res.status_code, 200)
        # Check status
        res2 = self.client.get("/api/victim/status?ip=198.51.100.99")
        self.assertFalse(res2.get_json()["data"]["is_quarantined"])

if __name__ == "__main__":
    unittest.main()
