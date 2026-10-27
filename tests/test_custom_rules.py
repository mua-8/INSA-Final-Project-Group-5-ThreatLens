"""Tests for Phase 2: Safe Declarative Custom Detection Rule Engine.

Validates:
1. Declarative rule schema validation and condition normalization.
2. Safe operator matching (eq, neq, in, not_in, contains, startswith, endswith).
3. Sliding window and distinct count episode detection.
4. Entity grouping (source_ip, username, host, source_ip,host).
5. Safe handling of missing grouping values and safe attribute lookups.
6. Alert creation, SOC-grade description, evidence tracking, and correlation without KeyError.
7. Absence of dynamic code execution (eval, exec).
8. Live engine synchronization on rule updates/toggles.
9. Concrete API-level end-to-end test for CR-01 (SSH disconnect storm: threshold 5, window 5m).
10. Preservation of built-in detection rules DR-01 through DR-05.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import tempfile
import unittest

from backend import api, repository as repo
from backend.api import app, reset_detection_engine, sync_rule_to_engine, _detection_engines
from backend.database import get_connection, init_db
from backend.detection import (
    Alert,
    ConfigError,
    DetectionConfig,
    DetectionEngine,
    RULE_NAMES,
    _DESCRIBERS,
    evaluate_custom_rule,
    matches_custom_rule,
    validate_custom_rule_conditions,
)
from backend.parser import DISCONNECT, Event, parse_text
from typing import Optional


def _mk_event(
    sec_offset: int,
    outcome: str = "failure",
    event_type: str = "failed_login",
    username: str = "deploy",
    source_ip: str = "203.0.113.10",
    host: str = "web01",
    port: int = 2222,
    method: Optional[str] = None,
    raw_line: str = "",
    base_time: datetime = None,
    event_id: int = None,
) -> Event:
    """Helper to synthesize structured Event objects for detection testing."""
    if base_time is None:
        base_time = datetime(2026, 10, 24, 13, 0, 0, tzinfo=timezone.utc)
    ts = base_time + timedelta(seconds=sec_offset)
    if event_type == "disconnect":
        outcome = "unknown"
        method = None
    if not raw_line:
        raw_line = f"Oct 24 13:{sec_offset // 60:02d}:{sec_offset % 60:02d} {host} sshd[{port}]: {event_type} for {username} from {source_ip} port {port}"
    line_hash = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()[:16]
    return Event(
        timestamp=ts,
        host=host,
        username=username,
        source_ip=source_ip,
        port=port,
        method=method,
        outcome=outcome,
        event_type=event_type,
        raw_line=raw_line,
        line_hash=line_hash,
        id=event_id,
    )


class TestCustomRuleConditionsValidation(unittest.TestCase):
    """Test suite area 1-5: Schema validation and operator security."""

    def test_01_valid_threshold_rule_validation(self):
        cond = {
            "type": "threshold",
            "group_by": "source_ip",
            "match": {"event_type": "disconnect", "outcome": "unknown"},
            "match_operators": {"event_type": "eq", "outcome": "eq"},
        }
        res = validate_custom_rule_conditions(cond)
        self.assertEqual(res["type"], "threshold")
        self.assertEqual(res["group_by"], "source_ip")
        self.assertEqual(res["match"]["event_type"], "disconnect")
        self.assertEqual(res["match_operators"]["event_type"], "eq")
        self.assertIsNone(res["distinct_field"])

    def test_02_valid_distinct_count_rule_validation(self):
        cond = {
            "type": "distinct_count",
            "group_by": "source_ip",
            "distinct_field": "username",
            "match": {"event_type": "failed_login"},
        }
        res = validate_custom_rule_conditions(cond)
        self.assertEqual(res["type"], "distinct_count")
        self.assertEqual(res["distinct_field"], "username")
        self.assertEqual(res["match_operators"]["event_type"], "eq")

    def test_03_unknown_condition_keys_rejected(self):
        bad_cond = {
            "type": "threshold",
            "unknown_key": "malicious_payload",
            "match": {"event_type": "disconnect"},
        }
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions(bad_cond)
        self.assertIn("Unknown condition keys", str(ctx.exception))

    def test_04_unsupported_operators_rejected(self):
        bad_ops = [
            {"match": {"method": "password"}, "match_operators": {"method": "regex"}},
            {"match": {"method": "password"}, "match_operators": {"method": "eval"}},
            {"match": {"method": "password"}, "match_operators": {"method": "like"}},
        ]
        for cond in bad_ops:
            with self.subTest(cond=cond):
                with self.assertRaises(ValueError) as ctx:
                    validate_custom_rule_conditions(cond)
                self.assertIn("Unsupported operator", str(ctx.exception))

    def test_05_malformed_json_and_invalid_field_types_rejected(self):
        # Malformed JSON string
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions("{bad json: 123")
        self.assertIn("Malformed JSON", str(ctx.exception))

        # Non-dict condition
        with self.assertRaises(ValueError):
            validate_custom_rule_conditions(["not", "a", "dict"])

        # Invalid field name in match
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"match": {"not_a_field": "val"}})
        self.assertIn("Unknown match field", str(ctx.exception))

        # Invalid distinct field for distinct_count
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"type": "distinct_count", "distinct_field": "invalid_field"})
        self.assertIn("distinct_count rules require 'distinct_field'", str(ctx.exception))

        # Invalid port value (out of range)
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"match": {"port": 70000}})
        self.assertIn("integer between 0 and 65535", str(ctx.exception))

    def test_reg_01_empty_conditions_rejected_for_custom_rules_preserved_for_builtins(self):
        # Empty condition dictionary rejected for custom rules
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({})
        self.assertIn("non-empty conditions", str(ctx.exception))

        # Empty string rejected for custom rules
        with self.assertRaises(ValueError):
            validate_custom_rule_conditions("")

        # Empty JSON object string rejected for custom rules
        with self.assertRaises(ValueError):
            validate_custom_rule_conditions("{}")

        # None rejected for custom rules
        with self.assertRaises(ValueError):
            validate_custom_rule_conditions(None)

        # Empty match dict rejected for custom rules
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"match": {}})
        self.assertIn("specify at least one match field", str(ctx.exception))

        # Built-in rules DR-01, DR-02, DR-03 preserve empty conditions
        self.assertEqual(validate_custom_rule_conditions({}, rule_id="DR-01"), {})
        self.assertEqual(validate_custom_rule_conditions("{}", rule_id="DR-02"), {})
        self.assertEqual(validate_custom_rule_conditions("", rule_id="DR-03"), {})
        self.assertEqual(validate_custom_rule_conditions(None, rule_id="DR-01"), {})

    def test_reg_02_legacy_conditions_unknown_keys_rejected(self):
        # Unknown keys in legacy condition dictionary must be rejected
        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"failure_threshold": 5, "unknown_field": "bad"}, rule_id="DR-04")
        self.assertIn("Unknown keys in legacy conditions", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            validate_custom_rule_conditions({"usernames": ["root"], "accepted_severity": "high", "bogus": 123}, rule_id="DR-05")
        self.assertIn("Unknown keys in legacy conditions", str(ctx.exception))

        # Invalid legacy value types
        with self.assertRaises(ConfigError):
            validate_custom_rule_conditions({"failure_threshold": -1}, rule_id="DR-04")

        with self.assertRaises(ConfigError):
            validate_custom_rule_conditions({"accepted_severity": "invalid_sev"}, rule_id="DR-05")

    def test_reg_03_invalid_operator_operand_types(self):
        # eq with invalid operand types
        # port must be int between 0 and 65535, reject str, bool, float, dict, list
        invalid_port_values = ["22", True, False, 22.5, [22], {"port": 22}, -1, 70000]
        for val in invalid_port_values:
            with self.subTest(port_val=val):
                with self.assertRaises(ValueError):
                    validate_custom_rule_conditions({"match": {"port": val}, "match_operators": {"port": "eq"}})

        # username (string field) must reject int, bool, list, dict
        invalid_str_values = [123, True, False, ["admin"], {"user": "admin"}]
        for val in invalid_str_values:
            with self.subTest(str_val=val):
                with self.assertRaises(ValueError):
                    validate_custom_rule_conditions({"match": {"username": val}, "match_operators": {"username": "eq"}})

    def test_reg_04_string_operators_with_non_string_targets(self):
        # contains, startswith, endswith must reject non-string targets and empty string
        for op in ("contains", "startswith", "endswith"):
            invalid_targets = [123, True, False, None, ["sub"], {"a": 1}, ""]
            for target in invalid_targets:
                with self.subTest(op=op, target=target):
                    with self.assertRaises(ValueError):
                        validate_custom_rule_conditions({
                            "match": {"username": target},
                            "match_operators": {"username": op},
                        })

            # String operators on numeric field 'port' must be rejected
            with self.assertRaises(ValueError) as ctx:
                validate_custom_rule_conditions({
                    "match": {"port": 22},
                    "match_operators": {"port": op},
                })
            self.assertIn("not supported on numeric field 'port'", str(ctx.exception))

    def test_reg_05_invalid_in_and_not_in_values(self):
        for op in ("in", "not_in"):
            # Rejects None, scalars, empty lists, heterogeneous lists, and lists > 100 items
            invalid_list_operands = [
                None,
                "admin",
                123,
                True,
                [],
                ["admin", 123],
                ["admin", None],
                ["admin", True],
            ]
            for operand in invalid_list_operands:
                with self.subTest(op=op, operand=operand):
                    with self.assertRaises(ValueError):
                        validate_custom_rule_conditions({
                            "match": {"username": operand},
                            "match_operators": {"username": op},
                        })

            # On port field, list must contain ints in range, not strings or booleans
            invalid_port_lists = [["22"], [True], [-5], [70000], [22, "80"]]
            for port_list in invalid_port_lists:
                with self.subTest(op=op, port_list=port_list):
                    with self.assertRaises(ValueError):
                        validate_custom_rule_conditions({
                            "match": {"port": port_list},
                            "match_operators": {"port": op},
                        })

            # List exceeding 100 items
            huge_list = [f"user_{i}" for i in range(101)]
            with self.assertRaises(ValueError) as ctx:
                validate_custom_rule_conditions({
                    "match": {"username": huge_list},
                    "match_operators": {"username": op},
                })
            self.assertIn("exceeds maximum limit", str(ctx.exception))

    def test_reg_06_builtin_dr04_and_dr05_validation(self):
        # DR-04 accepts valid failure_threshold
        res_dr04 = validate_custom_rule_conditions({"failure_threshold": 6}, rule_id="DR-04")
        self.assertEqual(res_dr04["failure_threshold"], 6)

        # DR-05 accepts valid usernames and accepted_severity
        res_dr05 = validate_custom_rule_conditions(
            {"usernames": ["root", "admin"], "accepted_severity": "critical"}, rule_id="DR-05"
        )
        self.assertEqual(res_dr05["usernames"], ["root", "admin"])
        self.assertEqual(res_dr05["accepted_severity"], "critical")



class TestCustomRuleMatchingEngine(unittest.TestCase):
    """Test suite area 6: Safe evaluation and operator mechanics."""

    def test_06_operator_eq_neq_in_not_in(self):
        ev = _mk_event(0, username="alice", event_type="disconnect", port=22)

        # eq
        self.assertTrue(matches_custom_rule(ev, {"username": "alice"}, {"username": "eq"}))
        self.assertFalse(matches_custom_rule(ev, {"username": "bob"}, {"username": "eq"}))

        # neq
        self.assertTrue(matches_custom_rule(ev, {"username": "bob"}, {"username": "neq"}))
        self.assertFalse(matches_custom_rule(ev, {"username": "alice"}, {"username": "neq"}))

        # in
        self.assertTrue(matches_custom_rule(ev, {"username": ["alice", "bob"]}, {"username": "in"}))
        self.assertFalse(matches_custom_rule(ev, {"username": ["charlie", "david"]}, {"username": "in"}))

        # not_in
        self.assertTrue(matches_custom_rule(ev, {"username": ["charlie", "david"]}, {"username": "not_in"}))
        self.assertFalse(matches_custom_rule(ev, {"username": ["alice", "bob"]}, {"username": "not_in"}))

    def test_07_operator_contains_startswith_endswith(self):
        ev = _mk_event(0, raw_line="Received disconnect from 192.0.2.1 port 54321:11: Normal Shutdown")

        # contains
        self.assertTrue(matches_custom_rule(ev, {"raw_line": "Normal Shutdown"}, {"raw_line": "contains"}))
        self.assertFalse(matches_custom_rule(ev, {"raw_line": "Auth fail"}, {"raw_line": "contains"}))

        # startswith
        self.assertTrue(matches_custom_rule(ev, {"raw_line": "Received disconnect"}, {"raw_line": "startswith"}))
        self.assertFalse(matches_custom_rule(ev, {"raw_line": "Normal Shutdown"}, {"raw_line": "startswith"}))

        # endswith
        self.assertTrue(matches_custom_rule(ev, {"raw_line": "Normal Shutdown"}, {"raw_line": "endswith"}))
        self.assertFalse(matches_custom_rule(ev, {"raw_line": "port 54321"}, {"raw_line": "endswith"}))

    def test_08_safe_handling_of_none_attributes(self):
        ev = _mk_event(0, username=None, method=None)
        # Should safely return False for string ops on None, not raise AttributeError
        self.assertFalse(matches_custom_rule(ev, {"username": "root"}, {"username": "contains"}))
        self.assertFalse(matches_custom_rule(ev, {"method": "password"}, {"method": "startswith"}))
        self.assertFalse(matches_custom_rule(ev, {"method": "password"}, {"method": "endswith"}))
        self.assertTrue(matches_custom_rule(ev, {"username": None}, {"username": "eq"}))


class TestCustomRuleDetectionLogic(unittest.TestCase):
    """Test suite areas 7-15: Sliding windows, thresholds, distinct count, and grouping."""

    def test_09_threshold_triggers_alert_at_exact_count(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-01", {
            "name": "SSH Disconnect Storm",
            "enabled": True,
            "threshold": 5,
            "window_minutes": 5,
            "severity": "medium",
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip",
                "match": {"event_type": "disconnect"},
            },
        })

        # 4 events: no alert
        events_4 = [_mk_event(i * 10, event_type="disconnect", source_ip="203.0.113.88") for i in range(4)]
        res_4 = engine.process(events_4)
        self.assertEqual(len(res_4.new_alerts), 0)
        self.assertEqual(len(engine.alerts), 0)

        # 5th event: triggers alert
        ev_5 = [_mk_event(50, event_type="disconnect", source_ip="203.0.113.88")]
        res_5 = engine.process(ev_5)
        self.assertEqual(len(res_5.new_alerts), 1)
        self.assertEqual(len(engine.alerts), 1)

        alert = engine.alerts[0]
        self.assertEqual(alert.rule_id, "CR-01")
        self.assertEqual(alert.rule_name, "SSH Disconnect Storm")
        self.assertEqual(alert.severity, "medium")
        self.assertEqual(len(alert.evidence_ids), 5)
        self.assertEqual(alert.source_ip, "203.0.113.88")

    def test_10_events_outside_window_do_not_trigger(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-01", {
            "name": "SSH Disconnect Storm",
            "enabled": True,
            "threshold": 5,
            "window_minutes": 5,
            "severity": "medium",
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip",
                "match": {"event_type": "disconnect"},
            },
        })

        # 5 events spaced 3 minutes apart (total span 12 min > 5 min window)
        events_spaced = [_mk_event(i * 180, event_type="disconnect", source_ip="203.0.113.89") for i in range(5)]
        res = engine.process(events_spaced)
        self.assertEqual(len(res.new_alerts), 0)
        self.assertEqual(len(engine.alerts), 0)

    def test_11_distinct_count_rule_handles_repeated_values(self):
        engine = DetectionEngine()
        engine.config.rules["DR-01"]["enabled"] = False
        engine.add_custom_rule("CR-DIST", {
            "name": "Multi-User Failed Logins",
            "enabled": True,
            "threshold": 3,
            "window_minutes": 10,
            "severity": "high",
            "conditions": {
                "type": "distinct_count",
                "group_by": "source_ip",
                "distinct_field": "username",
                "match": {"outcome": "failure"},
            },
        })

        # 6 failures all for 'deploy' -> 1 distinct user < threshold 3 -> no alert
        evs_same = [_mk_event(i * 10, username="deploy", outcome="failure") for i in range(6)]
        res1 = engine.process(evs_same)
        self.assertEqual(len(res1.new_alerts), 0)

        # 3 failures for distinct users: 'admin', 'root', 'support' -> triggers alert
        evs_diff = [
            _mk_event(70, username="admin", outcome="failure"),
            _mk_event(80, username="root", outcome="failure"),
            _mk_event(90, username="support", outcome="failure"),
        ]
        res2 = engine.process(evs_diff)
        self.assertEqual(len(res2.new_alerts), 1)
        alert = res2.new_alerts[0]
        self.assertIn("distinct username values", alert.explanation)
        self.assertGreaterEqual(len(alert.evidence_ids), 3)

    def test_12_grouping_by_username(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-USER", {
            "name": "Targeted User Storm",
            "enabled": True,
            "threshold": 4,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "username",
                "match": {"outcome": "failure"},
            },
        })

        # User 'victim' attacked from 4 different IPs -> reaches threshold 4 for 'victim'
        events = [
            _mk_event(10, username="victim", source_ip="198.51.100.1"),
            _mk_event(20, username="victim", source_ip="198.51.100.2"),
            _mk_event(30, username="victim", source_ip="198.51.100.3"),
            _mk_event(40, username="victim", source_ip="198.51.100.4"),
            # Noise for other user
            _mk_event(50, username="other", source_ip="198.51.100.1"),
        ]
        res = engine.process(events)
        self.assertEqual(len(res.new_alerts), 1)
        alert = res.new_alerts[0]
        self.assertEqual(alert.rule_id, "CR-USER")
        self.assertIn("user victim", alert.summary)

    def test_13_grouping_by_host(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-HOST", {
            "name": "Host Attack Blast",
            "enabled": True,
            "threshold": 3,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "host",
                "match": {"event_type": "disconnect"},
            },
        })

        events = [
            _mk_event(10, host="db-primary", event_type="disconnect", source_ip="10.0.0.1"),
            _mk_event(20, host="db-primary", event_type="disconnect", source_ip="10.0.0.2"),
            _mk_event(30, host="db-primary", event_type="disconnect", source_ip="10.0.0.3"),
            # Different host
            _mk_event(40, host="web-frontend", event_type="disconnect", source_ip="10.0.0.4"),
        ]
        res = engine.process(events)
        self.assertEqual(len(res.new_alerts), 1)
        self.assertEqual(res.new_alerts[0].target_host, "db-primary")

    def test_14_missing_grouping_values_do_not_combine(self):
        engine = DetectionEngine()
        engine.config.rules["DR-01"]["enabled"] = False
        engine.add_custom_rule("CR-USER", {
            "name": "User Rule",
            "enabled": True,
            "threshold": 3,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "username",
                "match": {"outcome": "failure"},
            },
        })

        # 5 events with username=None -> must NEVER be grouped into a cluster
        events = [_mk_event(i * 10, username=None, outcome="failure") for i in range(5)]
        res = engine.process(events)
        self.assertEqual(len(res.new_alerts), 0)
        self.assertEqual(len(engine.alerts), 0)

    def test_15_custom_rule_correlation_and_absorption(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-01", {
            "name": "SSH Disconnect Storm",
            "enabled": True,
            "threshold": 5,
            "window_minutes": 5,
            "severity": "medium",
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip",
                "match": {"event_type": "disconnect"},
            },
        })

        # Episode 1: 5 events in minute 0..1
        ep1 = [_mk_event(i * 10, event_type="disconnect", source_ip="192.0.2.77") for i in range(5)]
        res1 = engine.process(ep1)
        self.assertEqual(len(res1.new_alerts), 1)
        self.assertEqual(len(engine.alerts), 1)
        alert_id = res1.new_alerts[0].id

        # Episode 2: 3 more events at minute 3 (within dedupe gap of 30 min)
        ep2 = [_mk_event(180 + i * 10, event_type="disconnect", source_ip="192.0.2.77") for i in range(3)]
        res2 = engine.process(ep2)
        # Should absorb into existing alert, not create a second alert
        self.assertEqual(len(res2.new_alerts), 0)
        self.assertEqual(len(res2.updated_alerts), 1)
        self.assertEqual(len(engine.alerts), 1)
        self.assertEqual(engine.alerts[0].id, alert_id)
        self.assertEqual(len(engine.alerts[0].evidence_ids), 8)

    def test_16_rule_toggle_takes_effect_immediately(self):
        engine = DetectionEngine()
        engine.add_custom_rule("CR-TOGGLE", {
            "name": "Toggleable Rule",
            "enabled": False,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": {"type": "threshold", "match": {"event_type": "disconnect"}},
        })

        events = [_mk_event(10, event_type="disconnect"), _mk_event(20, event_type="disconnect")]
        res1 = engine.process(events)
        self.assertEqual(len(res1.new_alerts), 0)

        # Enable rule
        engine.config.rules["CR-TOGGLE"]["enabled"] = True
        events2 = [_mk_event(30, event_type="disconnect")]
        res2 = engine.process(events2)
        self.assertEqual(len(res2.new_alerts), 1)

    def test_17_invalid_rule_config_safely_ignored_by_engine(self):
        engine = DetectionEngine()
        # Custom rule with completely malformed conditions
        engine.config.rules["CR-BROKEN"] = {
            "name": "Broken Rule",
            "enabled": True,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": "INVALID JSON {{{{",
        }
        # Engine must not raise an exception and continue cleanly
        res = engine.process([_mk_event(0)])
        self.assertEqual(len(res.new_alerts), 0)

    def test_reg_07_independent_grouping_and_correlation_keys(self):
        engine = DetectionEngine()
        # Group by source_ip,host
        engine.add_custom_rule("CR-IP-HOST", {
            "name": "Distinct Host-IP Pairs",
            "enabled": True,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip,host",
                "match": {"event_type": "disconnect"},
            },
        })

        events = [
            # Pair 1: 192.168.1.1 on web01 (2 events)
            _mk_event(10, event_type="disconnect", source_ip="192.168.1.1", host="web01"),
            _mk_event(20, event_type="disconnect", source_ip="192.168.1.1", host="web01"),
            # Pair 2: 192.168.1.1 on db01 (2 events) - same IP, different host
            _mk_event(30, event_type="disconnect", source_ip="192.168.1.1", host="db01"),
            _mk_event(40, event_type="disconnect", source_ip="192.168.1.1", host="db01"),
        ]
        res = engine.process(events)
        self.assertEqual(len(res.new_alerts), 2)
        # Verify distinct correlation keys and target hosts
        hosts = {a.target_host for a in res.new_alerts}
        self.assertEqual(hosts, {"web01", "db01"})
        self.assertEqual(len({a.id for a in res.new_alerts}), 2)

    def test_reg_08_missing_grouping_values_are_ignored(self):
        engine = DetectionEngine()
        # Test group_by="source_ip,host" when host is None or source_ip is None
        engine.add_custom_rule("CR-IP-HOST-MISSING", {
            "name": "Missing Host Pair",
            "enabled": True,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip,host",
                "match": {"event_type": "disconnect"},
            },
        })

        events = [
            _mk_event(10, event_type="disconnect", source_ip="192.168.1.1", host=None),
            _mk_event(20, event_type="disconnect", source_ip="192.168.1.1", host=None),
            _mk_event(30, event_type="disconnect", source_ip=None, host="web01"),
            _mk_event(40, event_type="disconnect", source_ip=None, host="web01"),
        ]
        res = engine.process(events)
        self.assertEqual(len(res.new_alerts), 0)


class TestCustomRuleAPIIntegration(unittest.TestCase):
    """Test suite areas 16-25: API integration, live sync, persistence, CR-01 scenario."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        self._orig_db_path = getattr(api, "DB_PATH", "threatlens.db")
        api.DB_PATH = self.db_path
        reset_detection_engine(self.db_path)

        # Initialize schema
        self.conn = init_db(self.db_path)

        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        reset_detection_engine(self.db_path)
        if hasattr(self, "conn") and self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
        api.DB_PATH = getattr(self, "_orig_db_path", "threatlens.db")
        if os.path.exists(self.db_path):
            try:
                os.unlink(self.db_path)
            except Exception:
                pass

    def _query_db(self, sql, params=()):
        conn = get_connection(self.db_path)
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            return cur.fetchall()
        finally:
            conn.close()

    def test_18_api_rejects_invalid_custom_rule_conditions(self):
        # 1. Invalid operator
        resp1 = self.client.post("/api/rules", json={
            "rule_id": "CR-BAD",
            "name": "Bad Rule",
            "conditions": {"match": {"username": "root"}, "match_operators": {"username": "exec"}},
        })
        self.assertEqual(resp1.status_code, 400)
        self.assertIn("Unsupported operator", resp1.get_json()["error"])

        # 2. Unknown field
        resp2 = self.client.post("/api/rules", json={
            "rule_id": "CR-BAD2",
            "name": "Bad Rule 2",
            "conditions": {"match": {"non_existent_field": "123"}},
        })
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("Unknown match field", resp2.get_json()["error"])

    def test_19_api_cr01_ssh_disconnect_storm_end_to_end(self):
        """CR-01 end-to-end: threshold 5, window 5m, 4 events no alert, 5th event alerts."""
        # 1. Register custom rule CR-01
        rule_payload = {
            "rule_id": "CR-01",
            "name": "SSH Disconnect Storm",
            "description": "Bursts of disconnect events from a single IP",
            "severity": "medium",
            "enabled": True,
            "threshold": 5,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip",
                "match": {"event_type": "disconnect"},
            },
        }
        res_create = self.client.post("/api/rules", json=rule_payload)
        self.assertEqual(res_create.status_code, 201)
        self.assertEqual(res_create.get_json()["data"]["rule_id"], "CR-01")

        # 2. Ingest 4 disconnect log lines (below threshold)
        log_4 = (
            "Oct 24 13:00:10 srv01 sshd[1001]: Disconnected from 198.51.100.99 port 5001\n"
            "Oct 24 13:00:20 srv01 sshd[1002]: Disconnected from 198.51.100.99 port 5002\n"
            "Oct 24 13:00:30 srv01 sshd[1003]: Disconnected from 198.51.100.99 port 5003\n"
            "Oct 24 13:00:40 srv01 sshd[1004]: Disconnected from 198.51.100.99 port 5004\n"
        )
        res_ingest_4 = self.client.post(
            "/api/ingest",
            data=log_4,
            content_type="text/plain",
            headers={"X-Filename": "disconnect_4.log"},
        )
        self.assertEqual(res_ingest_4.status_code, 201)
        data_4 = res_ingest_4.get_json()["data"]
        self.assertEqual(data_4["events_stored"], 4)
        self.assertEqual(data_4["new_alerts"], 0)

        # Verify alerts list is empty
        res_alerts_0 = self.client.get("/api/alerts?rule_id=CR-01")
        self.assertEqual(res_alerts_0.status_code, 200)
        self.assertEqual(res_alerts_0.get_json()["data"]["count"], 0)

        # 3. Ingest 5th disconnect log line (reaches threshold 5)
        log_5th = "Oct 24 13:00:50 srv01 sshd[1005]: Disconnected from 198.51.100.99 port 5005\n"
        res_ingest_5th = self.client.post(
            "/api/ingest",
            data=log_5th,
            content_type="text/plain",
            headers={"X-Filename": "disconnect_5th.log"},
        )
        self.assertEqual(res_ingest_5th.status_code, 201)
        data_5 = res_ingest_5th.get_json()["data"]
        self.assertEqual(data_5["events_stored"], 1)
        self.assertEqual(data_5["new_alerts"], 1)

        # 4. Verify created alert details
        res_alerts_1 = self.client.get("/api/alerts?rule_id=CR-01")
        self.assertEqual(res_alerts_1.status_code, 200)
        alert_list = res_alerts_1.get_json()["data"]["alerts"]
        self.assertEqual(len(alert_list), 1)
        alert = alert_list[0]
        self.assertEqual(alert["rule_id"], "CR-01")
        self.assertEqual(alert["rule_name"], "SSH Disconnect Storm")
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(alert["source_ip"], "198.51.100.99")

        # 5. Verify single alert detail with evidence
        alert_id = alert["id"]
        res_detail = self.client.get(f"/api/alerts/{alert_id}")
        self.assertEqual(res_detail.status_code, 200)
        detail_data = res_detail.get_json()["data"]
        self.assertEqual(len(detail_data["evidence"]), 5)

        # 6. Verify escalation into incident
        res_inc = self.client.post("/api/incidents", json={
            "title": "Incident for CR-01 SSH Disconnect Storm",
            "severity": "medium",
            "alert_ids": [alert_id],
        })
        self.assertEqual(res_inc.status_code, 201)
        inc_id = res_inc.get_json()["data"]["incident_id"]
        self.assertGreater(inc_id, 0)

    def test_20_builtin_rules_dr01_through_dr05_unaffected(self):
        """Ensure standard DR-01 SSH brute force detection functions identically."""
        log = "\n".join([
            f"Oct 24 13:00:{i * 10:02d} web01 sshd[200{i}]: Failed password for deploy from 203.0.113.55 port 400{i} ssh2"
            for i in range(5)
        ]) + "\n"

        res = self.client.post(
            "/api/ingest",
            data=log,
            content_type="text/plain",
            headers={"X-Filename": "brute_force.log"},
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.get_json()["data"]["new_alerts"], 1)

        res_alerts = self.client.get("/api/alerts?rule_id=DR-01")
        self.assertEqual(res_alerts.status_code, 200)
        alerts = res_alerts.get_json()["data"]["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_name"], "SSH brute force")

    def test_api_reg_01_empty_conditions_rejected_and_not_persisted(self):
        # Empty condition dictionary
        resp1 = self.client.post("/api/rules", json={
            "rule_id": "CR-EMPTY1",
            "name": "Empty Conditions Rule",
            "conditions": {},
        })
        self.assertEqual(resp1.status_code, 400)
        self.assertIn("non-empty conditions", resp1.get_json()["error"])
        rows = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-EMPTY1'")
        self.assertEqual(rows[0][0], 0)

        # Empty match dict
        resp2 = self.client.post("/api/rules", json={
            "rule_id": "CR-EMPTY2",
            "name": "Empty Match Rule",
            "conditions": {"match": {}},
        })
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("specify at least one match field", resp2.get_json()["error"])
        rows2 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-EMPTY2'")
        self.assertEqual(rows2[0][0], 0)

    def test_api_reg_02_legacy_rule_unknown_key_rejected_and_unchanged(self):
        orig_row = self._query_db("SELECT conditions FROM detection_rules WHERE rule_id = 'DR-04'")
        orig_cond = orig_row[0][0]

        resp = self.client.patch("/api/rules/DR-04", json={
            "conditions": {"failure_threshold": 5, "unknown_injected_key": "malicious"}
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unknown keys in legacy conditions", resp.get_json()["error"])

        curr_row = self._query_db("SELECT conditions FROM detection_rules WHERE rule_id = 'DR-04'")
        self.assertEqual(curr_row[0][0], orig_cond)

    def test_api_reg_03_invalid_operand_type_rejected_and_not_persisted(self):
        # Port with string target
        resp1 = self.client.post("/api/rules", json={
            "rule_id": "CR-BAD-PORT",
            "name": "String Port",
            "conditions": {"match": {"port": "22"}, "match_operators": {"port": "eq"}},
        })
        self.assertEqual(resp1.status_code, 400)
        rows1 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-BAD-PORT'")
        self.assertEqual(rows1[0][0], 0)

        # Username with integer target
        resp2 = self.client.post("/api/rules", json={
            "rule_id": "CR-BAD-USER",
            "name": "Int Username",
            "conditions": {"match": {"username": 123}, "match_operators": {"username": "eq"}},
        })
        self.assertEqual(resp2.status_code, 400)
        rows2 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-BAD-USER'")
        self.assertEqual(rows2[0][0], 0)

    def test_api_reg_04_string_operator_invalid_target_rejected_and_not_persisted(self):
        # contains on numeric port
        resp1 = self.client.post("/api/rules", json={
            "rule_id": "CR-CONTAINS-PORT",
            "name": "Contains Port",
            "conditions": {"match": {"port": 22}, "match_operators": {"port": "contains"}},
        })
        self.assertEqual(resp1.status_code, 400)
        self.assertIn("not supported on numeric field 'port'", resp1.get_json()["error"])
        rows1 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-CONTAINS-PORT'")
        self.assertEqual(rows1[0][0], 0)

        # startswith on username with integer target
        resp2 = self.client.post("/api/rules", json={
            "rule_id": "CR-STARTSWITH-INT",
            "name": "Startswith Int",
            "conditions": {"match": {"username": 42}, "match_operators": {"username": "startswith"}},
        })
        self.assertEqual(resp2.status_code, 400)
        rows2 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-STARTSWITH-INT'")
        self.assertEqual(rows2[0][0], 0)

    def test_api_reg_05_in_operator_invalid_values_rejected_and_not_persisted(self):
        # in with None target
        resp1 = self.client.post("/api/rules", json={
            "rule_id": "CR-IN-NONE",
            "name": "In None",
            "conditions": {"match": {"username": None}, "match_operators": {"username": "in"}},
        })
        self.assertEqual(resp1.status_code, 400)
        rows1 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-IN-NONE'")
        self.assertEqual(rows1[0][0], 0)

        # not_in with scalar string target
        resp2 = self.client.post("/api/rules", json={
            "rule_id": "CR-NOTIN-SCALAR",
            "name": "NotIn Scalar",
            "conditions": {"match": {"username": "admin"}, "match_operators": {"username": "not_in"}},
        })
        self.assertEqual(resp2.status_code, 400)
        rows2 = self._query_db("SELECT COUNT(*) FROM detection_rules WHERE rule_id = 'CR-NOTIN-SCALAR'")
        self.assertEqual(rows2[0][0], 0)

    def test_api_reg_06_dr04_dr05_updates_persistence_and_runtime_detection(self):
        # 1. Update DR-04
        resp_p4 = self.client.patch("/api/rules/DR-04", json={
            "threshold": 4,
            "conditions": {"failure_threshold": 4},
        })
        self.assertEqual(resp_p4.status_code, 200)
        row_p4 = self._query_db("SELECT threshold, conditions FROM detection_rules WHERE rule_id = 'DR-04'")[0]
        self.assertEqual(row_p4[0], 4)
        self.assertIn('"failure_threshold": 4', row_p4[1])

        # 2. Update DR-05
        resp_p5 = self.client.patch("/api/rules/DR-05", json={
            "severity": "critical",
            "conditions": {"usernames": ["root", "admin"], "accepted_severity": "critical"},
        })
        self.assertEqual(resp_p5.status_code, 200)
        row_p5 = self._query_db("SELECT severity, conditions FROM detection_rules WHERE rule_id = 'DR-05'")[0]
        self.assertEqual(row_p5[0], "critical")

        # 3. Runtime detection for DR-05 (direct root login attempt)
        root_log = "Oct 24 13:00:10 srv01 sshd[1234]: Accepted password for root from 192.168.1.50 port 54321 ssh2\n"
        resp_ing = self.client.post(
            "/api/ingest",
            data=root_log,
            content_type="text/plain",
            headers={"X-Filename": "root_login.log"},
        )
        self.assertEqual(resp_ing.status_code, 201)
        self.assertEqual(resp_ing.get_json()["data"]["new_alerts"], 1)

        alert_rows = self._query_db("SELECT rule_id, severity, status FROM alerts WHERE rule_id = 'DR-05'")
        self.assertGreaterEqual(len(alert_rows), 1)
        self.assertEqual(alert_rows[0][1], "critical")

    def test_api_reg_07_independent_grouping_persists_distinct_alerts(self):
        resp_create = self.client.post("/api/rules", json={
            "rule_id": "CR-IP-HOST",
            "name": "Distinct Host-IP Pairs",
            "enabled": True,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip,host",
                "match": {"event_type": "disconnect"},
            },
        })
        self.assertEqual(resp_create.status_code, 201)

        log = (
            "Oct 24 13:00:10 hostA sshd[1001]: Disconnected from 198.51.100.99 port 5001\n"
            "Oct 24 13:00:20 hostA sshd[1002]: Disconnected from 198.51.100.99 port 5002\n"
            "Oct 24 13:00:30 hostB sshd[1003]: Disconnected from 198.51.100.99 port 5003\n"
            "Oct 24 13:00:40 hostB sshd[1004]: Disconnected from 198.51.100.99 port 5004\n"
        )
        resp_ing = self.client.post(
            "/api/ingest",
            data=log,
            content_type="text/plain",
            headers={"X-Filename": "pairs.log"},
        )
        self.assertEqual(resp_ing.status_code, 201)
        self.assertEqual(resp_ing.get_json()["data"]["new_alerts"], 2)

        rows = self._query_db(
            "SELECT id, source_ip, target_host FROM alerts WHERE rule_id = 'CR-IP-HOST' ORDER BY id ASC"
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], "198.51.100.99")
        self.assertEqual(rows[0][2], "hostA")
        self.assertEqual(rows[1][1], "198.51.100.99")
        self.assertEqual(rows[1][2], "hostB")

    def test_api_reg_08_missing_grouping_values_never_generate_alerts(self):
        resp_create = self.client.post("/api/rules", json={
            "rule_id": "CR-USER-GRP",
            "name": "Missing User Grouping Rule",
            "enabled": True,
            "threshold": 2,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "username",
                "match": {"event_type": "disconnect"},
            },
        })
        self.assertEqual(resp_create.status_code, 201)

        # Disconnect lines do not have username
        log = (
            "Oct 24 13:00:10 srv01 sshd[1001]: Disconnected from 198.51.100.99 port 5001\n"
            "Oct 24 13:00:20 srv01 sshd[1002]: Disconnected from 198.51.100.99 port 5002\n"
            "Oct 24 13:00:30 srv01 sshd[1003]: Disconnected from 198.51.100.99 port 5003\n"
        )
        resp_ing = self.client.post(
            "/api/ingest",
            data=log,
            content_type="text/plain",
            headers={"X-Filename": "no_user.log"},
        )
        self.assertEqual(resp_ing.status_code, 201)
        self.assertEqual(resp_ing.get_json()["data"]["new_alerts"], 0)

        rows = self._query_db("SELECT COUNT(*) FROM alerts WHERE rule_id = 'CR-USER-GRP'")
        self.assertEqual(rows[0][0], 0)

    def test_api_reg_09_live_rule_updates_and_toggles(self):
        # 1. Create rule with threshold 4
        resp_create = self.client.post("/api/rules", json={
            "rule_id": "CR-LIVE-API",
            "name": "Live Rule Updates and Toggles",
            "enabled": True,
            "threshold": 4,
            "window_minutes": 5,
            "conditions": {
                "type": "threshold",
                "group_by": "source_ip",
                "match": {"event_type": "disconnect"},
            },
        })
        self.assertEqual(resp_create.status_code, 201)

        # 2. Ingest 2 disconnect events -> 0 new alerts
        log_2 = (
            "Oct 24 13:00:10 srv01 sshd[1001]: Disconnected from 192.0.2.11 port 5001\n"
            "Oct 24 13:00:20 srv01 sshd[1002]: Disconnected from 192.0.2.11 port 5002\n"
        )
        resp1 = self.client.post("/api/ingest", data=log_2, content_type="text/plain", headers={"X-Filename": "live1.log"})
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp1.get_json()["data"]["new_alerts"], 0)

        # 3. Live update threshold to 2
        resp_patch = self.client.patch("/api/rules/CR-LIVE-API", json={"threshold": 2})
        self.assertEqual(resp_patch.status_code, 200)
        rows_thresh = self._query_db("SELECT threshold FROM detection_rules WHERE rule_id = 'CR-LIVE-API'")
        self.assertEqual(rows_thresh[0][0], 2)

        # 4. Ingest 2 disconnect events from new IP -> triggers alert immediately
        log_new_ip = (
            "Oct 24 13:00:30 srv01 sshd[1003]: Disconnected from 192.0.2.22 port 5003\n"
            "Oct 24 13:00:40 srv01 sshd[1004]: Disconnected from 192.0.2.22 port 5004\n"
        )
        resp2 = self.client.post("/api/ingest", data=log_new_ip, content_type="text/plain", headers={"X-Filename": "live2.log"})
        self.assertEqual(resp2.status_code, 201)
        self.assertEqual(resp2.get_json()["data"]["new_alerts"], 1)

        # 5. Live toggle rule disabled
        resp_toggle_off = self.client.patch("/api/rules/CR-LIVE-API/toggle", json={"enabled": False})
        self.assertEqual(resp_toggle_off.status_code, 200)
        rows_en0 = self._query_db("SELECT enabled FROM detection_rules WHERE rule_id = 'CR-LIVE-API'")
        self.assertEqual(rows_en0[0][0], 0)

        # 6. Ingest 2 disconnect events while disabled -> 0 alerts
        log_off_ip = (
            "Oct 24 13:00:50 srv01 sshd[1005]: Disconnected from 192.0.2.33 port 5005\n"
            "Oct 24 13:01:00 srv01 sshd[1006]: Disconnected from 192.0.2.33 port 5006\n"
        )
        resp3 = self.client.post("/api/ingest", data=log_off_ip, content_type="text/plain", headers={"X-Filename": "live3.log"})
        self.assertEqual(resp3.status_code, 201)
        self.assertEqual(resp3.get_json()["data"]["new_alerts"], 0)

        # 7. Live toggle rule enabled
        resp_toggle_on = self.client.patch("/api/rules/CR-LIVE-API/toggle", json={"enabled": True})
        self.assertEqual(resp_toggle_on.status_code, 200)
        rows_en1 = self._query_db("SELECT enabled FROM detection_rules WHERE rule_id = 'CR-LIVE-API'")
        self.assertEqual(rows_en1[0][0], 1)

        # 8. Ingest 2 disconnect events while enabled -> triggers alert immediately
        log_on_ip = (
            "Oct 24 13:01:10 srv01 sshd[1007]: Disconnected from 192.0.2.44 port 5007\n"
            "Oct 24 13:01:20 srv01 sshd[1008]: Disconnected from 192.0.2.44 port 5008\n"
        )
        resp4 = self.client.post("/api/ingest", data=log_on_ip, content_type="text/plain", headers={"X-Filename": "live4.log"})
        self.assertEqual(resp4.status_code, 201)
        self.assertEqual(resp4.get_json()["data"]["new_alerts"], 1)


if __name__ == "__main__":
    unittest.main()
