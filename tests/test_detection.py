"""Tests for Module C: detection engine, rules, correlation, configuration.

Scenarios are written as realistic sshd log lines, parsed with the real parser,
then fed to the engine, so the parser and the detection engine are tested together.
"""

import itertools
import json
import random
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from backend.detection import (
    DEFAULT_CONFIG, ConfigError, DetectionConfig, DetectionEngine,
)
from backend.parser import parse_file, parse_text

YEAR = 2026
BASE = datetime(2026, 10, 24, 13, 0, 0)
ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"
CONFIG_FILE = ROOT / "config" / "detection_config.json"

_ports = itertools.count(40000)


# ---------------------------------------------------------------- helpers

def lines(sec, kind, user="deploy", ip="203.0.113.9"):
    """Build the log line(s) sshd would write. `sec` is seconds after BASE."""
    stamp = (BASE + timedelta(seconds=sec)).strftime("%b %d %H:%M:%S")
    port = next(_ports)
    head = f"{stamp} web01 sshd[{port}]: "
    if kind == "fail":
        return [head + f"Failed password for {user} from {ip} port {port} ssh2"]
    if kind == "invalid":   # sshd logs two lines for one invalid-user attempt
        return [head + f"Invalid user {user} from {ip} port {port}",
                head + f"Failed password for invalid user {user} from {ip} port {port} ssh2"]
    if kind == "ok":
        return [head + f"Accepted password for {user} from {ip} port {port} ssh2"]
    raise ValueError(kind)


def make_events(*specs):
    """specs are (sec, kind, user, ip) tuples; returns parsed Event objects."""
    text = []
    for spec in specs:
        text += lines(*spec)
    result = parse_text("\n".join(text), YEAR)
    assert result.malformed_count == 0
    return result.events


def run(*specs, config=None):
    engine = DetectionEngine(config)
    engine.process(make_events(*specs))
    return engine


def rule_ids(engine):
    return sorted(a.rule_id for a in engine.alerts)


def alert_for(engine, rule_id):
    found = [a for a in engine.alerts if a.rule_id == rule_id]
    assert len(found) == 1, f"expected one {rule_id} alert, got {len(found)}"
    return found[0]


# ------------------------------------------------- acceptance tests (RSD slide 14)

class AcceptanceTests(unittest.TestCase):
    def test_ac01_clean_baseline_raises_zero_alerts(self):
        parsed = parse_file(str(SAMPLES / "baseline.log"), YEAR)
        engine = DetectionEngine()
        engine.process(parsed.events)
        self.assertEqual(engine.alerts, [])

    def test_ac02_ten_failures_in_two_minutes_gives_one_alert_with_ten_events(self):
        engine = run(*[(i * 12, "fail", "deploy", "203.0.113.50") for i in range(10)])
        self.assertEqual(rule_ids(engine), ["DR-01"])
        alert = engine.alerts[0]
        self.assertEqual(len(alert.evidence_ids), 10)
        self.assertEqual(alert.severity, "medium")

    def test_ac03_failures_then_accepted_login_raises_critical(self):
        specs = [(i * 20, "fail", "alice", "198.51.100.5") for i in range(6)]
        specs.append((200, "ok", "alice", "198.51.100.5"))
        alert = alert_for(run(*specs), "DR-04")
        self.assertEqual(alert.severity, "critical")

    def test_ac05_uploading_same_events_twice_adds_no_duplicates(self):
        events = make_events(*[(i * 10, "fail", "deploy") for i in range(8)])
        engine = DetectionEngine()
        first = engine.process(events)
        second = engine.process(events)
        self.assertEqual(len(first.new_alerts), 1)
        self.assertEqual(second.new_alerts, [])
        self.assertEqual(second.updated_alerts, [])
        self.assertEqual(second.duplicate_events, 8)
        self.assertEqual(len(engine.alerts), 1)
        self.assertEqual(len(engine.alerts[0].evidence_ids), 8)


# ----------------------------------------------------------------- DR-01

class BruteForceTests(unittest.TestCase):
    def test_four_failures_do_not_fire(self):
        self.assertEqual(run(*[(i * 10, "fail") for i in range(4)]).alerts, [])

    def test_five_failures_fire(self):
        engine = run(*[(i * 10, "fail") for i in range(5)])
        self.assertEqual(rule_ids(engine), ["DR-01"])

    def test_window_boundary_is_inclusive_at_five_minutes(self):
        fires = run(*[(s, "fail") for s in (0, 60, 120, 180, 300)])
        self.assertEqual(rule_ids(fires), ["DR-01"])

    def test_failures_spread_over_more_than_window_do_not_fire(self):
        quiet = run(*[(s, "fail") for s in (0, 70, 140, 210, 301)])
        self.assertEqual(quiet.alerts, [])

    def test_failures_from_different_ips_are_not_combined(self):
        specs = [(i * 10, "fail", "deploy", f"203.0.113.{i}") for i in range(1, 8)]
        self.assertEqual(run(*specs).alerts, [])

    def test_invalid_user_double_logging_is_counted_once(self):
        # 3 invalid-user attempts = 6 log lines, but only 3 failed attempts.
        engine = run((0, "invalid", "a"), (10, "invalid", "b"), (20, "invalid", "c"))
        self.assertNotIn("DR-01", rule_ids(engine))

    def test_evidence_is_exactly_the_triggering_events(self):
        specs = [(i * 10, "fail", "deploy", "203.0.113.9") for i in range(5)]
        specs += [(i * 10, "fail", "deploy", "203.0.113.200") for i in range(3)]  # other IP
        engine = run(*specs)
        alert = alert_for(engine, "DR-01")
        self.assertEqual(alert.source_ip, "203.0.113.9")
        self.assertEqual(len(alert.evidence_ids), 5)


# ----------------------------------------------------------------- DR-02

class UsernameEnumerationTests(unittest.TestCase):
    def test_two_invalid_usernames_do_not_fire(self):
        engine = run((0, "invalid", "admin"), (30, "invalid", "test"))
        self.assertEqual(engine.alerts, [])

    def test_three_distinct_invalid_usernames_fire(self):
        engine = run((0, "invalid", "admin"), (30, "invalid", "test"), (60, "invalid", "oracle"))
        self.assertEqual(rule_ids(engine), ["DR-02"])
        self.assertEqual(engine.alerts[0].severity, "medium")

    def test_same_invalid_username_repeated_does_not_count_as_enumeration(self):
        engine = run(*[(i * 10, "invalid", "admin") for i in range(3)])
        self.assertNotIn("DR-02", rule_ids(engine))

    def test_usernames_outside_window_do_not_fire(self):
        engine = run((0, "invalid", "a"), (200, "invalid", "b"), (400, "invalid", "c"))
        self.assertEqual(engine.alerts, [])


# ----------------------------------------------------------------- DR-03

class PasswordSprayingTests(unittest.TestCase):
    USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]

    def test_slow_spray_across_six_users_fires_high(self):
        engine = run(*[(i * 90, "fail", u) for i, u in enumerate(self.USERS)])
        self.assertEqual(rule_ids(engine), ["DR-03"])   # too slow for brute force
        self.assertEqual(engine.alerts[0].severity, "high")

    def test_four_users_do_not_fire(self):
        engine = run(*[(i * 90, "fail", u) for i, u in enumerate(self.USERS[:4])])
        self.assertEqual(engine.alerts, [])

    def test_many_failures_against_one_user_is_brute_force_not_spraying(self):
        engine = run(*[(i * 10, "fail", "alice") for i in range(8)])
        self.assertEqual(rule_ids(engine), ["DR-01"])

    def test_users_spread_wider_than_ten_minutes_do_not_fire(self):
        engine = run(*[(i * 200, "fail", u) for i, u in enumerate(self.USERS)])
        self.assertNotIn("DR-03", rule_ids(engine))


# ----------------------------------------------------------------- DR-04

class SuccessAfterFailuresTests(unittest.TestCase):
    def test_evidence_contains_failures_and_the_accepted_login(self):
        specs = [(i * 20, "fail", "alice") for i in range(5)] + [(150, "ok", "alice")]
        alert = alert_for(run(*specs), "DR-04")
        self.assertEqual(len(alert.evidence_ids), 6)
        self.assertEqual(alert.severity, "critical")
        self.assertIn("Accepted login", alert.summary)

    def test_four_failures_then_success_does_not_fire(self):
        specs = [(i * 20, "fail", "alice") for i in range(4)] + [(150, "ok", "alice")]
        self.assertNotIn("DR-04", rule_ids(run(*specs)))

    def test_failures_older_than_ten_minutes_do_not_count(self):
        specs = [(i * 5, "fail", "alice") for i in range(5)] + [(11 * 60, "ok", "alice")]
        engine = run(*specs)
        self.assertNotIn("DR-04", rule_ids(engine))
        self.assertIn("DR-01", rule_ids(engine))

    def test_success_from_a_different_ip_does_not_fire(self):
        specs = [(i * 20, "fail", "alice", "198.51.100.5") for i in range(6)]
        specs.append((150, "ok", "alice", "198.51.100.6"))
        self.assertNotIn("DR-04", rule_ids(run(*specs)))

    def test_normal_user_with_one_typo_is_not_flagged(self):
        engine = run((0, "fail", "alice", "10.0.0.5"), (6, "ok", "alice", "10.0.0.5"))
        self.assertEqual(engine.alerts, [])

    def test_failures_and_success_in_separate_uploads_still_correlate(self):
        engine = DetectionEngine()
        engine.process(make_events(*[(i * 20, "fail", "alice") for i in range(5)]))
        result = engine.process(make_events((150, "ok", "alice")))
        self.assertEqual([a.rule_id for a in result.new_alerts], ["DR-04"])


# ----------------------------------------------------------------- DR-05

class RootLoginTests(unittest.TestCase):
    def test_single_failed_root_login_is_medium(self):
        alert = alert_for(run((0, "fail", "root")), "DR-05")
        self.assertEqual(alert.severity, "medium")

    def test_accepted_root_login_escalates_to_high(self):
        engine = run((0, "fail", "root"), (30, "ok", "root"))
        alert = alert_for(engine, "DR-05")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(len(alert.evidence_ids), 2)

    def test_non_root_logins_do_not_fire(self):
        self.assertEqual(run((0, "fail", "alice"), (10, "ok", "alice")).alerts, [])

    def test_root_attempts_hours_apart_are_separate_alerts(self):
        engine = run((0, "fail", "root"), (3 * 3600, "fail", "root"))
        self.assertEqual(rule_ids(engine), ["DR-05", "DR-05"])

    def test_privileged_usernames_are_configurable(self):
        config = DetectionConfig.from_dict({"rules": {"DR-05": {"usernames": ["root", "admin"]}}})
        self.assertEqual(rule_ids(run((0, "fail", "admin"), config=config)), ["DR-05"])


# --------------------------------------------- correlation and deduplication (FR-11)

class CorrelationTests(unittest.TestCase):
    def test_ongoing_attack_across_uploads_updates_one_alert(self):
        engine = DetectionEngine()
        first = engine.process(make_events(*[(i * 10, "fail") for i in range(5)]))
        alert = first.new_alerts[0]
        second = engine.process(make_events(*[(100 + i * 10, "fail") for i in range(5)]))
        self.assertEqual(second.new_alerts, [])
        self.assertEqual(second.updated_alerts, [alert])
        self.assertEqual(len(engine.alerts), 1)
        self.assertEqual(len(alert.evidence_ids), 10)
        self.assertEqual(alert.id, 1)

    def test_attacks_hours_apart_are_separate_alerts(self):
        specs = [(i * 10, "fail") for i in range(5)]
        specs += [(4 * 3600 + i * 10, "fail") for i in range(5)]
        engine = run(*specs)
        self.assertEqual(rule_ids(engine), ["DR-01", "DR-01"])
        self.assertEqual([a.id for a in engine.alerts], [1, 2])

    def test_different_ips_get_separate_alerts(self):
        specs = [(i * 10, "fail", "deploy", "203.0.113.1") for i in range(5)]
        specs += [(i * 10, "fail", "deploy", "203.0.113.2") for i in range(5)]
        engine = run(*specs)
        self.assertEqual(sorted(a.source_ip for a in engine.alerts),
                         ["203.0.113.1", "203.0.113.2"])

    def test_one_attack_can_raise_several_rules(self):
        specs = [(i * 20, "fail", "alice") for i in range(6)] + [(150, "ok", "alice")]
        self.assertEqual(rule_ids(run(*specs)), ["DR-01", "DR-04"])

    def test_event_order_does_not_matter(self):
        specs = [(i * 10, "fail") for i in range(10)]
        shuffled = specs[:]
        random.Random(7).shuffle(shuffled)
        a, b = run(*specs), run(*shuffled)
        self.assertEqual(rule_ids(a), rule_ids(b))
        self.assertEqual(len(a.alerts[0].evidence_ids), len(b.alerts[0].evidence_ids))

    def test_every_alert_links_only_to_real_events(self):
        events = make_events(*[(i * 10, "fail") for i in range(6)])
        known = {e.line_hash for e in events}
        engine = DetectionEngine()
        engine.process(events)
        for alert in engine.alerts:
            self.assertTrue(set(alert.evidence_ids) <= known)

    def test_database_ids_are_used_as_evidence_when_events_have_them(self):
        events = make_events(*[(i * 10, "fail") for i in range(5)])
        for number, event in enumerate(events, start=100):
            event.id = number
        engine = DetectionEngine()
        engine.process(events)
        self.assertEqual(engine.alerts[0].evidence_ids, [100, 101, 102, 103, 104])


# ------------------------------------------------------------- alert content (FR-09, FR-14)

class AlertContentTests(unittest.TestCase):
    def setUp(self):
        self.alert = run(*[(i * 10, "fail", "deploy", "203.0.113.50") for i in range(6)]).alerts[0]

    def test_alert_stores_rule_severity_ip_time_range_and_summary(self):
        a = self.alert
        self.assertEqual((a.rule_id, a.severity, a.source_ip, a.status),
                         ("DR-01", "medium", "203.0.113.50", "new"))
        self.assertEqual(a.first_seen, BASE)
        self.assertEqual(a.last_seen, BASE + timedelta(seconds=50))
        self.assertIn("6 failed logins", a.summary)

    def test_explanation_states_the_rule_and_threshold(self):
        self.assertIn("5 or more", self.alert.explanation)
        self.assertIn("5 minutes", self.alert.explanation)

    def test_alert_serialises_to_json(self):
        data = json.loads(json.dumps(self.alert.to_dict()))
        self.assertEqual(data["rule_id"], "DR-01")
        self.assertEqual(data["evidence_count"], 6)
        self.assertEqual(len(data["evidence_ids"]), 6)

    def test_hostile_username_stays_plain_text_in_summary(self):
        engine = run((0, "invalid", "<script>alert(1)</script>"),
                     (10, "invalid", "b"), (20, "invalid", "c"))
        # stored as text; the dashboard is responsible for escaping it (RSD slide 13)
        self.assertIn("<script>", alert_for(engine, "DR-02").summary)


# ------------------------------------------------------------- configuration (FR-08)

class ConfigTests(unittest.TestCase):
    def test_lower_threshold_makes_rule_fire_earlier(self):
        config = DetectionConfig.from_dict({"rules": {"DR-01": {"threshold": 3}}})
        self.assertEqual(rule_ids(run(*[(i * 10, "fail") for i in range(3)], config=config)),
                         ["DR-01"])

    def test_wider_window_makes_slow_attack_fire(self):
        slow = [(s, "fail") for s in (0, 120, 240, 360, 480)]
        self.assertEqual(run(*slow).alerts, [])
        config = DetectionConfig.from_dict({"rules": {"DR-01": {"window_minutes": 10}}})
        self.assertEqual(rule_ids(run(*slow, config=config)), ["DR-01"])

    def test_disabled_rule_does_not_fire(self):
        config = DetectionConfig.from_dict({"rules": {"DR-01": {"enabled": False}}})
        self.assertEqual(run(*[(i * 10, "fail") for i in range(8)], config=config).alerts, [])

    def test_severity_is_configurable(self):
        config = DetectionConfig.from_dict({"rules": {"DR-01": {"severity": "high"}}})
        engine = run(*[(i * 10, "fail") for i in range(5)], config=config)
        self.assertEqual(engine.alerts[0].severity, "high")

    def test_shipped_config_file_matches_built_in_defaults(self):
        from_file = DetectionConfig.from_file(str(CONFIG_FILE))
        self.assertEqual(from_file.rules, DetectionConfig.default().rules)
        self.assertEqual(from_file.dedupe_gap, DetectionConfig.default().dedupe_gap)

    def test_invalid_configs_are_rejected(self):
        bad = [
            {"rules": {"DR-01": {"threshold": 0}}},
            {"rules": {"DR-01": {"threshold": -3}}},
            {"rules": {"DR-01": {"threshold": "5"}}},
            {"rules": {"DR-01": {"threshold": True}}},
            {"rules": {"DR-01": {"threshold": 10 ** 9}}},
            {"rules": {"DR-01": {"severity": "extreme"}}},
            {"rules": {"DR-01": {"enabled": "yes"}}},
            {"rules": {"DR-01": {"colour": "red"}}},
            {"rules": {"DR-99": {"threshold": 3}}},
            {"rules": {"DR-05": {"usernames": []}}},
            {"rules": {"DR-05": {"usernames": [""]}}},
            {"dedupe_gap_minutes": 0},
            {"unknown": 1},
            [],
        ]
        for config in bad:
            with self.subTest(config=config):
                with self.assertRaises(ConfigError):
                    DetectionConfig.from_dict(config)

    def test_missing_or_broken_config_file_raises_config_error(self):
        with self.assertRaises(ConfigError):
            DetectionConfig.from_file(str(ROOT / "config" / "does_not_exist.json"))

    def test_defaults_are_not_modified_by_overrides(self):
        DetectionConfig.from_dict({"rules": {"DR-05": {"usernames": ["x"]}}})
        self.assertEqual(DEFAULT_CONFIG["rules"]["DR-05"]["usernames"], ["root"])


# ------------------------------------------------- synthetic attack files end to end

class SampleLogScenarioTests(unittest.TestCase):
    def detect(self, name):
        parsed = parse_file(str(SAMPLES / name), YEAR)
        self.assertEqual(parsed.malformed_count, 0)
        engine = DetectionEngine()
        engine.process(parsed.events)
        return engine

    def test_brute_force_file(self):
        engine = self.detect("attack_brute_force_10.log")
        self.assertEqual(rule_ids(engine), ["DR-01"])
        self.assertEqual(len(engine.alerts[0].evidence_ids), 10)

    def test_username_enumeration_file(self):
        engine = self.detect("attack_username_enumeration.log")
        self.assertEqual(rule_ids(engine), ["DR-02"])

    def test_password_spraying_file(self):
        engine = self.detect("attack_password_spraying.log")
        self.assertEqual(rule_ids(engine), ["DR-03"])

    def test_success_after_failures_file(self):
        engine = self.detect("attack_success_after_failures.log")
        self.assertEqual(rule_ids(engine), ["DR-01", "DR-04"])
        self.assertEqual(alert_for(engine, "DR-04").severity, "critical")

    def test_root_login_file(self):
        engine = self.detect("attack_root_login.log")
        self.assertEqual(rule_ids(engine), ["DR-05"])
        self.assertEqual(engine.alerts[0].severity, "high")

    def test_uploading_each_attack_file_twice_creates_no_extra_alerts(self):
        for name in sorted(p.name for p in SAMPLES.glob("attack_*.log")):
            with self.subTest(file=name):
                parsed = parse_file(str(SAMPLES / name), YEAR)
                engine = DetectionEngine()
                engine.process(parsed.events)
                count = len(engine.alerts)
                again = engine.process(parse_file(str(SAMPLES / name), YEAR).events)
                self.assertEqual(len(engine.alerts), count)
                self.assertEqual(again.new_alerts + again.updated_alerts, [])


# ------------------------------------------------------------------ performance

class PerformanceTests(unittest.TestCase):
    def test_ten_thousand_events_process_quickly(self):
        import time
        text = []
        for i in range(10_000):
            ip = f"198.51.100.{i % 200}"
            stamp = (BASE + timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            text.append(f"{stamp} web01 sshd[{i}]: Failed password for user{i % 7} "
                        f"from {ip} port {20000 + i} ssh2")
        events = parse_text("\n".join(text), YEAR).events
        start = time.time()
        DetectionEngine().process(events)
        self.assertLess(time.time() - start, 30)    # RSD target: 10,000 lines < 30 s


if __name__ == "__main__":
    unittest.main()
