"""ThreatLens - Detection engine and alert generation (Module C).

Takes the structured events produced by backend.parser and raises
explainable alerts for the five RSD detection rules:

    DR-01  SSH brute force         5+ failed logins from one IP in 5 min      Medium
    DR-02  Username enumeration    3+ distinct invalid usernames, 5 min       Medium
    DR-03  Password spraying       failures against 5+ distinct users, 10 min High
    DR-04  Success after failures  accepted login within 10 min of 5+ fails   Critical
    DR-05  Root login attempt      any root attempt; accepted root escalates  Medium/High

How it works
------------
1. Events are grouped by source IP and sorted by time.
2. Each rule finds "episodes": runs of events that satisfy its threshold inside
   its time window (FR-07, FR-08).
3. Every episode becomes a candidate alert that keeps the exact evidence events
   that triggered it (FR-10).
4. Candidates are correlated with existing alerts so one ongoing attack updates
   one alert instead of creating many (FR-11).

Design notes
------------
* A "failed login attempt" is a failure line that names an auth method
  ("Failed password for ..."). The extra "Invalid user X from ..." line that
  sshd writes for the same attempt has no method, so it is not counted twice.
* Thresholds and windows come from a validated config (FR-08).
* The engine is pure Python and database-agnostic. Module B stores what it returns.
"""

from __future__ import annotations

import json
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Optional

from backend.parser import ACCEPTED_LOGIN, INVALID_USER

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
STATUS_NEW = "new"   # later statuses (investigating, resolved, false positive) are set by Module B

RULE_NAMES = {
    "DR-01": "SSH brute force",
    "DR-02": "Username enumeration",
    "DR-03": "Password spraying",
    "DR-04": "Success after failures",
    "DR-05": "Root login attempt",
}

DEFAULT_CONFIG = {
    "dedupe_gap_minutes": 30,
    "rules": {
        "DR-01": {"enabled": True, "threshold": 5, "window_minutes": 5, "severity": "medium"},
        "DR-02": {"enabled": True, "threshold": 3, "window_minutes": 5, "severity": "medium"},
        "DR-03": {"enabled": True, "threshold": 5, "window_minutes": 10, "severity": "high"},
        "DR-04": {"enabled": True, "failure_threshold": 5, "window_minutes": 10,
                  "severity": "critical"},
        "DR-05": {"enabled": True, "usernames": ["root"], "severity": "medium",
                  "accepted_severity": "high"},
    },
}

_RULE_SCHEMA = {
    "DR-01": {"enabled": "bool", "threshold": "posint", "window_minutes": "posint",
              "severity": "severity"},
    "DR-02": {"enabled": "bool", "threshold": "posint", "window_minutes": "posint",
              "severity": "severity"},
    "DR-03": {"enabled": "bool", "threshold": "posint", "window_minutes": "posint",
              "severity": "severity"},
    "DR-04": {"enabled": "bool", "failure_threshold": "posint", "window_minutes": "posint",
              "severity": "severity"},
    "DR-05": {"enabled": "bool", "usernames": "names", "severity": "severity",
              "accepted_severity": "severity"},
}

MAX_CONFIG_NUMBER = 100_000


# --------------------------------------------------------------------------
# Configuration (FR-08)
# --------------------------------------------------------------------------

class ConfigError(ValueError):
    """Raised when a detection configuration is invalid."""


def _check_value(where: str, kind: str, value):
    if kind == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false")
    elif kind == "posint":
        if (isinstance(value, bool) or not isinstance(value, int)
                or not 0 < value <= MAX_CONFIG_NUMBER):
            raise ConfigError(f"{where} must be a whole number from 1 to {MAX_CONFIG_NUMBER}")
    elif kind == "severity":
        if value not in SEVERITY_ORDER:
            raise ConfigError(f"{where} must be one of {sorted(SEVERITY_ORDER)}")
    elif kind == "names":
        if (not isinstance(value, list) or not value or len(value) > 50
                or not all(isinstance(v, str) and 0 < len(v) <= 128 for v in value)):
            raise ConfigError(f"{where} must be a non-empty list of usernames")


@dataclass(frozen=True)
class DetectionConfig:
    dedupe_gap: timedelta
    rules: dict

    @classmethod
    def default(cls) -> "DetectionConfig":
        return cls.from_dict({})

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionConfig":
        if not isinstance(data, dict):
            raise ConfigError("configuration must be an object")
        unknown = set(data) - {"dedupe_gap_minutes", "rules"}
        if unknown:
            raise ConfigError(f"unknown configuration keys: {sorted(unknown)}")

        gap = data.get("dedupe_gap_minutes", DEFAULT_CONFIG["dedupe_gap_minutes"])
        _check_value("dedupe_gap_minutes", "posint", gap)

        overrides = data.get("rules", {})
        if not isinstance(overrides, dict):
            raise ConfigError("rules must be an object")

        rules = {}
        for rule_id, defaults in DEFAULT_CONFIG["rules"].items():
            merged = {k: (list(v) if isinstance(v, list) else v) for k, v in defaults.items()}
            override = overrides.get(rule_id, {})
            if not isinstance(override, dict):
                raise ConfigError(f"{rule_id} settings must be an object")
            for key, value in override.items():
                if key not in _RULE_SCHEMA[rule_id]:
                    raise ConfigError(f"{rule_id}: unknown setting '{key}'")
                _check_value(f"{rule_id}.{key}", _RULE_SCHEMA[rule_id][key], value)
                merged[key] = value
            rules[rule_id] = merged

        unknown_rules = set(overrides) - set(rules)
        if unknown_rules:
            raise ConfigError(f"unknown rules: {sorted(unknown_rules)}")
        return cls(dedupe_gap=timedelta(minutes=gap), rules=rules)

    @classmethod
    def from_file(cls, path: str) -> "DetectionConfig":
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read configuration: {exc}")
        return cls.from_dict(data)


# --------------------------------------------------------------------------
# Event helpers
# --------------------------------------------------------------------------

def event_ref(event) -> str:
    """Stable identifier used to link alerts to events (FR-10).

    Uses the database id when the event has one (Module B), otherwise the
    parser's line hash.
    """
    ref = getattr(event, "id", None)
    return ref if ref is not None else event.line_hash


def is_failed_attempt(event) -> bool:
    """A failed login attempt: a failure that names an auth method."""
    return event.outcome == "failure" and event.method is not None


def is_invalid_user_event(event) -> bool:
    return event.event_type == INVALID_USER and bool(event.username)


def is_accepted_login(event) -> bool:
    return event.event_type == ACCEPTED_LOGIN and event.outcome == "success"


def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    source_ip: str
    settings: dict
    events: dict = field(default_factory=dict, repr=False)   # ref -> Event (the evidence)
    id: Optional[int] = None
    status: str = STATUS_NEW
    severity: str = "low"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    summary: str = ""
    explanation: str = ""
    evidence_ids: list = field(default_factory=list)

    def refresh(self) -> None:
        """Recompute times, evidence list, severity and text from the evidence."""
        ordered = sorted(self.events.items(), key=lambda item: (item[1].timestamp, str(item[0])))
        self.evidence_ids = [ref for ref, _ in ordered]
        self.first_seen = ordered[0][1].timestamp
        self.last_seen = ordered[-1][1].timestamp
        self.severity, self.summary, self.explanation = _DESCRIBERS[self.rule_id](self)

    def absorb(self, other: "Alert") -> bool:
        """Merge another candidate for the same attack. Returns True if anything changed."""
        before = (len(self.events), self.severity, self.last_seen)
        for ref, event in other.events.items():
            self.events.setdefault(ref, event)
        self.refresh()
        return before != (len(self.events), self.severity, self.last_seen)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "status": self.status,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "summary": self.summary,
            "explanation": self.explanation,
            "settings": self.settings,
            "evidence_count": len(self.evidence_ids),
            "evidence_ids": list(self.evidence_ids),
        }


def _new_alert(rule_id: str, ip: str, events: Iterable, settings: dict) -> Alert:
    alert = Alert(rule_id=rule_id, rule_name=RULE_NAMES[rule_id], source_ip=ip,
                  settings=dict(settings),
                  events={event_ref(e): e for e in events})
    alert.refresh()
    return alert


# --------------------------------------------------------------------------
# Explanations: severity, summary and rule explanation for each rule (FR-09, FR-14)
# --------------------------------------------------------------------------

def _names(users: List[str], limit: int = 5) -> str:
    shown = ", ".join(users[:limit])
    return shown + (", ..." if len(users) > limit else "")


def _describe_dr01(a: Alert):
    s, n = a.settings, len(a.events)
    summary = (f"{n} failed logins from {a.source_ip} between "
               f"{_fmt(a.first_seen)} and {_fmt(a.last_seen)}")
    explanation = (f"SSH brute force (DR-01): {n} failed logins from {a.source_ip}. "
                   f"Rule fires at {s['threshold']} or more failed logins from one IP "
                   f"within {s['window_minutes']} minutes.")
    return s["severity"], summary, explanation


def _describe_dr02(a: Alert):
    s = a.settings
    users = sorted({e.username for e in a.events.values()})
    summary = (f"{len(users)} distinct invalid usernames tried from {a.source_ip} "
               f"({_names(users)})")
    explanation = (f"Username enumeration (DR-02): {len(users)} distinct invalid usernames "
                   f"from {a.source_ip}. Rule fires at {s['threshold']} or more distinct "
                   f"invalid usernames from one IP within {s['window_minutes']} minutes.")
    return s["severity"], summary, explanation


def _describe_dr03(a: Alert):
    s = a.settings
    users = sorted({e.username for e in a.events.values() if e.username})
    summary = (f"Failed logins against {len(users)} distinct users from {a.source_ip} "
               f"({_names(users)})")
    explanation = (f"Password spraying (DR-03): {len(a.events)} failed logins against "
                   f"{len(users)} distinct users from {a.source_ip}. Rule fires at "
                   f"{s['threshold']} or more distinct users from one IP within "
                   f"{s['window_minutes']} minutes.")
    return s["severity"], summary, explanation


def _describe_dr04(a: Alert):
    s = a.settings
    failures = [e for e in a.events.values() if e.outcome == "failure"]
    accepted = [e for e in a.events.values() if e.outcome == "success"]
    users = sorted({e.username for e in accepted if e.username})
    summary = (f"Accepted login for {_names(users) or 'unknown user'} from {a.source_ip} "
               f"after {len(failures)} failed logins")
    explanation = (f"Success after failures (DR-04): {len(accepted)} accepted login(s) from "
                   f"{a.source_ip} within {s['window_minutes']} minutes of "
                   f"{s['failure_threshold']} or more failed logins from the same IP. "
                   f"This may mean the attacker guessed a valid password.")
    return s["severity"], summary, explanation


def _describe_dr05(a: Alert):
    s = a.settings
    accepted = [e for e in a.events.values() if e.outcome == "success"]
    failed = len(a.events) - len(accepted)
    severity = s["accepted_severity"] if accepted else s["severity"]
    summary = (f"{len(a.events)} root login attempts from {a.source_ip} "
               f"({len(accepted)} accepted, {failed} failed)")
    explanation = (f"Root login attempt (DR-05): login attempts as a privileged account "
                   f"({_names(s['usernames'])}) from {a.source_ip}. Any attempt raises "
                   f"'{s['severity']}'; an accepted login raises '{s['accepted_severity']}'.")
    return severity, summary, explanation


_DESCRIBERS: Dict[str, Callable] = {
    "DR-01": _describe_dr01, "DR-02": _describe_dr02, "DR-03": _describe_dr03,
    "DR-04": _describe_dr04, "DR-05": _describe_dr05,
}


# --------------------------------------------------------------------------
# Time-window logic
# --------------------------------------------------------------------------

def _find_episodes(events: list, window: timedelta, threshold: int,
                   key: Optional[Callable] = None) -> List[list]:
    """Find runs of events that meet a threshold inside a sliding time window.

    `events` must be sorted by time and belong to one source IP.
    With key=None the threshold counts events; otherwise it counts distinct key values.
    Every event inside any triggering window is evidence. Windows that overlap or
    touch are merged into one episode, so a single continuous attack gives one result.
    """
    marked = [False] * len(events)
    counts: Counter = Counter()
    left = 0
    highest_marked = -1

    for right, event in enumerate(events):
        if key:
            counts[key(event)] += 1
        while event.timestamp - events[left].timestamp > window:
            if key:
                old = key(events[left])
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
            left += 1
        size = len(counts) if key else right - left + 1
        if size >= threshold:
            for i in range(max(left, highest_marked + 1), right + 1):
                marked[i] = True
            highest_marked = right

    episodes, current = [], []
    for i, event in enumerate(events):
        if not marked[i]:
            if current:
                episodes.append(current)
                current = []
            continue
        if current and event.timestamp - current[-1].timestamp > window:
            episodes.append(current)
            current = []
        current.append(event)
    if current:
        episodes.append(current)
    return episodes


# --------------------------------------------------------------------------
# The five rules. Each takes one IP's events (sorted) and returns candidate alerts.
# --------------------------------------------------------------------------

def detect_dr01(ip: str, events: list, s: dict, gap: timedelta) -> List[Alert]:
    failures = [e for e in events if is_failed_attempt(e)]
    window = timedelta(minutes=s["window_minutes"])
    return [_new_alert("DR-01", ip, ep, s)
            for ep in _find_episodes(failures, window, s["threshold"])]


def detect_dr02(ip: str, events: list, s: dict, gap: timedelta) -> List[Alert]:
    invalid = [e for e in events if is_invalid_user_event(e)]
    window = timedelta(minutes=s["window_minutes"])
    return [_new_alert("DR-02", ip, ep, s)
            for ep in _find_episodes(invalid, window, s["threshold"],
                                     key=lambda e: e.username)]


def detect_dr03(ip: str, events: list, s: dict, gap: timedelta) -> List[Alert]:
    failures = [e for e in events if is_failed_attempt(e) and e.username]
    window = timedelta(minutes=s["window_minutes"])
    return [_new_alert("DR-03", ip, ep, s)
            for ep in _find_episodes(failures, window, s["threshold"],
                                     key=lambda e: e.username)]


def detect_dr04(ip: str, events: list, s: dict, gap: timedelta) -> List[Alert]:
    failures = [e for e in events if is_failed_attempt(e)]
    times = [e.timestamp for e in failures]
    window = timedelta(minutes=s["window_minutes"])
    alerts = []
    for event in events:
        if not is_accepted_login(event):
            continue
        lo = bisect_left(times, event.timestamp - window)
        hi = bisect_right(times, event.timestamp)
        recent = failures[lo:hi]
        if len(recent) >= s["failure_threshold"]:
            alerts.append(_new_alert("DR-04", ip, recent + [event], s))
    return alerts


def detect_dr05(ip: str, events: list, s: dict, gap: timedelta) -> List[Alert]:
    privileged = set(s["usernames"])
    attempts = [e for e in events
                if e.username in privileged
                and ((e.outcome == "failure" and e.method is not None) or is_accepted_login(e))]
    alerts, current = [], []
    for event in attempts:
        if current and event.timestamp - current[-1].timestamp > gap:
            alerts.append(_new_alert("DR-05", ip, current, s))
            current = []
        current.append(event)
    if current:
        alerts.append(_new_alert("DR-05", ip, current, s))
    return alerts


DETECTORS: Dict[str, Callable] = {
    "DR-01": detect_dr01, "DR-02": detect_dr02, "DR-03": detect_dr03,
    "DR-04": detect_dr04, "DR-05": detect_dr05,
}


# --------------------------------------------------------------------------
# Correlation and deduplication (FR-11)
# --------------------------------------------------------------------------

def _correlate(candidates: List[Alert], existing: List[Alert], gap: timedelta):
    """Fold candidates into existing alerts. Returns (created, updated)."""
    index: Dict[tuple, List[Alert]] = {}
    for alert in existing:
        index.setdefault((alert.rule_id, alert.source_ip), []).append(alert)

    created: List[Alert] = []
    updated: List[Alert] = []
    for cand in sorted(candidates, key=lambda a: (a.first_seen, a.rule_id)):
        bucket = index.setdefault((cand.rule_id, cand.source_ip), [])
        match = next((a for a in bucket
                      if cand.first_seen <= a.last_seen + gap
                      and cand.last_seen >= a.first_seen - gap), None)
        if match is None:
            bucket.append(cand)
            created.append(cand)
        elif match.absorb(cand) and match not in created and match not in updated:
            updated.append(match)
    return created, updated


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

@dataclass
class DetectionResult:
    new_alerts: List[Alert] = field(default_factory=list)
    updated_alerts: List[Alert] = field(default_factory=list)
    events_processed: int = 0
    duplicate_events: int = 0


class DetectionEngine:
    """Runs all rules over events and keeps alerts deduplicated across uploads."""

    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig.default()
        self.alerts: List[Alert] = []
        self._history: Dict[str, dict] = {}     # source_ip -> {ref: event}
        self._next_id = 1

    def process(self, new_events: Iterable) -> DetectionResult:
        """Add newly ingested events and evaluate every rule (FR-07)."""
        result = DetectionResult()
        affected = set()

        for event in new_events:
            ref = event_ref(event)
            bucket = self._history.setdefault(event.source_ip, {})
            if ref in bucket:
                result.duplicate_events += 1     # same line uploaded again
                continue
            bucket[ref] = event
            affected.add(event.source_ip)
            result.events_processed += 1

        candidates: List[Alert] = []
        for ip in sorted(affected):
            events = sorted(self._history[ip].values(), key=lambda e: e.timestamp)
            for rule_id, detector in DETECTORS.items():
                settings = self.config.rules[rule_id]
                if settings["enabled"]:
                    candidates.extend(detector(ip, events, settings, self.config.dedupe_gap))

        created, updated = _correlate(candidates, self.alerts, self.config.dedupe_gap)
        for alert in created:
            alert.id = self._next_id
            self._next_id += 1
            self.alerts.append(alert)

        result.new_alerts = created
        result.updated_alerts = updated
        return result


# --------------------------------------------------------------------------
# Command line demo:  python -m backend.detection sample_logs/attack_brute_force_10.log 2026
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from backend.parser import parse_file

    if len(sys.argv) < 2:
        sys.exit("usage: python -m backend.detection <logfile> [year] [config.json]")
    year = int(sys.argv[2]) if len(sys.argv) > 2 else datetime.now().year
    config = DetectionConfig.from_file(sys.argv[3]) if len(sys.argv) > 3 else None

    parsed = parse_file(sys.argv[1], year)
    engine = DetectionEngine(config)
    outcome = engine.process(parsed.events)
    print(f"events={outcome.events_processed} duplicates={outcome.duplicate_events} "
          f"malformed={parsed.malformed_count} alerts={len(engine.alerts)}")
    for alert in engine.alerts:
        print(f"[{alert.severity.upper():8}] #{alert.id} {alert.rule_id} {alert.rule_name}: "
              f"{alert.summary} ({len(alert.evidence_ids)} evidence events)")
