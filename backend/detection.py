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

import ipaddress
import json
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from backend.parser import ACCEPTED_LOGIN, INVALID_USER, Event


def is_loopback_address(ip: Optional[str]) -> bool:
    """Check if an IP address is a loopback address (e.g. 127.0.0.1, ::1)."""
    if not ip:
        return False
    clean = str(ip).strip().strip("[]")
    if clean.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(clean).is_loopback
    except ValueError:
        return False


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

    def add_custom_rule(self, rule_id: str, settings: dict) -> None:
        """Register or update a custom rule in this configuration."""
        clean_id = (rule_id or "").strip().upper()
        if not clean_id:
            raise ConfigError("Rule ID cannot be empty")
        self.rules[clean_id] = dict(settings)


# --------------------------------------------------------------------------
# Custom Declarative Detection Rules Engine
# --------------------------------------------------------------------------

ALLOWED_RULE_TYPES = {"threshold", "distinct_count"}
ALLOWED_GROUP_BY = {"source_ip", "username", "host", "source_ip,host"}
ALLOWED_MATCH_FIELDS = {
    "event_type", "outcome", "username", "source_ip", "host", "port", "method", "raw_line"
}
STRING_MATCH_FIELDS = {
    "event_type", "outcome", "username", "source_ip", "host", "method", "raw_line"
}
NULLABLE_MATCH_FIELDS = {"username", "source_ip", "host", "port", "method"}
ALLOWED_OPERATORS = {
    "eq", "neq", "in", "not_in", "contains", "startswith", "endswith"
}
STRING_OPERATORS = {"contains", "startswith", "endswith"}
LIST_OPERATORS = {"in", "not_in"}
ALLOWED_DISTINCT_FIELDS = {
    "username", "source_ip", "host", "port", "method", "event_type"
}
LEGACY_KEYS = {"failure_threshold", "usernames", "accepted_severity"}
LEGACY_ALLOWED_KEYS = {"failure_threshold", "usernames", "accepted_severity"}


def _validate_legacy_conditions(cond: dict) -> dict:
    """Validate legacy built-in condition dictionaries (DR-04, DR-05)."""
    unknown = set(cond) - LEGACY_ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Unknown keys in legacy conditions: {sorted(unknown)}")

    if "failure_threshold" in cond:
        _check_value("failure_threshold", "posint", cond["failure_threshold"])
    if "usernames" in cond:
        _check_value("usernames", "names", cond["usernames"])
    if "accepted_severity" in cond:
        _check_value("accepted_severity", "severity", cond["accepted_severity"])

    return dict(cond)


def validate_custom_rule_conditions(conditions: Any, rule_id: Optional[str] = None) -> dict:
    """Validate and normalize declarative conditions for custom detection rules.

    Supports 'threshold' and 'distinct_count' rule types, safe operators on allowlisted
    Event fields, and safe grouping dimensions ('source_ip', 'username', 'host', 'source_ip,host').

    Rejects invalid types, malformed structures, unsupported combinations, and empty/unrestricted
    custom rule conditions with clear ValueError messages.
    Does not use eval/exec or dynamic code execution.
    """
    clean_rule_id = (rule_id or "").strip().upper() if rule_id else None

    # Handle built-in rules that naturally have empty conditions (DR-01, DR-02, DR-03)
    if clean_rule_id in ("DR-01", "DR-02", "DR-03"):
        if conditions is None or conditions == "" or conditions == {} or conditions == "{}":
            return {}

    # Parse JSON if string
    if isinstance(conditions, str):
        raw_str = conditions.strip()
        if not raw_str or raw_str == "{}":
            if clean_rule_id in ("DR-01", "DR-02", "DR-03"):
                return {}
            raise ValueError("Custom detection rules require non-empty conditions with valid match criteria")
        try:
            cond = json.loads(raw_str)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Malformed JSON in conditions: {exc}")
    elif isinstance(conditions, dict):
        cond = dict(conditions)
    else:
        raise ValueError("Conditions must be a JSON object / dictionary")

    if not isinstance(cond, dict):
        raise ValueError("Conditions must be a dictionary object")

    # Reject empty condition dict for custom rules
    if not cond:
        if clean_rule_id in ("DR-01", "DR-02", "DR-03"):
            return {}
        raise ValueError("Custom detection rules require non-empty conditions with valid match criteria")

    # Check for legacy built-in conditions (DR-04, DR-05)
    if clean_rule_id in ("DR-04", "DR-05") or any(k in cond for k in LEGACY_KEYS):
        return _validate_legacy_conditions(cond)

    # Custom declarative rule schema validation
    allowed_top_keys = {
        "type", "group_by", "distinct_field", "match", "match_operators",
        "threshold", "window_minutes", "severity", "name", "description"
    }
    unknown_keys = set(cond) - allowed_top_keys
    if unknown_keys:
        raise ValueError(f"Unknown condition keys: {sorted(unknown_keys)}")

    rule_type = cond.get("type", "threshold")
    if not isinstance(rule_type, str) or rule_type not in ALLOWED_RULE_TYPES:
        raise ValueError(f"Invalid rule type '{rule_type}'. Allowed types: {sorted(ALLOWED_RULE_TYPES)}")

    group_by = cond.get("group_by", "source_ip")
    if not isinstance(group_by, str) or group_by not in ALLOWED_GROUP_BY:
        raise ValueError(f"Invalid group_by '{group_by}'. Allowed values: {sorted(ALLOWED_GROUP_BY)}")

    distinct_field = cond.get("distinct_field")
    if rule_type == "distinct_count":
        if not distinct_field or not isinstance(distinct_field, str) or distinct_field not in ALLOWED_DISTINCT_FIELDS:
            raise ValueError(f"distinct_count rules require 'distinct_field' in {sorted(ALLOWED_DISTINCT_FIELDS)}")
    else:
        if distinct_field is not None:
            if not isinstance(distinct_field, str) or distinct_field not in ALLOWED_DISTINCT_FIELDS:
                raise ValueError(f"Invalid distinct_field '{distinct_field}' for threshold rule")

    match = cond.get("match")
    if match is None or not isinstance(match, dict) or len(match) == 0:
        raise ValueError("Custom detection rules must specify at least one match field in 'match'")

    match_operators = cond.get("match_operators", {})
    if not isinstance(match_operators, dict):
        raise ValueError("'match_operators' must be an object / dictionary")

    for field_name in match_operators:
        if field_name not in match:
            raise ValueError(f"Operator specified for field '{field_name}' which is not present in 'match'")

    clean_operators = {}
    for field_name, match_val in match.items():
        if field_name not in ALLOWED_MATCH_FIELDS:
            raise ValueError(f"Unknown match field '{field_name}'. Allowed fields: {sorted(ALLOWED_MATCH_FIELDS)}")

        if field_name in match_operators:
            op = match_operators[field_name]
        elif isinstance(match_val, list):
            op = "in"
        else:
            op = "eq"

        if not isinstance(op, str) or op not in ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported operator '{op}'. Allowed operators: {sorted(ALLOWED_OPERATORS)}")

        if op in ("in", "not_in"):
            if match_val is None or not isinstance(match_val, list) or len(match_val) == 0:
                val_type = type(match_val).__name__ if match_val is not None else "None"
                raise ValueError(f"Operator '{op}' for field '{field_name}' requires a non-empty list of values (got {val_type})")
            if len(match_val) > 100:
                raise ValueError(f"List for field '{field_name}' exceeds maximum limit of 100 items")

            if field_name == "port":
                if not all(isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535 for p in match_val):
                    raise ValueError(f"'port' with operator '{op}' requires a list of integers between 0 and 65535")
            else:
                max_len = 2048 if field_name == "raw_line" else 256
                if not all(isinstance(v, str) and len(v) <= max_len for v in match_val):
                    raise ValueError(f"Field '{field_name}' with operator '{op}' requires a list of strings <= {max_len} chars")

        elif op in ("contains", "startswith", "endswith"):
            if field_name == "port":
                raise ValueError(f"Operator '{op}' is not supported on numeric field 'port'")
            if match_val is None or not isinstance(match_val, str) or len(match_val) == 0:
                val_type = type(match_val).__name__ if match_val is not None else "None"
                raise ValueError(f"Operator '{op}' for field '{field_name}' requires a non-empty string target (got {val_type})")
            max_len = 2048 if field_name == "raw_line" else 256
            if len(match_val) > max_len:
                raise ValueError(f"String target for field '{field_name}' exceeds maximum length {max_len}")

        elif op in ("eq", "neq"):
            if field_name == "port":
                if match_val is not None and (not isinstance(match_val, int) or isinstance(match_val, bool) or not (0 <= match_val <= 65535)):
                    val_type = type(match_val).__name__
                    raise ValueError(f"Field 'port' with operator '{op}' requires an integer between 0 and 65535 (got {val_type})")
            else:
                if match_val is not None and not isinstance(match_val, str):
                    val_type = type(match_val).__name__
                    raise ValueError(f"Field '{field_name}' with operator '{op}' requires a string target (got {val_type})")
                max_len = 2048 if field_name == "raw_line" else 256
                if match_val is not None and len(match_val) > max_len:
                    raise ValueError(f"Match value for '{field_name}' exceeds maximum length {max_len}")

        clean_operators[field_name] = op

    return {
        "type": rule_type,
        "group_by": group_by,
        "distinct_field": distinct_field,
        "match": match,
        "match_operators": clean_operators,
    }


def matches_custom_rule(event, match_dict: dict, operators_dict: dict) -> bool:
    """Evaluate whether an Event satisfies all declarative match criteria (AND semantics).

    Pure Python evaluation without eval/exec/compilation. Safe against None attributes.
    """
    if not match_dict:
        return False

    for field_name, target in match_dict.items():
        val = getattr(event, field_name, None)
        op = operators_dict.get(field_name, "in" if isinstance(target, list) else "eq")

        if op == "eq":
            if val != target:
                return False
        elif op == "neq":
            if val == target:
                return False
        elif op == "in":
            if not isinstance(target, (list, tuple, set)) or val not in target:
                return False
        elif op == "not_in":
            if isinstance(target, (list, tuple, set)) and val in target:
                return False
        elif op == "contains":
            if val is None or not isinstance(val, str) or not isinstance(target, str) or target not in val:
                return False
        elif op == "startswith":
            if val is None or not isinstance(val, str) or not isinstance(target, str) or not val.startswith(target):
                return False
        elif op == "endswith":
            if val is None or not isinstance(val, str) or not isinstance(target, str) or not val.endswith(target):
                return False
        else:
            return False

    return True


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
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    source_ip: Optional[str]
    settings: dict
    events: dict = field(default_factory=dict, repr=False)   # ref -> Event (the evidence)
    id: Optional[int] = None
    target_host: Optional[str] = None
    status: str = STATUS_NEW
    severity: str = "low"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    summary: str = ""
    explanation: str = ""
    evidence_ids: list = field(default_factory=list)

    def refresh(self) -> None:
        """Recompute times, evidence list, severity, target host and text from the evidence."""
        ordered = sorted(self.events.items(), key=lambda item: (item[1].timestamp, str(item[0])))
        if not ordered:
            return
        self.evidence_ids = [ref for ref, _ in ordered]
        self.first_seen = ordered[0][1].timestamp
        self.last_seen = ordered[-1][1].timestamp
        if self.target_host is None:
            self.target_host = next((getattr(e, "host", None) for e in self.events.values() if getattr(e, "host", None)), None)
        describer = _DESCRIBERS.get(self.rule_id, _describe_custom_rule)
        self.severity, self.summary, self.explanation = describer(self)

    def absorb(self, other: "Alert") -> bool:
        """Merge another candidate for the same attack. Returns True if anything changed."""
        before = (len(self.events), self.severity, self.last_seen)
        for ref, event in other.events.items():
            self.events.setdefault(ref, event)
        if self.target_host is None and other.target_host:
            self.target_host = other.target_host
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
            "target_host": self.target_host,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "summary": self.summary,
            "explanation": self.explanation,
            "settings": self.settings,
            "evidence_count": len(self.evidence_ids),
            "evidence_ids": list(self.evidence_ids),
        }


def _new_alert(rule_id: str, ip: Optional[str], events: Iterable, settings: dict,
               target_host: Optional[str] = None) -> Alert:
    rule_name = RULE_NAMES.get(rule_id) or settings.get("name") or rule_id
    alert = Alert(rule_id=rule_id, rule_name=rule_name, source_ip=ip,
                  target_host=target_host,
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
    location = f" from {a.source_ip}" if a.source_ip else ""
    summary = (f"{len(a.events)} root login attempts{location} "
               f"({len(accepted)} accepted, {failed} failed)")
    explanation = (f"Root login attempt (DR-05): login attempts as a privileged account "
                   f"({_names(s['usernames'])}){location}. Any attempt raises "
                   f"'{s['severity']}'; an accepted login raises '{s['accepted_severity']}'.")
    return severity, summary, explanation


def _describe_custom_rule(a: Alert) -> Tuple[str, str, str]:
    """Generate SOC-grade severity, summary, and explanation for custom declarative rules."""
    s = a.settings or {}
    severity = str(s.get("severity") or "medium").lower()
    if severity not in SEVERITY_ORDER:
        severity = "medium"
    n = len(a.events)
    rule_name = a.rule_name or a.rule_id
    group_by = s.get("group_by") or (
        s.get("conditions", {}).get("group_by") if isinstance(s.get("conditions"), dict) else None
    ) or "source_ip"

    if group_by == "username":
        users = sorted({e.username for e in a.events.values() if e.username})
        entity = f"user {_names(users) if users else 'unknown'}"
    elif group_by == "host":
        entity = f"host {a.target_host or 'unknown'}"
    elif group_by == "source_ip,host":
        entity = f"source {a.source_ip or 'unknown'} on host {a.target_host or 'unknown'}"
    else:
        entity = f"source {a.source_ip or 'unknown'}"

    cond = s.get("conditions") if isinstance(s.get("conditions"), dict) else {}
    rule_type = cond.get("type") or s.get("type", "threshold")
    threshold = s.get("threshold") or cond.get("threshold", 5)
    window_minutes = s.get("window_minutes") or cond.get("window_minutes", 5)

    summary = (f"{rule_name} ({a.rule_id}): {n} events from {entity} between "
               f"{_fmt(a.first_seen)} and {_fmt(a.last_seen)}")

    if rule_type == "distinct_count":
        distinct_field = cond.get("distinct_field") or s.get("distinct_field", "distinct values")
        distinct_vals = sorted({str(getattr(e, distinct_field, "")) for e in a.events.values() if getattr(e, distinct_field, None) is not None})
        explanation = (f"Custom rule {rule_name} ({a.rule_id}): {len(distinct_vals)} distinct {distinct_field} values "
                       f"({_names(distinct_vals)}) observed across {n} events for {entity}. "
                       f"Rule triggers at {threshold} or more distinct {distinct_field} values within {window_minutes} minutes.")
    else:
        explanation = (f"Custom rule {rule_name} ({a.rule_id}): {n} matching events observed for {entity}. "
                       f"Rule triggers at {threshold} or more matching events within {window_minutes} minutes.")

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

def evaluate_custom_rule(
    rule_id: str,
    settings: dict,
    cond: dict,
    events: List[Event],
    group_val: Any,
    group_by: str,
    gap: timedelta,
) -> List[Alert]:
    """Find episodes matching a custom declarative rule and produce candidate Alerts."""
    match_dict = cond.get("match", {})
    operators_dict = cond.get("match_operators", {})
    matching_events = [e for e in events if matches_custom_rule(e, match_dict, operators_dict)]
    if not matching_events:
        return []

    threshold = int(settings.get("threshold") or cond.get("threshold", 5))
    window_minutes = int(settings.get("window_minutes") or cond.get("window_minutes", 5))
    window = timedelta(minutes=window_minutes)

    rule_type = cond.get("type", "threshold")
    if rule_type == "distinct_count":
        distinct_field = cond.get("distinct_field")
        if not distinct_field:
            return []
        valid_events = [e for e in matching_events if getattr(e, distinct_field, None) is not None]
        episodes = _find_episodes(valid_events, window, threshold, key=lambda e: getattr(e, distinct_field))
    else:
        episodes = _find_episodes(matching_events, window, threshold, key=None)

    alerts = []
    for ep in episodes:
        if group_by == "source_ip":
            source_ip = group_val
            target_host = next((e.host for e in ep if e.host), None)
        elif group_by == "host":
            target_host = group_val
            source_ip = next((e.source_ip for e in ep if e.source_ip), "0.0.0.0")
        elif group_by == "source_ip,host":
            source_ip, target_host = group_val
        elif group_by == "username":
            source_ip = next((e.source_ip for e in ep if e.source_ip), "0.0.0.0")
            target_host = next((e.host for e in ep if e.host), None)
        else:
            source_ip = next((e.source_ip for e in ep if e.source_ip), "0.0.0.0")
            target_host = next((e.host for e in ep if e.host), None)

        rule_name = settings.get("name") or RULE_NAMES.get(rule_id, rule_id)
        merged_settings = dict(settings)
        merged_settings["group_by"] = group_by
        merged_settings["group_val"] = str(group_val)
        if "conditions" not in merged_settings:
            merged_settings["conditions"] = cond

        alert = Alert(
            rule_id=rule_id,
            rule_name=rule_name,
            source_ip=source_ip,
            target_host=target_host,
            settings=merged_settings,
            events={event_ref(e): e for e in ep},
        )
        alert.refresh()
        alerts.append(alert)
    return alerts


# --------------------------------------------------------------------------
# Correlation and deduplication (FR-11)
# --------------------------------------------------------------------------

def _alert_correlation_key(alert: Alert) -> tuple:
    """Derive correlation key preserving exact behavior for DR-01..05 while isolating custom rule groups."""
    if alert.rule_id in DETECTORS:
        host = next((getattr(e, "host", None) for e in alert.events.values() if getattr(e, "host", None)), None) if is_loopback_address(alert.source_ip) else None
        return (alert.rule_id, alert.source_ip, host)

    group_by = alert.settings.get("group_by") or (
        alert.settings.get("conditions", {}).get("group_by") if isinstance(alert.settings.get("conditions"), dict) else None
    ) or "source_ip"

    if group_by == "username":
        uname = alert.settings.get("group_val") or next((e.username for e in alert.events.values() if e.username), None)
        return (alert.rule_id, "user", uname)
    elif group_by == "host":
        host = alert.settings.get("group_val") or alert.target_host or next((e.host for e in alert.events.values() if e.host), None)
        return (alert.rule_id, "host", host)
    elif group_by == "source_ip,host":
        return (alert.rule_id, "ip_host", alert.source_ip, alert.target_host)
    else:
        host = next((getattr(e, "host", None) for e in alert.events.values() if getattr(e, "host", None)), None) if is_loopback_address(alert.source_ip) else None
        return (alert.rule_id, "ip", alert.source_ip, host)


def _correlate(candidates: List[Alert], existing: List[Alert], gap: timedelta):
    """Fold candidates into existing alerts. Returns (created, updated)."""
    index: Dict[tuple, List[Alert]] = {}
    for alert in existing:
        index.setdefault(_alert_correlation_key(alert), []).append(alert)

    created: List[Alert] = []
    updated: List[Alert] = []
    for cand in sorted(candidates, key=lambda a: (a.first_seen, a.rule_id)):
        bucket = index.setdefault(_alert_correlation_key(cand), [])
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
        self._history: Dict[Any, dict] = {}      # hkey -> {line_hash: event}
        self._by_username: Dict[str, dict] = {}  # username -> {line_hash: event}
        self._by_host: Dict[str, dict] = {}      # host -> {line_hash: event}
        self._by_ip_host: Dict[tuple, dict] = {} # (ip, host) -> {line_hash: event}
        self._next_id = 1

    @staticmethod
    def _history_key(source_ip: Optional[str], host: Optional[str] = None):
        """Derive history grouping key, isolating loopback traffic by host."""
        if source_ip and is_loopback_address(source_ip):
            return (source_ip, host)
        return source_ip

    def _index_event(self, event: Event) -> None:
        """Store an event into all relevant grouping indices."""
        hkey = self._history_key(event.source_ip, event.host)
        self._history.setdefault(hkey, {})[event.line_hash] = event
        if event.username:
            self._by_username.setdefault(event.username, {})[event.line_hash] = event
        if event.host:
            self._by_host.setdefault(event.host, {})[event.line_hash] = event
        if event.source_ip and event.host:
            self._by_ip_host.setdefault((event.source_ip, event.host), {})[event.line_hash] = event

    def add_custom_rule(self, rule_id: str, settings: dict) -> None:
        """Register or update a custom rule in the running engine."""
        clean_id = (rule_id or "").strip().upper()
        if not clean_id:
            raise ValueError("Rule ID cannot be empty")
        self.config.rules[clean_id] = dict(settings)

    def process(self, new_events: Iterable) -> DetectionResult:
        """Add newly ingested events and evaluate every rule (FR-07)."""
        result = DetectionResult()
        affected_ips = set()
        affected_users = set()
        affected_hosts = set()
        affected_ip_hosts = set()

        for event in new_events:
            host = getattr(event, "host", None)
            hkey = self._history_key(event.source_ip, host)
            bucket = self._history.setdefault(hkey, {})
            # Deduplicate by line_hash or matching event id
            if event.line_hash in bucket or (event.id is not None and any(e.id == event.id for e in bucket.values())):
                result.duplicate_events += 1     # same line uploaded again
                continue
            self._index_event(event)
            affected_ips.add(hkey)
            if event.username:
                affected_users.add(event.username)
            if event.host:
                affected_hosts.add(event.host)
            if event.source_ip and event.host:
                affected_ip_hosts.add((event.source_ip, event.host))
            result.events_processed += 1

        candidates: List[Alert] = []

        # 1. Evaluate built-in rules (DR-01 through DR-05)
        for hkey in sorted(affected_ips, key=lambda x: (x is None, str(x))):
            ip = hkey[0] if isinstance(hkey, tuple) else hkey
            events = sorted(self._history[hkey].values(), key=lambda e: e.timestamp)
            for rule_id, detector in DETECTORS.items():
                if ip is None and rule_id != "DR-05":
                    # Rules DR-01 through DR-04 require a valid source IP for correlation
                    continue
                settings = self.config.rules.get(rule_id)
                if settings and settings.get("enabled"):
                    candidates.extend(detector(ip, events, settings, self.config.dedupe_gap))

        # 2. Evaluate custom declarative rules
        for rule_id, settings in self.config.rules.items():
            if rule_id in DETECTORS or not settings or not settings.get("enabled"):
                continue
            try:
                raw_cond = settings.get("conditions")
                if not raw_cond and any(k in settings for k in ("match", "group_by", "type")):
                    raw_cond = settings
                cond = validate_custom_rule_conditions(raw_cond)
            except Exception:
                continue

            group_by = cond.get("group_by", "source_ip")
            if group_by == "source_ip":
                for hkey in sorted(affected_ips, key=lambda x: (x is None, str(x))):
                    ip = hkey[0] if isinstance(hkey, tuple) else hkey
                    if not ip:
                        continue
                    events = sorted(self._history[hkey].values(), key=lambda e: e.timestamp)
                    candidates.extend(
                        evaluate_custom_rule(rule_id, settings, cond, events, ip, "source_ip", self.config.dedupe_gap)
                    )
            elif group_by == "username":
                for uname in sorted(affected_users):
                    if not uname:
                        continue
                    events = sorted(self._by_username[uname].values(), key=lambda e: e.timestamp)
                    candidates.extend(
                        evaluate_custom_rule(rule_id, settings, cond, events, uname, "username", self.config.dedupe_gap)
                    )
            elif group_by == "host":
                for h in sorted(affected_hosts):
                    if not h:
                        continue
                    events = sorted(self._by_host[h].values(), key=lambda e: e.timestamp)
                    candidates.extend(
                        evaluate_custom_rule(rule_id, settings, cond, events, h, "host", self.config.dedupe_gap)
                    )
            elif group_by == "source_ip,host":
                for (ip, h) in sorted(affected_ip_hosts):
                    if not ip or not h:
                        continue
                    events = sorted(self._by_ip_host[(ip, h)].values(), key=lambda e: e.timestamp)
                    candidates.extend(
                        evaluate_custom_rule(rule_id, settings, cond, events, (ip, h), "source_ip,host", self.config.dedupe_gap)
                    )

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
