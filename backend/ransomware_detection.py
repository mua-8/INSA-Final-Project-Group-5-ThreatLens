"""ThreatLens — Phase 2: Ransomware Detection Engine.

Provides automated, explainable, and defensive detection of suspicious file activity:
1. High-frequency file modification, rename, and deletion bursts (Detection A).
2. Changes to designated canary / honeyfiles (Detection B).
3. Rapid suspicious file-extension mutations (Detection C).
4. Multi-indicator correlation, evidence tracking, and incident escalation (Detection D).

Architectural separation:
- Operates on normalized file events (persisted in file_events table).
- Strictly isolated from SSH authentication detection (DR-01 through DR-05).
- Fully idempotent: re-evaluations and duplicate ingestions never produce duplicate alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from backend import repository as repo


# --------------------------------------------------------------------------
# Constants & Rule Definitions
# --------------------------------------------------------------------------

RULE_RW_BURST_MODIFY = "RW-BURST-01"
RULE_RW_BURST_RENAME = "RW-BURST-02"
RULE_RW_BURST_DELETE = "RW-BURST-03"
RULE_RW_BURST_COMBINED = "RW-BURST-04"
RULE_RW_CANARY = "RW-CANARY-01"
RULE_RW_SUSPICIOUS_EXT = "RW-EXT-01"

DEFAULT_SUSPICIOUS_EXTENSIONS = [
    ".locked", ".crypto", ".enc", ".crypted", ".ransom", ".darkbit"
]

RULE_METADATA = {
    RULE_RW_BURST_MODIFY: {
        "name": "File modification burst",
        "severity": "high",
        "description": "High-frequency file modifications exceeding threshold within time window.",
    },
    RULE_RW_BURST_RENAME: {
        "name": "File rename burst",
        "severity": "high",
        "description": "High-frequency file renames exceeding threshold within time window.",
    },
    RULE_RW_BURST_DELETE: {
        "name": "File deletion burst",
        "severity": "high",
        "description": "High-frequency file deletions exceeding threshold within time window.",
    },
    RULE_RW_BURST_COMBINED: {
        "name": "Combined activity burst",
        "severity": "critical",
        "description": "Aggregate high-frequency file modifications, renames, and deletions.",
    },
    RULE_RW_CANARY: {
        "name": "Canary file tampering",
        "severity": "critical",
        "description": "Modification, rename, deletion, or creation of a registered canary/honeyfile.",
    },
    RULE_RW_SUSPICIOUS_EXT: {
        "name": "Suspicious extension mutation",
        "severity": "medium",
        "description": "File renamed to a known ransomware extension from a different original extension.",
    },
}


# --------------------------------------------------------------------------
# Path & Timestamp Normalization Helpers
# --------------------------------------------------------------------------

def normalize_path(path: Optional[str]) -> str:
    """Normalize file path for strict, prefix-safe comparison."""
    if not path:
        return ""
    clean = str(path).strip().replace("\x00", "")
    norm = os.path.normpath(clean)
    if len(norm) > 1 and norm.endswith("/"):
        norm = norm.rstrip("/")
    return norm


def parse_utc_timestamp(ts_val: Any) -> Optional[datetime]:
    """Parse ISO-8601 or datetime into timezone-aware UTC datetime."""
    if not ts_val:
        return None
    if isinstance(ts_val, datetime):
        return ts_val.astimezone(timezone.utc) if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)
    try:
        ts_str = str(ts_val).strip()
        if ts_str.endswith("Z") or ts_str.endswith("z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# --------------------------------------------------------------------------
# Configuration Data Model
# --------------------------------------------------------------------------

@dataclass
class RansomwareConfig:
    burst_window_seconds: int = 10
    burst_modify_threshold: int = 50
    burst_rename_threshold: int = 50
    burst_delete_threshold: int = 50
    burst_combined_threshold: int = 80
    suspicious_extensions: List[str] = field(default_factory=lambda: list(DEFAULT_SUSPICIOUS_EXTENSIONS))
    canary_enabled: bool = True
    burst_enabled: bool = True
    extension_enabled: bool = True
    correlation_window_seconds: int = 900  # 15 minutes
    dedupe_gap_seconds: int = 300          # 5 minutes

    def validate(self) -> None:
        """Validate config parameters."""
        if self.burst_window_seconds <= 0:
            raise ValueError("burst_window_seconds must be a positive integer")
        if self.burst_modify_threshold <= 0:
            raise ValueError("burst_modify_threshold must be a positive integer")
        if self.burst_rename_threshold <= 0:
            raise ValueError("burst_rename_threshold must be a positive integer")
        if self.burst_delete_threshold <= 0:
            raise ValueError("burst_delete_threshold must be a positive integer")
        if self.burst_combined_threshold <= 0:
            raise ValueError("burst_combined_threshold must be a positive integer")
        if not isinstance(self.suspicious_extensions, list):
            raise ValueError("suspicious_extensions must be a list of string extensions")
        if self.correlation_window_seconds <= 0:
            raise ValueError("correlation_window_seconds must be a positive integer")
        if self.dedupe_gap_seconds <= 0:
            raise ValueError("dedupe_gap_seconds must be a positive integer")

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "RansomwareConfig":
        exts_raw = row["suspicious_extensions"]
        try:
            exts = json.loads(exts_raw) if exts_raw else list(DEFAULT_SUSPICIOUS_EXTENSIONS)
        except Exception:
            exts = list(DEFAULT_SUSPICIOUS_EXTENSIONS)

        cfg = cls(
            burst_window_seconds=row["burst_window_seconds"],
            burst_modify_threshold=row["burst_modify_threshold"],
            burst_rename_threshold=row["burst_rename_threshold"],
            burst_delete_threshold=row["burst_delete_threshold"],
            burst_combined_threshold=row["burst_combined_threshold"],
            suspicious_extensions=[
                e.strip().lower() if e.strip().startswith(".") else f".{e.strip().lower()}"
                for e in exts if isinstance(e, str) and e.strip()
            ],
            canary_enabled=bool(row["canary_enabled"]),
            burst_enabled=bool(row["burst_enabled"]),
            extension_enabled=bool(row["extension_enabled"]),
            correlation_window_seconds=row["correlation_window_seconds"],
            dedupe_gap_seconds=row["dedupe_gap_seconds"],
        )
        cfg.validate()
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return {
            "burst_window_seconds": self.burst_window_seconds,
            "burst_modify_threshold": self.burst_modify_threshold,
            "burst_rename_threshold": self.burst_rename_threshold,
            "burst_delete_threshold": self.burst_delete_threshold,
            "burst_combined_threshold": self.burst_combined_threshold,
            "suspicious_extensions": list(self.suspicious_extensions),
            "canary_enabled": self.canary_enabled,
            "burst_enabled": self.burst_enabled,
            "extension_enabled": self.extension_enabled,
            "correlation_window_seconds": self.correlation_window_seconds,
            "dedupe_gap_seconds": self.dedupe_gap_seconds,
        }


# --------------------------------------------------------------------------
# Candidate Alert & Detection Results
# --------------------------------------------------------------------------

@dataclass
class CandidateAlert:
    rule_id: str
    rule_name: str
    severity: str
    target_host: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    summary: str
    explanation: str
    settings: Dict[str, Any]
    event_db_ids: List[int] = field(default_factory=list)
    dedupe_key: str = ""


@dataclass
class RansomwareDetectionResult:
    new_alerts: List[Dict[str, Any]] = field(default_factory=list)
    updated_alerts: List[Dict[str, Any]] = field(default_factory=list)
    new_incidents: List[Dict[str, Any]] = field(default_factory=list)
    updated_incidents: List[Dict[str, Any]] = field(default_factory=list)
    events_evaluated: int = 0


# --------------------------------------------------------------------------
# Detection Engine
# --------------------------------------------------------------------------

class RansomwareDetectionEngine:
    """Consumes normalized file events and evaluates ransomware indicators."""

    def __init__(self, config: Optional[RansomwareConfig] = None):
        self.config = config or RansomwareConfig()

    def load_config_from_db(self, conn: sqlite3.Connection) -> None:
        """Refresh configuration from database policy row."""
        row = repo.get_ransomware_policy(conn, "default")
        if row:
            self.config = RansomwareConfig.from_row(row)

    # =========================================================================
    # Detection A: High-Frequency File Activity (Burst Detection)
    # =========================================================================

    def evaluate_bursts(
        self,
        device_id: str,
        events: List[Dict[str, Any]],
    ) -> List[CandidateAlert]:
        """Detect bursts of file modifications, renames, deletions, and combined activity.

        Uses a sliding window counting distinct normalized paths to prevent duplicate-event inflation.
        Overlapping triggering windows are merged into a single contiguous burst episode.
        """
        if not self.config.burst_enabled or not events:
            return []

        # Sort events chronologically
        valid_events = []
        for e in events:
            ts = parse_utc_timestamp(e.get("timestamp"))
            if ts is not None and e.get("file_path"):
                valid_events.append({
                    "id": e.get("id"),
                    "event_id": e.get("event_id"),
                    "device_id": device_id,
                    "timestamp_dt": ts,
                    "timestamp_iso": ts.isoformat(),
                    "event_type": str(e.get("event_type") or "").strip().lower(),
                    "file_path": normalize_path(e.get("file_path")),
                    "previous_path": normalize_path(e.get("previous_path")),
                })

        valid_events.sort(key=lambda x: x["timestamp_dt"])
        if not valid_events:
            return []

        window_td = timedelta(seconds=self.config.burst_window_seconds)

        # Evaluate each burst metric independently
        burst_specs = [
            (
                RULE_RW_BURST_MODIFY,
                "file_modified",
                self.config.burst_modify_threshold,
                RULE_METADATA[RULE_RW_BURST_MODIFY]["severity"],
                lambda ev: {ev["file_path"]} if ev["event_type"] == "file_modified" else set(),
                "file modifications",
            ),
            (
                RULE_RW_BURST_RENAME,
                "file_renamed",
                self.config.burst_rename_threshold,
                RULE_METADATA[RULE_RW_BURST_RENAME]["severity"],
                lambda ev: ({ev["file_path"]} | ({ev["previous_path"]} if ev["previous_path"] else set()))
                if ev["event_type"] == "file_renamed" else set(),
                "file renames",
            ),
            (
                RULE_RW_BURST_DELETE,
                "file_deleted",
                self.config.burst_delete_threshold,
                RULE_METADATA[RULE_RW_BURST_DELETE]["severity"],
                lambda ev: {ev["file_path"]} if ev["event_type"] == "file_deleted" else set(),
                "file deletions",
            ),
            (
                RULE_RW_BURST_COMBINED,
                "combined",
                self.config.burst_combined_threshold,
                RULE_METADATA[RULE_RW_BURST_COMBINED]["severity"],
                lambda ev: ({ev["file_path"]} | ({ev["previous_path"]} if ev["previous_path"] else set())),
                "distinct file operations",
            ),
        ]

        candidates: List[CandidateAlert] = []

        for rule_id, filter_type, threshold, severity, path_extractor, label in burst_specs:
            marked = [False] * len(valid_events)
            left = 0
            highest_marked = -1

            # Two-pointer sliding window over events
            for right, right_ev in enumerate(valid_events):
                # Shrink window from left until within window_td
                while right_ev["timestamp_dt"] - valid_events[left]["timestamp_dt"] > window_td:
                    left += 1

                # Gather distinct paths in current window
                window_paths: Set[str] = set()
                window_event_count = 0
                for i in range(left, right + 1):
                    ev = valid_events[i]
                    paths = path_extractor(ev)
                    if paths:
                        window_paths.update(paths)
                        window_event_count += 1

                if len(window_paths) >= threshold:
                    for i in range(max(left, highest_marked + 1), right + 1):
                        marked[i] = True
                    highest_marked = right

            # Group marked events into contiguous episodes
            episodes: List[List[Dict[str, Any]]] = []
            curr_ep: List[Dict[str, Any]] = []
            for i, ev in enumerate(valid_events):
                if not marked[i]:
                    if curr_ep:
                        episodes.append(curr_ep)
                        curr_ep = []
                    continue
                if curr_ep and ev["timestamp_dt"] - curr_ep[-1]["timestamp_dt"] > window_td:
                    episodes.append(curr_ep)
                    curr_ep = []
                curr_ep.append(ev)
            if curr_ep:
                episodes.append(curr_ep)

            # Convert each episode into a CandidateAlert
            for ep in episodes:
                ep_paths: Set[str] = set()
                ep_db_ids: List[int] = []
                ep_event_ids: List[str] = []
                for ev in ep:
                    paths = path_extractor(ev)
                    if paths:
                        ep_paths.update(paths)
                        if ev["id"]:
                            ep_db_ids.append(ev["id"])
                        if ev["event_id"]:
                            ep_event_ids.append(ev["event_id"])

                if len(ep_paths) < threshold:
                    continue

                first_ts = ep[0]["timestamp_dt"]
                last_ts = ep[-1]["timestamp_dt"]
                distinct_count = len(ep_paths)
                raw_count = len(ep)

                meta = RULE_METADATA[rule_id]
                rule_name = meta["name"]
                summary = (
                    f"{distinct_count} {label} within {self.config.burst_window_seconds}s "
                    f"on endpoint {device_id} ({raw_count} raw events)"
                )
                sample_paths = sorted(list(ep_paths))[:20]
                explanation = (
                    f"High-frequency file burst detected on endpoint '{device_id}' ({rule_name} - {rule_id}): "
                    f"{distinct_count} distinct paths observed across {raw_count} raw events between "
                    f"{first_ts.strftime('%Y-%m-%d %H:%M:%S UTC')} and {last_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}. "
                    f"Threshold crossed: >= {threshold} distinct paths in {self.config.burst_window_seconds}s. "
                    f"Sample affected paths: {', '.join(sample_paths[:5])}."
                )

                settings = {
                    "rule_id": rule_id,
                    "device_id": device_id,
                    "metric": "distinct_paths",
                    "threshold": threshold,
                    "window_seconds": self.config.burst_window_seconds,
                    "distinct_paths_count": distinct_count,
                    "raw_event_count": raw_count,
                    "sample_paths": sample_paths,
                    "qualifying_event_ids": ep_event_ids[:50],
                }

                # Stable deduplication key based on rule, device, and epoch window bucket
                bucket_epoch = int(first_ts.timestamp()) // max(1, self.config.dedupe_gap_seconds)
                dedupe_key = f"{rule_id}:{device_id}:{bucket_epoch}"

                candidates.append(CandidateAlert(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    target_host=device_id,
                    source_ip="127.0.0.1",
                    first_seen=first_ts,
                    last_seen=last_ts,
                    summary=summary,
                    explanation=explanation,
                    settings=settings,
                    event_db_ids=ep_db_ids,
                    dedupe_key=dedupe_key,
                ))

        return candidates

    # =========================================================================
    # Detection B: Canary/Honeyfile Monitoring
    # =========================================================================

    def evaluate_canaries(
        self,
        conn: sqlite3.Connection,
        device_id: str,
        events: List[Dict[str, Any]],
    ) -> List[CandidateAlert]:
        """Detect access, modification, rename, or deletion of designated canary files.

        Enforces exact normalized path equality (no prefix matching).
        Evaluates both file_path and previous_path for rename events.
        """
        if not self.config.canary_enabled or not events:
            return []

        # Load enabled canaries applicable to this device
        canary_rows = repo.list_canary_files(conn, device_id=device_id, enabled=1)
        if not canary_rows:
            return []

        canaries = []
        for r in canary_rows:
            c_norm = normalize_path(r["file_path"])
            if c_norm:
                canaries.append({
                    "id": r["id"],
                    "canary_id": r["canary_id"],
                    "file_path": c_norm,
                    "original_path": r["file_path"],
                    "device_id": r["device_id"],
                    "description": r["description"],
                    "severity": r["severity"],
                })

        candidates: List[CandidateAlert] = []

        for e in events:
            ev_path = normalize_path(e.get("file_path"))
            prev_path = normalize_path(e.get("previous_path"))
            ev_type = str(e.get("event_type") or "").strip().lower()
            ev_ts = parse_utc_timestamp(e.get("timestamp")) or datetime.now(timezone.utc)
            ev_db_id = e.get("id")
            ev_id = e.get("event_id")

            for c in canaries:
                # Scoping check: match global canary or specific device
                if c["device_id"] and c["device_id"] != device_id:
                    continue

                c_path = c["file_path"]
                is_match = False
                match_role = ""

                # Exact equality matching (never prefix matching)
                if ev_path == c_path:
                    is_match = True
                    match_role = "target"
                elif ev_type == "file_renamed" and prev_path and prev_path == c_path:
                    is_match = True
                    match_role = "origin"

                if is_match:
                    action_label = {
                        "file_modified": "modified",
                        "file_deleted": "deleted",
                        "file_created": "created/replaced",
                        "file_renamed": "renamed away" if match_role == "origin" else "renamed into",
                    }.get(ev_type, ev_type)

                    meta = RULE_METADATA[RULE_RW_CANARY]
                    summary = (
                        f"Canary file '{c['original_path']}' was {action_label} "
                        f"on endpoint {device_id}"
                    )
                    explanation = (
                        f"Canary / Honeyfile tampering alert ({meta['name']} - {RULE_RW_CANARY}): "
                        f"Registered decoy file '{c['original_path']}' (Canary ID: {c['canary_id']}) "
                        f"was {action_label} by file event '{ev_id}' on endpoint '{device_id}'. "
                        f"Description: {c['description'] or 'Designated defensive decoy'}."
                    )
                    settings = {
                        "rule_id": RULE_RW_CANARY,
                        "canary_id": c["canary_id"],
                        "canary_path": c["original_path"],
                        "action": ev_type,
                        "match_role": match_role,
                        "device_id": device_id,
                        "file_path": e.get("file_path"),
                        "previous_path": e.get("previous_path"),
                        "event_id": ev_id,
                    }

                    dedupe_key = f"{RULE_RW_CANARY}:{device_id}:{c['canary_id']}:{ev_id}"

                    candidates.append(CandidateAlert(
                        rule_id=RULE_RW_CANARY,
                        rule_name=meta["name"],
                        severity=c["severity"] or meta["severity"],
                        target_host=device_id,
                        source_ip="127.0.0.1",
                        first_seen=ev_ts,
                        last_seen=ev_ts,
                        summary=summary,
                        explanation=explanation,
                        settings=settings,
                        event_db_ids=[ev_db_id] if ev_db_id else [],
                        dedupe_key=dedupe_key,
                    ))

        return candidates

    # =========================================================================
    # Detection C: Suspicious Extension Changes
    # =========================================================================

    def evaluate_extensions(
        self,
        device_id: str,
        events: List[Dict[str, Any]],
    ) -> List[CandidateAlert]:
        """Detect rename events that mutate a file's extension to a suspicious extension.

        Requires observable previous_path. Distinguishes genuine extension change from unchanged extension.
        """
        if not self.config.extension_enabled or not events:
            return []

        suspicious_set = {
            e.lower() if e.startswith(".") else f".{e.lower()}"
            for e in self.config.suspicious_extensions
        }

        candidates: List[CandidateAlert] = []

        for e in events:
            ev_type = str(e.get("event_type") or "").strip().lower()
            if ev_type != "file_renamed":
                continue

            prev_path = e.get("previous_path")
            target_path = e.get("file_path")
            if not prev_path or not str(prev_path).strip():
                # Missing source path treated as incomplete evidence, not fabricated extension change
                continue

            target_path_str = str(target_path).strip()
            prev_path_str = str(prev_path).strip()

            target_ext = e.get("file_extension")
            if not target_ext:
                last_dot = target_path_str.rfind(".")
                last_slash = max(target_path_str.rfind("/"), target_path_str.rfind("\\"))
                target_ext = target_path_str[last_dot:].lower() if last_dot > last_slash else ""
            else:
                target_ext = str(target_ext).strip().lower()
                if target_ext and not target_ext.startswith("."):
                    target_ext = f".{target_ext}"

            # Derive original extension
            last_dot_prev = prev_path_str.rfind(".")
            last_slash_prev = max(prev_path_str.rfind("/"), prev_path_str.rfind("\\"))
            orig_ext = prev_path_str[last_dot_prev:].lower() if last_dot_prev > last_slash_prev else ""

            # Check if target extension is suspicious AND genuinely changed
            if target_ext in suspicious_set and target_ext != orig_ext:
                ev_ts = parse_utc_timestamp(e.get("timestamp")) or datetime.now(timezone.utc)
                meta = RULE_METADATA[RULE_RW_SUSPICIOUS_EXT]

                summary = (
                    f"Suspicious extension mutation '{orig_ext or 'none'}' -> '{target_ext}' "
                    f"on endpoint {device_id}"
                )
                explanation = (
                    f"Suspicious extension change detected ({meta['name']} - {RULE_RW_SUSPICIOUS_EXT}): "
                    f"File '{prev_path_str}' was renamed to '{target_path_str}' on endpoint '{device_id}'. "
                    f"Extension mutated from '{orig_ext or 'none'}' to known suspicious extension '{target_ext}'. "
                    f"This signal indicates potential bulk encryption activity."
                )
                settings = {
                    "rule_id": RULE_RW_SUSPICIOUS_EXT,
                    "device_id": device_id,
                    "target_extension": target_ext,
                    "original_extension": orig_ext,
                    "file_path": target_path_str,
                    "previous_path": prev_path_str,
                    "event_id": e.get("event_id"),
                }

                dedupe_key = f"{RULE_RW_SUSPICIOUS_EXT}:{device_id}:{e.get('event_id')}"

                candidates.append(CandidateAlert(
                    rule_id=RULE_RW_SUSPICIOUS_EXT,
                    rule_name=meta["name"],
                    severity=meta["severity"],
                    target_host=device_id,
                    source_ip="127.0.0.1",
                    first_seen=ev_ts,
                    last_seen=ev_ts,
                    summary=summary,
                    explanation=explanation,
                    settings=settings,
                    event_db_ids=[e["id"]] if e.get("id") else [],
                    dedupe_key=dedupe_key,
                ))

        return candidates

    # =========================================================================
    # Detection D: Correlation, Incident Management & Deduplication
    # =========================================================================

    def correlate_and_persist(
        self,
        conn: sqlite3.Connection,
        candidates: List[CandidateAlert],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Correlate candidate alerts with existing alerts and active incidents.

        Guarantees idempotency and safe multi-indicator severity escalation.
        """
        if not candidates:
            return [], [], [], []

        new_alerts: List[Dict[str, Any]] = []
        updated_alerts: List[Dict[str, Any]] = []
        new_incidents: List[Dict[str, Any]] = []
        updated_incidents: List[Dict[str, Any]] = []

        dedupe_gap = timedelta(seconds=self.config.dedupe_gap_seconds)
        correlation_window = timedelta(seconds=self.config.correlation_window_seconds)

        # Process each candidate alert
        for cand in candidates:
            device_id = cand.target_host
            rule_id = cand.rule_id

            # Check for existing alert in database within dedupe_gap
            existing_rows = conn.execute(
                """SELECT * FROM alerts
                   WHERE rule_id = ? AND target_host = ?
                   ORDER BY last_seen DESC LIMIT 5""",
                (rule_id, device_id),
            ).fetchall()

            matched_alert_id = None
            for ex in existing_rows:
                ex_last = parse_utc_timestamp(ex["last_seen"])
                ex_first = parse_utc_timestamp(ex["first_seen"])
                if ex_last and ex_first:
                    if cand.first_seen <= ex_last + dedupe_gap and cand.last_seen >= ex_first - dedupe_gap:
                        matched_alert_id = ex["id"]
                        matched_alert_row = ex
                        break

            if matched_alert_id is not None:
                # Update existing alert if new evidence is present
                existing_ev_ids = {
                    r[0] for r in conn.execute(
                        "SELECT file_event_id FROM alert_file_evidence WHERE alert_id = ?",
                        (matched_alert_id,),
                    ).fetchall()
                }

                new_ev_ids = [eid for eid in cand.event_db_ids if eid not in existing_ev_ids]

                # Update timestamp and evidence if new events arrived
                if new_ev_ids:
                    cand_last_str = cand.last_seen.isoformat()
                    repo.update_alert(
                        conn,
                        matched_alert_id,
                        severity=cand.severity,
                        last_seen=cand_last_str,
                        summary=cand.summary,
                        explanation=cand.explanation,
                        target_host=device_id,
                    )
                    repo.insert_alert_file_evidence(conn, matched_alert_id, new_ev_ids)
                    updated_alerts.append({
                        "id": matched_alert_id,
                        "rule_id": rule_id,
                        "summary": cand.summary,
                        "target_host": device_id,
                        "last_seen": cand_last_str,
                    })
                alert_id_for_incident = matched_alert_id
                alert_severity_for_incident = cand.severity
            else:
                # Insert new alert
                alert_dict = {
                    "rule_id": cand.rule_id,
                    "rule_name": cand.rule_name,
                    "severity": cand.severity,
                    "status": "new",
                    "source_ip": cand.source_ip,
                    "target_host": device_id,
                    "first_seen": cand.first_seen.isoformat(),
                    "last_seen": cand.last_seen.isoformat(),
                    "summary": cand.summary,
                    "explanation": cand.explanation,
                    "settings": cand.settings,
                }
                new_id = repo.insert_alert(conn, alert_dict)
                if cand.event_db_ids:
                    repo.insert_alert_file_evidence(conn, new_id, cand.event_db_ids)

                alert_dict["id"] = new_id
                new_alerts.append(alert_dict)
                alert_id_for_incident = new_id
                alert_severity_for_incident = cand.severity

            # -----------------------------------------------------------------
            # Incident Correlation for endpoint
            # -----------------------------------------------------------------
            # Look for an active incident for this endpoint within correlation window
            open_incidents = conn.execute(
                """SELECT * FROM incidents
                   WHERE status IN ('open', 'in_progress')
                     AND (title LIKE ? OR description LIKE ?)
                   ORDER BY updated_at DESC LIMIT 1""",
                (f"%{device_id}%", f"%{device_id}%"),
            ).fetchall()

            matched_inc = None
            if open_incidents:
                inc = open_incidents[0]
                inc_updated = parse_utc_timestamp(inc["updated_at"])
                if inc_updated and (cand.last_seen - inc_updated) <= correlation_window:
                    matched_inc = inc

            if matched_inc:
                inc_id = matched_inc["id"]
                repo.link_alert_to_incident(conn, inc_id, alert_id_for_incident)

                # Determine if severity escalation is warranted
                # Canary tampering or multi-rule combinations escalate to critical
                all_linked_alerts = repo.get_incident_alerts(conn, inc_id)
                rule_ids_linked = {a["rule_id"] for a in all_linked_alerts}

                new_inc_sev = matched_inc["severity"]
                if RULE_RW_CANARY in rule_ids_linked or len(rule_ids_linked) >= 2 or alert_severity_for_incident == "critical":
                    new_inc_sev = "critical"
                elif alert_severity_for_incident == "high" and new_inc_sev not in ("high", "critical"):
                    new_inc_sev = "high"

                updated_desc = (
                    f"Correlated ransomware activity on {device_id}. "
                    f"Active alerts: {', '.join(sorted(rule_ids_linked))}."
                )
                repo.update_incident(conn, inc_id, severity=new_inc_sev, description=updated_desc)
                updated_incidents.append({"id": inc_id, "severity": new_inc_sev, "device_id": device_id})
            else:
                # Create a new incident
                inc_sev = "critical" if (rule_id == RULE_RW_CANARY or alert_severity_for_incident == "critical") else "high"
                inc_title = f"Ransomware Activity Detected: {device_id}"
                inc_desc = f"Correlated ransomware indicators detected on endpoint {device_id}. Triggered rule: {cand.rule_name} ({rule_id})."
                new_inc_id = repo.insert_incident(conn, title=inc_title, description=inc_desc, severity=inc_sev)
                repo.link_alert_to_incident(conn, new_inc_id, alert_id_for_incident)
                repo.insert_incident_note(
                    conn,
                    new_inc_id,
                    note=f"Incident opened automatically: {cand.summary}",
                    author="ThreatLens Detection Engine",
                )
                new_incidents.append({"id": new_inc_id, "title": inc_title, "severity": inc_sev, "device_id": device_id})

        return new_alerts, updated_alerts, new_incidents, updated_incidents

    # =========================================================================
    # Master Processing Entry Point
    # =========================================================================

    def process_file_events(
        self,
        conn: sqlite3.Connection,
        events: Optional[List[Dict[str, Any]]] = None,
        device_id: Optional[str] = None,
        since_time: Optional[str] = None,
    ) -> RansomwareDetectionResult:
        """Evaluate burst, canary, and extension detection rules for provided or recent events."""
        self.load_config_from_db(conn)

        # If events not directly passed, query events from file_events
        if events is None:
            clauses, params = [], []
            if device_id:
                clauses.append("device_id = ?")
                params.append(device_id.strip())
            if since_time:
                clauses.append("timestamp >= ?")
                params.append(since_time)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            rows = conn.execute(f"SELECT * FROM file_events {where} ORDER BY timestamp ASC", params).fetchall()
            events = [dict(r) for r in rows]

        if not events:
            return RansomwareDetectionResult()

        # Group events by device_id to strictly isolate endpoints
        events_by_device: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            dev = (ev.get("device_id") or "").strip()
            if dev:
                events_by_device.setdefault(dev, []).append(ev)

        all_candidates: List[CandidateAlert] = []

        for dev, dev_events in events_by_device.items():
            # 1. Bursts (Detection A)
            burst_candidates = self.evaluate_bursts(dev, dev_events)
            all_candidates.extend(burst_candidates)

            # 2. Canaries (Detection B)
            canary_candidates = self.evaluate_canaries(conn, dev, dev_events)
            all_candidates.extend(canary_candidates)

            # 3. Suspicious Extensions (Detection C)
            ext_candidates = self.evaluate_extensions(dev, dev_events)
            all_candidates.extend(ext_candidates)

        # 4. Correlation & Persistence (Detection D)
        new_al, upd_al, new_inc, upd_inc = self.correlate_and_persist(conn, all_candidates)

        return RansomwareDetectionResult(
            new_alerts=new_al,
            updated_alerts=upd_al,
            new_incidents=new_inc,
            updated_incidents=upd_inc,
            events_evaluated=len(events),
        )


# --------------------------------------------------------------------------
# Singleton Engine Registry & Lifecycle
# --------------------------------------------------------------------------

_ransomware_engines: Dict[str, RansomwareDetectionEngine] = {}


def get_ransomware_engine(db_path: str = "threatlens.db") -> RansomwareDetectionEngine:
    """Retrieve or initialize the RansomwareDetectionEngine for the given database."""
    abs_path = os.path.abspath(db_path)
    if abs_path not in _ransomware_engines:
        engine = RansomwareDetectionEngine()
        _ransomware_engines[abs_path] = engine
    return _ransomware_engines[abs_path]


def reset_ransomware_engine(db_path: str = "threatlens.db") -> None:
    """Clear cached engine instance (used in test teardowns)."""
    abs_path = os.path.abspath(db_path)
    _ransomware_engines.pop(abs_path, None)
