"""Local heuristic detector for suspected SSH brute-force authentication activity."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from threatlens_agent.detection.base import BaseDetector
from threatlens_agent.models.events import Event, EventSeverity, validate_iso_timestamp

logger = logging.getLogger(__name__)

RULE_ID = "TL-DET-LINUX-SSH-BRUTEFORCE"


@dataclass
class TrackedAttempt:
    """Represents a single failed authentication attempt, coalescing duplicate records."""

    event_ids: list[str] = field(default_factory=list)
    timestamp_epoch: float = 0.0
    timestamp_iso: str = ""
    username: str | None = None
    port: int | None = None
    invalid_user: bool = False


class SshBruteForceDetector(BaseDetector):
    """Detects repeated SSH authentication failures from a single source IP against a target host."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 120,
        coalesce_window_seconds: float = 2.0,
        time_provider: Callable[[], float] = time.time,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.coalesce_window_seconds = coalesce_window_seconds
        self._time_provider = time_provider

        # History mapping: (source_ip, target_host) -> list[TrackedAttempt]
        self._history: dict[tuple[str, str], list[TrackedAttempt]] = {}
        # Set of event_ids already processed to prevent duplicate processing
        self._seen_event_ids: set[str] = set()
        # Set of event_ids that have already contributed to an emitted alert
        self._alerted_event_ids: set[str] = set()

    @property
    def name(self) -> str:
        return "ssh_bruteforce"

    def reset(self) -> None:
        """Clear all in-memory tracking state."""
        self._history.clear()
        self._seen_event_ids.clear()
        self._alerted_event_ids.clear()

    def analyze(self, events: list[Event]) -> list[Event]:
        """Process incoming events and return detection events if thresholds are exceeded."""
        if not events:
            return []

        now_epoch = self._time_provider()
        now_dt = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
        now_iso = now_dt.isoformat()

        # Step 1: Filter and track eligible SSH failure events
        for ev in events:
            # Avoid processing the exact same event twice
            if ev.event_id in self._seen_event_ids:
                continue
            self._seen_event_ids.add(ev.event_id)

            # Only analyze SSH authentication failure and invalid user events
            if ev.source != "linux_auth":
                continue
            if ev.event_type not in ("ssh_auth_failure", "ssh_invalid_user"):
                continue

            source_ip = ev.source_ip
            if not source_ip:
                # Cannot group without a source IP
                continue

            target_host = str(ev.attributes.get("target_host") or "unknown_host")
            group_key = (source_ip, target_host)

            try:
                ev_dt = validate_iso_timestamp(ev.timestamp)
                ev_epoch = ev_dt.timestamp()
            except Exception:
                ev_epoch = now_epoch

            username = ev.username
            port = ev.attributes.get("port")
            invalid_user = bool(ev.attributes.get("invalid_user", False))

            if group_key not in self._history:
                self._history[group_key] = []

            # Check if this event can be coalesced with a recent attempt
            # (e.g. 'Invalid user test' immediately paired with 'Failed password for invalid user test')
            coalesced = False
            for prev in reversed(self._history[group_key]):
                if abs(ev_epoch - prev.timestamp_epoch) <= self.coalesce_window_seconds:
                    if prev.username == username and (port is None or prev.port == port):
                        prev.event_ids.append(ev.event_id)
                        prev.invalid_user = prev.invalid_user or invalid_user
                        coalesced = True
                        break

            if not coalesced:
                self._history[group_key].append(
                    TrackedAttempt(
                        event_ids=[ev.event_id],
                        timestamp_epoch=ev_epoch,
                        timestamp_iso=ev.timestamp,
                        username=username,
                        port=port,
                        invalid_user=invalid_user,
                    )
                )

        # Step 2: Evaluate sliding windows and generate detection alerts
        detections: list[Event] = []

        for (source_ip, target_host), attempts in list(self._history.items()):
            # Prune attempts outside the sliding window
            valid_attempts = [
                att for att in attempts if (now_epoch - att.timestamp_epoch) <= self.window_seconds
            ]
            self._history[(source_ip, target_host)] = valid_attempts

            if len(valid_attempts) < self.threshold:
                continue

            # Gather all supporting event IDs for these attempts
            supporting_ids = [eid for att in valid_attempts for eid in att.event_ids]

            # Avoid re-alerting if no new events were added since last alert
            new_events = [eid for eid in supporting_ids if eid not in self._alerted_event_ids]
            if not new_events:
                continue

            # Mark all current supporting IDs as alerted
            self._alerted_event_ids.update(supporting_ids)

            count = len(valid_attempts)
            usernames = sorted({att.username for att in valid_attempts if att.username})
            first_ts = valid_attempts[0].timestamp_iso
            last_ts = valid_attempts[-1].timestamp_iso

            # Escalate to critical if failure count is double the threshold
            severity = EventSeverity.CRITICAL if count >= self.threshold * 2 else EventSeverity.HIGH

            explanation = (
                f"Observed {count} suspected SSH authentication failures from source IP {source_ip} "
                f"targeting host '{target_host}' within {self.window_seconds}s "
                f"(configured threshold: {self.threshold}). Targeted accounts: "
                f"{', '.join(usernames) if usernames else 'unspecified'}. "
                f"This pattern is consistent with automated password guessing or brute-force behavior."
            )

            detection_event = Event(
                event_id=str(uuid.uuid4()),
                device_id=events[0].device_id if events else "unknown_device",
                timestamp=now_iso,
                source="threatlens_detection",
                event_type="potential_ssh_bruteforce",
                severity=severity,
                source_ip=source_ip,
                username=usernames[0] if len(usernames) == 1 else None,
                raw_event=explanation,
                attributes={
                    "rule_id": RULE_ID,
                    "rule_name": "Potential Linux SSH Brute-Force Authentication Activity",
                    "target_host": target_host,
                    "failure_count": count,
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                    "first_failure_at": first_ts,
                    "last_failure_at": last_ts,
                    "targeted_usernames": usernames,
                    "supporting_event_ids": supporting_ids,
                    "explanation": explanation,
                },
            )
            detections.append(detection_event)
            logger.warning(
                "Triggered detection %s: %d failures from %s against %s",
                RULE_ID,
                count,
                source_ip,
                target_host,
            )

        return detections
