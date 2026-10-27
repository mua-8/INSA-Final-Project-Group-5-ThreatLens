# ThreatLens - Detection Engine (Module C)

Detects suspicious SSH authentication patterns and produces explainable alerts.
Code: `backend/detection.py`. Tests: `tests/test_detection.py`. Settings: `config/detection_config.json`.

## Data flow

```
raw log text -> parser (backend/parser.py) -> Event objects
             -> DetectionEngine.process(events)
             -> alerts (each linked to its exact evidence events)
```

1. Events are grouped by source IP and sorted by time.
2. Each enabled rule looks for **episodes**: runs of events that meet its threshold inside its time window.
3. Each episode becomes a candidate alert that keeps the exact events that triggered it.
4. Candidates are **correlated** with existing alerts so one ongoing attack updates one alert.

The engine does not touch a database. Module B stores what it returns.

## Rules (RSD slide 9)

| ID | Rule | Fires when | Severity | Evidence |
| --- | --- | --- | --- | --- |
| DR-01 | SSH brute force | 5 or more failed logins from one IP within 5 minutes | Medium | the failed logins |
| DR-02 | Username enumeration | 3 or more distinct invalid usernames from one IP within 5 minutes | Medium | the invalid-user events |
| DR-03 | Password spraying | failed logins against 5 or more distinct users from one IP within 10 minutes | High | the failed logins |
| DR-04 | Success after failures | an accepted login within 10 minutes of 5 or more failures from the same IP | Critical | the failures plus the accepted login |
| DR-05 | Root login attempt | any failed or accepted login as `root` | Medium, High if accepted | the root attempts |
| DR-06 | SQL injection attack | hostile SQL injection payloads (UNION, OR 1=1, DROP, quotes) | High | the SQLi events |

The window is inclusive: events exactly 5 minutes apart count as inside a 5-minute window.

## Automated Prevention & Active Defense
When high-severity attacks occur (such as DR-01 SSH brute force, DR-04 compromise, DR-05 accepted root, or DR-06 SQL injection):
1. **Automated IP Quarantine**: Attacker IP is inserted into `blocked_ips` and all subsequent requests are blocked with `HTTP 403 Forbidden`.
2. **SQL Injection Neutralization**: All database interaction strictly uses DB-API parameterized queries (`?`), guaranteeing zero hostile SQL interpretation.
3. **Defense Audit Trail**: Mitigations are recorded in `defense_actions` table for continuous telemetry.
4. **Admin Remediation Guidance**: Actionable remediation steps with copyable firewall (`iptables`/`ufw`), SSH (`/etc/ssh/sshd_config`), and database hardening instructions.


### What counts as a failed login

A failed login is a failure line that names an authentication method, such as
`Failed password for alice ...`. For an unknown user, sshd writes two lines
(`Invalid user X ...` and `Failed password for invalid user X ...`). Only the
second one is counted as a failed login, so one attempt is never counted twice.
Both lines are still used as evidence for DR-02.

## Alerts (FR-09, FR-10, FR-12)

| Field | Meaning |
| --- | --- |
| `id` | Sequential number assigned by the engine |
| `rule_id`, `rule_name` | Which rule fired |
| `severity` | `low`, `medium`, `high` or `critical` |
| `status` | Starts as `new`. Module B changes it to investigating, resolved or false positive |
| `source_ip` | The attacking IP |
| `first_seen`, `last_seen` | Time range of the evidence |
| `summary` | One line for the dashboard |
| `explanation` | The rule, the threshold and the window, in plain words |
| `settings` | The thresholds used when the alert was raised |
| `evidence_ids` | The exact events that triggered it |

`alert.to_dict()` returns all of this as JSON-ready data.

Evidence ids are the event's database `id` if the event has one, otherwise the
parser's `line_hash`.

## Duplicate prevention (FR-11)

Alerts are matched by rule and source IP. A new episode is merged into an
existing alert when it starts within `dedupe_gap_minutes` (default 30) of that
alert's time range. Merging adds the new evidence and extends `last_seen`.

- Uploading the same file twice adds no events and no alerts.
- An attack that continues in a later upload updates the same alert.
- Two attacks from the same IP more than 30 minutes apart are separate alerts.

## Configuration (FR-08)

Edit `config/detection_config.json`; no code changes needed.

```json
{
  "dedupe_gap_minutes": 30,
  "rules": {
    "DR-01": {"enabled": true, "threshold": 5, "window_minutes": 5, "severity": "medium"},
    "DR-04": {"enabled": true, "failure_threshold": 5, "window_minutes": 10, "severity": "critical"},
    "DR-05": {"enabled": true, "usernames": ["root"], "severity": "medium", "accepted_severity": "high"}
  }
}
```

Any setting you leave out keeps its default. Invalid values (zero or negative
numbers, unknown rules or settings, bad severities) raise `ConfigError`.

## Using it

```python
from backend.parser import parse_file
from backend.detection import DetectionEngine, DetectionConfig

engine = DetectionEngine(DetectionConfig.from_file("config/detection_config.json"))
parsed = parse_file("sample_logs/attack_brute_force_10.log", 2026)
result = engine.process(parsed.events)

for alert in result.new_alerts:       # alerts to INSERT
    print(alert.to_dict())
for alert in result.updated_alerts:   # alerts to UPDATE (new evidence, later last_seen)
    print(alert.id, len(alert.evidence_ids))
```

Command line demo:

```bash
python -m backend.detection sample_logs/attack_success_after_failures.log 2026
```

### Notes for Module B (backend API)

- Call `engine.process(parsed.events)` after parsing an upload.
- Save each `new_alerts` item as a row in `alerts`, and one `alert_evidence` row per entry in `evidence_ids`.
- For `updated_alerts`, update the alert row and add the new `alert_evidence` rows.
- If events get a database `id` (set `event.id = row_id` before calling `process`), `evidence_ids` will contain those ids directly.
- The engine keeps its event history and alerts in memory. After a server restart, create a new engine and run `process` on the stored events to rebuild; alert ids are then renumbered, so match them to stored rows by rule, IP and `first_seen`.

## Test scenarios

Run: `python -m unittest discover -s tests -v`

| Area | What is tested |
| --- | --- |
| Acceptance AC-01, AC-02, AC-03, AC-05 | Clean baseline gives zero alerts; 10 failures in 2 minutes give one alert with 10 evidence events; failures then success give a critical alert; uploading twice adds nothing |
| DR-01 | Below threshold, at threshold, window boundary, separate IPs, no double-counting of invalid-user lines, exact evidence |
| DR-02 | Distinct versus repeated usernames, window limit |
| DR-03 | Slow spray fires, four users do not, one user is brute force not spraying |
| DR-04 | Evidence includes the accepted login; 4 failures, old failures, different IP, one typo and cross-upload cases |
| DR-05 | Failed root is Medium, accepted root is High, non-root ignored, configurable usernames |
| Correlation | Ongoing attack updates one alert, separate attacks stay separate, event order does not matter, evidence links are real |
| Configuration | Overrides, disabled rules, 14 kinds of invalid config rejected, shipped file equals defaults |
| Sample logs | Each `attack_*.log` fires exactly the expected rules; re-uploading changes nothing |
| Performance | 10,000 events processed well under the 30 second target |

## Sample attack logs

| File | Expected result |
| --- | --- |
| `attack_brute_force_10.log` | DR-01, 10 evidence events |
| `attack_username_enumeration.log` | DR-02 |
| `attack_password_spraying.log` | DR-03 |
| `attack_success_after_failures.log` | DR-01 and DR-04 (Critical) |
| `attack_root_login.log` | DR-05 (High) |

## Known limits

- Rules look at one source IP at a time. A distributed attack from many IPs is not correlated.
- Thresholds are starting values from the RSD and should be tuned against real baseline logs.
- Log timestamps have no year or timezone, so the caller passes the year to the parser.
- An alert is evidence of suspicious behaviour, not proof of compromise.
