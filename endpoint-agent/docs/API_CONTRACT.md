# ThreatLens Endpoint Agent — API & Transport Contract

This document describes the endpoint agent's internal interfaces, mock transport used in isolated tests, and the implemented HTTP contract between the endpoint agent and the ThreatLens SIEM backend in this monorepo.

---

## 1. Implemented Local Interfaces (Milestone 1)

These programmatic interfaces are fully implemented, typed, and unit-tested within the agent codebase.

### A. `threatlens_agent.models.events.Event`
Unified model representing security telemetry across platforms:

```python
class Event:
    schema_version: str  # Default: "1.0.0"
    event_id: str  # UUIDv4 string
    device_id: str  # Stable UUIDv4 string
    timestamp: str  # ISO-8601 UTC string (e.g., "2026-10-26T06:00:00.000000+00:00")
    source: str  # Provider name (e.g., "linux_auth", "windows_security")
    event_type: str  # Event category (e.g., "ssh_auth_failure", "process_creation")
    severity: EventSeverity  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str | None  # Validated IPv4/IPv6 string or None
    username: str | None  # User identity or None
    raw_event: str | None  # Sanitized raw log text
    attributes: dict[str, Any]  # Sanitized structured key-value attributes
```

### B. `threatlens_agent.storage.queue.EventQueue`
Durable SQLite buffer providing atomic operations:

- `enqueue(event: Event) -> bool`: Inserts single event. Rejects duplicate `event_id` idempotently.
- `enqueue_batch(events: list[Event]) -> int`: Inserts batch within a single transaction.
- `get_pending_batch(limit: int, mark_in_flight: bool = True) -> list[Event]`: Leases FIFO batch.
- `mark_delivered(event_ids: list[str]) -> int`: Purges or marks acknowledged events based on `retention_policy`.
- `mark_failed(event_ids: list[str], error_message: str | None = None) -> int`: Returns in-flight events to pending.
- `reset_in_flight() -> int`: Resets orphaned in-flight events to pending on initialization.
- `get_stats() -> QueueStats`: Returns real-time metrics (pending, in-flight, delivered, size in bytes).

### C. `threatlens_agent.storage.checkpoint.CheckpointManager`
File position and rotation tracker:

- `get_file_checkpoint(path: Path | str) -> FileCheckpoint`: Retrieves stored byte offset and inode.
- `update_file_checkpoint(path: Path | str, offset: int, inode: int, size: int, mtime: float) -> None`: Persists updated offset atomically.
- `inspect_file_rotation(path: Path | str, checkpoint: FileCheckpoint) -> tuple[int, bool, bool]`: Detects inode changes and truncations, safely returning starting seek offset.

### D. `threatlens_agent.collectors.linux_auth.LinuxAuthCollector`
Linux authentication log collector implementing `BaseCollector`:

- `name: "linux_auth"`
- `is_supported() -> bool`: Returns `True` on Linux systems.
- `start() -> None`: Probes candidate log files and journald availability.
- `collect() -> list[Event]`: Returns newly observed and parsed `Event` models.
- `get_diagnostics() -> dict[str, Any]`: Returns source readability and active status.

### E. `threatlens_agent.collectors.windows_event.WindowsEventLogCollector`
Windows Security Event Log and optional Sysmon collector implementing `BaseCollector`:

- `name: "windows_event_log"`
- `is_supported() -> bool`: Returns `True` on Windows hosts or when injected with `SyntheticWindowsEventAdapter`.
- `start() -> None`: Probes channel accessibility, verifies `Event Log Readers` permissions, and initializes checkpoints.
- `collect() -> list[Event]`: Queries `BaseWindowsEventAdapter`, detects log clearing, updates checkpoints, and normalizes events.
- `get_diagnostics() -> dict[str, Any]`: Reports channel status, permissions, Sysmon availability, and total collected counts.

#### Supported Normalized Windows Event Types:
1. `windows_logon_failure` (Event ID 4625):
   - `severity`: `high`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `logon_type`, `logon_type_name`, `status`, `sub_status`, `failure_reason`, `workstation`, `source_port`, `logon_process_name`, `authentication_package_name`.
2. `windows_logon_success` (Event ID 4624):
   - `severity`: `informational`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `logon_type`, `logon_type_name`, `workstation`, `source_port`, `logon_process_name`, `authentication_package_name`, `elevated_status`.
3. `windows_special_privilege_assigned` (Event ID 4672):
   - `severity`: `medium`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `subject_domain`, `subject_user_sid`, `privileges` (list of strings).
4. `windows_process_creation` (Event ID 4688):
   - `severity`: `informational`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `new_process_name`, `process_id`, `parent_process_name`, `creator_process_id`, `subject_domain`, `subject_user_sid`, `mandatory_label`. `command_line` is omitted unless explicitly opted in.
5. `sysmon_process_creation` (Sysmon Event ID 1):
   - `severity`: `informational`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `image`, `parent_image`, `hashes`.
6. `sysmon_network_connection` (Sysmon Event ID 3):
   - `severity`: `informational`
   - `attributes`: `event_id`, `channel`, `provider`, `record_id`, `image`, `destination_ip`, `destination_port`, `protocol`.

### F. `threatlens_agent.detection.ssh_bruteforce.SshBruteForceDetector`
Local threshold and sliding-window detector implementing `BaseDetector`:

- `name: "ssh_bruteforce"`
- `analyze(events: list[Event]) -> list[Event]`: Evaluates failure counts per `(source_ip, target_host)` and returns `potential_ssh_bruteforce` detection events when threshold is met.
- `reset() -> None`: Resets in-memory tracking state.

### G. `threatlens_agent.transport.base.BaseTransport`
Abstract interface for event dispatch:

- `send_batch(events: list[Event]) -> TransportResult`: Submits batch and returns status.
- `is_available() -> bool`: Reports whether transport is configured.
- `close() -> None`: Releases network sockets.

---

## 2. Mock Transport Behavior (Local Simulation)

Until the backend team finalizes the ingestion service, the test suite and local simulations use `MockHttpServer` (`threatlens_agent.transport.mock`):

### Outgoing Payload (Agent -> Server)
```http
POST /api/v1/events HTTP/1.1
Host: 127.0.0.1:port
Content-Type: application/json
Accept: application/json
User-Agent: ThreatLens-Agent/0.1.0
X-Device-ID: 660a4260-a61c-4abb-a9b7-b851abfcc378
Authorization: Bearer <api_key>

{
  "device_id": "660a4260-a61c-4abb-a9b7-b851abfcc378",
  "agent_version": "0.1.0",
  "sent_at": 1793000000.0,
  "events": [
    {
      "schema_version": "1.0.0",
      "event_id": "848e0018-c266-4be9-ba5c-d3fa03f568ce",
      "device_id": "660a4260-a61c-4abb-a9b7-b851abfcc378",
      "timestamp": "2026-10-26T06:00:00.000000+00:00",
      "source": "linux_auth",
      "event_type": "ssh_auth_failure",
      "severity": "high",
      "source_ip": "192.168.1.50",
      "username": "admin",
      "raw_event": "Failed password for admin from 192.168.1.50 port 44211 ssh2",
      "attributes": {
        "port": 44211,
        "service": "ssh"
      }
    }
  ]
}
```

### Mock Ingestion Response (Server -> Agent)
The mock server acknowledges received event IDs:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ok",
  "acknowledged": [
    "848e0018-c266-4be9-ba5c-d3fa03f568ce"
  ]
}
```

---

## 3. Implemented ThreatLens SIEM Backend Contract

The monorepo backend implements `POST /api/v1/events` for endpoint-agent
batch ingestion. The agent-to-backend path has been exercised in a local
integration smoke test. This does not by itself verify production deployment
or native Windows collection.

### Authentication and configuration

- The backend must be configured with `THREATLENS_AGENT_API_KEY`.
- The agent sends `Authorization: Bearer <api_key>`.
- The agent also sends `X-Device-ID` and JSON content type headers.
- Configure the agent's backend URL and API key through its configuration
  and environment variables. Do not commit real API keys.

### Request

The JSON body includes:

- `device_id`: device identifier for the batch.
- `agent_version`: agent version string.
- `sent_at`: optional numeric Unix timestamp.
- `events`: non-empty list of normalized event objects.

Each event includes its UUID `event_id`, `device_id`, timezone-aware ISO-8601
`timestamp`, `source`, `event_type`, severity, and optional source IP,
username, raw event text, and structured attributes.

The backend validates the request body and event fields, including UUID
event IDs, timezone-aware timestamps, accepted severity values, source IP
format, and the expected JSON/object types. The request body is limited to
5 MB.

### Successful acknowledgement

A successful ingestion returns HTTP 200 and a response shaped like:

```json
{
  "ok": true,
  "status": "ok",
  "acknowledged": ["<event-uuid>"],
  "count": 1
}
```

The `acknowledged` array contains event IDs accepted by the backend. The
agent uses acknowledgements to manage its local delivery queue.

### Duplicate and error behavior

- Re-submitting an identical event ID with identical event content is
  idempotent and returns a successful acknowledgement.
- Reusing an event ID for conflicting content returns HTTP 409.
- Missing or invalid API-key configuration prevents authenticated ingestion.
- Invalid JSON or invalid event fields are rejected rather than accepted as
  valid telemetry.

### Verification status and remaining work

The repository's local integration smoke test previously verified that the
agent sent three synthetic events, the backend stored all three, identical
retries were acknowledged, and a conflicting duplicate received HTTP 409.
The same demo must be rerun against the monorepo copy before finalizing this
integration.

Native Windows event collection still requires testing on a real Windows
host with appropriate permissions and audit policy. Production deployment,
device enrollment, TLS configuration, and operational rate-limit behavior
must be assessed separately before production use.
