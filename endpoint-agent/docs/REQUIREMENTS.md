# ThreatLens Endpoint Agent — Requirements & Constraints

This document defines the functional, environmental, and security requirements governing the ThreatLens Endpoint Agent.

---

## 1. Supported Operating Systems & Python Runtimes

### Target Operating Systems
- **Linux**:
  - Ubuntu 20.04, 22.04, 24.04 LTS
  - Debian 11 (Bullseye), 12 (Bookworm)
  - Kali Linux (rolling / 2023+)
  - Red Hat Enterprise Linux / Rocky / AlmaLinux 8+
- **Microsoft Windows**:
  - Windows 10 & 11 (64-bit)
  - Windows Server 2019, 2022

### Python Environment
- **Runtime**: Python `>= 3.10` (compatible with 3.10, 3.11, 3.12, 3.13, 3.14).
- **Core Dependencies**: Strictly minimized. Standard library preferred; only `PyYAML >= 6.0` is required for production execution.
- **Development Dependencies**: `pytest >= 8.0.0`, `ruff >= 0.4.0`.

---

## 2. Functional Requirements

### FR-01: Configuration Management
- The agent must load settings from a YAML configuration file or fall back to safe default parameters.
- The agent must support environment variable overrides for containerized or automated deployment.
- The agent must fail at startup with clear, actionable validation error messages if parameters are invalid.

### FR-02: Stable Device Identity
- The agent must generate a stable UUIDv4 identifier on its initial launch.
- The device identifier must be stored persistently in the configured data directory and reused across application restarts and reboots.
- The identity must not rely on fragile or volatile hardware fingerprints.

### FR-03: Unified Event Schema
- The agent must normalize platform events into a typed `Event` model conforming to Schema Version `1.0.0`.
- All timestamps must be in UTC formatted as ISO-8601 with explicit timezone offsets (`Z` or `+00:00`).
- Fields must include `event_id`, `device_id`, `timestamp`, `source`, `event_type`, `severity`, optional `source_ip`, `username`, `raw_event`, and structured `attributes`.

### FR-04: Durable Local Storage
- The agent must buffer unacknowledged telemetry in a local SQLite database configured with Write-Ahead Logging (WAL) mode.
- Duplicate event submissions with identical `event_id` must be detected and rejected safely without data loss.
- In-flight events interrupted by a crash or reboot must be safely restored to `pending` status upon restart.
- Configurable limits (`max_events`, `max_disk_mb`) must prevent unbounded disk space consumption.

### FR-05: Resilient Transport
- The agent must support HTTPS communication with strict certificate validation enabled by default.
- Transmission attempts must implement bounded exponential backoff with randomized jitter.
- The transport must never retry indefinitely or hang indefinitely; request and connection timeouts must be enforced.
- If network connectivity is lost, events must remain securely buffered in the local queue.
- Events must be marked as delivered only upon receiving an explicit HTTP 2xx server acknowledgment.

### FR-06: Command-Line Interface
- The agent must provide an ergonomic CLI supporting `status`, `validate-config`, `version`, `queue-stats`, and `flush`.
- Standard non-zero exit codes must be emitted on failure (1 for operational errors, 2 for syntax/argument errors).

---

## 3. Security & Compliance Constraints

1. **Isolation**: Development must remain completely independent of the ThreatLens backend/frontend repositories.
2. **No Stealth or Surveillance**: The agent must operate visibly without process hiding, keystroke recording, or unauthorized background surveillance.
3. **No Arbitrary Remote Execution**: The agent must never accept or execute arbitrary remote shell commands.
4. **Access Control**: Local state files must be created with restricted filesystem permissions (`0700` for directories, `0600` for state files on POSIX).
5. **Secret Protection**: API tokens, private keys, and passwords must never be stored in plain text example files, logged to disk, or transmitted unredacted.
