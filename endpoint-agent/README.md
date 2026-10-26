# ThreatLens Endpoint Agent

Cross-platform, resilient endpoint telemetry agent designed to monitor host security events, normalize platform data, buffer unsent events locally, and securely forward telemetry to the ThreatLens SIEM platform.

---

## 1. Project Overview & Scope

### What the Agent Is
- An independent, lightweight endpoint monitoring agent written in Python.
- Designed to run on client hosts (Linux distributions including Kali and Ubuntu, and Microsoft Windows).
- A resilient telemetry collector that normalizes operating system events into a unified event schema.
- A locally buffered system using durable SQLite storage so that network outages or backend restarts do not result in telemetry loss.
- An auditable, transparent monitoring tool adhering strictly to security best practices.

### What the Agent Is NOT
- **Not a SIEM backend**: The agent does not store platform-wide logs, manage alerts, or provide dashboard UIs.
- **Not a competing database or analytics platform**: It collects and buffers host telemetry only until acknowledged by the backend.
- **Not an unauthorized surveillance or stealth tool**: It does not hide its processes, capture keystrokes, execute arbitrary remote shell commands, or run unsigned suspicious files.

### Relationship to the ThreatLens SIEM Project
This component lives in the ThreatLens SIEM monorepo under `endpoint-agent/`. It remains independently testable, but its HTTP transport is integrated with the SIEM backend at `POST /api/v1/events`. The backend requires `THREATLENS_AGENT_API_KEY` to be configured, and the agent sends the corresponding Bearer token. See `docs/API_CONTRACT.md` for the implemented contract and validation behavior.

---

## 2. Current Implementation Status

| Capability | Milestone | Status | Details |
| :--- | :--- | :--- | :--- |
| **Shared Agent Core** | Milestone 1 | **Complete** | Configuration, Device ID, Event Schema, SQLite Queue, Transport, CLI |
| **Linux Monitoring** | Milestone 2 | **Complete** | OpenSSH parser, `/var/log/auth.log`, `/var/log/secure`, `journald`, SSH Brute-Force Detector |
| **Windows Monitoring** | Milestone 3 | **Complete** | Security Event Log (4625, 4624, 4672, 4688), Sysmon extension, Checkpointing |
| **Backend Integration** | Milestone 4 | **Integrated; local smoke-tested** | HTTP batch forwarding to `POST /api/v1/events`; see `docs/API_CONTRACT.md`. Production deployment and native-host verification remain separate tasks. |
| **Suspicious File Scanner** | Milestone 5 | Planned | Optional local static analysis (entropy, hashing) |
| **Packaging & Daemons** | Milestone 6 | Planned | systemd service unit, Windows Service installer |

---

## 3. Getting Started

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Linux (Ubuntu, Debian, Kali Linux, Fedora) or Microsoft Windows

### Creating a Virtual Environment
```bash
# From the ThreatLens SIEM monorepo root
cd endpoint-agent

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
# .venv\Scripts\Activate.ps1
```

### Installing Development Dependencies
```bash
pip install -e ".[dev]"
```

---

## 4. Running the CLI

The agent provides a clean command-line interface via `threatlens-agent` (or `python -m threatlens_agent`):

### View Version and Platform Information
```bash
threatlens-agent version
# Or with JSON output:
threatlens-agent --json version
```

### Validate Configuration
```bash
threatlens-agent validate-config config/agent.example.yaml
```

### Inspect Agent Health, Active Collectors, and Queue Status
```bash
threatlens-agent -c config/agent.example.yaml status
```

### Execute a Telemetry Collection & Detection Cycle
```bash
threatlens-agent -c config/agent.example.yaml collect
```

### Inspect Local SQLite Queue Metrics
```bash
threatlens-agent -c config/agent.example.yaml queue-stats
```

### Flush Queued Events to Backend
```bash
threatlens-agent -c config/agent.example.yaml flush --limit 50
```

---

## 5. Linux Telemetry & SSH Brute-Force Monitoring

### Telemetry Sources Probed
The Linux collector discovers and monitors:
1. `/var/log/auth.log` (Debian, Ubuntu, Kali Linux)
2. `/var/log/secure` (RHEL, CentOS, Fedora, Rocky)
3. `systemd-journald` (`journalctl -u ssh -u sshd`) if file logs are missing or restricted

### Checkpoint & Rotation Resilience
- Checkpoints are saved in `data/checkpoints.json` (mode `0600`).
- The collector detects log rotation (inode changes) and file truncation, safely resetting seek offsets to `0` to prevent data loss.

### Supported OpenSSH Records
- Failed password authentication for valid and invalid accounts
- Invalid user notifications
- Accepted password and public-key authentications
- Failed public-key and none-auth attempts
- Maximum authentication attempts exceeded notices
- Preauth connection termination and disconnects
- IPv4 and standard / bracketed IPv6 addresses

### Local SSH Brute-Force Detector
- **Rule ID**: `TL-DET-LINUX-SSH-BRUTEFORCE`
- **Default Threshold**: 5 failed attempts within 120 seconds (configurable).
- **Grouping**: Strictly groups by `(source_ip, target_host)`.
- **Coalescing**: Transparently combines paired `Invalid user` and `Failed password for invalid user` logs from a single attempt so they count as 1 attempt, preventing artificial inflation.
- **Deduplication**: Suppresses re-alerting on previously alerted event batches.

---

## 6. Windows Telemetry & Monitoring

### Supported Windows Event Sources
The Windows collector monitors:
1. **Security Event Log Channel**: Primary event source for authentication, privilege elevation, and process execution telemetry.
2. **Optional Sysmon Operational Channel** (`Microsoft-Windows-Sysmon/Operational`): Optional source for extended process creation and network connection records.

### Supported Event IDs and Normalization
The agent parses and normalizes these Windows events into the Common Event Schema:
- **Event 4625** (`windows_logon_failure`): Captures target account username, domain, logon type (e.g. Network, Interactive, RemoteInteractive), status/substatus error codes, failure reason, workstation, and source IP address / port. Severity: `high`.
- **Event 4624** (`windows_logon_success`): Captures target account, domain, logon type, source IP address, logon process, authentication package, and elevation status. Severity: `informational`.
- **Event 4672** (`windows_special_privilege_assigned`): Captures subject account, domain, and structured list of assigned privileges (e.g. `SeSecurityPrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege`). Severity: `medium`.
- **Event 4688** (`windows_process_creation`): Captures new process image path, process ID, parent process name, creator process ID, subject account, and mandatory integrity label. Severity: `informational`.

### Privacy by Design: Command-Line Privacy
For process creation (Event 4688 and Sysmon Event 1), `CommandLine` arguments are **excluded by default** (`include_command_line: false`) to prevent accidental leakage of sensitive flags, tokens, or credentials passed in shell arguments.

### Permissions & Audit Policy Dependencies
- **Permissions**: Accessing the Windows `Security` channel requires administrative privileges or membership in the built-in `Event Log Readers` local group. When permissions are denied, the collector logs a clear diagnostic without crashing the agent.
- **Audit Policy Requirements**: Windows does not log events 4672 and 4688 by default unless the appropriate Advanced Audit Policies are enabled in Local Security Policy or Group Policy (`Audit Process Creation`, `Audit Special Privilege Use`). The agent does not modify audit policies automatically.
- **Sysmon**: Sysmon is strictly optional (`enable_sysmon: false` by default). The agent detects whether the Sysmon operational channel is present and accessible, but does not install or configure Sysmon.

### Incremental Checkpointing & Deduplication
- Windows event records are tracked by monotonic 64-bit `EventRecordID` persisted in `data/checkpoints.json` under `windows_channel:<channel>`.
- **Discontinuity & Log Clearing Detection**: If the Security log is cleared or wrapped, the collector detects that current record IDs are lower than the saved checkpoint, resets the offset safely, and resumes collection without data loss.
- **Deduplication**: In-memory ring buffer deduplication and deterministic UUIDv5 event identifiers (`uuid5(NAMESPACE_DNS, f"{device_id}:{channel}:{record_id}")`) prevent duplicate event ingestion into the local queue.

---

## 7. Manual Testing on Windows and Linux Hosts

### Running on a Real Windows Host
To test the collector on a live Windows machine:
1. Ensure the user running the agent belongs to the `Event Log Readers` group or run as Administrator.
2. Enable Windows collection in `config/agent.yaml`:
   ```yaml
   monitoring:
     enabled_collectors: ["windows_event_log"]
     windows:
       enabled: true
       channels: ["Security"]
       enable_sysmon: false
   ```
3. Trigger a test failed logon (e.g., attempt `runas /user:baduser cmd.exe`).
4. Execute collection:
   ```powershell
   python -m threatlens_agent -c config/agent.yaml collect
   ```
5. Check status:
   ```powershell
   python -m threatlens_agent -c config/agent.yaml status
   ```

### Manual Testing on a Linux Host
1. **Verify Read Permissions**: Ensure read access to `/var/log/auth.log` (`adm` group):
   ```bash
   sudo usermod -aG adm "$USER"
   newgrp adm
   ```
2. **Trigger a Test SSH Failure**:
   ```bash
   ssh -o PubkeyAuthentication=no invalidtestuser@127.0.0.1
   ```
3. **Run Collection**:
   ```bash
   threatlens-agent -c config/agent.example.yaml collect
   ```

---

## 8. Running Automated Tests & Linting

All unit and integration tests run entirely in user space without requiring network access, root privileges, or a physical Windows host (using synthetic fixtures and injectable adapters):

```bash
# Run complete test suite (112 tests)
pytest

# Run linter
ruff check .

# Check code formatting
ruff format --check .
```

---

## 9. Known Limitations (Milestone 3)

1. **Host Log Permissions**: In production, reading `/var/log/auth.log` on Linux requires `adm` group membership; reading Windows `Security` log requires `Event Log Readers` group or Administrator privileges.
2. **Audit Policy Dependency**: Events 4672 and 4688 require corresponding Windows Audit Policies to be enabled by system administrators.
3. **Mock-Assisted Transport**: HTTP transport remains decoupled pending the ThreatLens SIEM backend team's final ingestion API contract.
4. **Foreground CLI**: The agent currently executes as a foreground CLI. Background service management (`systemd` daemon, Windows Service) is scheduled for Milestone 6.
