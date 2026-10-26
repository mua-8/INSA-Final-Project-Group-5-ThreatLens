# ThreatLens Endpoint Agent — Project Roadmap

This roadmap defines the sequential development milestones for the ThreatLens Endpoint Agent project.

---

## Milestone Status Overview

| Milestone | Title | Focus Area | Status | Target Platforms |
| :--- | :--- | :--- | :--- | :--- |
| **Milestone 1** | **Shared Agent Core** | Foundation, Storage, Transport, Schema | **COMPLETED** | Linux, Windows |
| **Milestone 2** | **Linux Monitoring** | SSH Brute Force, Auth Log, systemd | **COMPLETED** | Linux (Ubuntu, Kali, Debian, RHEL) |
| **Milestone 3** | **Windows Monitoring**| Security Event Log, Logon, Sysmon | **COMPLETED** | Windows 10/11, Windows Server |
| **Milestone 4** | **Backend Integration** | ThreatLens SIEM API & Enrollment | *NEXT* | All |
| **Milestone 5** | **Static File Scanner**| Entropy, Hashing, PE/ELF Headers | Planned | All |
| **Milestone 6** | **Packaging & Daemons**| systemd Units, Windows Service, MSI | Planned | Linux, Windows |

---

## Detailed Milestone Definitions

### Milestone 1: Shared Agent Core (COMPLETED)
- [x] Configure Python package with PEP 621 `pyproject.toml` and `src/` layout.
- [x] Configure Ruff linter/formatter and pytest automated test suite.
- [x] Validated configuration loader supporting safe YAML and environment variables.
- [x] Stable persistent device identity with restricted filesystem permissions (`0700`/`0600`).
- [x] Common Event Schema v1.0.0 with ISO-8601 UTC timestamps and automated secret redaction.
- [x] Durable SQLite event queue with WAL mode, duplicate rejection, and crash resilience.
- [x] Transport abstraction with HTTPS, bounded retries, exponential backoff, jitter, and mock server.
- [x] CLI commands: `status`, `validate-config`, `version`, `queue-stats`, `flush`.
- [x] 100% automated test coverage across 63 unit and integration test cases.

---

### Milestone 2: Linux Telemetry & Monitoring (COMPLETED)
- [x] Implement `LinuxAuthCollector` to probe and monitor `/var/log/auth.log` and `/var/log/secure`.
- [x] Connect with `systemd-journald` for distributions using binary journal logging.
- [x] Implement incremental tailing with persistent file checkpointing (`checkpoints.json`).
- [x] Handle log rotation (inode tracking) and file truncation safely without losing future events.
- [x] Parse representative OpenSSH events (valid/invalid users, success/failure, publickey/password/none).
- [x] Normalize SSH authentication events into Common Event Schema (`ssh_auth_failure`, `ssh_auth_success`, `ssh_invalid_user`).
- [x] Implement local heuristic detection for repeated SSH authentication failures (`TL-DET-LINUX-SSH-BRUTEFORCE`).
- [x] Group attempts strictly by `(source_ip, target_host)` with sliding time window evaluation.
- [x] Coalesce paired invalid-user attempts to avoid double-counting.
- [x] Surface collector diagnostics and detection counts via agent health reporting and CLI (`threatlens-agent collect`).
- [x] 100% automated test coverage across 92 unit and integration test cases.

---

### Milestone 3: Windows Telemetry & Monitoring (COMPLETED)
- [x] Implement `WindowsEventLogCollector` targeting the Windows `Security` channel.
- [x] Normalize Windows Security Event IDs:
  - Event ID 4625 (An account failed to log on -> `windows_logon_failure`).
  - Event ID 4624 (An account was successfully logged on -> `windows_logon_success`).
  - Event ID 4672 (Special privileges assigned to logon -> `windows_special_privilege_assigned`).
  - Event ID 4688 (A new process has been created -> `windows_process_creation`).
- [x] Enforce command-line argument privacy by default (`include_command_line: false`).
- [x] Channel checkpointing using monotonic 64-bit `EventRecordID`s with log-clearing discontinuity detection.
- [x] Isolate Windows dependencies using `BaseWindowsEventAdapter` with `PowershellWindowsEventAdapter` and `SyntheticWindowsEventAdapter`.
- [x] Support optional Sysmon channel discovery (`Microsoft-Windows-Sysmon/Operational`) and parsing extension point.
- [x] 100% automated test coverage across 112 unit and integration test cases using synthetic fixtures.

---

## Milestone 4: ThreatLens Backend Integration
- [ ] Collaborate with ThreatLens SIEM backend team on finalized ingestion API contract.
- [ ] Implement agent enrollment handshake (`POST /api/v1/enroll`).
- [ ] Transition from mock HTTP transport to production backend transport.
- [ ] Implement periodic agent health ping / heartbeat dispatch.
- [ ] Test end-to-end event transmission with real backend staging instances.

---

## Milestone 5: Suspicious File Static Analysis
- [ ] Implement `FileScanner` module for explicit, user-authorized file inspection.
- [ ] Calculate cryptographic digests (SHA-256, SHA-1, MD5).
- [ ] Compute Shannon entropy to detect packed, encrypted, or obfuscated payloads.
- [ ] Parse PE (Portable Executable) and ELF headers for suspicious section names and imports.
- [ ] Emit structured `file_analysis` events without ever executing untrusted files.

---

## Milestone 6: Packaging & Daemon Management
- [ ] Create Linux `systemd` service unit definition (`threatlens-agent.service`).
- [ ] Provide automated Linux installation and uninstallation scripts (`install.sh`, `uninstall.sh`).
- [ ] Implement Windows Service wrapper using `pywin32` or standard service runner.
- [ ] Create Windows installer script / MSI packaging definition.
- [ ] Production documentation, system logging integration, and release hardening.
