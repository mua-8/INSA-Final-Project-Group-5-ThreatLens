# ThreatLens Endpoint Agent — Security Architecture & Guidelines

This document outlines the security architecture, credential management, local data isolation, network transport security, and privacy practices of the ThreatLens Endpoint Agent.

---

## 1. Threat Model & Principles

The agent operates in environments where host security, data integrity, and privacy are critical. The design adheres to the following principles:

1. **Principle of Least Privilege**: The agent runs in standard user space where feasible. It does not require root privileges for core storage, queuing, and transport operations.
2. **Confidentiality of Telemetry**: Telemetry may capture host context; all transmissions require TLS encryption. Sensitive values (passwords, tokens) are redacted at ingestion.
3. **Integrity of Queued Records**: Local storage guarantees that events cannot be tampered with or silently lost during system crashes or power outages.
4. **Transparency & Auditability**: The agent maintains standard logs, does not conceal its processes, and provides a clear CLI for inspecting system status.

---

## 2. Credential Management

- **No Hardcoded Credentials**: No passwords, API tokens, device tokens, or private keys are ever stored in source code.
- **Safe Example Configurations**: `config/agent.example.yaml` provides empty/null values for secrets (`api_key: null`). Real credentials must never be committed to Git.
- **Environment Variable Injection**: Credentials should be injected at runtime via environment variables (e.g. `THREATLENS_API_KEY`).
- **Secret Masking in Logs & Dumps**: The configuration system explicitly masks secrets (`to_dict(mask_secrets=True)`) when dumping or printing configurations. Calling `status` or debug logging never reveals the API token.

---

## 3. Filesystem Permissions & Local Data Protection

- **State Directory Permissions**: On POSIX systems (Linux), the agent sets permission mode `0700` (`drwx------`) on its local data directory (`data/` or `$THREATLENS_DATA_DIR`). Other unprivileged users on the host cannot read or browse stored events.
- **File Permissions**: The state file (`device_state.json`), checkpoint state (`checkpoints.json`), and database files (`events_queue.db`) are created with permission mode `0600` (`-rw-------`), ensuring only the agent process owner can read or write data.
- **Atomic State Updates**: State and checkpoint persistence use atomic file replacement via temporary files in the same directory (`os.replace`), preventing corrupted state files if power is lost during a write.
- **Non-Destructive Read-Only Log Access**: Telemetry collection tails operating system log files (`/var/log/auth.log`, `/var/log/secure`) and `systemd-journald` strictly in read-only mode (`open(..., 'r')`). The agent never alters, rotates, removes, or tampers with system log files.
- **Log Access Permissions**: System authentication logs on Linux typically require `adm` group membership or standard daemon service privileges. On Windows, reading the `Security` channel requires membership in the `Event Log Readers` local group or administrative rights. The collector degrades gracefully without crashing if a source is unreadable or permission is denied.
- **Windows Audit Policy Non-Interference**: The agent operates as a passive observer and never modifies Windows audit policies (e.g. `auditpol.exe`), never modifies registry settings, and never installs Sysmon automatically. Missing audit policies simply mean corresponding events are not emitted by Windows; the agent reports source availability transparently in diagnostics.

---

## 4. Network & TLS Security

- **Strict Certificate Validation**: Transport defaults to `tls_verify: true` using Python's standard `ssl.create_default_context()`. Certificate chains and hostnames are validated.
- **Private PKI Support**: For enterprise environments using internal Certificate Authorities (CAs), `ca_bundle` can be configured to point to an approved PEM certificate bundle.
- **Bounded Exponential Backoff**: The agent never overwhelms remote servers during outages. It enforces maximum retries and randomized jitter to prevent "thundering herd" conditions upon backend recovery.

---

## 5. Privacy & Data Redaction

Security logs often inadvertently contain credentials (e.g., users accidentally typing passwords into username fields). The agent applies automated sanitization before events enter local storage:

- **Raw Event Sanitization**: Regular expression filters mask patterns such as `password=<val>`, `passwd=<val>`, `secret=<val>`, or `token=<val>` as `[REDACTED]`.
- **Attribute Scrubbing**: Key-value metadata dictionaries are recursively inspected. Any key matching credential keywords (`password`, `secret`, `token`, `api_key`) is replaced with `[REDACTED]`.
- **Process Creation Command-Line Privacy**: To protect command-line parameters (which frequently contain database passwords, API tokens, or personal identifiers), process creation events (Event 4688 and Sysmon 1) exclude `CommandLine` arguments by default (`include_command_line: false`).

---

## 6. Prohibited Behaviors & Non-Features

The agent explicitly rejects features that compromise endpoint safety:
- **No Arbitrary Remote Execution**: The agent cannot execute remote shell commands sent by the backend.
- **No Stealth or Anti-Detection**: The agent does not hook rootkits, conceal processes, or tamper with system audit trails.
- **No Automatic File Execution**: Optional future file scanning (Milestone 5) is strictly static analysis (cryptographic hashing, entropy calculation). The agent will never automatically execute unknown or suspicious binaries.
