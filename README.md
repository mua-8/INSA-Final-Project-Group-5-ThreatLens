# ThreatLens SIEM — Log Ingestion and Parsing Module

## Overview
ThreatLens is a lightweight Security Information and Event Management (SIEM) system. This module is responsible for:
- Ingesting Linux OpenSSH authentication log text and uploaded files.
- Parsing syslog and OpenSSH events (timestamps, hostname, username, source IP, source port, authentication method, outcome).
- Classifying key security events (`FAILED_LOGIN`, `INVALID_USER`, `ACCEPTED_LOGIN`, `DISCONNECT`, `UNKNOWN`).
- Preserving original raw log lines verbatim for auditability and compliance.
- Safely handling malformed lines without pipeline interruption.
- Reporting comprehensive ingestion metrics and parsing statistics.
- Preventing duplicate uploads via payload hashing.

## Project Structure
```text
.
├── app/
│   ├── __init__.py
│   ├── api/             # FastAPI routers and ingestion endpoints (Phase 6)
│   ├── core/            # Configuration and security/hashing helpers
│   ├── models/          # Pydantic data models & contracts (Phase 2)
│   │   ├── __init__.py
│   │   └── events.py
│   ├── parsers/         # OpenSSH regex parsing engine (Phase 3)
│   └── services/        # Ingestion workflow & deduplication service (Phase 5)
├── tests/               # Unit and integration test suite
│   ├── __init__.py
│   └── test_models.py
├── requirements.txt
└── README.md
```

## Setup & Running Tests

### Virtual Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running Tests
```bash
pytest
```
