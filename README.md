# ThreatLens SIEM

ThreatLens is a defensive Security Information and Event Management (SIEM)
project. It combines backend event ingestion and detection, a web dashboard,
and an endpoint agent that collects and forwards host telemetry.

## Components

- `backend/` — SIEM API, endpoint-event ingestion, persistence, and related
  backend services.
- `app/` — log ingestion, parsing, event models, and associated services.
- `frontend/` — React/Vite security operations dashboard.
- `endpoint-agent/` — Python agent for Linux authentication telemetry and
  supported Windows Security/Sysmon event normalization, local SQLite
  buffering, and HTTP forwarding.
- `tests/` — SIEM backend tests.
- `endpoint-agent/tests/` — endpoint-agent unit and integration tests.

## Requirements

- Python 3.10 or newer for the endpoint agent.
- Python dependencies specified by the SIEM project.
- Node.js and npm for the frontend.
- Linux host for native Linux authentication collection. Native Windows
  collection must be verified on a Windows host with appropriate permissions.

## Backend setup

Create and activate a Python virtual environment appropriate for this
repository, then install the backend dependencies specified by the project's
dependency files.

Run the SIEM backend using the project's configured entry point. For the
local integration demo, the Flask application is imported from
`backend.api` and served on a loopback address.

## Endpoint-agent setup

From the repository root:

```bash
cd endpoint-agent
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Configure the agent using `endpoint-agent/config/agent.example.yaml` as a
reference. Set the backend URL and API key for your environment. Never commit
real credentials or production secrets.

The continuous loop script requires `THREATLENS_API_KEY` to be set. It
defaults to the local backend URL `http://127.0.0.1:5000`; set
`THREATLENS_BACKEND_URL` when the backend is elsewhere.

## Endpoint ingestion contract

The endpoint agent submits batches to `POST /api/v1/events` using a Bearer
API key. The backend requires `THREATLENS_AGENT_API_KEY` to be configured.
See `endpoint-agent/docs/API_CONTRACT.md` for the request, validation,
acknowledgement, and retry behavior.

## Tests and build

Run the SIEM backend tests from the repository root:

```bash
python -m pytest tests -q
```

Run the endpoint-agent tests from `endpoint-agent/` as shown above.

Build the frontend:

```bash
cd frontend
npm install
npm run build
```

## Integration demo

The integration smoke test is maintained at `scripts/integration_smoke_test.py`. It uses a temporary database,
a randomly generated demo API key, and synthetic events. Review the script
before running it and ensure its configured Python interpreter paths exist.

## Security notes

- Use only authorized systems and test data.
- Keep API keys and environment files out of version control.
- The endpoint agent buffers pending telemetry locally and forwards it to
  the configured SIEM backend.
- Synthetic Windows events in tests do not replace testing native collection
  on a real Windows host with the required audit settings and permissions.
