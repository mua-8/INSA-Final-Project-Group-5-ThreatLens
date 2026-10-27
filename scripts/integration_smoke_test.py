import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SIEM_DIR = Path(__file__).resolve().parents[1]
AGENT_DIR = SIEM_DIR / "endpoint-agent"
SIEM_PY = SIEM_DIR / ".venv-integration" / "bin" / "python"
AGENT_PY = AGENT_DIR / ".venv" / "bin" / "python"


def request_json(url, method="GET", payload=None, headers=None):
    request_headers = dict(headers or {})
    body = None

    if payload is not None:
        body = json.dumps(payload).encode()
        request_headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url, data=body, headers=request_headers, method=method
    )

    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else {}


def main():
    assert SIEM_PY.is_file(), f"SIEM Python not found: {SIEM_PY}"
    assert AGENT_PY.is_file(), f"Agent Python not found: {AGENT_PY}"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    base_url = f"http://127.0.0.1:{port}"
    api_key = secrets.token_urlsafe(32)

    print("=" * 65)
    print("THREATLENS SIEM + ENDPOINT AGENT INTEGRATION TEST")
    print("=" * 65)

    # All demo data lives in a temporary directory outside the repository.
    with tempfile.TemporaryDirectory(prefix="threatlens-demo-") as tmp:
        temp_dir = Path(tmp)
        db_path = temp_dir / "siem.db"
        agent_data = temp_dir / "agent-data"
        events_path = temp_dir / "events.json"
        server_log_path = temp_dir / "server.log"

        env = os.environ.copy()
        env["THREATLENS_DB"] = str(db_path)
        env["THREATLENS_AGENT_API_KEY"] = api_key
        env["PYTHONPATH"] = str(SIEM_DIR)

        server = None

        with server_log_path.open("w+") as server_log:
            try:
                server = subprocess.Popen(
                    [
                        str(SIEM_PY),
                        "-c",
                        (
                            "from backend.api import app; "
                            f"app.run(host='127.0.0.1', port={port}, "
                            "debug=False, use_reloader=False)"
                        ),
                    ],
                    cwd=SIEM_DIR,
                    env=env,
                    stdout=server_log,
                    stderr=subprocess.STDOUT,
                )

                # Wait for the API to become ready.
                for _ in range(50):
                    if server.poll() is not None:
                        raise RuntimeError(
                            f"SIEM server exited with code {server.returncode}"
                        )
                    try:
                        with urllib.request.urlopen(
                            base_url + "/", timeout=1
                        ) as response:
                            if response.status == 200:
                                break
                    except Exception:
                        time.sleep(0.2)
                else:
                    raise RuntimeError("SIEM API did not become ready")

                print("[PASS] SIEM API started with an isolated database")

                # Run the actual agent against the local SIEM API.
                # Paths and credentials are passed through environment variables.
                agent_code = r'''
import json
import os
import uuid
from datetime import datetime, timezone

from threatlens_agent.agent import ThreatLensAgent
from threatlens_agent.config import AgentConfig, QueueConfig, TransportConfig
from threatlens_agent.models.events import Event, EventSeverity

device_name = "demo-node-01"
base_url = os.environ["DEMO_BASE_URL"]
api_key = os.environ["DEMO_API_KEY"]
data_dir = os.environ["DEMO_AGENT_DATA"]
events_path = os.environ["DEMO_EVENTS_PATH"]

config = AgentConfig(
    display_name=device_name,
    data_dir=data_dir,
    batch_size=50,
    queue=QueueConfig(retention_policy="delete_on_delivery"),
    transport=TransportConfig(
        backend_url=base_url,
        events_endpoint="/api/v1/events",
        api_key=api_key,
        max_retries=2,
    ),
)

agent = ThreatLensAgent(config)

def timestamp():
    return datetime.now(timezone.utc).isoformat()

events = [
    Event(
        event_id=str(uuid.uuid4()),
        device_id=agent.device_info.device_id,
        timestamp=timestamp(),
        source="linux_auth",
        event_type="ssh_auth_failure",
        severity=EventSeverity.HIGH,
        source_ip="192.168.1.101",
        username="root",
        raw_event="Failed password for root from 192.168.1.101 port 52210 ssh2",
        attributes={"port": 52210, "service": "ssh"},
    ),
    Event(
        event_id=str(uuid.uuid4()),
        device_id=agent.device_info.device_id,
        timestamp=timestamp(),
        source="windows_event",
        event_type="windows_logon_failure",
        severity=EventSeverity.HIGH,
        source_ip="192.168.1.105",
        username="Administrator",
        raw_event="An account failed to log on. Event ID: 4625",
        attributes={"event_id": 4625, "channel": "Security", "logon_type": 3},
    ),
    Event(
        event_id=str(uuid.uuid4()),
        device_id=agent.device_info.device_id,
        timestamp=timestamp(),
        source="sysmon",
        event_type="sysmon_process_creation",
        severity=EventSeverity.INFORMATIONAL,
        source_ip=None,
        username="SYSTEM",
        raw_event="Process Create: whoami.exe /priv",
        attributes={"event_id": 1, "image": "whoami.exe", "process_id": 8412},
    ),
]

try:
    agent.record_events(events)
    print(f"Agent queued {len(events)} synthetic events.")

    with open(events_path, "w", encoding="utf-8") as file:
        json.dump([event.to_dict() for event in events], file)

    flushed = agent.flush()
    print(f"Agent flush result: {flushed!r}")
finally:
    agent.close()
'''

                agent_env = os.environ.copy()
                agent_env.update({
                    "DEMO_BASE_URL": base_url,
                    "DEMO_API_KEY": api_key,
                    "DEMO_AGENT_DATA": str(agent_data),
                    "DEMO_EVENTS_PATH": str(events_path),
                })

                result = subprocess.run(
                    [str(AGENT_PY), "-c", agent_code],
                    cwd=AGENT_DIR,
                    env=agent_env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                print(result.stdout, end="")

                if result.returncode != 0:
                    raise RuntimeError(
                        "Endpoint agent failed:\n" + result.stderr
                    )

                # Verify that the backend persisted all three events.
                status, stored = request_json(base_url + "/api/v1/events")
                assert status == 200, f"Unexpected GET status: {status}"
                assert stored.get("count") == 3, (
                    f"Expected 3 stored events, got {stored.get('count')}"
                )
                print("[PASS] SIEM stored all 3 agent events")

                with events_path.open(encoding="utf-8") as file:
                    event_dicts = json.load(file)

                headers = {"Authorization": f"Bearer {api_key}"}
                payload = {
                    "device_id": event_dicts[0]["device_id"],
                    "events": event_dicts,
                }

                # Retrying identical events must be idempotent.
                status, retry = request_json(
                    base_url + "/api/v1/events",
                    method="POST",
                    payload=payload,
                    headers=headers,
                )
                assert status == 200, f"Retry returned HTTP {status}"
                assert len(retry.get("acknowledged", [])) == 3, (
                    "Retry did not acknowledge all 3 event IDs"
                )
                print("[PASS] Identical retry acknowledged all 3 events")

                # Reusing an ID with changed content must return HTTP 409.
                changed_event = dict(
                    event_dicts[0],
                    severity="critical",
                    username="demo-tampered-user",
                )
                conflict_payload = {
                    "device_id": payload["device_id"],
                    "events": [changed_event],
                }

                try:
                    request_json(
                        base_url + "/api/v1/events",
                        method="POST",
                        payload=conflict_payload,
                        headers=headers,
                    )
                except urllib.error.HTTPError as error:
                    if error.code != 409:
                        raise AssertionError(
                            f"Expected HTTP 409, got HTTP {error.code}"
                        ) from error
                else:
                    raise AssertionError(
                        "Changed event with an existing ID was not rejected"
                    )

                print("[PASS] Conflicting duplicate rejected with HTTP 409")

                # Check the existing SSH log ingestion pipeline.
                ssh_lines = [
                    (
                        f"Oct 24 14:00:0{i} srv1 sshd[{100+i}]: "
                        "Failed password for root from "
                        f"198.51.100.77 port {40000+i} ssh2"
                    )
                    for i in range(1, 6)
                ]
                ingest_req = urllib.request.Request(
                    base_url + "/api/ingest",
                    data=("\n".join(ssh_lines) + "\n").encode(),
                    headers={"X-Filename": "demo_ssh.log"},
                    method="POST",
                )

                with urllib.request.urlopen(ingest_req, timeout=10) as response:
                    ingest = json.loads(response.read().decode())

                data = ingest.get("data", {})
                stored_count = data.get("events_stored")
                assert stored_count == 5, (
                    f"Expected 5 ingested SSH events, got {stored_count!r}"
                )
                print(
                    "[PASS] SSH ingestion stored 5 events; "
                    f"new alerts reported: {data.get('new_alerts', 'unknown')}"
                )

                print("\nALL INTEGRATION ASSERTIONS PASSED")

            finally:
                if server is not None and server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)

                # Show server output only if the test failed.
                if sys.exc_info()[0] is not None:
                    server_log.seek(0)
                    print("\n--- SIEM server log ---", file=sys.stderr)
                    print(server_log.read(), file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nINTEGRATION TEST FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
