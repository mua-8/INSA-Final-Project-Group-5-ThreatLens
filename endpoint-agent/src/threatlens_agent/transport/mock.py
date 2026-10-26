"""Mock transport and mock HTTP server for testing and local simulation."""

from __future__ import annotations

import http.server
import json
import logging
import socketserver
import threading
from typing import Any

from threatlens_agent.models.events import Event
from threatlens_agent.transport.base import BaseTransport, TransportResult

logger = logging.getLogger(__name__)


class MockTransport(BaseTransport):
    """In-memory mock transport for controlled unit and integration testing."""

    def __init__(
        self,
        should_succeed: bool = True,
        status_code: int = 200,
        fail_with_retryable: bool = True,
        error_message: str = "Simulated network failure",
        partial_ack_count: int | None = None,
    ) -> None:
        self.should_succeed = should_succeed
        self.status_code = status_code
        self.fail_with_retryable = fail_with_retryable
        self.error_message = error_message
        self.partial_ack_count = partial_ack_count

        self.sent_batches: list[list[Event]] = []
        self.calls_count: int = 0

    def is_available(self) -> bool:
        return True

    def send_batch(self, events: list[Event]) -> TransportResult:
        self.calls_count += 1
        self.sent_batches.append(events)

        if not self.should_succeed:
            return TransportResult(
                success=False,
                acknowledged_event_ids=[],
                retryable=self.fail_with_retryable,
                status_code=self.status_code,
                error_message=self.error_message,
            )

        if self.partial_ack_count is not None:
            acked = [ev.event_id for ev in events[: self.partial_ack_count]]
        else:
            acked = [ev.event_id for ev in events]

        return TransportResult(
            success=True,
            acknowledged_event_ids=acked,
            retryable=False,
            status_code=self.status_code,
        )

    def close(self) -> None:
        """No-op for in-memory mock."""


class MockServerRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handler for the mock backend HTTP test server."""

    server: MockHttpServer  # Type annotation for reference

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard stderr request logging during tests."""

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        # Record incoming request in server
        self.server.received_requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": post_data.decode("utf-8") if post_data else "",
            }
        )

        response_status = self.server.configured_status
        response_body = self.server.configured_body

        if response_body is None:
            # Default auto-acknowledgment
            try:
                data = json.loads(post_data.decode("utf-8")) if post_data else {}
                events = data.get("events", [])
                ack_ids = [e.get("event_id") for e in events if "event_id" in e]
                payload = json.dumps({"status": "ok", "acknowledged": ack_ids})
            except Exception:
                payload = json.dumps({"status": "ok", "acknowledged": []})
        else:
            payload = response_body

        self.send_response(response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))


class MockHttpServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded local mock HTTP server for transport integration tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        super().__init__((host, port), MockServerRequestHandler)
        self.received_requests: list[dict[str, Any]] = []
        self.configured_status: int = 200
        self.configured_body: str | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)

    @property
    def url(self) -> str:
        host, port = self.server_address
        return f"http://{host}:{port}"
