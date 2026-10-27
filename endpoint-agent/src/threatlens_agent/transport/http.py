"""HTTP/HTTPS transport implementation with bounded retries and jitter."""

from __future__ import annotations

import json
import logging
import random
import ssl
import time
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threatlens_agent import __version__
from threatlens_agent.config import TransportConfig
from threatlens_agent.models.events import Event
from threatlens_agent.transport.base import BaseTransport, TransportResult

logger = logging.getLogger(__name__)


class HttpTransport(BaseTransport):
    """Secure HTTPS transport with bounded exponential backoff, jitter, and cert validation."""

    def __init__(
        self,
        config: TransportConfig,
        device_id: str | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.device_id = device_id or "unknown"
        self._sleep = sleep_fn
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with strict certificate verification by default."""
        if not self.config.tls_verify:
            logger.warning(
                "TLS verification is explicitly DISABLED. Not recommended in production."
            )
            ctx = ssl._create_unverified_context()
            return ctx

        ctx = ssl.create_default_context()
        if self.config.ca_bundle:
            ctx.load_verify_locations(cafile=self.config.ca_bundle)
        return ctx

    def is_available(self) -> bool:
        """Return True if backend_url is configured."""
        return bool(self.config.backend_url)

    def _build_url(self) -> str:
        """Construct full target URL from base URL and endpoint path."""
        if not self.config.backend_url:
            raise ValueError("Cannot transmit: transport.backend_url is not configured")
        base = self.config.backend_url.rstrip("/")
        endpoint = self.config.events_endpoint.lstrip("/")
        return f"{base}/{endpoint}"

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate bounded exponential backoff with jitter."""
        # Exponential delay: base * (2 ** attempt)
        delay = self.config.backoff_base_seconds * (2**attempt)
        delay = min(delay, self.config.backoff_max_seconds)

        # Apply jitter
        if self.config.jitter_ratio > 0:
            jitter_range = delay * self.config.jitter_ratio
            delay = delay + random.uniform(-jitter_range, jitter_range)

        return max(0.0, delay)

    def send_batch(self, events: list[Event]) -> TransportResult:
        """Transmit a batch of events with bounded retries."""
        if not events:
            return TransportResult(success=True, acknowledged_event_ids=[])

        if not self.is_available():
            return TransportResult(
                success=False,
                retryable=True,
                error_message="Transport unavailable: backend_url is not configured",
            )

        target_url = self._build_url()
        event_ids = [ev.event_id for ev in events]
        payload_data = {
            "device_id": self.device_id,
            "agent_version": __version__,
            "sent_at": time.time(),
            "events": [ev.to_dict() for ev in events],
        }
        body = json.dumps(payload_data).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"ThreatLens-Agent/{__version__}",
            "X-Device-ID": self.device_id,
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        timeout = self.config.connect_timeout_seconds + self.config.read_timeout_seconds
        last_error = ""
        last_status: int | None = None

        # Total attempts = 1 (initial) + max_retries
        total_attempts = 1 + self.config.max_retries

        for attempt in range(total_attempts):
            req = Request(target_url, data=body, headers=headers, method="POST")
            try:
                with urlopen(req, timeout=timeout, context=self._ssl_context) as resp:
                    status = resp.status
                    raw_body = resp.read().decode("utf-8")

                # Handle successful HTTP status
                if 200 <= status < 300:
                    acknowledged_ids = self._parse_acknowledgments(raw_body, event_ids)
                    logger.info(
                        "Successfully transmitted %d events to backend (status %d)",
                        len(acknowledged_ids),
                        status,
                    )
                    return TransportResult(
                        success=True,
                        acknowledged_event_ids=acknowledged_ids,
                        retryable=False,
                        status_code=status,
                    )

            except HTTPError as exc:
                last_status = exc.code
                last_error = f"HTTP {exc.code}: {exc.reason}"
                logger.warning(
                    "Transport attempt %d/%d failed with %s",
                    attempt + 1,
                    total_attempts,
                    last_error,
                )

                # Client errors (4xx) except 429 Too Many Requests are non-retryable
                if 400 <= exc.code < 500 and exc.code != 429:
                    return TransportResult(
                        success=False,
                        retryable=False,
                        status_code=exc.code,
                        error_message=f"Non-retryable client error: {last_error}",
                    )

            except URLError as exc:
                last_status = None
                last_error = f"Network connection error: {exc.reason}"
                logger.warning(
                    "Transport attempt %d/%d network failure: %s",
                    attempt + 1,
                    total_attempts,
                    last_error,
                )

            except TimeoutError as exc:
                last_status = None
                last_error = f"Connection timed out: {exc}"
                logger.warning(
                    "Transport attempt %d/%d timeout: %s",
                    attempt + 1,
                    total_attempts,
                    last_error,
                )

            except Exception as exc:
                last_status = None
                last_error = f"Unexpected transport exception: {exc}"
                logger.error(
                    "Transport attempt %d/%d unexpected error: %s",
                    attempt + 1,
                    total_attempts,
                    last_error,
                    exc_info=True,
                )

            # If more attempts remain, back off before retrying
            if attempt < total_attempts - 1:
                delay = self._calculate_backoff(attempt)
                logger.debug("Backing off for %.2f seconds before retry", delay)
                self._sleep(delay)

        return TransportResult(
            success=False,
            retryable=True,
            status_code=last_status,
            error_message=f"Exceeded max retries ({self.config.max_retries}). Last error: {last_error}",
        )

    def _parse_acknowledgments(self, response_body: str, default_event_ids: list[str]) -> list[str]:
        """Safely parse server acknowledgment response."""
        if not response_body or not response_body.strip():
            # Server returned 2xx with empty body; treat all sent events as acknowledged
            return default_event_ids

        try:
            data = json.loads(response_body)
            if isinstance(data, dict):
                # Check for explicit list of acknowledged IDs
                if "acknowledged" in data and isinstance(data["acknowledged"], list):
                    return [str(eid) for eid in data["acknowledged"]]
                if "acknowledged_event_ids" in data and isinstance(
                    data["acknowledged_event_ids"], list
                ):
                    return [str(eid) for eid in data["acknowledged_event_ids"]]
            # If JSON is valid but does not provide explicit IDs, treat all sent as acknowledged
            return default_event_ids
        except json.JSONDecodeError as exc:
            logger.warning(
                "Received HTTP 2xx but failed to parse response JSON: %s. "
                "Defaulting to all events acknowledged.",
                exc,
            )
            return default_event_ids

    def close(self) -> None:
        """Release any open transport resources."""
