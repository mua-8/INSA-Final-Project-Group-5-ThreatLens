"""Transport abstraction for transmitting telemetry events to remote services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from threatlens_agent.models.events import Event


@dataclass
class TransportResult:
    """Outcome of an event batch transmission attempt."""

    success: bool
    acknowledged_event_ids: list[str] = field(default_factory=list)
    retryable: bool = False
    status_code: int | None = None
    error_message: str | None = None

    @property
    def acknowledged_count(self) -> int:
        return len(self.acknowledged_event_ids)


class BaseTransport(ABC):
    """Abstract interface for event transport implementations."""

    @abstractmethod
    def send_batch(self, events: list[Event]) -> TransportResult:
        """Transmit a batch of events to the receiving service."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the transport is configured and operational."""

    @abstractmethod
    def close(self) -> None:
        """Release underlying network resources."""
