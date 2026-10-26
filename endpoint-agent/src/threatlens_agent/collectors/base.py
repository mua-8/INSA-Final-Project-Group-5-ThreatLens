"""Base collector contract for future platform-specific telemetry collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from threatlens_agent.models.events import Event


class BaseCollector(ABC):
    """Abstract interface for event sources across platforms."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this collector."""

    @abstractmethod
    def is_supported(self) -> bool:
        """Check whether the collector can run on the current host system."""

    @abstractmethod
    def start(self) -> None:
        """Initialize and start background collection if applicable."""

    @abstractmethod
    def stop(self) -> None:
        """Gracefully stop collector resources."""

    @abstractmethod
    def collect(self) -> list[Event]:
        """Poll and return a batch of newly observed events."""
