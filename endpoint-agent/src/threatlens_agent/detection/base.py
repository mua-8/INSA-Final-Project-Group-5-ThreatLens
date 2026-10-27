"""Base detector abstraction for local telemetry analysis."""

from __future__ import annotations

from abc import ABC, abstractmethod

from threatlens_agent.models.events import Event


class BaseDetector(ABC):
    """Abstract interface for local heuristic and anomaly detection rules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector identifier."""

    @abstractmethod
    def analyze(self, events: list[Event]) -> list[Event]:
        """Analyze batch of newly observed events and return any detected alerts."""

    @abstractmethod
    def reset(self) -> None:
        """Reset internal detector state (e.g. for testing or reconfiguration)."""
