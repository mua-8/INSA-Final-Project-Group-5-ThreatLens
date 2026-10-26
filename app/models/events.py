"""Data contracts for ThreatLens SIEM log ingestion and parsing."""

from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuthEventType(str, Enum):
    """Enumeration of recognized authentication and session event types."""

    FAILED_LOGIN = "FAILED_LOGIN"
    INVALID_USER = "INVALID_USER"
    ACCEPTED_LOGIN = "ACCEPTED_LOGIN"
    DISCONNECT = "DISCONNECT"
    UNKNOWN = "UNKNOWN"


class ParsedAuthEvent(BaseModel):
    """Normalized data representation of a parsed authentication log line.

    Preserves the original raw log line verbatim for auditability and compliance,
    while extracting structured metadata and security context where available.
    """

    model_config = ConfigDict(frozen=False, extra="ignore")

    raw_log: str = Field(
        ...,
        description="The exact unparsed original log line, preserved for auditing and traceability.",
    )
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Normalized event timestamp in UTC timezone.",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Originating host or device name reporting the event.",
    )
    service: Optional[str] = Field(
        default="sshd",
        description="Service or daemon originating the event (typically sshd).",
    )
    event_type: AuthEventType = Field(
        default=AuthEventType.UNKNOWN,
        description="Classified authentication or session event type.",
    )
    auth_method: Optional[str] = Field(
        default=None,
        description="Authentication mechanism utilized (e.g. password, publickey, keyboard-interactive).",
    )
    username: Optional[str] = Field(
        default=None,
        description="Target username involved in the authentication event.",
    )
    src_ip: Optional[str] = Field(
        default=None,
        description="Source IP address (IPv4 or IPv6) of the remote client.",
    )
    src_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Source port number of the remote connection (1-65535).",
    )
    is_malformed: bool = Field(
        default=False,
        description="True if the line was structurally corrupted or unparseable. Distinct from UNKNOWN event type.",
    )
    parsing_error: Optional[str] = Field(
        default=None,
        description="Diagnostic description if the line was marked malformed or failed validation.",
    )
    line_number: Optional[int] = Field(
        default=None,
        ge=1,
        description="1-based line number of the entry within the ingested batch or file.",
    )
    is_invalid_user: bool = Field(
        default=False,
        description="True if the event indicates an attempt involving a non-existent or invalid user.",
    )

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp_to_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        """Ensure any timestamp is consistently converted to UTC."""
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("src_ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate that source IP is a syntactically valid IPv4 or IPv6 address when present."""
        if v is None:
            return None
        trimmed = v.strip()
        if not trimmed:
            return None
        try:
            ipaddress.ip_address(trimmed)
            return trimmed
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: '{v}'") from exc

    @field_validator("src_port")
    @classmethod
    def validate_port_range(cls, v: Optional[int]) -> Optional[int]:
        """Validate port range 1-65535 when provided."""
        if v is None:
            return None
        if not (1 <= v <= 65535):
            raise ValueError(f"Source port must be between 1 and 65535 inclusive, got {v}")
        return v


class ParsingStatistics(BaseModel):
    """Aggregate statistics for an ingestion job or batch."""

    model_config = ConfigDict(frozen=False)

    total_lines: int = Field(
        default=0,
        ge=0,
        description="Total number of log lines ingested.",
    )
    parsed_count: int = Field(
        default=0,
        ge=0,
        description="Number of log lines successfully parsed into structured events.",
    )
    malformed_count: int = Field(
        default=0,
        ge=0,
        description="Number of lines flagged as malformed / unparseable.",
    )
    duplicate_count: int = Field(
        default=0,
        ge=0,
        description="Number of duplicate lines or duplicate batches detected.",
    )
    processing_time_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Processing duration in milliseconds.",
    )


class IngestionReport(BaseModel):
    """Structured response contract for log ingestion operations."""

    model_config = ConfigDict(frozen=False)

    status: str = Field(
        default="success",
        description="Ingestion execution status (e.g. success, partial, failed, duplicate).",
    )
    message: str = Field(
        default="Log ingestion completed",
        description="Human-readable summary of ingestion execution.",
    )
    statistics: ParsingStatistics = Field(
        default_factory=ParsingStatistics,
        description="Detailed ingestion metrics and line accounting.",
    )
    events: List[ParsedAuthEvent] = Field(
        default_factory=list,
        description="List of structured parsed authentication events produced by the ingestion.",
    )
    batch_id: Optional[str] = Field(
        default=None,
        description="Unique identifier for the ingested batch or file.",
    )
    file_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 digest of the ingested file or text payload for deduplication tracking.",
    )
