"""Business logic, ingestion pipelines, and deduplication services."""

from app.services.ingestion import ingest_log_lines

__all__ = ["ingest_log_lines"]
