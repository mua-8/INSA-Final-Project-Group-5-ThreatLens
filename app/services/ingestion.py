"""Log ingestion service for ThreatLens SIEM.

Coordinates batch ingestion of raw OpenSSH log lines into normalized
ParsedAuthEvent objects, collecting execution metrics and parsing statistics.
"""

from datetime import datetime, timezone
import time
from typing import Iterable, List, Optional

from app.models.events import (
    AuthEventType,
    IngestionReport,
    ParsedAuthEvent,
    ParsingStatistics,
)
from app.parsers.openssh import parse_openssh_line


def ingest_log_lines(
    lines: Iterable[str],
    reference_time: Optional[datetime] = None,
) -> IngestionReport:
    """Ingest and parse an iterable of raw OpenSSH log lines.

    Processes input lines sequentially, assigning 1-based line numbers,
    normalizing timestamps against a consistent batch reference time,
    safely isolating errors on individual lines, and aggregating statistics.

    Args:
        lines: An iterable of raw log line strings.
        reference_time: Optional reference datetime for syslog year inference.
            If omitted, the current UTC time is captured once at batch start.

    Returns:
        IngestionReport containing parsing statistics and parsed events.
    """
    start_time = time.perf_counter()

    # Determine a single, consistent UTC reference time for the entire batch
    if reference_time is not None:
        batch_ref_time = (
            reference_time.astimezone(timezone.utc)
            if reference_time.tzinfo is not None
            else reference_time.replace(tzinfo=timezone.utc)
        )
    else:
        batch_ref_time = datetime.now(timezone.utc)

    events: List[ParsedAuthEvent] = []
    parsed_count = 0
    malformed_count = 0

    for line_number, line in enumerate(lines, start=1):
        try:
            event = parse_openssh_line(
                raw_log=line,
                reference_time=batch_ref_time,
                line_number=line_number,
            )
        except Exception as exc:
            # Unexpected parser exception: record as malformed without aborting the batch
            event = ParsedAuthEvent(
                raw_log=line,
                event_type=AuthEventType.UNKNOWN,
                is_malformed=True,
                parsing_error=f"Unexpected parser failure: {exc}",
                line_number=line_number,
            )

        events.append(event)
        if event.is_malformed:
            malformed_count += 1
        else:
            parsed_count += 1

    total_lines = len(events)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    statistics = ParsingStatistics(
        total_lines=total_lines,
        parsed_count=parsed_count,
        malformed_count=malformed_count,
        duplicate_count=0,
        processing_time_ms=elapsed_ms,
    )

    message = f"Successfully processed {total_lines} lines ({parsed_count} parsed, {malformed_count} malformed)"

    return IngestionReport(
        status="success",
        message=message,
        statistics=statistics,
        events=events,
    )
