"""Windows Event Log querying adapters supporting live PowerShell execution and synthetic test injection."""

from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseWindowsEventAdapter(ABC):
    """Abstract interface for querying Windows Event Log channels."""

    @abstractmethod
    def query_events(
        self,
        channel: str,
        event_ids: list[int] | None = None,
        after_record_id: int | None = None,
        max_events: int = 100,
    ) -> list[dict[str, Any]]:
        """Query and return batch of event records matching criteria."""

    @abstractmethod
    def is_channel_available(self, channel: str) -> bool:
        """Check whether the specified event log channel exists and is accessible."""

    @abstractmethod
    def check_permissions(self, channel: str) -> tuple[bool, str | None]:
        """Check whether current process has read permissions for the channel.

        Returns (is_permitted, failure_reason).
        """


class PowershellWindowsEventAdapter(BaseWindowsEventAdapter):
    """Production Windows event query adapter executing Get-WinEvent via PowerShell.

    Isolates all Windows-specific process calls and safely reports unavailable on Linux.
    """

    def __init__(self, powershell_path: str | None = None) -> None:
        self._ps_path = powershell_path or self._find_powershell()

    @staticmethod
    def _find_powershell() -> str | None:
        """Locate powershell.exe or pwsh executable."""
        return shutil.which("powershell.exe") or shutil.which("pwsh") or shutil.which("powershell")

    def is_channel_available(self, channel: str) -> bool:
        """Check whether channel exists on Windows."""
        if platform.system() != "Windows" or not self._ps_path:
            return False

        cmd = [
            self._ps_path,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogNames() -contains '{channel}'",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            return "true" in res.stdout.strip().lower()
        except Exception as exc:
            logger.debug("Failed probing channel availability for %s: %s", channel, exc)
            return False

    def check_permissions(self, channel: str) -> tuple[bool, str | None]:
        """Check read access to event channel."""
        if platform.system() != "Windows":
            return False, "Host is not running Windows"
        if not self._ps_path:
            return False, "PowerShell executable not found"

        cmd = [
            self._ps_path,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"try {{ [void](Get-WinEvent -LogName '{channel}' -MaxEvents 1 -ErrorAction Stop); Write-Output 'OK' }} catch {{ Write-Output $_.Exception.Message }}",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            output = res.stdout.strip()
            if output == "OK" or "No events were found" in output:
                return True, None
            if "Access is denied" in output or "UnauthorizedAccess" in output:
                return False, f"Permission denied accessing channel '{channel}'"
            return False, output
        except Exception as exc:
            return False, f"Failed checking permissions: {exc}"

    def query_events(
        self,
        channel: str,
        event_ids: list[int] | None = None,
        after_record_id: int | None = None,
        max_events: int = 100,
    ) -> list[dict[str, Any]]:
        """Query events using Get-WinEvent XML filter for high performance."""
        if platform.system() != "Windows" or not self._ps_path:
            return []

        # Construct XPath / XML query
        predicates: list[str] = []
        if event_ids:
            id_subquery = " or ".join(f"EventID={eid}" for eid in event_ids)
            predicates.append(f"({id_subquery})")
        if after_record_id is not None and after_record_id > 0:
            predicates.append(f"EventRecordID > {after_record_id}")

        filter_clause = " and ".join(predicates) if predicates else "*"
        xml_query = (
            f"<QueryList><Query Id='0' Path='{channel}'>"
            f"<Select Path='{channel}'>*[System[{filter_clause}]]</Select>"
            f"</Query></QueryList>"
        )

        ps_script = f"""
        $ErrorActionPreference = 'Stop'
        try {{
            $xml = @'
{xml_query}
'@
            $events = Get-WinEvent -FilterXml $xml -MaxEvents {max_events} -Oldest
            $result = @()
            foreach ($e in $events) {{
                $data = @{{
                    'Id' = $e.Id
                    'RecordId' = $e.RecordId
                    'TimeCreated' = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
                    'ProviderName' = $e.ProviderName
                    'Channel' = $e.LogName
                    'Computer' = $e.MachineName
                }}
                $xmlObj = [xml]$e.ToXml()
                if ($xmlObj.Event.EventData.Data) {{
                    $eventData = @{{}}
                    foreach ($d in $xmlObj.Event.EventData.Data) {{
                        if ($d.Name) {{ $eventData[$d.Name] = $d.'#text' }}
                    }}
                    $data['EventData'] = $eventData
                }}
                $result += $data
            }}
            $result | ConvertTo-Json -Compress -Depth 4
        }} catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {{
            Write-Output '[]'
        }} catch {{
            if ($_.Exception.Message -match 'No events were found') {{
                Write-Output '[]'
            }} else {{
                throw $_
            }}
        }}
        """

        cmd = [self._ps_path, "-NoProfile", "-NonInteractive", "-Command", ps_script]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
            if res.returncode != 0:
                err_msg = res.stderr.strip() or res.stdout.strip()
                if "No events were found" in err_msg:
                    return []
                logger.warning("PowerShell query failed (exit %d): %s", res.returncode, err_msg)
                return []

            out = res.stdout.strip()
            if not out or out == "[]":
                return []
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, list):
                return parsed
            return []
        except subprocess.TimeoutExpired:
            logger.warning("PowerShell query timed out after 15 seconds")
            return []
        except Exception as exc:
            logger.warning("Failed executing PowerShell event query: %s", exc)
            return []


class SyntheticWindowsEventAdapter(BaseWindowsEventAdapter):
    """Injectable synthetic event adapter for automated tests and offline simulation."""

    def __init__(
        self,
        records: list[dict[str, Any]] | None = None,
        available_channels: set[str] | None = None,
        permission_denied_channels: set[str] | None = None,
    ) -> None:
        self.records: list[dict[str, Any]] = list(records or [])
        self.available_channels = (
            set(available_channels)
            if available_channels is not None
            else {"Security", "Microsoft-Windows-Sysmon/Operational"}
        )
        self.permission_denied_channels = set(permission_denied_channels or [])
        self.simulate_query_error: Exception | None = None
        self.queries_executed: list[dict[str, Any]] = []

    def add_record(self, record: dict[str, Any]) -> None:
        """Append a single synthetic record."""
        self.records.append(record)

    def add_records(self, records: list[dict[str, Any]]) -> None:
        """Append multiple synthetic records."""
        self.records.extend(records)

    def is_channel_available(self, channel: str) -> bool:
        """Check channel availability against configured set."""
        return channel in self.available_channels

    def check_permissions(self, channel: str) -> tuple[bool, str | None]:
        """Check channel permissions against configured denied set."""
        if channel in self.permission_denied_channels:
            return False, f"Access is denied to channel '{channel}'"
        if channel not in self.available_channels:
            return False, f"Channel '{channel}' is unavailable"
        return True, None

    def query_events(
        self,
        channel: str,
        event_ids: list[int] | None = None,
        after_record_id: int | None = None,
        max_events: int = 100,
    ) -> list[dict[str, Any]]:
        """Query synthetic records with filtering and bounds."""
        self.queries_executed.append(
            {
                "channel": channel,
                "event_ids": event_ids,
                "after_record_id": after_record_id,
                "max_events": max_events,
            }
        )

        if self.simulate_query_error is not None:
            raise self.simulate_query_error

        if channel in self.permission_denied_channels:
            raise PermissionError(f"Access is denied to channel '{channel}'")

        if channel not in self.available_channels:
            return []

        matched: list[dict[str, Any]] = []
        for rec in self.records:
            rec_channel = rec.get("Channel") or "Security"
            if rec_channel.lower() != channel.lower():
                continue

            rec_id_val = rec.get("Id") or rec.get("EventID")
            if event_ids is not None and rec_id_val not in event_ids:
                continue

            rec_record_id = rec.get("RecordId") or rec.get("EventRecordID") or 0
            if after_record_id is not None and rec_record_id <= after_record_id:
                continue

            matched.append(rec)

        # Sort by record ID ascending
        matched.sort(key=lambda r: int(r.get("RecordId") or r.get("EventRecordID") or 0))
        return matched[:max_events]
