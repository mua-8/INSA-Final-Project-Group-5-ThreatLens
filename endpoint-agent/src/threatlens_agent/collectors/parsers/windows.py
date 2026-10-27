"""Normalization and parsing for Windows Security Event Log records and Sysmon telemetry."""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from threatlens_agent.models.events import Event, EventSeverity, EventValidationError

logger = logging.getLogger(__name__)

# Known Windows logon types
LOGON_TYPES: dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# XML namespace for Windows Event Log schema
EVT_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


def clean_str(val: Any) -> str | None:
    """Trim string and treat placeholder dashes or empty values as None."""
    if val is None:
        return None
    s = str(val).strip()
    if not s or s == "-":
        return None
    return s


def clean_ip(val: Any) -> str | None:
    """Validate and return clean IPv4 or IPv6 address string, or None if invalid or placeholder."""
    s = clean_str(val)
    if not s:
        return None
    # Strip port if present in IPv4 (e.g., 192.0.2.1:54321)
    if ":" in s and not s.startswith("[") and s.count(":") == 1:
        s = s.split(":", 1)[0]
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def clean_int(val: Any) -> int | None:
    """Parse numeric string or integer, including hex strings (e.g. 0x1f4)."""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s or s == "-":
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def parse_privilege_list(priv_val: Any) -> list[str]:
    """Parse Windows privilege list from multiline string or list."""
    if isinstance(priv_val, list):
        return [str(p).strip() for p in priv_val if str(p).strip()]
    if isinstance(priv_val, str):
        # Split on newlines, carriage returns, tabs, or whitespace
        tokens = re.split(r"[\r\n\t]+", priv_val)
        return [t.strip() for t in tokens if t.strip() and t.strip() != "-"]
    return []


def parse_event_timestamp(ts_val: Any) -> str:
    """Normalize raw timestamp into valid ISO-8601 UTC string."""
    if not ts_val:
        return datetime.now(timezone.utc).isoformat()

    s = str(ts_val).strip()

    # Handle PowerShell /Date(1730000000000)/ epoch format
    match = re.match(r"^/Date\((\d+)\)/$", s)
    if match:
        epoch_ms = int(match.group(1))
        dt = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
        return dt.isoformat()

    # Normalize trailing Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_xml_event(xml_str: str) -> dict[str, Any] | None:
    """Extract structured dictionary from raw Windows Event Log XML."""
    try:
        root = ET.fromstring(xml_str)
    except Exception as exc:
        logger.debug("Failed to parse XML event: %s", exc)
        return None

    # Handle with or without namespace
    def find_elem(parent: ET.Element, tag: str) -> ET.Element | None:
        el = parent.find(f"ns:{tag}", EVT_NS)
        if el is None:
            el = parent.find(tag)
        return el

    system = find_elem(root, "System")
    if system is None:
        return None

    data: dict[str, Any] = {}

    provider = find_elem(system, "Provider")
    if provider is not None:
        data["ProviderName"] = provider.attrib.get("Name")

    event_id_el = find_elem(system, "EventID")
    if event_id_el is not None and event_id_el.text:
        data["Id"] = clean_int(event_id_el.text)

    record_id_el = find_elem(system, "EventRecordID")
    if record_id_el is not None and record_id_el.text:
        data["RecordId"] = clean_int(record_id_el.text)

    time_created = find_elem(system, "TimeCreated")
    if time_created is not None:
        data["TimeCreated"] = time_created.attrib.get("SystemTime")

    channel_el = find_elem(system, "Channel")
    if channel_el is not None and channel_el.text:
        data["Channel"] = channel_el.text

    computer_el = find_elem(system, "Computer")
    if computer_el is not None and computer_el.text:
        data["Computer"] = computer_el.text

    # Extract EventData or UserData
    event_data = find_elem(root, "EventData")
    if event_data is not None:
        data_fields: dict[str, Any] = {}
        # Iterate over Data children
        for child in event_data:
            name = child.attrib.get("Name")
            if name:
                data_fields[name] = child.text
        data["EventData"] = data_fields

    return data


class WindowsEventParser:
    """Normalizes Windows Security Event Log records into common Event schema."""

    SUPPORTED_EVENT_IDS = {4625, 4624, 4672, 4688}

    def __init__(self, device_id: str, include_command_line: bool = False) -> None:
        self.device_id = device_id
        self.include_command_line = include_command_line

    def parse(self, record: dict[str, Any] | str) -> Event | None:
        """Parse and normalize a Windows Event Log record (dict or XML string).

        Returns normalized Event, or None if unsupported, ignored, or malformed.
        """
        raw_dict: dict[str, Any]
        raw_str: str | None = None

        if isinstance(record, str):
            raw_str = record
            parsed = parse_xml_event(record)
            if not parsed:
                return None
            raw_dict = parsed
        elif isinstance(record, dict):
            raw_dict = record
        else:
            logger.debug("Unsupported record type: %s", type(record))
            return None

        # Extract Event ID
        event_id_val = clean_int(
            raw_dict.get("Id") or raw_dict.get("EventID") or raw_dict.get("event_id")
        )
        if event_id_val not in self.SUPPORTED_EVENT_IDS:
            return None

        # Flatten event data fields: merge nested EventData or Properties into top-level lookup
        fields: dict[str, Any] = dict(raw_dict)
        if isinstance(raw_dict.get("EventData"), dict):
            fields.update(raw_dict["EventData"])
        if isinstance(raw_dict.get("Data"), dict):
            fields.update(raw_dict["Data"])

        # Core header metadata
        channel = clean_str(raw_dict.get("Channel") or "Security") or "Security"
        provider = (
            clean_str(
                raw_dict.get("ProviderName")
                or raw_dict.get("Provider")
                or "Microsoft-Windows-Security-Auditing"
            )
            or "Microsoft-Windows-Security-Auditing"
        )
        record_id = clean_int(raw_dict.get("RecordId") or raw_dict.get("EventRecordID"))
        computer = clean_str(raw_dict.get("Computer") or raw_dict.get("MachineName"))
        timestamp = parse_event_timestamp(raw_dict.get("TimeCreated") or raw_dict.get("timestamp"))

        # Deterministic UUIDv5 if record_id is available for idempotent deduplication
        if record_id is not None:
            event_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.device_id}:{channel}:{record_id}")
            )
        else:
            event_uuid = str(uuid.uuid4())

        # Construct specific normalized event
        try:
            if event_id_val == 4625:
                return self._parse_event_4625(
                    fields=fields,
                    event_uuid=event_uuid,
                    timestamp=timestamp,
                    channel=channel,
                    provider=provider,
                    record_id=record_id,
                    computer=computer,
                    raw_str=raw_str,
                )
            elif event_id_val == 4624:
                return self._parse_event_4624(
                    fields=fields,
                    event_uuid=event_uuid,
                    timestamp=timestamp,
                    channel=channel,
                    provider=provider,
                    record_id=record_id,
                    computer=computer,
                    raw_str=raw_str,
                )
            elif event_id_val == 4672:
                return self._parse_event_4672(
                    fields=fields,
                    event_uuid=event_uuid,
                    timestamp=timestamp,
                    channel=channel,
                    provider=provider,
                    record_id=record_id,
                    computer=computer,
                    raw_str=raw_str,
                )
            elif event_id_val == 4688:
                return self._parse_event_4688(
                    fields=fields,
                    event_uuid=event_uuid,
                    timestamp=timestamp,
                    channel=channel,
                    provider=provider,
                    record_id=record_id,
                    computer=computer,
                    raw_str=raw_str,
                )
        except EventValidationError as exc:
            logger.warning("Event validation failed for event %d: %s", event_id_val, exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error normalizing event %d: %s", event_id_val, exc)
            return None

        return None

    def _parse_event_4625(
        self,
        fields: dict[str, Any],
        event_uuid: str,
        timestamp: str,
        channel: str,
        provider: str,
        record_id: int | None,
        computer: str | None,
        raw_str: str | None,
    ) -> Event:
        """Parse Event ID 4625: An account failed to log on."""
        target_user = clean_str(fields.get("TargetUserName"))
        target_domain = clean_str(fields.get("TargetDomainName"))
        target_sid = clean_str(fields.get("TargetUserSid"))
        logon_type = clean_int(fields.get("LogonType"))
        logon_type_name = LOGON_TYPES.get(logon_type) if logon_type is not None else None
        status = clean_str(fields.get("Status"))
        sub_status = clean_str(fields.get("SubStatus"))
        failure_reason = clean_str(fields.get("FailureReason"))
        workstation = clean_str(fields.get("WorkstationName"))
        raw_ip = clean_str(fields.get("IpAddress"))
        ip_addr = clean_ip(raw_ip)
        port = clean_int(fields.get("IpPort"))
        logon_process = clean_str(fields.get("LogonProcessName"))
        auth_package = clean_str(fields.get("AuthenticationPackageName"))

        attributes: dict[str, Any] = {
            "event_id": 4625,
            "channel": channel,
            "provider": provider,
        }
        if record_id is not None:
            attributes["record_id"] = record_id
        if computer:
            attributes["computer"] = computer
        if target_domain:
            attributes["target_domain"] = target_domain
        if target_sid:
            attributes["target_user_sid"] = target_sid
        if logon_type is not None:
            attributes["logon_type"] = logon_type
        if logon_type_name:
            attributes["logon_type_name"] = logon_type_name
        if status:
            attributes["status"] = status
        if sub_status:
            attributes["sub_status"] = sub_status
        if failure_reason:
            attributes["failure_reason"] = failure_reason
        if workstation:
            attributes["workstation"] = workstation
        if port is not None:
            attributes["source_port"] = port
        if logon_process:
            attributes["logon_process_name"] = logon_process
        if auth_package:
            attributes["authentication_package_name"] = auth_package
        if raw_ip and not ip_addr:
            attributes["raw_source_address"] = raw_ip

        raw_display = (
            raw_str
            or f"Logon failure for user '{target_user or 'unknown'}' (status {status or 'unknown'})"
        )

        event = Event(
            event_id=event_uuid,
            device_id=self.device_id,
            timestamp=timestamp,
            source="windows_security",
            event_type="windows_logon_failure",
            severity=EventSeverity.HIGH,
            source_ip=ip_addr,
            username=target_user,
            raw_event=raw_display,
            attributes=attributes,
        )
        event.validate()
        return event

    def _parse_event_4624(
        self,
        fields: dict[str, Any],
        event_uuid: str,
        timestamp: str,
        channel: str,
        provider: str,
        record_id: int | None,
        computer: str | None,
        raw_str: str | None,
    ) -> Event:
        """Parse Event ID 4624: An account was successfully logged on."""
        target_user = clean_str(fields.get("TargetUserName"))
        target_domain = clean_str(fields.get("TargetDomainName"))
        target_sid = clean_str(fields.get("TargetUserSid"))
        logon_type = clean_int(fields.get("LogonType"))
        logon_type_name = LOGON_TYPES.get(logon_type) if logon_type is not None else None
        workstation = clean_str(fields.get("WorkstationName"))
        raw_ip = clean_str(fields.get("IpAddress"))
        ip_addr = clean_ip(raw_ip)
        port = clean_int(fields.get("IpPort"))
        logon_process = clean_str(fields.get("LogonProcessName"))
        auth_package = clean_str(fields.get("AuthenticationPackageName"))
        elevated_token = clean_str(fields.get("ElevatedToken"))

        attributes: dict[str, Any] = {
            "event_id": 4624,
            "channel": channel,
            "provider": provider,
        }
        if record_id is not None:
            attributes["record_id"] = record_id
        if computer:
            attributes["computer"] = computer
        if target_domain:
            attributes["target_domain"] = target_domain
        if target_sid:
            attributes["target_user_sid"] = target_sid
        if logon_type is not None:
            attributes["logon_type"] = logon_type
        if logon_type_name:
            attributes["logon_type_name"] = logon_type_name
        if workstation:
            attributes["workstation"] = workstation
        if port is not None:
            attributes["source_port"] = port
        if logon_process:
            attributes["logon_process_name"] = logon_process
        if auth_package:
            attributes["authentication_package_name"] = auth_package
        if elevated_token:
            attributes["elevated_status"] = elevated_token
        if raw_ip and not ip_addr:
            attributes["raw_source_address"] = raw_ip

        raw_display = (
            raw_str
            or f"Logon success for user '{target_user or 'unknown'}' (logon type {logon_type})"
        )

        event = Event(
            event_id=event_uuid,
            device_id=self.device_id,
            timestamp=timestamp,
            source="windows_security",
            event_type="windows_logon_success",
            severity=EventSeverity.INFORMATIONAL,
            source_ip=ip_addr,
            username=target_user,
            raw_event=raw_display,
            attributes=attributes,
        )
        event.validate()
        return event

    def _parse_event_4672(
        self,
        fields: dict[str, Any],
        event_uuid: str,
        timestamp: str,
        channel: str,
        provider: str,
        record_id: int | None,
        computer: str | None,
        raw_str: str | None,
    ) -> Event:
        """Parse Event ID 4672: Special privileges assigned to new logon."""
        subject_user = clean_str(fields.get("SubjectUserName"))
        subject_domain = clean_str(fields.get("SubjectDomainName"))
        subject_sid = clean_str(fields.get("SubjectUserSid"))
        privilege_list = parse_privilege_list(fields.get("PrivilegeList"))

        attributes: dict[str, Any] = {
            "event_id": 4672,
            "channel": channel,
            "provider": provider,
        }
        if record_id is not None:
            attributes["record_id"] = record_id
        if computer:
            attributes["computer"] = computer
        if subject_domain:
            attributes["subject_domain"] = subject_domain
        if subject_sid:
            attributes["subject_user_sid"] = subject_sid
        if privilege_list:
            attributes["privileges"] = privilege_list

        raw_display = (
            raw_str or f"Special privileges assigned to logon for '{subject_user or 'unknown'}'"
        )

        event = Event(
            event_id=event_uuid,
            device_id=self.device_id,
            timestamp=timestamp,
            source="windows_security",
            event_type="windows_special_privilege_assigned",
            severity=EventSeverity.MEDIUM,
            source_ip=None,
            username=subject_user,
            raw_event=raw_display,
            attributes=attributes,
        )
        event.validate()
        return event

    def _parse_event_4688(
        self,
        fields: dict[str, Any],
        event_uuid: str,
        timestamp: str,
        channel: str,
        provider: str,
        record_id: int | None,
        computer: str | None,
        raw_str: str | None,
    ) -> Event:
        """Parse Event ID 4688: A new process has been created."""
        new_process = clean_str(fields.get("NewProcessName"))
        process_id = clean_str(fields.get("ProcessId") or fields.get("NewProcessId"))
        parent_process = clean_str(fields.get("ParentProcessName"))
        creator_pid = clean_str(fields.get("CreatorProcessId"))
        subject_user = clean_str(fields.get("SubjectUserName"))
        subject_domain = clean_str(fields.get("SubjectDomainName"))
        subject_sid = clean_str(fields.get("SubjectUserSid"))
        mandatory_label = clean_str(fields.get("MandatoryLabel"))

        attributes: dict[str, Any] = {
            "event_id": 4688,
            "channel": channel,
            "provider": provider,
        }
        if record_id is not None:
            attributes["record_id"] = record_id
        if computer:
            attributes["computer"] = computer
        if new_process:
            attributes["new_process_name"] = new_process
        if process_id:
            attributes["process_id"] = process_id
        if parent_process:
            attributes["parent_process_name"] = parent_process
        if creator_pid:
            attributes["creator_process_id"] = creator_pid
        if subject_domain:
            attributes["subject_domain"] = subject_domain
        if subject_sid:
            attributes["subject_user_sid"] = subject_sid
        if mandatory_label:
            attributes["mandatory_label"] = mandatory_label

        # Respect privacy: do not expose command-line arguments unless explicitly enabled
        if self.include_command_line and fields.get("CommandLine"):
            attributes["command_line"] = clean_str(fields.get("CommandLine"))

        raw_display = (
            raw_str
            or f"Process creation: '{new_process or 'unknown'}' by '{subject_user or 'unknown'}'"
        )

        event = Event(
            event_id=event_uuid,
            device_id=self.device_id,
            timestamp=timestamp,
            source="windows_security",
            event_type="windows_process_creation",
            severity=EventSeverity.INFORMATIONAL,
            source_ip=None,
            username=subject_user,
            raw_event=raw_display,
            attributes=attributes,
        )
        event.validate()
        return event


class SysmonEventParser:
    """Extension parser for Microsoft-Windows-Sysmon/Operational events."""

    SUPPORTED_EVENT_IDS = {1, 3}

    def __init__(self, device_id: str, include_command_line: bool = False) -> None:
        self.device_id = device_id
        self.include_command_line = include_command_line

    def parse(self, record: dict[str, Any] | str) -> Event | None:
        """Parse Sysmon Event 1 (Process Create) or Event 3 (Network Connection)."""
        raw_dict: dict[str, Any]
        if isinstance(record, str):
            parsed = parse_xml_event(record)
            if not parsed:
                return None
            raw_dict = parsed
        elif isinstance(record, dict):
            raw_dict = record
        else:
            return None

        event_id = clean_int(raw_dict.get("Id") or raw_dict.get("EventID"))
        if event_id not in self.SUPPORTED_EVENT_IDS:
            return None

        fields: dict[str, Any] = dict(raw_dict)
        if isinstance(raw_dict.get("EventData"), dict):
            fields.update(raw_dict["EventData"])

        channel = clean_str(raw_dict.get("Channel") or "Microsoft-Windows-Sysmon/Operational")
        provider = clean_str(raw_dict.get("ProviderName") or "Microsoft-Windows-Sysmon")
        record_id = clean_int(raw_dict.get("RecordId") or raw_dict.get("EventRecordID"))
        computer = clean_str(raw_dict.get("Computer") or raw_dict.get("MachineName"))
        timestamp = parse_event_timestamp(raw_dict.get("TimeCreated") or raw_dict.get("timestamp"))

        if record_id is not None:
            event_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.device_id}:{channel}:{record_id}")
            )
        else:
            event_uuid = str(uuid.uuid4())

        try:
            if event_id == 1:
                image = clean_str(fields.get("Image"))
                user = clean_str(fields.get("User"))
                hashes = clean_str(fields.get("Hashes"))
                parent_image = clean_str(fields.get("ParentImage"))

                attrs: dict[str, Any] = {
                    "event_id": 1,
                    "channel": channel,
                    "provider": provider,
                }
                if record_id is not None:
                    attrs["record_id"] = record_id
                if computer:
                    attrs["computer"] = computer
                if image:
                    attrs["image"] = image
                if parent_image:
                    attrs["parent_image"] = parent_image
                if hashes:
                    attrs["hashes"] = hashes
                if self.include_command_line and fields.get("CommandLine"):
                    attrs["command_line"] = clean_str(fields.get("CommandLine"))

                event = Event(
                    event_id=event_uuid,
                    device_id=self.device_id,
                    timestamp=timestamp,
                    source="windows_sysmon",
                    event_type="sysmon_process_creation",
                    severity=EventSeverity.INFORMATIONAL,
                    source_ip=None,
                    username=user,
                    raw_event=f"Sysmon process create: '{image}' by '{user}'",
                    attributes=attrs,
                )
                event.validate()
                return event

            elif event_id == 3:
                image = clean_str(fields.get("Image"))
                user = clean_str(fields.get("User"))
                src_ip = clean_ip(fields.get("SourceIp"))
                dst_ip = clean_str(fields.get("DestinationIp"))
                dst_port = clean_int(fields.get("DestinationPort"))
                protocol = clean_str(fields.get("Protocol"))

                attrs = {
                    "event_id": 3,
                    "channel": channel,
                    "provider": provider,
                }
                if record_id is not None:
                    attrs["record_id"] = record_id
                if computer:
                    attrs["computer"] = computer
                if image:
                    attrs["image"] = image
                if dst_ip:
                    attrs["destination_ip"] = dst_ip
                if dst_port is not None:
                    attrs["destination_port"] = dst_port
                if protocol:
                    attrs["protocol"] = protocol

                event = Event(
                    event_id=event_uuid,
                    device_id=self.device_id,
                    timestamp=timestamp,
                    source="windows_sysmon",
                    event_type="sysmon_network_connection",
                    severity=EventSeverity.INFORMATIONAL,
                    source_ip=src_ip,
                    username=user,
                    raw_event=f"Sysmon network connection: {image} -> {dst_ip}:{dst_port}",
                    attributes=attrs,
                )
                event.validate()
                return event
        except Exception as exc:
            logger.warning("Failed normalizing Sysmon event %d: %s", event_id, exc)
            return None

        return None
