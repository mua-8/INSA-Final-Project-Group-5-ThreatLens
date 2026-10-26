"""Unit tests for WindowsEventParser and SysmonEventParser."""

import json
from pathlib import Path

from threatlens_agent.collectors.parsers.windows import SysmonEventParser, WindowsEventParser
from threatlens_agent.models.events import EventSeverity

DEVICE_ID = "win-dev-test-01"
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_parse_event_4625_logon_failure() -> None:
    """Verify Event 4625 failed logon parsing and attribute normalization."""
    parser = WindowsEventParser(device_id=DEVICE_ID)
    raw = {
        "Id": 4625,
        "RecordId": 10001,
        "TimeCreated": "2026-10-26T06:12:30.123456+00:00",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WIN-SRV-2022.corp.local",
        "EventData": {
            "TargetUserName": "Administrator",
            "TargetDomainName": "CORP",
            "TargetUserSid": "S-1-5-21-500",
            "LogonType": "3",
            "Status": "0xC000006D",
            "SubStatus": "0xC0000064",
            "FailureReason": "%%2313",
            "WorkstationName": "WORKSTATION-01",
            "IpAddress": "192.0.2.10",
            "IpPort": "54123",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        },
    }

    event = parser.parse(raw)
    assert event is not None
    assert event.event_type == "windows_logon_failure"
    assert event.severity == EventSeverity.HIGH
    assert event.device_id == DEVICE_ID
    assert event.username == "Administrator"
    assert event.source_ip == "192.0.2.10"
    assert event.timestamp == "2026-10-26T06:12:30.123456+00:00"

    attrs = event.attributes
    assert attrs["event_id"] == 4625
    assert attrs["channel"] == "Security"
    assert attrs["record_id"] == 10001
    assert attrs["computer"] == "WIN-SRV-2022.corp.local"
    assert attrs["target_domain"] == "CORP"
    assert attrs["logon_type"] == 3
    assert attrs["logon_type_name"] == "Network"
    assert attrs["status"] == "0xC000006D"
    assert attrs["sub_status"] == "0xC0000064"
    assert attrs["workstation"] == "WORKSTATION-01"
    assert attrs["source_port"] == 54123
    assert attrs["logon_process_name"] == "NtLmSsp"


def test_parse_event_4624_logon_success() -> None:
    """Verify Event 4624 successful logon parsing and attribute normalization."""
    parser = WindowsEventParser(device_id=DEVICE_ID)
    raw = {
        "Id": 4624,
        "RecordId": 10002,
        "TimeCreated": "2026-10-26T06:13:00.000000+00:00",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WIN-SRV-2022.corp.local",
        "EventData": {
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "LogonType": "2",
            "WorkstationName": "WIN-SRV-2022",
            "IpAddress": "192.0.2.15",
            "IpPort": "0",
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "ElevatedToken": "%%1842",
        },
    }

    event = parser.parse(raw)
    assert event is not None
    assert event.event_type == "windows_logon_success"
    assert event.severity == EventSeverity.INFORMATIONAL
    assert event.device_id == DEVICE_ID
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.15"

    attrs = event.attributes
    assert attrs["event_id"] == 4624
    assert attrs["logon_type"] == 2
    assert attrs["logon_type_name"] == "Interactive"
    assert attrs["elevated_status"] == "%%1842"
    assert attrs["authentication_package_name"] == "Negotiate"


def test_parse_event_4672_special_privileges() -> None:
    """Verify Event 4672 special privileges assigned parsing and privilege list splitting."""
    parser = WindowsEventParser(device_id=DEVICE_ID)
    raw = {
        "Id": 4672,
        "RecordId": 10003,
        "TimeCreated": "2026-10-26T06:13:01.000000+00:00",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WIN-SRV-2022.corp.local",
        "EventData": {
            "SubjectUserName": "Administrator",
            "SubjectDomainName": "CORP",
            "SubjectUserSid": "S-1-5-21-500",
            "PrivilegeList": "SeSecurityPrivilege\n\tSeBackupPrivilege\n\tSeRestorePrivilege\n\tSeTakeOwnershipPrivilege\n\tSeDebugPrivilege",
        },
    }

    event = parser.parse(raw)
    assert event is not None
    assert event.event_type == "windows_special_privilege_assigned"
    assert event.severity == EventSeverity.MEDIUM
    assert event.device_id == DEVICE_ID
    assert event.username == "Administrator"
    assert event.source_ip is None

    attrs = event.attributes
    assert attrs["event_id"] == 4672
    assert "privileges" in attrs
    assert attrs["privileges"] == [
        "SeSecurityPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeDebugPrivilege",
    ]


def test_parse_event_4688_process_creation_and_command_line_privacy() -> None:
    """Verify Event 4688 process creation parsing and verify command-line arguments are NOT exposed by default."""
    # 1. Default parser: include_command_line=False
    parser_default = WindowsEventParser(device_id=DEVICE_ID)
    raw = {
        "Id": 4688,
        "RecordId": 10004,
        "TimeCreated": "2026-10-26T06:14:00.000000+00:00",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Computer": "WIN-SRV-2022.corp.local",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": "0x1f4",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "CreatorProcessId": "0x1a0",
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "CommandLine": "cmd.exe /c whoami --sensitive-token=SECRET123",
            "MandatoryLabel": "Mandatory Label\\High",
        },
    }

    event = parser_default.parse(raw)
    assert event is not None
    assert event.event_type == "windows_process_creation"
    assert event.severity == EventSeverity.INFORMATIONAL
    assert event.username == "alice"
    assert event.source_ip is None

    attrs = event.attributes
    assert attrs["event_id"] == 4688
    assert attrs["new_process_name"] == "C:\\Windows\\System32\\cmd.exe"
    assert attrs["process_id"] == "0x1f4"
    assert attrs["parent_process_name"] == "C:\\Windows\\explorer.exe"
    assert attrs["creator_process_id"] == "0x1a0"

    # Privacy guarantee: command_line is NOT present in attributes
    assert "command_line" not in attrs

    # 2. Configured parser: include_command_line=True
    parser_with_cmd = WindowsEventParser(device_id=DEVICE_ID, include_command_line=True)
    event_cmd = parser_with_cmd.parse(raw)
    assert event_cmd is not None
    assert "command_line" in event_cmd.attributes
    # Verify sensitive token redaction from Event model post-init
    assert "SECRET123" not in event_cmd.attributes["command_line"]
    assert "[REDACTED]" in event_cmd.attributes["command_line"]


def test_missing_and_optional_fields() -> None:
    """Verify parser handles placeholder dashes and missing optional fields cleanly."""
    parser = WindowsEventParser(device_id=DEVICE_ID)
    raw = {
        "Id": 4625,
        "RecordId": 10005,
        "TimeCreated": "2026-10-26T06:15:00.000000+00:00",
        "Channel": "Security",
        "EventData": {
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "LogonType": "3",
            "Status": "0xC000006D",
            "SubStatus": "0xC0000064",
            "WorkstationName": "-",
            "IpAddress": "-",
            "IpPort": "-",
        },
    }

    event = parser.parse(raw)
    assert event is not None
    assert event.username is None
    assert event.source_ip is None
    assert event.attributes.get("workstation") is None
    assert event.attributes.get("source_port") is None
    assert event.attributes.get("target_domain") is None


def test_malformed_records() -> None:
    """Verify non-dict, empty dict, and malformed inputs return None without crashing."""
    parser = WindowsEventParser(device_id=DEVICE_ID)

    assert parser.parse({}) is None
    assert parser.parse(None) is None  # type: ignore[arg-type]
    assert parser.parse(12345) is None  # type: ignore[arg-type]
    assert parser.parse("not an xml string") is None
    assert (
        parser.parse({"Id": 4625, "TimeCreated": "corrupted-date"}) is not None
    )  # falls back to UTC


def test_unknown_event_ids() -> None:
    """Verify unmonitored event IDs are safely ignored."""
    parser = WindowsEventParser(device_id=DEVICE_ID)

    assert parser.parse({"Id": 9999, "Channel": "Security"}) is None
    assert parser.parse({"Id": 7036, "Channel": "System"}) is None
    assert parser.parse({"Id": 1102, "Channel": "Security"}) is None


def test_xml_event_string_parsing() -> None:
    """Verify parser accepts raw Windows Event Log XML strings."""
    parser = WindowsEventParser(device_id=DEVICE_ID)
    xml_str = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4624</EventID>
        <EventRecordID>30001</EventRecordID>
        <TimeCreated SystemTime="2026-10-26T06:20:00.000000Z"/>
        <Channel>Security</Channel>
        <Computer>WIN-SRV-2022</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">bob</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="IpAddress">192.0.2.55</Data>
        <Data Name="IpPort">49152</Data>
      </EventData>
    </Event>
    """

    event = parser.parse(xml_str)
    assert event is not None
    assert event.event_type == "windows_logon_success"
    assert event.username == "bob"
    assert event.source_ip == "192.0.2.55"
    assert event.attributes["logon_type"] == 10
    assert event.attributes["logon_type_name"] == "RemoteInteractive"
    assert event.attributes["record_id"] == 30001


def test_sysmon_event_parser() -> None:
    """Verify optional SysmonEventParser handles Process Create (1) and Network Connection (3)."""
    sysmon_parser = SysmonEventParser(device_id=DEVICE_ID)

    # Event 1: Process Creation
    evt1 = {
        "Id": 1,
        "RecordId": 20001,
        "TimeCreated": "2026-10-26T06:17:00.000000+00:00",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventData": {
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "User": "CORP\\alice",
            "CommandLine": "powershell.exe -enc AAAA",
            "Hashes": "SHA256=1234567890ABCDEF",
            "ParentImage": "C:\\Windows\\explorer.exe",
        },
    }
    event1 = sysmon_parser.parse(evt1)
    assert event1 is not None
    assert event1.event_type == "sysmon_process_creation"
    assert event1.source == "windows_sysmon"
    assert event1.username == "CORP\\alice"
    assert event1.attributes["image"] == "C:\\Windows\\System32\\powershell.exe"
    assert event1.attributes["hashes"] == "SHA256=1234567890ABCDEF"
    # Verify command line is NOT included by default
    assert "command_line" not in event1.attributes

    # Event 3: Network Connection
    evt3 = {
        "Id": 3,
        "RecordId": 20002,
        "TimeCreated": "2026-10-26T06:18:00.000000+00:00",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventData": {
            "Image": "C:\\Windows\\System32\\curl.exe",
            "User": "CORP\\alice",
            "SourceIp": "192.0.2.10",
            "DestinationIp": "198.51.100.25",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
    }
    event3 = sysmon_parser.parse(evt3)
    assert event3 is not None
    assert event3.event_type == "sysmon_network_connection"
    assert event3.source_ip == "192.0.2.10"
    assert event3.attributes["destination_ip"] == "198.51.100.25"
    assert event3.attributes["destination_port"] == 443
    assert event3.attributes["protocol"] == "tcp"


def test_parse_from_fixture_file() -> None:
    """Verify parsing full set of realistic records from json fixture file."""
    fixture_path = FIXTURES_DIR / "windows_events.json"
    with open(fixture_path, encoding="utf-8") as f:
        records = json.load(f)

    win_parser = WindowsEventParser(device_id=DEVICE_ID)
    sysmon_parser = SysmonEventParser(device_id=DEVICE_ID)

    parsed_events = []
    for rec in records:
        if rec.get("Channel") == "Microsoft-Windows-Sysmon/Operational":
            ev = sysmon_parser.parse(rec)
        else:
            ev = win_parser.parse(rec)
        if ev:
            parsed_events.append(ev)

    # 4 Security events (4625, 4624, 4672, 4688) + 1 partial 4625 + 2 Sysmon events = 7 events (9999 ignored)
    assert len(parsed_events) == 7
    event_types = {e.event_type for e in parsed_events}
    assert "windows_logon_failure" in event_types
    assert "windows_logon_success" in event_types
    assert "windows_special_privilege_assigned" in event_types
    assert "windows_process_creation" in event_types
    assert "sysmon_process_creation" in event_types
    assert "sysmon_network_connection" in event_types
