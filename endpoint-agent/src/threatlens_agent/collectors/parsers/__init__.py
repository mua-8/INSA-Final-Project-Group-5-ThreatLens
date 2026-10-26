"""Parsers for operating system telemetry logs."""

from threatlens_agent.collectors.parsers.ssh import OpenSshLogParser, SshParsedEvent
from threatlens_agent.collectors.parsers.windows import SysmonEventParser, WindowsEventParser

__all__ = [
    "OpenSshLogParser",
    "SshParsedEvent",
    "SysmonEventParser",
    "WindowsEventParser",
]
