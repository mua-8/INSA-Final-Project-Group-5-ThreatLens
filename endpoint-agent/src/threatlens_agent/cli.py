"""Command-line interface for ThreatLens Endpoint Agent."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from collections.abc import Sequence

from threatlens_agent import __schema_version__, __version__
from threatlens_agent.agent import ThreatLensAgent, setup_logging
from threatlens_agent.config import AgentConfig, ConfigValidationError


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="threatlens-agent",
        description="ThreatLens Endpoint Agent - Security Telemetry Collection and Dispatch",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        metavar="PATH",
        help="Path to YAML configuration file (default: $THREATLENS_CONFIG_PATH or default settings)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose DEBUG logging",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Format output as JSON",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. status command
    subparsers.add_parser(
        "status",
        help="Display agent operational health, device identity, and queue status",
    )

    # 2. validate-config command
    validate_parser = subparsers.add_parser(
        "validate-config",
        help="Validate configuration file format and settings",
    )
    validate_parser.add_argument(
        "file",
        nargs="?",
        help="Optional path to configuration YAML to validate (overrides --config)",
    )

    # 3. version command
    subparsers.add_parser(
        "version",
        help="Show agent version, event schema version, and runtime platform",
    )

    # 4. queue-stats command
    subparsers.add_parser(
        "queue-stats",
        help="Inspect local SQLite event queue metrics and storage consumption",
    )

    # 5. flush command
    flush_parser = subparsers.add_parser(
        "flush",
        help="Attempt transmission of currently queued events to the backend",
    )
    flush_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of events to dispatch in this batch",
    )

    # 6. collect command
    subparsers.add_parser(
        "collect",
        help="Execute one round of telemetry collection and local threat detection",
    )

    return parser


def cmd_version(as_json: bool) -> int:
    """Handler for 'version' command."""
    info = {
        "agent_version": __version__,
        "schema_version": __schema_version__,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
    }
    if as_json:
        print(json.dumps(info, indent=2))
    else:
        print(f"ThreatLens Endpoint Agent v{info['agent_version']}")
        print(f"  Schema Version : {info['schema_version']}")
        print(f"  Python Version : {info['python_version']}")
        print(f"  Platform       : {info['platform']} ({info['architecture']})")
    return 0


def cmd_validate_config(config_path: str | None, as_json: bool) -> int:
    """Handler for 'validate-config' command."""
    try:
        config = AgentConfig.load(config_path)
        out = {
            "valid": True,
            "message": "Configuration is valid",
            "config_path": str(config_path) if config_path else "default/environment",
            "data_dir": str(config.get_data_dir_path()),
            "transport_configured": bool(config.transport.backend_url),
            "log_level": config.log_level,
        }
        if as_json:
            print(json.dumps(out, indent=2))
        else:
            print("✓ Configuration validation SUCCESS")
            print(f"  Config Source        : {out['config_path']}")
            print(f"  Data Directory       : {out['data_dir']}")
            print(f"  Backend Configured   : {out['transport_configured']}")
            print(f"  Log Level            : {out['log_level']}")
        return 0
    except ConfigValidationError as exc:
        err = {
            "valid": False,
            "error": str(exc),
            "field": exc.field_name,
        }
        if as_json:
            print(json.dumps(err, indent=2))
        else:
            print("✗ Configuration validation FAILED", file=sys.stderr)
            print(f"  Error : {exc}", file=sys.stderr)
            if exc.field_name:
                print(f"  Field : {exc.field_name}", file=sys.stderr)
        return 1
    except Exception as exc:
        err = {"valid": False, "error": str(exc)}
        if as_json:
            print(json.dumps(err, indent=2))
        else:
            print(f"✗ Unexpected configuration error: {exc}", file=sys.stderr)
        return 1


def cmd_status(config: AgentConfig, as_json: bool) -> int:
    """Handler for 'status' command."""
    try:
        agent = ThreatLensAgent(config)
        health = agent.get_health()
        agent.close()

        if as_json:
            print(json.dumps(health.to_dict(), indent=2))
        else:
            print("ThreatLens Endpoint Agent Status")
            print(f"  Overall Health     : {'HEALTHY' if health.healthy else 'DEGRADED'}")
            print(f"  Device ID          : {health.device_id}")
            print(f"  Hostname           : {health.hostname}")
            print(f"  Agent Version      : {health.agent_version}")
            print(f"  Uptime (seconds)   : {health.uptime_seconds:.1f}s")
            print(f"  Transport Ready    : {health.transport_available}")
            print(f"  Pending Queue Size : {health.queue_stats.pending_count}")
            print(f"  In-Flight Queue    : {health.queue_stats.in_flight_count}")
            print(f"  Total Queue Events : {health.queue_stats.total_count}")
            print(f"  Queue DB Size      : {health.queue_stats.database_size_bytes} bytes")
            print(f"  Detections Emitted : {health.total_detections_emitted}")
            if health.collector_diagnostics:
                print("  Collector Sources  :")
                for c_name, diag in health.collector_diagnostics.items():
                    active_srcs = diag.get("active_sources", [])
                    print(f"    - {c_name}: active={active_srcs or 'none'}")
                    if c_name == "windows_event_log":
                        for ch_name, ch_info in diag.get("channels", {}).items():
                            if ch_info.get("status") == "permission_denied":
                                print(
                                    f"      * {ch_name}: PERMISSION DENIED ({ch_info.get('error')})"
                                )
                            elif ch_info.get("status") == "channel_not_found":
                                print(f"      * {ch_name}: Channel not found")
                        sysmon_info = diag.get("sysmon", {})
                        if sysmon_info.get("enabled"):
                            print(f"      * Sysmon: status={sysmon_info.get('status')}")
            if health.last_transport_error:
                print(f"  Last Transport Err : {health.last_transport_error}")
        return 0
    except Exception as exc:
        if as_json:
            print(json.dumps({"healthy": False, "error": str(exc)}, indent=2))
        else:
            print(f"Error querying agent status: {exc}", file=sys.stderr)
        return 1


def cmd_queue_stats(config: AgentConfig, as_json: bool) -> int:
    """Handler for 'queue-stats' command."""
    try:
        agent = ThreatLensAgent(config)
        stats = agent.queue.get_stats()
        agent.close()

        if as_json:
            print(json.dumps(stats.to_dict(), indent=2))
        else:
            print("ThreatLens Event Queue Statistics")
            print(f"  Pending Events     : {stats.pending_count}")
            print(f"  In-Flight Events   : {stats.in_flight_count}")
            print(f"  Delivered Events   : {stats.delivered_count}")
            print(f"  Total Records      : {stats.total_count}")
            print(
                f"  Database Size (MB) : {round(stats.database_size_bytes / (1024 * 1024), 3)} MB"
            )
            print(f"  Oldest Pending     : {stats.oldest_pending_timestamp or 'None'}")
            print(f"  Newest Pending     : {stats.newest_pending_timestamp or 'None'}")
        return 0
    except Exception as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"Error inspecting queue: {exc}", file=sys.stderr)
        return 1


def cmd_flush(config: AgentConfig, limit: int | None, as_json: bool) -> int:
    """Handler for 'flush' command."""
    try:
        agent = ThreatLensAgent(config)
        count = agent.flush(limit=limit)
        health = agent.get_health()
        agent.close()

        res = {
            "flushed_count": count,
            "pending_remaining": health.queue_stats.pending_count,
            "transport_error": health.last_transport_error,
        }
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Flushed {count} event(s) to backend.")
            print(f"Remaining pending events in queue: {health.queue_stats.pending_count}")
            if health.last_transport_error:
                print(f"Transport notice: {health.last_transport_error}", file=sys.stderr)
        return 0
    except Exception as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"Error during flush: {exc}", file=sys.stderr)
        return 1


def cmd_collect(config: AgentConfig, as_json: bool) -> int:
    """Handler for 'collect' command."""
    try:
        agent = ThreatLensAgent(config)
        collected, detections = agent.collect_and_detect()
        health = agent.get_health()
        agent.close()

        res = {
            "events_collected": collected,
            "detections_triggered": detections,
            "pending_queue_size": health.queue_stats.pending_count,
            "collector_diagnostics": health.collector_diagnostics,
        }
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print("ThreatLens Telemetry Collection Completed")
            print(f"  Events Collected     : {collected}")
            print(f"  Detections Triggered : {detections}")
            print(f"  Pending Queue Size   : {health.queue_stats.pending_count}")
            for c_name, diag in health.collector_diagnostics.items():
                active_srcs = diag.get("active_sources", [])
                print(f"  Collector '{c_name}' active sources: {active_srcs or 'none'}")
                if c_name == "windows_event_log":
                    for ch_name, ch_info in diag.get("channels", {}).items():
                        if ch_info.get("status") == "permission_denied":
                            print(f"    [!] {ch_name}: Permission denied - {ch_info.get('error')}")
                        elif ch_info.get("status") == "channel_not_found":
                            print(f"    [!] {ch_name}: Channel unavailable on host")
        return 0
    except Exception as exc:
        if as_json:
            print(json.dumps({"error": str(exc)}, indent=2))
        else:
            print(f"Error during collection: {exc}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level)

    if args.command == "version":
        return cmd_version(args.json)

    if args.command == "validate-config":
        path = args.file or args.config_path
        return cmd_validate_config(path, args.json)

    # For commands that require loaded configuration
    try:
        config = AgentConfig.load(args.config_path)
        if args.verbose:
            config.log_level = "DEBUG"
    except ConfigValidationError as exc:
        if args.json:
            print(json.dumps({"error": f"Invalid configuration: {exc}"}))
        else:
            print(f"Configuration Error: {exc}", file=sys.stderr)
        return 1

    if args.command == "status":
        return cmd_status(config, args.json)

    if args.command == "queue-stats":
        return cmd_queue_stats(config, args.json)

    if args.command == "flush":
        return cmd_flush(config, args.limit, args.json)

    if args.command == "collect":
        return cmd_collect(config, args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
