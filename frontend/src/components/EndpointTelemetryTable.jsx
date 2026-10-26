import DataTable from "./DataTable.jsx";
import { SeverityBadge } from "./Badges.jsx";

function formatTimestamp(value) {
  if (!value) return "-";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString();
}

export default function EndpointTelemetryTable({ events = [], loading = false }) {
  const columns = [
    {
      key: "timestamp",
      label: "TIMESTAMP",
      render: (event) => (
        <span className="text-xs text-slate-300">
          {formatTimestamp(event.timestamp)}
        </span>
      ),
    },
    {
      key: "device_id",
      label: "DEVICE ID",
      render: (event) => (
        <span className="font-mono text-xs text-cyan-300">
          {event.device_id || "-"}
        </span>
      ),
    },
    {
      key: "event_type",
      label: "EVENT TYPE",
      render: (event) => event.event_type || "-",
    },
    {
      key: "severity",
      label: "SEVERITY",
      render: (event) => <SeverityBadge severity={event.severity} />,
    },
    {
      key: "source_ip",
      label: "SOURCE IP",
      render: (event) => event.source_ip || "-",
    },
    {
      key: "username",
      label: "USERNAME",
      render: (event) => event.username || "-",
    },
  ];

  return (
    <DataTable
      title="Endpoint Agent Telemetry"
      count={events.length}
      columns={columns}
      rows={events}
      emptyText={
        loading
          ? "Loading endpoint telemetry..."
          : "No endpoint events received yet. Start the agent and send events to ThreatLens."
      }
    />
  );
}
