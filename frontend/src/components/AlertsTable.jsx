import DataTable from "./DataTable.jsx";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";

const columns = [
  { key: "timestamp", label: "Timestamp", render: (r) => <span className="font-mono text-xs text-slate-300">{formatTimestamp(r.timestamp)}</span> },
  { key: "type", label: "Alert Type", render: (r) => r.type },
  { key: "severity", label: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
  { key: "sourceIp", label: "Source IP", render: (r) => <span className="font-mono text-xs">{r.sourceIp}</span> },
  { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status} /> },
];

export default function AlertsTable({ alerts }) {
  return (
    <DataTable
      title="Recent Alerts"
      count={alerts.length}
      columns={columns}
      rows={alerts}
      emptyText="No alerts detected yet."
    />
  );
}
