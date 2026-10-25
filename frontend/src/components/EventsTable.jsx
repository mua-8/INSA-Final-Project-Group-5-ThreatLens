import DataTable from "./DataTable.jsx";
import { StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";

const columns = [
  { key: "timestamp", label: "Timestamp", render: (r) => <span className="font-mono text-xs text-slate-300">{formatTimestamp(r.timestamp)}</span> },
  { key: "username", label: "Username", render: (r) => <span className="font-mono text-xs">{r.username}</span> },
  { key: "eventType", label: "Event Type", render: (r) => r.eventType },
  { key: "sourceIp", label: "Source IP", render: (r) => <span className="font-mono text-xs">{r.sourceIp}</span> },
  { key: "status", label: "Status", render: (r) => <StatusBadge status={r.status} /> },
];

export default function EventsTable({ events }) {
  return (
    <DataTable
      title="Recent Events"
      count={events.length}
      columns={columns}
      rows={events}
      emptyText="No SSH events recorded yet."
    />
  );
}
