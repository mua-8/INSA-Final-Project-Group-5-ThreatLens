import React, { useState, useMemo } from "react";
import DataTable from "./DataTable.jsx";
import { StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import { FaSearch, FaFilter, FaTerminal } from "react-icons/fa";

export default function EventsTable({ events = [], onSelectEvent }) {
  const [search, setSearch] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("all");

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      const matchSearch =
        search === "" ||
        (e.sourceIp && e.sourceIp.toLowerCase().includes(search.toLowerCase())) ||
        (e.username && e.username.toLowerCase().includes(search.toLowerCase())) ||
        (e.eventType && e.eventType.toLowerCase().includes(search.toLowerCase())) ||
        (e.rawLine && e.rawLine.toLowerCase().includes(search.toLowerCase()));

      const matchOutcome =
        outcomeFilter === "all" ||
        (outcomeFilter === "failure" && (e.status?.toLowerCase().includes("fail") || e.eventType?.toLowerCase().includes("fail"))) ||
        (outcomeFilter === "success" && (e.status?.toLowerCase().includes("success") || e.eventType?.toLowerCase().includes("accept")));

      return matchSearch && matchOutcome;
    });
  }, [events, search, outcomeFilter]);

  const columns = [
    {
      key: "id",
      label: "ID",
      render: (r) => <span className="font-mono text-xs text-accent">#{r.id || "?"}</span>,
    },
    {
      key: "timestamp",
      label: "Timestamp",
      render: (r) => <span className="font-mono text-xs text-slate-300">{formatTimestamp(r.timestamp)}</span>,
    },
    {
      key: "username",
      label: "Target User",
      render: (r) => <span className="font-mono text-xs font-semibold text-white">{r.username}</span>,
    },
    {
      key: "eventType",
      label: "Event Type",
      render: (r) => <span className="text-xs text-slate-200">{r.eventType}</span>,
    },
    {
      key: "sourceIp",
      label: "Source IP",
      render: (r) => <span className="font-mono text-xs text-slate-200">{r.sourceIp}</span>,
    },
    {
      key: "status",
      label: "Outcome",
      render: (r) => <StatusBadge status={r.status} />,
    },
    {
      key: "actions",
      label: "Action",
      render: (r) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            if (onSelectEvent) onSelectEvent(r);
          }}
          className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 border border-slate-700 transition hover:bg-slate-700 hover:text-white font-medium"
        >
          <FaTerminal size={10} className="text-accent" />
          <span>Raw Log</span>
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-3">
      {/* Search and Filter toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search events by user, IP, or raw syslog text..."
            className="w-full rounded-lg border border-slate-700 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <FaFilter className="text-slate-500 text-xs" />
          <select
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
          >
            <option value="all">All Outcomes</option>
            <option value="failure">Failed Attempts</option>
            <option value="success">Successful Logins</option>
          </select>
        </div>
      </div>

      <DataTable
        title="Ingested SSH Authentication Events (Click row to inspect raw syslog & hash)"
        count={filteredEvents.length}
        columns={columns}
        rows={filteredEvents}
        onRowClick={onSelectEvent}
        emptyText="No events match the active filter criteria."
      />
    </div>
  );
}
