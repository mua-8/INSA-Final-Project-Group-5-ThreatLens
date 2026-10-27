import React, { useState, useMemo } from "react";
import DataTable from "./DataTable.jsx";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import { FaSearch, FaFilter, FaExternalLinkAlt } from "react-icons/fa";

export default function AlertsTable({ alerts = [], onSelectAlert }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const matchSearch =
        search === "" ||
        (a.sourceIp && a.sourceIp.toLowerCase().includes(search.toLowerCase())) ||
        (a.targetHost && a.targetHost.toLowerCase().includes(search.toLowerCase())) ||
        (a.type && a.type.toLowerCase().includes(search.toLowerCase())) ||
        (a.ruleId && a.ruleId.toLowerCase().includes(search.toLowerCase()));

      const matchSeverity =
        severityFilter === "all" ||
        (a.severity && a.severity.toLowerCase() === severityFilter.toLowerCase());

      return matchSearch && matchSeverity;
    });
  }, [alerts, search, severityFilter]);

  const columns = [
    {
      key: "id",
      label: "ID",
      render: (r) => <span className="font-mono text-xs text-accent">#{r.id}</span>,
    },
    {
      key: "timestamp",
      label: "Detected At (UTC)",
      render: (r) => <span className="font-mono text-xs text-slate-300">{formatTimestamp(r.timestamp)}</span>,
    },
    {
      key: "type",
      label: "Detection Rule / Alert",
      render: (r) => (
        <div>
          <span className="font-semibold text-white">{r.type}</span>
          {r.ruleId && <span className="ml-2 font-mono text-[10px] text-accent">({r.ruleId})</span>}
        </div>
      ),
    },
    {
      key: "severity",
      label: "Severity",
      render: (r) => <SeverityBadge severity={r.severity} />,
    },
    {
      key: "targetHost",
      label: "Target Host",
      render: (r) => (
        <span className="font-mono text-xs text-emerald-400 font-medium">
          {r.targetHost || "server"}
        </span>
      ),
    },
    {
      key: "sourceIp",
      label: "Source IP",
      render: (r) => <span className="font-mono text-xs text-slate-200">{r.sourceIp}</span>,
    },
    {
      key: "status",
      label: "Status",
      render: (r) => <StatusBadge status={r.status} />,
    },
    {
      key: "actions",
      label: "Action",
      render: (r) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            if (onSelectAlert) onSelectAlert(r);
          }}
          className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 text-xs text-accent border border-accent/30 transition hover:bg-accent hover:text-primary font-medium"
        >
          <span>Triage</span>
          <FaExternalLinkAlt size={10} />
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
            placeholder="Filter alerts by host, IP, rule, or type..."
            className="w-full rounded-lg border border-slate-700 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2">
          <FaFilter className="text-slate-500 text-xs" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <DataTable
        title="Correlated Security Alerts"
        count={filteredAlerts.length}
        columns={columns}
        rows={filteredAlerts}
        onRowClick={onSelectAlert}
        emptyText="No alerts match the active filter criteria."
      />
    </div>
  );
}
