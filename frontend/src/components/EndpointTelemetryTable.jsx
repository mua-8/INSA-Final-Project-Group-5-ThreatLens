import React, { useState } from "react";
import DataTable from "./DataTable.jsx";
import { SeverityBadge } from "./Badges.jsx";
import { FiMonitor, FiTerminal, FiServer, FiCpu, FiX, FiCode } from "react-icons/fi";

function formatTimestamp(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export default function EndpointTelemetryTable({ events = [], loading = false }) {
  const [inspectEvent, setInspectEvent] = useState(null);

  const columns = [
    {
      key: "timestamp",
      label: "TIMESTAMP",
      render: (event) => (
        <span className="font-mono text-xs text-slate-300">
          {formatTimestamp(event.timestamp)}
        </span>
      ),
    },
    {
      key: "device_id",
      label: "DEVICE ID / HOST",
      render: (event) => (
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono text-xs font-bold text-cyan-300">
            {event.device_id || "unknown-host"}
          </span>
        </div>
      ),
    },
    {
      key: "source",
      label: "COLLECTOR SOURCE",
      render: (event) => {
        const isWindows = String(event.source || "").toLowerCase().includes("win");
        return (
          <span
            className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${
              isWindows
                ? "bg-blue-950/70 text-blue-300 border-blue-800/60"
                : "bg-slate-800 text-slate-300 border-slate-700/80"
            }`}
          >
            {isWindows ? <FiMonitor size={10} /> : <FiServer size={10} />}
            {event.source || "agent"}
          </span>
        );
      },
    },
    {
      key: "event_type",
      label: "EVENT CLASSIFICATION",
      render: (event) => (
        <span className="font-mono text-xs text-slate-200 bg-slate-950/60 px-2 py-0.5 rounded border border-slate-800">
          {event.event_type || "-"}
        </span>
      ),
    },
    {
      key: "severity",
      label: "SEVERITY",
      render: (event) => <SeverityBadge severity={event.severity} />,
    },
    {
      key: "source_ip",
      label: "NETWORK ORIGIN",
      render: (event) => (
        <span className="font-mono text-xs text-slate-300">
          {event.source_ip || "127.0.0.1"}
        </span>
      ),
    },
    {
      key: "username",
      label: "IDENTITY",
      render: (event) => (
        <span className="font-mono text-xs text-amber-300 font-semibold">
          {event.username || "-"}
        </span>
      ),
    },
  ];

  return (
    <>
      <DataTable
        title="Cross-Platform Endpoint Telemetry"
        badge="EDR Agent Stream"
        count={events.length}
        columns={columns}
        rows={events}
        onRowClick={(row) => setInspectEvent(row)}
        emptyText={
          loading
            ? "Hydrating live endpoint telemetry stream..."
            : "No endpoint events received yet. Start the ThreatLens agent daemon to stream logs."
        }
      />

      {/* Raw Endpoint Telemetry Modal */}
      {inspectEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-150">
          <div className="w-full max-w-2xl rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FiCpu className="text-cyan-400 text-lg" />
                <h3 className="font-bold text-white text-sm">
                  Endpoint Agent Telemetry Inspector
                </h3>
              </div>
              <button
                onClick={() => setInspectEvent(null)}
                className="text-slate-400 hover:text-white transition"
              >
                <FiX size={18} />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Device ID:</span>
                <span className="text-cyan-300 font-bold">{inspectEvent.device_id}</span>
              </div>
              <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Event Type:</span>
                <span className="text-amber-300 font-bold">{inspectEvent.event_type}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 text-xs font-semibold block mb-1">
                Raw Event Payload:
              </span>
              <pre className="p-3 bg-slate-950 text-slate-200 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                {inspectEvent.raw_event || JSON.stringify(inspectEvent, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectEvent(null)}
                className="bg-slate-800 hover:bg-slate-700 text-white font-semibold px-4 py-2 rounded-xl text-xs transition"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
