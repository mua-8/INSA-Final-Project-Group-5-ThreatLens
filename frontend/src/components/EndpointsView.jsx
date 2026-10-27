import React, { useState, useEffect, useMemo, useCallback } from "react";
import DataTable from "./DataTable.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import {
  getEndpoints,
  getEndpointDetails,
  enrollEndpoint,
  updateEndpoint,
  updateEndpointStatus,
} from "../services/api.js";
import {
  FaSearch,
  FaFilter,
  FaPlus,
  FaTimes,
  FaDesktop,
  FaLinux,
  FaWindows,
  FaApple,
  FaCheckCircle,
  FaExclamationCircle,
  FaBan,
  FaEdit,
  FaStream,
  FaNetworkWired,
  FaClock,
} from "react-icons/fa";

function getEndpointHealth(endpoint) {
  if (!endpoint) return { label: "Unknown", color: "slate", icon: FaExclamationCircle };
  const rawStatus = (endpoint.status || "").toLowerCase();
  if (rawStatus === "disabled") {
    return {
      label: "Disabled",
      badgeClass: "bg-red-950/40 border-red-500/50 text-red-400",
      dotClass: "bg-red-500",
      icon: FaBan,
    };
  }

  // Check last_seen for offline threshold (15 minutes)
  if (!endpoint.last_seen) {
    return {
      label: rawStatus === "enrolled" ? "Enrolled (Pending First Telemetry)" : "Offline (No Telemetry)",
      badgeClass: "bg-slate-800 border-slate-700 text-slate-400",
      dotClass: "bg-slate-500",
      icon: FaExclamationCircle,
    };
  }

  try {
    const lastSeenMs = new Date(endpoint.last_seen.replace("Z", "+00:00")).getTime();
    const nowMs = Date.now();
    const diffMins = (nowMs - lastSeenMs) / (1000 * 60);
    if (diffMins > 15) {
      return {
        label: "Offline",
        badgeClass: "bg-amber-950/40 border-amber-500/50 text-amber-400",
        dotClass: "bg-amber-500",
        icon: FaExclamationCircle,
      };
    }
  } catch {
    // fallback
  }

  return {
    label: "Active / Healthy",
    badgeClass: "bg-emerald-950/40 border-emerald-500/50 text-emerald-400",
    dotClass: "bg-emerald-400",
    icon: FaCheckCircle,
  };
}

function OsBadge({ os }) {
  const cleanOs = (os || "linux").toLowerCase();
  let Icon = FaLinux;
  let label = "Linux";
  if (cleanOs.includes("win")) {
    Icon = FaWindows;
    label = "Windows";
  } else if (cleanOs.includes("mac") || cleanOs.includes("darwin")) {
    Icon = FaApple;
    label = "macOS";
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-slate-800/80 border border-slate-700 text-slate-300">
      <Icon size={11} className="text-accent" />
      <span>{label}</span>
    </span>
  );
}

export default function EndpointsView() {
  const [endpoints, setEndpoints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [togglingId, setTogglingId] = useState(null);

  // Detail Modal State
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editHostname, setEditHostname] = useState("");
  const [editIp, setEditIp] = useState("");
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Enroll Modal State
  const [showEnrollModal, setShowEnrollModal] = useState(false);
  const [enrollDeviceId, setEnrollDeviceId] = useState("");
  const [enrollHostname, setEnrollHostname] = useState("");
  const [enrollOs, setEnrollOs] = useState("linux");
  const [enrollIp, setEnrollIp] = useState("");
  const [enrollVersion, setEnrollVersion] = useState("1.0.0");
  const [enrollSubmitting, setEnrollSubmitting] = useState(false);
  const [enrollError, setEnrollError] = useState(null);

  const loadEndpoints = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getEndpoints();
      const list = res.data?.endpoints || res.endpoints || res.data || [];
      setEndpoints(Array.isArray(list) ? list : []);
    } catch (err) {
      setError(err.message || "Failed to load endpoint fleet.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEndpoints();
  }, [loadEndpoints]);

  const loadDetail = async (deviceId) => {
    setDetailLoading(true);
    try {
      const res = await getEndpointDetails(deviceId);
      const ep = res.data || res;
      setSelectedEndpoint(ep);
      setEditHostname(ep.hostname || "");
      setEditIp(ep.ip_address || "");
      setIsEditing(false);
    } catch (err) {
      alert(`Failed to load device details: ${err.message}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleToggleStatus = async (ep) => {
    const isCurrentlyDisabled = (ep.status || "").toLowerCase() === "disabled";
    const targetStatus = isCurrentlyDisabled ? "active" : "disabled";
    setTogglingId(ep.device_id);
    try {
      await updateEndpointStatus(ep.device_id, targetStatus);
      await loadEndpoints();
      if (selectedEndpoint && selectedEndpoint.device_id === ep.device_id) {
        await loadDetail(ep.device_id);
      }
    } catch (err) {
      alert(`Failed to update status for ${ep.device_id}: ${err.message}`);
    } finally {
      setTogglingId(null);
    }
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    if (!selectedEndpoint) return;
    setEditSubmitting(true);
    try {
      await updateEndpoint(selectedEndpoint.device_id, {
        hostname: editHostname.trim(),
        ip_address: editIp.trim() || null,
      });
      setIsEditing(false);
      await loadDetail(selectedEndpoint.device_id);
      await loadEndpoints();
    } catch (err) {
      alert(`Failed to update endpoint: ${err.message}`);
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleEnroll = async (e) => {
    e.preventDefault();
    const cleanId = enrollDeviceId.trim();
    const cleanHost = enrollHostname.trim();
    if (!cleanId || !cleanHost) {
      setEnrollError("Device ID and Hostname are required.");
      return;
    }

    setEnrollSubmitting(true);
    setEnrollError(null);
    try {
      await enrollEndpoint({
        device_id: cleanId,
        hostname: cleanHost,
        os: enrollOs,
        ip_address: enrollIp.trim() || null,
        agent_version: enrollVersion.trim() || "1.0.0",
        status: "active",
      });
      setShowEnrollModal(false);
      setEnrollDeviceId("");
      setEnrollHostname("");
      setEnrollIp("");
      await loadEndpoints();
    } catch (err) {
      setEnrollError(err.message || "Failed to enroll endpoint device.");
    } finally {
      setEnrollSubmitting(false);
    }
  };

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      const matchSearch =
        search === "" ||
        (ep.device_id && ep.device_id.toLowerCase().includes(search.toLowerCase())) ||
        (ep.hostname && ep.hostname.toLowerCase().includes(search.toLowerCase())) ||
        (ep.ip_address && ep.ip_address.toLowerCase().includes(search.toLowerCase()));

      const matchOs =
        osFilter === "all" ||
        (ep.os && ep.os.toLowerCase() === osFilter.toLowerCase());

      const health = getEndpointHealth(ep);
      const matchStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && health.label.includes("Active")) ||
        (statusFilter === "offline" && health.label.includes("Offline")) ||
        (statusFilter === "disabled" && health.label.includes("Disabled"));

      return matchSearch && matchOs && matchStatus;
    });
  }, [endpoints, search, osFilter, statusFilter]);

  const columns = [
    {
      key: "device_id",
      label: "Device ID",
      render: (r) => (
        <span className="font-mono text-xs font-bold text-accent">{r.device_id}</span>
      ),
    },
    {
      key: "hostname",
      label: "Hostname",
      render: (r) => (
        <span className="font-semibold text-xs text-white flex items-center gap-1.5">
          <FaDesktop size={11} className="text-slate-400" />
          <span>{r.hostname}</span>
        </span>
      ),
    },
    {
      key: "os",
      label: "Operating System",
      render: (r) => <OsBadge os={r.os} />,
    },
    {
      key: "health",
      label: "Fleet Health Status",
      render: (r) => {
        const health = getEndpointHealth(r);
        return (
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold border ${health.badgeClass}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${health.dotClass}`} />
            <span>{health.label}</span>
          </span>
        );
      },
    },
    {
      key: "ip_address",
      label: "IP Address",
      render: (r) => (
        <span className="font-mono text-xs text-slate-300">
          {r.ip_address || "—"}
        </span>
      ),
    },
    {
      key: "event_count",
      label: "Events Ingested",
      render: (r) => (
        <span className="font-mono text-xs text-accent font-semibold">
          {r.event_count ?? 0}
        </span>
      ),
    },
    {
      key: "last_seen",
      label: "Last Seen (UTC)",
      render: (r) => (
        <span className="font-mono text-xs text-slate-400">
          {formatTimestamp(r.last_seen)}
        </span>
      ),
    },
    {
      key: "actions",
      label: "Lifecycle Actions",
      render: (r) => {
        const isDisabled = (r.status || "").toLowerCase() === "disabled";
        const isToggling = togglingId === r.device_id;
        return (
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={isToggling}
              onClick={(e) => {
                e.stopPropagation();
                handleToggleStatus(r);
              }}
              className={`rounded px-2.5 py-1 text-xs font-semibold border transition ${
                isDisabled
                  ? "bg-emerald-950/30 text-emerald-300 border-emerald-600/40 hover:bg-emerald-900/40"
                  : "bg-red-950/30 text-red-300 border-red-600/40 hover:bg-red-900/40"
              } disabled:opacity-40`}
            >
              {isToggling ? "..." : isDisabled ? "Enable Agent" : "Disable Agent"}
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                loadDetail(r.device_id);
              }}
              className="rounded bg-slate-800 px-2.5 py-1 text-xs text-slate-300 border border-slate-700 hover:bg-slate-700 hover:text-white transition font-medium"
            >
              Inspect
            </button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 flex-1">
          <div className="relative min-w-[220px] max-w-sm">
            <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by device ID, hostname, IP..."
              className="w-full rounded-lg border border-slate-700 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-2">
            <FaFilter className="text-slate-500 text-xs" />
            <select
              value={osFilter}
              onChange={(e) => setOsFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
            >
              <option value="all">All Operating Systems</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
            >
              <option value="all">All Fleet Health States</option>
              <option value="active">Active / Healthy Only</option>
              <option value="offline">Offline Only</option>
              <option value="disabled">Disabled Only</option>
            </select>
          </div>
        </div>

        <button
          onClick={() => setShowEnrollModal(true)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 shadow-sm shadow-accent/20"
        >
          <FaPlus size={10} />
          <span>Enroll New Endpoint</span>
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-xs text-danger">
          {error}
        </div>
      )}

      {/* Fleet Table */}
      <DataTable
        title="Enrolled Endpoint Fleet & Agent Telemetry Status"
        count={filteredEndpoints.length}
        columns={columns}
        rows={filteredEndpoints}
        pageSize={10}
        onRowClick={(r) => loadDetail(r.device_id)}
        emptyText={
          loading
            ? "Querying endpoint fleet registry from SQLite..."
            : "No endpoints match the active filter criteria."
        }
      />

      {/* Endpoint Detail / Telemetry Modal */}
      {selectedEndpoint && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
                  <FaDesktop size={18} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-accent">
                      {selectedEndpoint.device_id}
                    </span>
                    <span className="text-slate-500">•</span>
                    <OsBadge os={selectedEndpoint.os} />
                  </div>
                  <h2 className="text-lg font-bold text-white">
                    {selectedEndpoint.hostname}
                  </h2>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 border border-slate-700 hover:bg-slate-700 hover:text-white transition"
                >
                  <FaEdit size={11} className="text-accent" />
                  <span>{isEditing ? "Cancel Edit" : "Edit Details"}</span>
                </button>
                <button
                  onClick={() => setSelectedEndpoint(null)}
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
                >
                  <FaTimes size={16} />
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
              {/* Edit Form */}
              {isEditing ? (
                <form onSubmit={handleSaveEdit} className="rounded-lg border border-accent/40 bg-accent/5 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-700/60 pb-2">
                    <h3 className="text-xs font-bold text-accent uppercase tracking-wider">
                      Update Endpoint Properties
                    </h3>
                    <span className="text-[11px] text-slate-400 font-mono">{selectedEndpoint.device_id}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Hostname *
                      </label>
                      <input
                        type="text"
                        required
                        value={editHostname}
                        onChange={(e) => setEditHostname(e.target.value)}
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        IP Address
                      </label>
                      <input
                        type="text"
                        value={editIp}
                        onChange={(e) => setEditIp(e.target.value)}
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setIsEditing(false)}
                      className="rounded bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={editSubmitting}
                      className="rounded bg-accent px-4 py-1 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                    >
                      {editSubmitting ? "Saving..." : "Save Properties"}
                    </button>
                  </div>
                </form>
              ) : null}

              {/* Status & Telemetry Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Health State</div>
                  <div className="mt-1">
                    {(() => {
                      const health = getEndpointHealth(selectedEndpoint);
                      return (
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold border ${health.badgeClass}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${health.dotClass}`} />
                          <span>{health.label}</span>
                        </span>
                      );
                    })()}
                  </div>
                </div>

                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">IP Address</div>
                  <div className="mt-1 font-mono text-xs font-semibold text-white">
                    {selectedEndpoint.ip_address || "—"}
                  </div>
                </div>

                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Agent Version</div>
                  <div className="mt-1 font-mono text-xs font-semibold text-slate-300">
                    v{selectedEndpoint.agent_version || "1.0.0"}
                  </div>
                </div>

                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Telemetry Ingested</div>
                  <div className="mt-1 font-mono text-xs font-bold text-accent">
                    {selectedEndpoint.event_count ?? 0} Events
                  </div>
                </div>
              </div>

              {/* Timing Metadata */}
              <div className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-700/60 bg-slate-900/30 px-4 py-3 text-xs text-slate-300">
                <div className="flex items-center gap-2">
                  <FaClock className="text-accent" />
                  <span className="text-slate-400">Enrolled:</span>
                  <span className="font-mono text-slate-200">
                    {formatTimestamp(selectedEndpoint.registered_at)}
                  </span>
                </div>
                <span className="text-slate-600">•</span>
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Last Telemetry:</span>
                  <span className="font-mono text-slate-200">
                    {formatTimestamp(selectedEndpoint.last_seen)}
                  </span>
                </div>
                <div className="ml-auto">
                  <button
                    type="button"
                    onClick={() => handleToggleStatus(selectedEndpoint)}
                    className="rounded bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-200 border border-slate-700 hover:bg-slate-700 transition"
                  >
                    {(selectedEndpoint.status || "").toLowerCase() === "disabled"
                      ? "Enable Agent"
                      : "Disable Agent"}
                  </button>
                </div>
              </div>

              {/* Recent Telemetry Stream */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <FaStream size={12} className="text-accent" />
                    <span>Recent Agent Telemetry ({selectedEndpoint.recent_events?.length || 0})</span>
                  </h3>
                  <span className="text-[11px] text-slate-500 font-mono">20 Most Recent Events</span>
                </div>

                {(!selectedEndpoint.recent_events || selectedEndpoint.recent_events.length === 0) ? (
                  <div className="rounded-lg border border-slate-700/50 bg-slate-900/30 p-6 text-center text-xs text-slate-500">
                    No endpoint agent telemetry ingested from this device yet.
                  </div>
                ) : (
                  <div className="overflow-x-auto rounded-lg border border-slate-700/60 bg-slate-900/60 max-h-60 overflow-y-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400 sticky top-0">
                        <tr>
                          <th className="px-3 py-2">Timestamp (UTC)</th>
                          <th className="px-3 py-2">Event Type</th>
                          <th className="px-3 py-2">Severity</th>
                          <th className="px-3 py-2">Source IP</th>
                          <th className="px-3 py-2">Username</th>
                          <th className="px-3 py-2">Raw Telemetry</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {selectedEndpoint.recent_events.map((ev, i) => (
                          <tr key={ev.event_id || i} className="hover:bg-slate-800/50">
                            <td className="px-3 py-1.5 font-mono whitespace-nowrap text-slate-400">
                              {formatTimestamp(ev.timestamp)}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-accent">
                              {ev.event_type}
                            </td>
                            <td className="px-3 py-1.5">
                              <span className="uppercase text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                                {ev.severity || "info"}
                              </span>
                            </td>
                            <td className="px-3 py-1.5 font-mono text-slate-300">
                              {ev.source_ip || "—"}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-white">
                              {ev.username || "—"}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-[11px] text-slate-400 truncate max-w-xs" title={ev.raw_event}>
                              {ev.raw_event || "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60 text-xs text-slate-400">
              <span>Endpoint: <span className="font-mono text-slate-300">{selectedEndpoint.device_id}</span></span>
              <button
                onClick={() => setSelectedEndpoint(null)}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-slate-600"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Enroll Modal */}
      {showEnrollModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-700 bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FaPlus size={12} className="text-accent" />
                <span>Enroll Endpoint Agent</span>
              </h3>
              <button
                onClick={() => setShowEnrollModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <FaTimes size={14} />
              </button>
            </div>

            {enrollError && (
              <div className="rounded-lg border border-danger/40 bg-danger/10 p-2.5 text-xs text-danger">
                {enrollError}
              </div>
            )}

            <form onSubmit={handleEnroll} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Device ID *
                  </label>
                  <input
                    type="text"
                    required
                    value={enrollDeviceId}
                    onChange={(e) => setEnrollDeviceId(e.target.value)}
                    placeholder="e.g. endpoint-02"
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Hostname *
                  </label>
                  <input
                    type="text"
                    required
                    value={enrollHostname}
                    onChange={(e) => setEnrollHostname(e.target.value)}
                    placeholder="e.g. soc-web-node"
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Operating System
                  </label>
                  <select
                    value={enrollOs}
                    onChange={(e) => setEnrollOs(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                  >
                    <option value="linux">Linux</option>
                    <option value="windows">Windows</option>
                    <option value="macos">macOS</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Agent Version
                  </label>
                  <input
                    type="text"
                    value={enrollVersion}
                    onChange={(e) => setEnrollVersion(e.target.value)}
                    placeholder="1.0.0"
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Initial IP Address (Optional)
                </label>
                <input
                  type="text"
                  value={enrollIp}
                  onChange={(e) => setEnrollIp(e.target.value)}
                  placeholder="e.g. 192.168.1.105"
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowEnrollModal(false)}
                  className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={enrollSubmitting}
                  className="rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                >
                  {enrollSubmitting ? "Enrolling..." : "Enroll Device"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
