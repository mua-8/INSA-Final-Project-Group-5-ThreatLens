import React, { useState, useEffect, useMemo, useCallback } from "react";
import DataTable from "./DataTable.jsx";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import {
  getIncidents,
  getIncidentDetails,
  createIncident,
  updateIncident,
  updateIncidentStatus,
  unlinkAlertFromIncident,
  addIncidentNote,
} from "../services/api.js";
import {
  FaSearch,
  FaFilter,
  FaPlus,
  FaFolderOpen,
  FaTimes,
  FaCommentAlt,
  FaShieldAlt,
  FaUserEdit,
  FaExclamationTriangle,
  FaCheckCircle,
  FaEdit,
  FaTrash,
  FaRedo,
  FaUserTag,
} from "react-icons/fa";

export default function IncidentsView({ onRefreshDashboard }) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  // Selected incident for detail view
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [newNote, setNewNote] = useState("");
  const [noteAuthor, setNoteAuthor] = useState("SOC Analyst");
  const [noteSubmitting, setNoteSubmitting] = useState(false);
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  // Edit incident state
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editSeverity, setEditSeverity] = useState("high");
  const [editAssignee, setEditAssignee] = useState("");
  const [editStatus, setEditStatus] = useState("open");
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Close / Resolve with reason dialog state
  const [showCloseDialog, setShowCloseDialog] = useState(false);
  const [targetStatus, setTargetStatus] = useState("closed");
  const [closeReason, setCloseReason] = useState("");
  const [closeSubmitting, setCloseSubmitting] = useState(false);

  // New incident modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createTitle, setCreateTitle] = useState("");
  const [createSeverity, setCreateSeverity] = useState("high");
  const [createDesc, setCreateDesc] = useState("");
  const [createAssignee, setCreateAssignee] = useState("");
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getIncidents();
      const list = res.data?.incidents || res.incidents || res.data || [];
      setIncidents(Array.isArray(list) ? list : []);
    } catch (err) {
      setError(err.message || "Failed to load incident cases.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const loadIncidentDetails = async (id) => {
    setDetailLoading(true);
    try {
      const res = await getIncidentDetails(id);
      const inc = res.data || res;
      setSelectedIncident(inc);
      setEditTitle(inc.title || "");
      setEditDesc(inc.description || "");
      setEditSeverity(inc.severity || "high");
      setEditAssignee(inc.assignee || "");
      setEditStatus(inc.status || "open");
    } catch (err) {
      console.error("Failed to load incident detail:", err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!selectedIncident?.id) return;
    setStatusSubmitting(true);
    try {
      await updateIncidentStatus(selectedIncident.id, newStatus);
      await loadIncidentDetails(selectedIncident.id);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to update incident status: " + err.message);
    } finally {
      setStatusSubmitting(false);
    }
  };

  const openCloseDialog = (status) => {
    setTargetStatus(status);
    setCloseReason("");
    setShowCloseDialog(true);
  };

  const handleConfirmClose = async (e) => {
    e.preventDefault();
    if (!selectedIncident?.id) return;
    setCloseSubmitting(true);
    try {
      await updateIncidentStatus(selectedIncident.id, targetStatus, closeReason.trim());
      setShowCloseDialog(false);
      setCloseReason("");
      await loadIncidentDetails(selectedIncident.id);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to close/resolve incident: " + err.message);
    } finally {
      setCloseSubmitting(false);
    }
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    if (!selectedIncident?.id || !editTitle.trim()) return;
    setEditSubmitting(true);
    try {
      await updateIncident(selectedIncident.id, {
        title: editTitle.trim(),
        description: editDesc.trim(),
        severity: editSeverity,
        status: editStatus,
        assignee: editAssignee.trim() || null,
      });
      setIsEditing(false);
      await loadIncidentDetails(selectedIncident.id);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to update incident: " + err.message);
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleUnlinkAlert = async (alertId) => {
    if (!selectedIncident?.id || !alertId) return;
    if (!window.confirm(`Unlink Alert #${alertId} from Incident #${selectedIncident.id}?`)) return;
    try {
      await unlinkAlertFromIncident(selectedIncident.id, alertId);
      await loadIncidentDetails(selectedIncident.id);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to unlink alert: " + err.message);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!selectedIncident?.id || !newNote.trim()) return;
    setNoteSubmitting(true);
    try {
      await addIncidentNote(
        selectedIncident.id,
        newNote.trim(),
        noteAuthor.trim() || "SOC Analyst"
      );
      setNewNote("");
      await loadIncidentDetails(selectedIncident.id);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to append case note: " + err.message);
    } finally {
      setNoteSubmitting(false);
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!createTitle.trim()) return;
    setCreateSubmitting(true);
    setCreateError(null);
    try {
      await createIncident({
        title: createTitle.trim(),
        severity: createSeverity,
        description: createDesc.trim() || "Manual SOC investigation case",
        assignee: createAssignee.trim() || null,
      });
      setCreateTitle("");
      setCreateDesc("");
      setCreateAssignee("");
      setShowCreateModal(false);
      loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setCreateError(err.message || "Failed to create incident.");
    } finally {
      setCreateSubmitting(false);
    }
  };

  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const matchSearch =
        search === "" ||
        (inc.title && inc.title.toLowerCase().includes(search.toLowerCase())) ||
        (inc.description && inc.description.toLowerCase().includes(search.toLowerCase())) ||
        (inc.assignee && inc.assignee.toLowerCase().includes(search.toLowerCase())) ||
        String(inc.id).includes(search);

      const matchStatus =
        statusFilter === "all" ||
        (inc.status && inc.status.toLowerCase() === statusFilter.toLowerCase());

      const matchSeverity =
        severityFilter === "all" ||
        (inc.severity && inc.severity.toLowerCase() === severityFilter.toLowerCase());

      return matchSearch && matchStatus && matchSeverity;
    });
  }, [incidents, search, statusFilter, severityFilter]);

  const columns = [
    {
      key: "id",
      label: "Case ID",
      render: (r) => <span className="font-mono text-xs text-accent font-bold">INC-#{r.id}</span>,
    },
    {
      key: "created_at",
      label: "Opened (UTC)",
      render: (r) => (
        <span className="font-mono text-xs text-slate-300">
          {formatTimestamp(r.created_at)}
        </span>
      ),
    },
    {
      key: "title",
      label: "Incident Title",
      render: (r) => (
        <div>
          <span className="font-semibold text-white">{r.title}</span>
          {r.description && (
            <p className="text-xs text-slate-400 truncate max-w-xs">{r.description}</p>
          )}
        </div>
      ),
    },
    {
      key: "severity",
      label: "Severity",
      render: (r) => <SeverityBadge severity={r.severity} />,
    },
    {
      key: "status",
      label: "Lifecycle Status",
      render: (r) => <StatusBadge status={r.status} />,
    },
    {
      key: "assignee",
      label: "Assignee",
      render: (r) => (
        <span className="font-mono text-xs text-slate-300 flex items-center gap-1">
          <FaUserTag size={10} className="text-accent/70" />
          <span>{r.assignee || "Unassigned"}</span>
        </span>
      ),
    },
    {
      key: "actions",
      label: "Action",
      render: (r) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            loadIncidentDetails(r.id);
          }}
          className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 text-xs text-slate-300 border border-slate-700 transition hover:bg-slate-700 hover:text-white font-medium"
        >
          <FaFolderOpen size={11} className="text-accent" />
          <span>Case Details</span>
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      {/* Search, Filter, and Action Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2 flex-1">
          <div className="relative min-w-[220px] max-w-sm">
            <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search incidents by ID, title, description..."
              className="w-full rounded-lg border border-slate-700 bg-slate-900/60 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-2">
            <FaFilter className="text-slate-500 text-xs" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="closed">Closed</option>
            </select>

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

        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 shadow-sm shadow-accent/20"
        >
          <FaPlus size={10} />
          <span>Create Incident</span>
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-xs text-danger">
          {error}
        </div>
      )}

      {/* Primary Incidents Table */}
      <DataTable
        title="Security Incident Cases"
        count={filteredIncidents.length}
        columns={columns}
        rows={filteredIncidents}
        pageSize={10}
        onRowClick={(r) => loadIncidentDetails(r.id)}
        emptyText={
          loading
            ? "Loading incident cases from SQLite..."
            : "No security incidents match the active filter criteria."
        }
      />

      {/* Incident Detail / Investigation Drawer Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">

            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
                  <FaShieldAlt size={18} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-accent">
                      INC-#{selectedIncident.id}
                    </span>
                    <span className="text-slate-500">•</span>
                    <span className="font-mono text-xs text-slate-400">
                      Opened {formatTimestamp(selectedIncident.created_at)}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-white">
                    {selectedIncident.title}
                  </h2>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 border border-slate-700 hover:bg-slate-700 hover:text-white transition"
                >
                  <FaEdit size={11} className="text-accent" />
                  <span>{isEditing ? "Cancel Edit" : "Edit Incident"}</span>
                </button>
                <button
                  onClick={() => {
                    setSelectedIncident(null);
                    setIsEditing(false);
                  }}
                  aria-label="Close dialog"
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
                >
                  <FaTimes size={16} />
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">

              {/* Edit Mode Form */}
              {isEditing ? (
                <form onSubmit={handleSaveEdit} className="rounded-lg border border-accent/40 bg-accent/5 p-4 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-700/60 pb-2">
                    <h3 className="text-xs font-bold text-accent uppercase tracking-wider">
                      Edit Incident Properties
                    </h3>
                    <span className="text-[11px] text-slate-400 font-mono">INC-#{selectedIncident.id}</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="sm:col-span-2">
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Incident Title *
                      </label>
                      <input
                        type="text"
                        required
                        value={editTitle}
                        onChange={(e) => setEditTitle(e.target.value)}
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                      />
                    </div>

                    <div>
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Severity
                      </label>
                      <select
                        value={editSeverity}
                        onChange={(e) => setEditSeverity(e.target.value)}
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                      >
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Lifecycle Status
                      </label>
                      <select
                        value={editStatus}
                        onChange={(e) => setEditStatus(e.target.value)}
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="closed">Closed</option>
                      </select>
                    </div>

                    <div className="sm:col-span-2">
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Assigned Analyst
                      </label>
                      <input
                        type="text"
                        value={editAssignee}
                        onChange={(e) => setEditAssignee(e.target.value)}
                        placeholder="e.g. analyst-1 or unassigned"
                        className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-white placeholder-slate-500 focus:border-accent focus:outline-none"
                      />
                    </div>

                    <div className="sm:col-span-2">
                      <label className="block text-[11px] font-medium text-slate-300 mb-1">
                        Case Description
                      </label>
                      <textarea
                        rows={2}
                        value={editDesc}
                        onChange={(e) => setEditDesc(e.target.value)}
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
                      disabled={editSubmitting || !editTitle.trim()}
                      className="rounded bg-accent px-4 py-1 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                    >
                      {editSubmitting ? "Saving..." : "Save Changes"}
                    </button>
                  </div>
                </form>
              ) : null}

              {/* Metadata Cards */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Severity</div>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedIncident.severity} />
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Current Status</div>
                  <div className="mt-1">
                    <StatusBadge status={selectedIncident.status} />
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Assigned Analyst</div>
                  <div className="mt-1 font-mono text-xs font-semibold text-accent flex items-center gap-1 truncate">
                    <FaUserTag size={10} className="text-accent/70 shrink-0" />
                    <span className="truncate">{selectedIncident.assignee || "Unassigned"}</span>
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Linked Alerts</div>
                  <div className="mt-1 font-mono text-xs font-bold text-accent">
                    {selectedIncident.alerts?.length || 0} Alerts
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Case Notes</div>
                  <div className="mt-1 font-mono text-xs font-bold text-slate-200">
                    {selectedIncident.notes?.length || 0} Notes
                  </div>
                </div>
              </div>

              {/* Close / Resolution Reason Display */}
              {selectedIncident.close_reason && (
                <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-3 text-xs">
                  <span className="font-semibold text-emerald-400">Resolution / Closure Rationale: </span>
                  <span className="text-slate-200">{selectedIncident.close_reason}</span>
                </div>
              )}

              {/* Status Update Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-700/60 bg-slate-800/60 p-3.5">
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                    Incident Lifecycle Status
                  </h4>
                  <p className="text-xs text-slate-400">
                    Update case triage state across the incident response cycle.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    disabled={statusSubmitting || selectedIncident.status === "open"}
                    onClick={() => handleStatusChange("open")}
                    className="rounded-lg bg-warning/20 px-2.5 py-1 text-xs font-semibold text-warning border border-warning/40 transition hover:bg-warning/30 disabled:opacity-40"
                  >
                    Open
                  </button>
                  <button
                    disabled={statusSubmitting || selectedIncident.status === "in_progress"}
                    onClick={() => handleStatusChange("in_progress")}
                    className="rounded-lg bg-sky-500/20 px-2.5 py-1 text-xs font-semibold text-sky-300 border border-sky-500/40 transition hover:bg-sky-500/30 disabled:opacity-40"
                  >
                    In Progress
                  </button>
                  <button
                    disabled={statusSubmitting || selectedIncident.status === "resolved"}
                    onClick={() => openCloseDialog("resolved")}
                    className="rounded-lg bg-emerald-500/20 px-2.5 py-1 text-xs font-semibold text-emerald-300 border border-emerald-500/40 transition hover:bg-emerald-500/30 disabled:opacity-40"
                  >
                    Resolve Case
                  </button>
                  <button
                    disabled={statusSubmitting || selectedIncident.status === "closed"}
                    onClick={() => openCloseDialog("closed")}
                    className="rounded-lg bg-slate-700 px-2.5 py-1 text-xs font-semibold text-slate-300 border border-slate-600 transition hover:bg-slate-600 disabled:opacity-40"
                  >
                    Close Case
                  </button>
                  {(selectedIncident.status === "closed" || selectedIncident.status === "resolved") && (
                    <button
                      disabled={statusSubmitting}
                      onClick={() => handleStatusChange("open")}
                      className="rounded-lg bg-indigo-500/20 px-2.5 py-1 text-xs font-semibold text-indigo-300 border border-indigo-500/40 transition hover:bg-indigo-500/30 disabled:opacity-40 inline-flex items-center gap-1"
                    >
                      <FaRedo size={10} />
                      <span>Reopen</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Linked Alerts */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Correlated Alerts Attached to Case ({selectedIncident.alerts?.length || 0})
                </h3>
                {(!selectedIncident.alerts || selectedIncident.alerts.length === 0) ? (
                  <div className="rounded-lg border border-slate-700/50 bg-slate-900/30 p-4 text-center text-xs text-slate-500">
                    No individual alerts linked to this incident.
                  </div>
                ) : (
                  <div className="divide-y divide-slate-800 rounded-lg border border-slate-700/60 bg-slate-900/50 overflow-hidden">
                    {selectedIncident.alerts.map((al) => (
                      <div key={al.id} className="p-3 text-xs flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-accent font-semibold">#{al.id}</span>
                          <span className="font-semibold text-white">{al.rule_name || al.title}</span>
                          <span className="font-mono text-slate-400">({al.rule_id})</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-slate-400">Host: {al.target_host || "server"}</span>
                          <SeverityBadge severity={al.severity} />
                          <button
                            type="button"
                            onClick={() => handleUnlinkAlert(al.id)}
                            className="rounded bg-danger/15 p-1.5 text-danger border border-danger/30 hover:bg-danger/25 transition text-xs"
                            title="Unlink alert from this incident"
                          >
                            <FaTrash size={10} />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Case Notes & Chronological Audit Timeline */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Analyst Case Notes & Triage Audit ({selectedIncident.notes?.length || 0})
                </h3>

                <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                  {(!selectedIncident.notes || selectedIncident.notes.length === 0) ? (
                    <div className="rounded-lg border border-slate-700/50 bg-slate-900/30 p-4 text-center text-xs text-slate-500">
                      No case notes appended yet. Document your triage actions below.
                    </div>
                  ) : (
                    selectedIncident.notes.map((n, i) => (
                      <div
                        key={n.id || i}
                        className="rounded-lg border border-slate-700/50 bg-slate-900/50 p-3 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-slate-400">
                          <span className="font-semibold text-accent flex items-center gap-1">
                            <FaUserEdit size={10} />
                            <span>{n.author || "SOC Analyst"}</span>
                          </span>
                          <span className="font-mono text-[11px]">
                            {formatTimestamp(n.created_at)}
                          </span>
                        </div>
                        <p className="text-slate-200 leading-relaxed font-sans">{n.body || n.note}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Append Note Form */}
                <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-slate-700/60">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-slate-400 whitespace-nowrap">Analyst ID:</label>
                    <input
                      type="text"
                      value={noteAuthor}
                      onChange={(e) => setNoteAuthor(e.target.value)}
                      placeholder="SOC Analyst"
                      className="rounded bg-slate-900/80 border border-slate-700 px-2 py-1 text-xs text-slate-200 font-mono w-40 focus:border-accent focus:outline-none"
                    />
                  </div>
                  <div className="flex gap-2">
                    <textarea
                      rows={2}
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      placeholder="Add investigation findings, containment steps, or triage summary..."
                      className="flex-1 rounded-lg bg-slate-900/80 border border-slate-700 p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={noteSubmitting || !newNote.trim()}
                      className="self-end rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-primary transition hover:bg-sky-300 disabled:opacity-40"
                    >
                      {noteSubmitting ? "Saving..." : "Add Note"}
                    </button>
                  </div>
                </form>
              </div>

            </div>

            {/* Footer */}
            <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60 text-xs text-slate-400">
              <span>Incident #{selectedIncident.id} • {selectedIncident.alerts?.length || 0} Linked Alerts</span>
              <button
                onClick={() => {
                  setSelectedIncident(null);
                  setIsEditing(false);
                }}
                className="rounded-lg bg-slate-700 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-slate-600"
              >
                Close Case Window
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Close / Resolve with Reason Dialog Modal */}
      {showCloseDialog && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-5 space-y-3 shadow-2xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FaCheckCircle className="text-accent" size={14} />
              <span>{targetStatus === "resolved" ? "Resolve Incident Case" : "Close Incident Case"}</span>
            </h3>
            <p className="text-xs text-slate-400">
              Please provide the resolution rationale, root-cause summary, or closure justification.
            </p>
            <textarea
              rows={3}
              required
              value={closeReason}
              onChange={(e) => setCloseReason(e.target.value)}
              placeholder="e.g. Malicious IP blocked at perimeter firewall; credentials rotated."
              className="w-full rounded bg-slate-950 border border-slate-700 p-2 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
            />
            <div className="flex justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={() => setShowCloseDialog(false)}
                className="rounded bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={closeSubmitting || !closeReason.trim()}
                onClick={handleConfirmClose}
                className="rounded bg-accent px-4 py-1.5 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
              >
                {closeSubmitting ? "Updating..." : "Confirm & Update"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-700 bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FaPlus size={12} className="text-accent" />
                <span>Create Security Incident Case</span>
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <FaTimes size={14} />
              </button>
            </div>

            {createError && (
              <div className="rounded-lg border border-danger/40 bg-danger/10 p-2.5 text-xs text-danger">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateIncident} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Incident Title *
                </label>
                <input
                  type="text"
                  required
                  value={createTitle}
                  onChange={(e) => setCreateTitle(e.target.value)}
                  placeholder="e.g. Distributed SSH Brute Force Surge"
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Initial Severity
                  </label>
                  <select
                    value={createSeverity}
                    onChange={(e) => setCreateSeverity(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Assigned Analyst
                  </label>
                  <input
                    type="text"
                    value={createAssignee}
                    onChange={(e) => setCreateAssignee(e.target.value)}
                    placeholder="e.g. analyst-1"
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Case Description & Scope
                </label>
                <textarea
                  rows={3}
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  placeholder="Describe initial indicators of compromise, affected hosts, or reason for case escalation..."
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting || !createTitle.trim()}
                  className="rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                >
                  {createSubmitting ? "Creating..." : "Open Incident Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
