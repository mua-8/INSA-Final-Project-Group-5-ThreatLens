import React, { useState, useEffect, useMemo, useCallback } from "react";
import DataTable from "./DataTable.jsx";
import { SeverityBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import {
  getDetectionRules,
  getDetectionRule,
  createDetectionRule,
  updateDetectionRule,
  toggleDetectionRule,
  getRuleAuditLogs,
} from "../services/api.js";
import {
  FaSearch,
  FaFilter,
  FaPlus,
  FaTimes,
  FaHistory,
  FaEdit,
  FaCheckCircle,
  FaTimesCircle,
  FaSlidersH,
  FaShieldAlt,
  FaCode,
} from "react-icons/fa";

export default function DetectionRulesView() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [enabledFilter, setEnabledFilter] = useState("all");
  const [togglingRuleId, setTogglingRuleId] = useState(null);

  // Create Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createRuleId, setCreateRuleId] = useState("");
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createSeverity, setCreateSeverity] = useState("medium");
  const [createThreshold, setCreateThreshold] = useState("5");
  const [createWindow, setCreateWindow] = useState("10");
  const [createConditions, setCreateConditions] = useState("{\n  \"event_type\": \"ssh_auth_failure\"\n}");
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState(null);

  // Edit Modal State
  const [editRule, setEditRule] = useState(null);
  const [editName, setEditName] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editSeverity, setEditSeverity] = useState("medium");
  const [editThreshold, setEditThreshold] = useState("5");
  const [editWindow, setEditWindow] = useState("10");
  const [editConditions, setEditConditions] = useState("{}");
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState(null);

  // Audit Modal State
  const [auditRuleId, setAuditRuleId] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);

  const loadRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getDetectionRules();
      const list = res.data?.rules || res.rules || res.data || [];
      setRules(Array.isArray(list) ? list : []);
    } catch (err) {
      setError(err.message || "Failed to load detection rules.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleToggle = async (rule) => {
    setTogglingRuleId(rule.rule_id);
    try {
      const newEnabled = !Boolean(rule.enabled);
      await toggleDetectionRule(rule.rule_id, newEnabled, "SOC Analyst");
      await loadRules();
    } catch (err) {
      alert(`Failed to toggle rule ${rule.rule_id}: ${err.message}`);
    } finally {
      setTogglingRuleId(null);
    }
  };

  const handleOpenEdit = (rule) => {
    setEditRule(rule);
    setEditName(rule.name || "");
    setEditDesc(rule.description || "");
    setEditSeverity(rule.severity || "medium");
    setEditThreshold(String(rule.threshold || 5));
    setEditWindow(String(rule.window_minutes || 10));
    try {
      const parsed = typeof rule.conditions === "string" ? JSON.parse(rule.conditions) : rule.conditions;
      setEditConditions(JSON.stringify(parsed || {}, null, 2));
    } catch {
      setEditConditions(rule.conditions || "{}");
    }
    setEditError(null);
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    if (!editRule) return;

    const thresholdNum = parseInt(editThreshold, 10);
    const windowNum = parseInt(editWindow, 10);
    if (isNaN(thresholdNum) || thresholdNum < 1) {
      setEditError("Threshold must be a positive integer >= 1.");
      return;
    }
    if (isNaN(windowNum) || windowNum < 1) {
      setEditError("Window (minutes) must be a positive integer >= 1.");
      return;
    }

    setEditSubmitting(true);
    setEditError(null);
    try {
      await updateDetectionRule(editRule.rule_id, {
        name: editName.trim(),
        description: editDesc.trim(),
        severity: editSeverity,
        threshold: thresholdNum,
        window_minutes: windowNum,
        conditions: editConditions.trim() || "{}",
        changed_by: "SOC Analyst",
      });
      setEditRule(null);
      await loadRules();
    } catch (err) {
      setEditError(err.message || "Failed to update detection rule.");
    } finally {
      setEditSubmitting(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    const cleanId = createRuleId.trim().toUpperCase();
    if (!cleanId) {
      setCreateError("Rule ID is required (e.g. DR-06).");
      return;
    }
    if (!createName.trim()) {
      setCreateError("Rule Name is required.");
      return;
    }

    const thresholdNum = parseInt(createThreshold, 10);
    const windowNum = parseInt(createWindow, 10);
    if (isNaN(thresholdNum) || thresholdNum < 1) {
      setCreateError("Threshold must be a positive integer >= 1.");
      return;
    }
    if (isNaN(windowNum) || windowNum < 1) {
      setCreateError("Window (minutes) must be a positive integer >= 1.");
      return;
    }

    setCreateSubmitting(true);
    setCreateError(null);
    try {
      await createDetectionRule({
        rule_id: cleanId,
        name: createName.trim(),
        description: createDesc.trim(),
        severity: createSeverity,
        threshold: thresholdNum,
        window_minutes: windowNum,
        conditions: createConditions.trim() || "{}",
        enabled: true,
        changed_by: "SOC Analyst",
      });
      setShowCreateModal(false);
      setCreateRuleId("");
      setCreateName("");
      setCreateDesc("");
      await loadRules();
    } catch (err) {
      setCreateError(err.message || "Failed to create detection rule.");
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleViewAudit = async (ruleId) => {
    setAuditRuleId(ruleId);
    setAuditLoading(true);
    try {
      const res = await getRuleAuditLogs(ruleId);
      const list = res.data?.audit_logs || res.audit_logs || res.data || [];
      setAuditLogs(Array.isArray(list) ? list : []);
    } catch (err) {
      alert(`Failed to load audit history: ${err.message}`);
    } finally {
      setAuditLoading(false);
    }
  };

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const matchSearch =
        search === "" ||
        (r.rule_id && r.rule_id.toLowerCase().includes(search.toLowerCase())) ||
        (r.name && r.name.toLowerCase().includes(search.toLowerCase())) ||
        (r.description && r.description.toLowerCase().includes(search.toLowerCase()));

      const matchSeverity =
        severityFilter === "all" ||
        (r.severity && r.severity.toLowerCase() === severityFilter.toLowerCase());

      const matchEnabled =
        enabledFilter === "all" ||
        (enabledFilter === "enabled" ? Boolean(r.enabled) : !Boolean(r.enabled));

      return matchSearch && matchSeverity && matchEnabled;
    });
  }, [rules, search, severityFilter, enabledFilter]);

  const columns = [
    {
      key: "rule_id",
      label: "Rule ID",
      render: (r) => (
        <span className="font-mono text-xs font-bold text-accent">{r.rule_id}</span>
      ),
    },
    {
      key: "name",
      label: "Rule Name & Narrative",
      render: (r) => (
        <div className="max-w-md">
          <div className="font-semibold text-white text-xs">{r.name}</div>
          {r.description && (
            <p className="text-[11px] text-slate-400 truncate max-w-sm">{r.description}</p>
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
      key: "parameters",
      label: "Threshold / Window",
      render: (r) => (
        <span className="font-mono text-xs text-slate-300">
          ≥{r.threshold} ev / {r.window_minutes}m
        </span>
      ),
    },
    {
      key: "enabled",
      label: "Status",
      render: (r) => {
        const isEnabled = Boolean(r.enabled);
        return (
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold border ${
              isEnabled
                ? "bg-emerald-950/40 border-emerald-500/50 text-emerald-400"
                : "bg-slate-800 border-slate-700 text-slate-400"
            }`}
          >
            {isEnabled ? <FaCheckCircle size={10} /> : <FaTimesCircle size={10} />}
            <span>{isEnabled ? "Enabled" : "Disabled"}</span>
          </span>
        );
      },
    },
    {
      key: "actions",
      label: "Actions",
      render: (r) => {
        const isEnabled = Boolean(r.enabled);
        const isToggling = togglingRuleId === r.rule_id;
        return (
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={isToggling}
              onClick={(e) => {
                e.stopPropagation();
                handleToggle(r);
              }}
              className={`rounded px-2.5 py-1 text-xs font-semibold border transition ${
                isEnabled
                  ? "bg-amber-950/30 text-amber-300 border-amber-600/40 hover:bg-amber-900/40"
                  : "bg-emerald-950/30 text-emerald-300 border-emerald-600/40 hover:bg-emerald-900/40"
              } disabled:opacity-40`}
            >
              {isToggling ? "..." : isEnabled ? "Disable" : "Enable"}
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                handleOpenEdit(r);
              }}
              className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 border border-slate-700 hover:bg-slate-700 hover:text-white transition"
              title="Edit rule parameters"
            >
              <FaEdit size={11} className="text-accent" />
            </button>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                handleViewAudit(r.rule_id);
              }}
              className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 border border-slate-700 hover:bg-slate-700 hover:text-white transition"
              title="View change audit trail"
            >
              <FaHistory size={11} className="text-slate-400" />
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
              placeholder="Search detection rules by ID or name..."
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

            <select
              value={enabledFilter}
              onChange={(e) => setEnabledFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="enabled">Enabled Only</option>
              <option value="disabled">Disabled Only</option>
            </select>
          </div>
        </div>

        <button
          onClick={() => setShowCreateModal(true)}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 shadow-sm shadow-accent/20"
        >
          <FaPlus size={10} />
          <span>Create Detection Rule</span>
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-xs text-danger">
          {error}
        </div>
      )}

      {/* Rules Table */}
      <DataTable
        title="SIEM Detection Engine Rules"
        count={filteredRules.length}
        columns={columns}
        rows={filteredRules}
        pageSize={10}
        emptyText={
          loading
            ? "Loading SIEM detection rules from SQLite..."
            : "No detection rules match the active filter criteria."
        }
      />

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-700 bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FaPlus size={12} className="text-accent" />
                <span>Create Detection Rule</span>
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

            <form onSubmit={handleCreate} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Rule ID * (e.g. DR-06)
                  </label>
                  <input
                    type="text"
                    required
                    value={createRuleId}
                    onChange={(e) => setCreateRuleId(e.target.value)}
                    placeholder="DR-06"
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 uppercase font-mono focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Severity
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
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Rule Name *
                </label>
                <input
                  type="text"
                  required
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  placeholder="e.g. Excessive Sudo Authentication Failures"
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Description / Explanation Narrative
                </label>
                <textarea
                  rows={2}
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  placeholder="Describe the attack technique and operational context..."
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 p-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Threshold (Events)
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    value={createThreshold}
                    onChange={(e) => setCreateThreshold(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Window (Minutes)
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    value={createWindow}
                    onChange={(e) => setCreateWindow(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Rule Conditions / Schema (JSON)
                </label>
                <textarea
                  rows={3}
                  value={createConditions}
                  onChange={(e) => setCreateConditions(e.target.value)}
                  className="w-full rounded-lg bg-slate-900/90 border border-slate-700 p-2 font-mono text-xs text-slate-300 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                >
                  {createSubmitting ? "Creating..." : "Create Rule"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Rule Modal */}
      {editRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-700 bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FaEdit size={13} className="text-accent" />
                <span>Edit Detection Rule: {editRule.rule_id}</span>
              </h3>
              <button
                onClick={() => setEditRule(null)}
                className="text-slate-400 hover:text-white"
              >
                <FaTimes size={14} />
              </button>
            </div>

            {editError && (
              <div className="rounded-lg border border-danger/40 bg-danger/10 p-2.5 text-xs text-danger">
                {editError}
              </div>
            )}

            <form onSubmit={handleSaveEdit} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Rule Name *
                </label>
                <input
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Severity
                  </label>
                  <select
                    value={editSeverity}
                    onChange={(e) => setEditSeverity(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 focus:border-accent focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Threshold (Events)
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    value={editThreshold}
                    onChange={(e) => setEditThreshold(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Window (Min)
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    value={editWindow}
                    onChange={(e) => setEditWindow(e.target.value)}
                    className="w-full rounded-lg bg-slate-900/80 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-accent focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  className="w-full rounded-lg bg-slate-900/80 border border-slate-700 p-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Conditions (JSON)
                </label>
                <textarea
                  rows={3}
                  value={editConditions}
                  onChange={(e) => setEditConditions(e.target.value)}
                  className="w-full rounded-lg bg-slate-900/90 border border-slate-700 p-2 font-mono text-xs text-slate-300 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setEditRule(null)}
                  className="rounded-lg bg-slate-800 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editSubmitting}
                  className="rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-primary hover:bg-sky-300 disabled:opacity-40"
                >
                  {editSubmitting ? "Saving..." : "Save Rule Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Audit Log Modal */}
      {auditRuleId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-xl rounded-2xl border border-slate-700 bg-card shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FaHistory size={13} className="text-accent" />
                <span>Audit Trail: {auditRuleId}</span>
              </h3>
              <button
                onClick={() => setAuditRuleId(null)}
                className="text-slate-400 hover:text-white"
              >
                <FaTimes size={14} />
              </button>
            </div>

            {auditLoading ? (
              <div className="py-8 text-center text-xs text-slate-400">Loading audit history...</div>
            ) : auditLogs.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-500">No modification records found for this rule.</div>
            ) : (
              <div className="divide-y divide-slate-800 max-h-80 overflow-y-auto pr-1">
                {auditLogs.map((log) => (
                  <div key={log.id} className="py-2.5 text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-accent uppercase font-bold text-[11px] px-1.5 py-0.5 rounded bg-accent/10 border border-accent/30">
                          {log.action}
                        </span>
                        <span className="text-slate-300 font-semibold">{log.changed_by}</span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400">
                        {formatTimestamp(log.changed_at)}
                      </span>
                    </div>
                    {log.details && (
                      <pre className="text-[11px] text-slate-400 bg-slate-950 p-2 rounded overflow-x-auto font-mono">
                        {log.details}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setAuditRuleId(null)}
                className="rounded-lg bg-slate-800 px-4 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-700"
              >
                Close Audit Trail
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
