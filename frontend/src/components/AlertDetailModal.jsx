import React, { useState, useEffect } from "react";
import { FaTimes, FaShieldAlt, FaClock, FaNetworkWired, FaCheckCircle, FaExclamationCircle, FaSearch, FaHistory, FaServer, FaUserCheck, FaFolderPlus } from "react-icons/fa";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import { getAlertDetails, updateAlertStatus, getAlertHistory, createIncident } from "../services/api.js";

export default function AlertDetailModal({ alert, onClose, onRefresh }) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [actor, setActor] = useState("SOC Analyst");
  const [reason, setReason] = useState("");
  const [statusHistory, setStatusHistory] = useState([]);

  // Escalation state
  const [showEscalate, setShowEscalate] = useState(false);
  const [escalateTitle, setEscalateTitle] = useState("");
  const [escalateSeverity, setEscalateSeverity] = useState("high");
  const [escalateSubmitting, setEscalateSubmitting] = useState(false);
  const [escalateFeedback, setEscalateFeedback] = useState("");

  useEffect(() => {
    if (!alert || !alert.id) return;
    let mounted = true;
    setLoading(true);
    setError(null);

    getAlertDetails(alert.id)
      .then((res) => {
        if (!mounted) return;
        const alertData = res.data || res;
        setDetails(alertData);
        if (alertData.status_history) {
          setStatusHistory(alertData.status_history);
        } else {
          getAlertHistory(alert.id)
            .then((hRes) => {
              if (mounted) {
                const hData = hRes.data || hRes;
                setStatusHistory(hData.status_history || []);
              }
            })
            .catch(() => {});
        }
      })
      .catch((err) => {
        if (!mounted) return;
        setError(err.message || "Failed to load alert details from backend.");
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [alert]);

  const handleStatusChange = async (newStatus) => {
    if (!alert || !alert.id) return;
    setUpdating(true);
    setFeedback("");
    try {
      const res = await updateAlertStatus(alert.id, newStatus, actor, reason);
      const resData = res.data || res;
      setDetails((prev) => ({ ...prev, status: newStatus }));
      if (resData.status_history) {
        setStatusHistory(resData.status_history);
      } else {
        const hRes = await getAlertHistory(alert.id);
        const hData = hRes.data || hRes;
        setStatusHistory(hData.status_history || []);
      }
      setFeedback(`Status updated to "${newStatus}" by ${actor}.`);
      setReason("");
      if (onRefresh) onRefresh();
    } catch (err) {
      setFeedback(`Error updating status: ${err.message}`);
    } finally {
      setUpdating(false);
    }
  };

  const handleOpenEscalate = () => {
    const defaultHost = details?.target_host || alert.target_host || alert.targetHost || "server";
    setEscalateTitle(`Incident: ${details?.rule_name || alert.type || "Security Alert"} on ${defaultHost}`);
    setEscalateSeverity((details?.severity || alert.severity || "high").toLowerCase());
    setShowEscalate((prev) => !prev);
    setEscalateFeedback("");
  };

  const handleSubmitEscalate = async (e) => {
    e.preventDefault();
    if (!escalateTitle.trim() || !alert?.id) return;
    setEscalateSubmitting(true);
    setEscalateFeedback("");
    try {
      const res = await createIncident({
        title: escalateTitle.trim(),
        severity: escalateSeverity,
        description: `Escalated from Alert #${alert.id} (${details?.rule_id || alert.ruleId}): ${details?.explanation || alert.explanation || ""}`,
        alert_ids: [alert.id],
      });
      const newIncId = res.data?.incident_id || res.incident_id || res.id;
      setEscalateFeedback(`✓ Successfully escalated to Incident #${newIncId || "Case"}! Linked alert #${alert.id}.`);
      setShowEscalate(false);
      if (currentStatus.toLowerCase() === "new") {
        handleStatusChange("investigating");
      }
      if (onRefresh) onRefresh();
    } catch (err) {
      setEscalateFeedback(`Failed to escalate: ${err.message}`);
    } finally {
      setEscalateSubmitting(false);
    }
  };

  if (!alert) return null;

  const currentStatus = details?.status || alert.status || "new";
  const evidenceList = details?.evidence || [];
  const targetHost = details?.target_host || alert.target_host || alert.targetHost || "server";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-danger/15 text-danger ring-1 ring-danger/40">
              <FaShieldAlt size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  {details?.rule_id || alert.ruleId || "RULE"}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="font-mono text-xs text-slate-400">Alert #{alert.id}</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                {details?.rule_name || alert.type || "Security Alert"}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
          >
            <FaTimes size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Severity</div>
              <div className="mt-1">
                <SeverityBadge severity={details?.severity || alert.severity} />
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Current Status</div>
              <div className="mt-1">
                <StatusBadge status={currentStatus} />
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Target Host</div>
              <div className="mt-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-emerald-400">
                <FaServer size={11} className="text-emerald-500/70" />
                <span>{targetHost}</span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Source IP</div>
              <div className="mt-1 font-mono text-xs font-semibold text-white">
                {details?.source_ip || alert.sourceIp || "-"}
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Evidence Count</div>
              <div className="mt-1 font-mono text-xs font-semibold text-accent">
                {loading ? "..." : `${evidenceList.length} Events`}
              </div>
            </div>
          </div>

          {/* Time Window */}
          <div className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-700/60 bg-slate-900/30 px-4 py-3 text-xs text-slate-300">
            <div className="flex items-center gap-2">
              <FaClock className="text-accent" />
              <span className="text-slate-400">First Detected:</span>
              <span className="font-mono text-slate-200">
                {formatTimestamp(details?.first_seen || alert.firstSeen || alert.timestamp)}
              </span>
            </div>
            <span className="text-slate-600">→</span>
            <div className="flex items-center gap-2">
              <FaHistory className="text-accent" />
              <span className="text-slate-400">Last Seen:</span>
              <span className="font-mono text-slate-200">
                {formatTimestamp(details?.last_seen || alert.lastSeen || alert.timestamp)}
              </span>
            </div>
          </div>

          {/* Explanation / Narrative */}
          <div className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Detection Explanation & Correlated Summary
            </h3>
            <p className="text-sm leading-relaxed text-slate-200 font-sans">
              {details?.explanation || alert.explanation || details?.summary || alert.summary || "No automated explanation available for this alert."}
            </p>
          </div>

          {/* Triage Action Bar & Attribution */}
          <div className="rounded-lg border border-slate-700/70 bg-slate-800/60 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Alert Lifecycle Triage
                </h4>
                <p className="text-xs text-slate-400">
                  Update alert status with analyst attribution and audit trail tracking.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  disabled={updating || currentStatus.toLowerCase() === "investigating"}
                  onClick={() => handleStatusChange("investigating")}
                  className="rounded-lg bg-warning/20 px-3 py-1.5 text-xs font-semibold text-warning border border-warning/40 transition hover:bg-warning/30 disabled:opacity-40"
                >
                  Mark Investigating
                </button>
                <button
                  disabled={updating || currentStatus.toLowerCase() === "resolved"}
                  onClick={() => handleStatusChange("resolved")}
                  className="rounded-lg bg-success/20 px-3 py-1.5 text-xs font-semibold text-success border border-success/40 transition hover:bg-success/30 disabled:opacity-40"
                >
                  Mark Resolved
                </button>
                <button
                  disabled={updating || currentStatus.toLowerCase() === "false_positive"}
                  onClick={() => handleStatusChange("false_positive")}
                  className="rounded-lg bg-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-300 border border-slate-600 transition hover:bg-slate-600 disabled:opacity-40"
                >
                  False Positive
                </button>
                <button
                  type="button"
                  onClick={handleOpenEscalate}
                  className="rounded-lg bg-indigo-600/30 px-3 py-1.5 text-xs font-semibold text-indigo-300 border border-indigo-500/40 transition hover:bg-indigo-600/40 inline-flex items-center gap-1.5 shadow-sm"
                >
                  <FaFolderPlus size={11} />
                  <span>Escalate to Incident</span>
                </button>
              </div>
            </div>

            {/* Analyst & Reason Inputs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-slate-700/60">
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Analyst Attribution
                </label>
                <input
                  type="text"
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  placeholder="e.g. SOC Analyst"
                  className="w-full rounded bg-slate-900/80 border border-slate-700 px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Triage Reason / Justification (Optional)
                </label>
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="e.g. Host isolated and credential rotation initiated."
                  className="w-full rounded bg-slate-900/80 border border-slate-700 px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                />
              </div>
            </div>

            {feedback && (
              <div className="text-xs text-accent font-medium animate-fadeIn">
                ✓ {feedback}
              </div>
            )}
          </div>

          {/* Incident Escalation Box */}
          {showEscalate && (
            <form
              onSubmit={handleSubmitEscalate}
              className="rounded-lg border border-indigo-500/40 bg-indigo-950/30 p-4 space-y-3 animate-fadeIn"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FaFolderPlus className="text-indigo-400" size={14} />
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                    Escalate to Formal Incident Case
                  </h4>
                </div>
                <button
                  type="button"
                  onClick={() => setShowEscalate(false)}
                  className="text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <div className="sm:col-span-3">
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    Incident Title
                  </label>
                  <input
                    type="text"
                    required
                    value={escalateTitle}
                    onChange={(e) => setEscalateTitle(e.target.value)}
                    className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
                    placeholder="Enter incident case title..."
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-300 mb-1">
                    Initial Severity
                  </label>
                  <select
                    value={escalateSeverity}
                    onChange={(e) => setEscalateSeverity(e.target.value)}
                    className="w-full rounded bg-slate-900 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 focus:border-indigo-500 focus:outline-none"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>

              <div className="flex items-center justify-between pt-1">
                <p className="text-[11px] text-slate-400">
                  This will create a new incident case, automatically link Alert #{alert.id}, and associate all {evidenceList.length} evidence records.
                </p>
                <button
                  type="submit"
                  disabled={escalateSubmitting || !escalateTitle.trim()}
                  className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow hover:bg-indigo-500 disabled:opacity-50 transition"
                >
                  {escalateSubmitting ? "Creating Case..." : "Create & Link Incident Case"}
                </button>
              </div>
            </form>
          )}

          {escalateFeedback && (
            <div className={`p-3 rounded-lg border text-xs font-medium animate-fadeIn ${
              escalateFeedback.includes("Failed")
                ? "bg-red-950/40 border-red-500/50 text-red-300"
                : "bg-emerald-950/40 border-emerald-500/50 text-emerald-300"
            }`}>
              {escalateFeedback}
            </div>
          )}

          {/* Persistent Status History Timeline */}
          {statusHistory && statusHistory.length > 0 && (
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-4 space-y-2">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Status Change Audit Trail ({statusHistory.length})
              </h3>
              <div className="divide-y divide-slate-800">
                {statusHistory.map((h, i) => (
                  <div key={h.id || i} className="py-2 text-xs flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-slate-500 text-[11px]">#{i + 1}</span>
                      <StatusBadge status={h.old_status} />
                      <span className="text-slate-500">→</span>
                      <StatusBadge status={h.new_status} />
                      {h.reason && (
                        <span className="text-slate-300 italic text-[11px] ml-1">
                          "{h.reason}"
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                      <span className="flex items-center gap-1 text-slate-300 font-medium">
                        <FaUserCheck size={10} className="text-accent" />
                        {h.actor}
                      </span>
                      <span className="font-mono text-slate-400">
                        {formatTimestamp(h.changed_at)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Linked Evidence Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Supporting Authentication Evidence
              </h3>
              <span className="text-xs text-slate-400 font-mono">
                {evidenceList.length} linked event{evidenceList.length === 1 ? "" : "s"}
              </span>
            </div>

            {loading && (
              <div className="py-8 text-center text-xs text-slate-400">
                Fetching linked evidence records from database...
              </div>
            )}

            {error && (
              <div className="rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
                {error}
              </div>
            )}

            {!loading && evidenceList.length === 0 && (
              <div className="rounded-lg border border-slate-700/60 bg-slate-900/30 p-6 text-center text-xs text-slate-500">
                No direct evidence records attached to this alert.
              </div>
            )}

            {!loading && evidenceList.length > 0 && (
              <div className="overflow-x-auto rounded-lg border border-slate-700/60 bg-slate-900/60 max-h-60 overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400 sticky top-0">
                    <tr>
                      <th className="px-3 py-2 font-mono">#</th>
                      <th className="px-3 py-2">Timestamp (UTC)</th>
                      <th className="px-3 py-2">Event Type</th>
                      <th className="px-3 py-2">Target Host</th>
                      <th className="px-3 py-2">User</th>
                      <th className="px-3 py-2">Outcome</th>
                      <th className="px-3 py-2">Raw Log Record</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {evidenceList.map((ev, idx) => (
                      <tr key={ev.id || idx} className="hover:bg-slate-800/50">
                        <td className="px-3 py-2 font-mono text-slate-500">{ev.id || idx + 1}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap text-slate-400">
                          {formatTimestamp(ev.timestamp)}
                        </td>
                        <td className="px-3 py-2 font-mono text-accent">
                          {ev.event_type || ev.eventType || "ssh_event"}
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-300">
                          {ev.host || targetHost}
                        </td>
                        <td className="px-3 py-2 font-mono text-white">{ev.username || "-"}</td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                              ev.outcome === "failure" || ev.status === "failure"
                                ? "bg-danger/20 text-danger border border-danger/40"
                                : "bg-success/20 text-success border border-success/40"
                            }`}
                          >
                            {ev.outcome || ev.status || "event"}
                          </span>
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-300 break-all">
                          {ev.raw_line || ev.rawLine || "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Alert ID #{alert.id} • Rule: <span className="font-mono text-slate-300">{details?.rule_id || alert.ruleId}</span>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-700 px-4 py-2 text-xs font-semibold text-white transition hover:bg-slate-600"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
