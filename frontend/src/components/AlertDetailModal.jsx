import React, { useState, useEffect } from "react";
import { FaTimes, FaShieldAlt, FaClock, FaNetworkWired, FaCheckCircle, FaExclamationCircle, FaSearch, FaHistory } from "react-icons/fa";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import { getAlertDetails, updateAlertStatus } from "../services/api.js";

export default function AlertDetailModal({ alert, onClose, onRefresh }) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [feedback, setFeedback] = useState("");

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
      await updateAlertStatus(alert.id, newStatus);
      setDetails((prev) => ({ ...prev, status: newStatus }));
      setFeedback(`Status updated to "${newStatus}" in SQLite database.`);
      if (onRefresh) onRefresh();
    } catch (err) {
      setFeedback(`Error updating status: ${err.message}`);
    } finally {
      setUpdating(false);
    }
  };

  if (!alert) return null;

  const currentStatus = details?.status || alert.status || "new";
  const evidenceList = details?.evidence || [];

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
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
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
              <div className="text-xs text-slate-400">Attacker IP</div>
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
              Detection Explanation
            </h3>
            <p className="text-sm leading-relaxed text-slate-200 font-sans">
              {details?.explanation || alert.explanation || details?.summary || alert.summary || "No automated explanation available for this alert."}
            </p>
          </div>

          {/* Triage Action Bar */}
          <div className="rounded-lg border border-slate-700/70 bg-slate-800/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Incident Triage & Status Update
                </h4>
                <p className="text-xs text-slate-400">
                  Updates <code className="font-mono text-accent">alerts.status</code> in SQLite via PATCH /api/alerts/:id/status
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
              </div>
            </div>

            {feedback && (
              <div className="mt-3 text-xs text-accent font-medium animate-fadeIn">
                ✓ {feedback}
              </div>
            )}
          </div>

          {/* Linked Evidence Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Correlated Raw Syslog Evidence (SQLite FK Join)
              </h3>
              <span className="text-xs text-slate-500 font-mono">
                table: <code className="text-accent">alert_evidence</code> ➔ <code className="text-accent">events</code>
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
                      <th className="px-3 py-2">Timestamp</th>
                      <th className="px-3 py-2">User</th>
                      <th className="px-3 py-2">Outcome</th>
                      <th className="px-3 py-2">Raw Syslog Record</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {evidenceList.map((ev, idx) => (
                      <tr key={ev.id || idx} className="hover:bg-slate-800/50">
                        <td className="px-3 py-2 font-mono text-slate-500">{ev.id || idx + 1}</td>
                        <td className="px-3 py-2 font-mono whitespace-nowrap text-slate-400">
                          {formatTimestamp(ev.timestamp)}
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
            Backend API: <span className="font-mono text-slate-300">GET /api/alerts/{alert.id}</span>
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
