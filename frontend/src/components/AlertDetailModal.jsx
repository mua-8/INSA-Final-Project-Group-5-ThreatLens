import React, { useState, useEffect } from "react";
import { FaTimes, FaShieldAlt, FaClock, FaNetworkWired, FaCheckCircle, FaExclamationCircle, FaSearch, FaHistory, FaServer, FaUserCheck, FaFolderPlus, FaUserTag, FaStickyNote, FaBiohazard, FaInfoCircle } from "react-icons/fa";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import {
  getAlertDetails,
  updateAlertStatus,
  getAlertHistory,
  createIncident,
  updateAlertAssignee,
  addAlertNote,
} from "../services/api.js";

export default function AlertDetailModal({ alert, onClose, onRefresh }) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [actor, setActor] = useState("SOC Analyst");
  const [reason, setReason] = useState("");
  const [statusHistory, setStatusHistory] = useState([]);
  const [assignee, setAssignee] = useState("");
  const [assigning, setAssigning] = useState(false);
  const [notes, setNotes] = useState([]);
  const [newNote, setNewNote] = useState("");
  const [noteAuthor, setNoteAuthor] = useState("SOC Analyst");
  const [noteSubmitting, setNoteSubmitting] = useState(false);

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
        setAssignee(alertData.assignee || alert.assignee || "");
        setNotes(alertData.notes || []);
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

  const handleAssign = async (e) => {
    if (e) e.preventDefault();
    if (!alert || !alert.id) return;
    setAssigning(true);
    setFeedback("");
    try {
      const res = await updateAlertAssignee(alert.id, assignee.trim(), actor);
      const resData = res.data || res;
      setDetails((prev) => ({ ...prev, assignee: resData.assignee }));
      if (resData.status_history) {
        setStatusHistory(resData.status_history);
      }
      setFeedback(assignee.trim() ? `Alert assigned to "${assignee.trim()}".` : "Alert unassigned.");
      if (onRefresh) onRefresh();
    } catch (err) {
      setFeedback(`Error assigning alert: ${err.message}`);
    } finally {
      setAssigning(false);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !alert?.id) return;
    setNoteSubmitting(true);
    setFeedback("");
    try {
      const res = await addAlertNote(alert.id, newNote.trim(), noteAuthor.trim() || actor);
      const resData = res.data || res;
      setNotes((prev) => [
        {
          id: resData.note_id || Date.now(),
          alert_id: alert.id,
          author: noteAuthor.trim() || actor,
          note: newNote.trim(),
          created_at: new Date().toISOString(),
        },
        ...prev,
      ]);
      setNewNote("");
      setFeedback("Investigation note added successfully.");
    } catch (err) {
      setFeedback(`Error adding note: ${err.message}`);
    } finally {
      setNoteSubmitting(false);
    }
  };

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
  const fileEvidenceList = details?.file_evidence || alert.fileEvidence || [];
  const targetHost = details?.target_host || alert.target_host || alert.targetHost || "server";
  const ruleId = details?.rule_id || alert.ruleId || alert.rule_id || "";
  const isRansomwareAlert = ruleId.startsWith("RW-") || fileEvidenceList.length > 0;
  const settings = typeof details?.settings === "object" ? (details.settings || {}) : (typeof alert.settings === "object" ? (alert.settings || {}) : {});

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 items-center justify-center rounded-lg ring-1 ${
              isRansomwareAlert
                ? "bg-rose-500/15 text-rose-400 ring-rose-500/40"
                : "bg-danger/15 text-danger ring-danger/40"
            }`}>
              {isRansomwareAlert ? <FaBiohazard size={20} /> : <FaShieldAlt size={20} />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  {ruleId || "RULE"}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="font-mono text-xs text-slate-400">Alert #{alert.id}</span>
                {isRansomwareAlert && (
                  <>
                    <span className="text-xs text-slate-500">•</span>
                    <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-300 uppercase tracking-wider border border-rose-500/30">
                      Ransomware Behavioral Threat
                    </span>
                  </>
                )}
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
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
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
              <div className="text-xs text-slate-400">Assigned Analyst</div>
              <div className="mt-1 flex items-center gap-1.5 font-mono text-xs font-semibold text-accent truncate" title={details?.assignee || alert.assignee || "Unassigned"}>
                <FaUserTag size={11} className="text-accent/70 shrink-0" />
                <span className="truncate">{details?.assignee || alert.assignee || "Unassigned"}</span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Evidence Count</div>
              <div className="mt-1 font-mono text-xs font-semibold text-accent">
                {loading
                  ? "..."
                  : fileEvidenceList.length > 0
                    ? `${fileEvidenceList.length} File Events`
                    : `${evidenceList.length} SSH Events`}
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

          {/* Ransomware Blast Radius & Behavioral Summary (Phase 3) */}
          {isRansomwareAlert && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-950/20 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <FaBiohazard className="text-rose-400" size={16} />
                  <span className="text-xs font-bold uppercase tracking-wider text-rose-300">
                    Ransomware Behavioral Threat Context
                  </span>
                </div>
                <span className="font-mono text-[11px] rounded bg-rose-500/20 px-2 py-0.5 text-rose-300 border border-rose-500/40 font-semibold">
                  Host: {targetHost}
                </span>
              </div>

              {/* Burst / Config Metrics if available */}
              {(settings.distinct_paths_count || settings.raw_event_count) && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-rose-500/20 text-xs">
                  <div className="rounded bg-slate-900/60 p-2.5 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Distinct Affected Paths</div>
                    <div className="font-mono font-bold text-rose-400 text-sm mt-0.5">
                      {settings.distinct_paths_count}
                    </div>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2.5 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Raw Burst Events</div>
                    <div className="font-mono font-bold text-amber-400 text-sm mt-0.5">
                      {settings.raw_event_count}
                    </div>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2.5 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Burst Time Window</div>
                    <div className="font-mono font-semibold text-slate-300 text-sm mt-0.5">
                      {settings.window_seconds || 10}s
                    </div>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2.5 border border-slate-800">
                    <div className="text-[10px] text-slate-400">Configured Threshold</div>
                    <div className="font-mono font-semibold text-slate-300 text-sm mt-0.5">
                      ≥ {settings.threshold || 50}
                    </div>
                  </div>
                </div>
              )}

              {/* Sample affected paths preview if available */}
              {Array.isArray(settings.sample_paths) && settings.sample_paths.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <div className="text-[11px] text-slate-400 font-medium">Sample Impacted File Paths:</div>
                  <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                    {settings.sample_paths.map((p, idx) => (
                      <span
                        key={idx}
                        className="font-mono text-[10px] bg-slate-900/90 px-2 py-0.5 rounded text-rose-200 border border-rose-500/25 max-w-xs truncate"
                        title={p}
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Notice explaining detection alert vs incident case */}
              <div className="flex items-start gap-2 rounded bg-slate-900/60 p-2.5 text-[11px] text-slate-400 border border-slate-800/80">
                <FaInfoCircle className="text-accent shrink-0 mt-0.5" />
                <span>
                  <strong className="text-slate-200">Alert vs Incident Distinction:</strong> This detection alert flags an isolated behavioral burst, canary trigger, or extension change. To coordinate multi-host remediation or retain evidence across endpoints, use the <strong className="text-indigo-400">"Escalate to Incident"</strong> action below.
                </span>
              </div>
            </div>
          )}

          {/* Triage Action Bar & Attribution */}
          <div className="rounded-lg border border-slate-700/70 bg-slate-800/60 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Alert Lifecycle Triage & Assignment
                </h4>
                <p className="text-xs text-slate-400">
                  Update alert status, assign to analysts, and maintain full audit accountability.
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

            {/* Analyst Assignment & Attribution Inputs */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 border-t border-slate-700/60">
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Assigned Analyst
                </label>
                <div className="flex gap-1.5">
                  <input
                    type="text"
                    value={assignee}
                    onChange={(e) => setAssignee(e.target.value)}
                    placeholder="e.g. analyst-1 or unassigned"
                    className="w-full rounded bg-slate-900/80 border border-slate-700 px-2 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                  />
                  <button
                    type="button"
                    disabled={assigning}
                    onClick={handleAssign}
                    className="rounded bg-accent/20 px-2.5 py-1 text-xs font-semibold text-accent border border-accent/40 hover:bg-accent/30 disabled:opacity-40 transition whitespace-nowrap"
                  >
                    {assigning ? "..." : "Save"}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Actor Attribution
                </label>
                <input
                  type="text"
                  value={actor}
                  onChange={(e) => setActor(e.target.value)}
                  placeholder="e.g. SOC Analyst"
                  className="w-full rounded bg-slate-900/80 border border-slate-700 px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Triage Reason (Optional)
                </label>
                <input
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="e.g. Verified legitimate administrative task."
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

          {/* Alert Investigation Notes Thread */}
          <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FaStickyNote className="text-accent" size={13} />
                <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Analyst Investigation Notes ({notes.length})
                </h3>
              </div>
              <span className="text-[11px] text-slate-500">Persistent SOC Case Notes</span>
            </div>

            {/* Note Input Form */}
            <form onSubmit={handleAddNote} className="space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
                <div className="sm:col-span-1">
                  <input
                    type="text"
                    value={noteAuthor}
                    onChange={(e) => setNoteAuthor(e.target.value)}
                    placeholder="Author name..."
                    className="w-full rounded bg-slate-900/90 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 focus:border-accent focus:outline-none"
                  />
                </div>
                <div className="sm:col-span-3 flex gap-2">
                  <input
                    type="text"
                    required
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    placeholder="Add investigative observations, findings, or triage details..."
                    className="flex-1 rounded bg-slate-900/90 border border-slate-700 px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-accent focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={noteSubmitting || !newNote.trim()}
                    className="rounded bg-accent/20 px-3 py-1.5 text-xs font-semibold text-accent border border-accent/40 hover:bg-accent/30 disabled:opacity-40 transition whitespace-nowrap"
                  >
                    {noteSubmitting ? "Adding..." : "Add Note"}
                  </button>
                </div>
              </div>
            </form>

            {/* Notes List */}
            {notes.length === 0 ? (
              <div className="text-center py-3 text-xs text-slate-500 border border-dashed border-slate-800 rounded">
                No investigation notes added yet. Record analyst observations above.
              </div>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto divide-y divide-slate-800/80">
                {notes.map((n) => (
                  <div key={n.id} className="pt-2 text-xs">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-300 flex items-center gap-1">
                        <FaUserCheck size={10} className="text-accent" />
                        {n.author || "Analyst"}
                      </span>
                      <span className="font-mono text-slate-500">{formatTimestamp(n.created_at)}</span>
                    </div>
                    <p className="mt-1 text-slate-200 text-xs font-sans leading-relaxed whitespace-pre-wrap">
                      {n.note}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>

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
          <div className="space-y-4">
            {/* Forensic File Evidence (Ransomware / File Telemetry) */}
            {fileEvidenceList.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Forensic File Telemetry & Blast Radius
                    </h3>
                    <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-mono font-bold text-rose-400 border border-rose-500/30">
                      {fileEvidenceList.length} file event{fileEvidenceList.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  <span className="text-xs text-slate-400 font-mono">
                    Host: <span className="text-emerald-400 font-semibold">{targetHost}</span>
                  </span>
                </div>

                <div className="overflow-x-auto rounded-lg border border-slate-700/60 bg-slate-900/60 max-h-64 overflow-y-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400 sticky top-0">
                      <tr>
                        <th className="px-3 py-2 font-mono">#</th>
                        <th className="px-3 py-2">Timestamp (UTC)</th>
                        <th className="px-3 py-2">Action</th>
                        <th className="px-3 py-2">Affected Path</th>
                        <th className="px-3 py-2">Previous Path (Rename)</th>
                        <th className="px-3 py-2">Process & PID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      {fileEvidenceList.map((fev, idx) => {
                        const evType = fev.event_type || fev.eventType || "file_event";
                        let typeColor = "bg-slate-700 text-slate-200 border-slate-600";
                        if (evType === "file_modified") typeColor = "bg-amber-500/20 text-amber-300 border-amber-500/40";
                        else if (evType === "file_renamed") typeColor = "bg-purple-500/20 text-purple-300 border-purple-500/40";
                        else if (evType === "file_deleted") typeColor = "bg-rose-500/20 text-rose-300 border-rose-500/40";
                        else if (evType === "file_created") typeColor = "bg-emerald-500/20 text-emerald-300 border-emerald-500/40";

                        return (
                          <tr key={fev.id || idx} className="hover:bg-slate-800/50">
                            <td className="px-3 py-2 font-mono text-slate-500">{fev.id || idx + 1}</td>
                            <td className="px-3 py-2 font-mono whitespace-nowrap text-slate-400">
                              {formatTimestamp(fev.timestamp)}
                            </td>
                            <td className="px-3 py-2 whitespace-nowrap">
                              <span className={`rounded px-1.5 py-0.5 text-[10px] font-mono font-medium border ${typeColor}`}>
                                {evType}
                              </span>
                            </td>
                            <td className="px-3 py-2 font-mono text-xs text-rose-200/90 break-all max-w-xs">
                              {fev.file_path || fev.filePath || "-"}
                            </td>
                            <td className="px-3 py-2 font-mono text-xs text-slate-400 break-all max-w-xs">
                              {fev.previous_path || fev.previousPath ? (
                                <span className="text-purple-300/80">from: {fev.previous_path || fev.previousPath}</span>
                              ) : (
                                <span className="text-slate-600">-</span>
                              )}
                            </td>
                            <td className="px-3 py-2 font-mono text-slate-300 whitespace-nowrap">
                              {fev.process_name || fev.processName ? (
                                <span>
                                  {fev.process_name || fev.processName}
                                  {(fev.process_id !== null && fev.process_id !== undefined) && (
                                    <span className="text-slate-500 text-[10px]"> (PID: {fev.process_id})</span>
                                  )}
                                </span>
                              ) : (
                                <span className="text-slate-600">-</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Supporting Authentication Evidence (SSH) */}
            {evidenceList.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Supporting Authentication Evidence (SSH)
                  </h3>
                  <span className="text-xs text-slate-400 font-mono">
                    {evidenceList.length} linked event{evidenceList.length === 1 ? "" : "s"}
                  </span>
                </div>

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
              </div>
            )}

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

            {!loading && fileEvidenceList.length === 0 && evidenceList.length === 0 && (
              <div className="rounded-lg border border-slate-700/60 bg-slate-900/30 p-6 text-center text-xs text-slate-500">
                No direct evidence records attached to this alert.
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
