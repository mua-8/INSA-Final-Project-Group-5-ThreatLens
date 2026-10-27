import React, { useState, useEffect, useMemo, useCallback } from "react";
import {
  FaBiohazard,
  FaShieldAlt,
  FaSearch,
  FaFilter,
  FaPlus,
  FaTimes,
  FaCheck,
  FaTrashAlt,
  FaEdit,
  FaPlay,
  FaRedo,
  FaInfoCircle,
  FaExclamationTriangle,
  FaLock,
  FaFileCode,
  FaServer,
  FaClock,
  FaExternalLinkAlt,
  FaSlidersH,
} from "react-icons/fa";
import { SeverityBadge, StatusBadge } from "./Badges.jsx";
import { formatTimestamp } from "../utils/normalize.js";
import {
  getRansomwareConfig,
  updateRansomwareConfig,
  getCanaries,
  createCanary,
  updateCanary,
  deleteCanary,
  getRansomwareAlerts,
  runRansomwareAnalysis,
  getEndpoints,
} from "../services/api.js";

export default function RansomwareView({ onSelectAlert, onRefreshDashboard }) {
  // Navigation within Ransomware Center
  const [activeSubTab, setActiveSubTab] = useState("overview"); // "overview" | "alerts" | "canaries" | "policy" | "analysis"

  // Data States
  const [alerts, setAlerts] = useState([]);
  const [canaries, setCanaries] = useState([]);
  const [config, setConfig] = useState(null);
  const [endpoints, setEndpoints] = useState([]);

  // Loading & Error States
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  // Filter States for Alerts
  const [alertSearch, setAlertSearch] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("all");
  const [alertHostFilter, setAlertHostFilter] = useState("all");

  // Canary Management States
  const [canarySearch, setCanarySearch] = useState("");
  const [showCanaryModal, setShowCanaryModal] = useState(false);
  const [editingCanary, setEditingCanary] = useState(null);
  const [canaryFilePath, setCanaryFilePath] = useState("");
  const [canaryId, setCanaryId] = useState("");
  const [canaryDeviceId, setCanaryDeviceId] = useState("");
  const [canarySeverity, setCanarySeverity] = useState("critical");
  const [canaryDesc, setCanaryDesc] = useState("");
  const [canaryEnabled, setCanaryEnabled] = useState(true);
  const [canarySubmitting, setCanarySubmitting] = useState(false);
  const [canaryError, setCanaryError] = useState(null);
  const [canaryDeleteTarget, setCanaryDeleteTarget] = useState(null);

  // Policy Form States
  const [policyForm, setPolicyForm] = useState(null);
  const [policySubmitting, setPolicySubmitting] = useState(false);
  const [policyFeedback, setPolicyFeedback] = useState(null);
  const [newExtInput, setNewExtInput] = useState("");

  // Analysis Runner States
  const [analysisDevice, setAnalysisDevice] = useState("");
  const [analysisRunning, setAnalysisRunning] = useState(false);
  const [analysisConfirm, setAnalysisConfirm] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);

  // Load all Ransomware Data
  const loadData = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    setError(null);
    try {
      const [alertsRes, canariesRes, configRes, endpointsRes] = await Promise.allSettled([
        getRansomwareAlerts(),
        getCanaries({ limit: 100 }),
        getRansomwareConfig(),
        getEndpoints(),
      ]);

      if (alertsRes.status === "fulfilled") {
        const raw = alertsRes.value;
        const al = Array.isArray(raw?.alerts)
          ? raw.alerts
          : Array.isArray(raw?.data?.alerts)
            ? raw.data.alerts
            : [];
        setAlerts(al);
      }

      if (canariesRes.status === "fulfilled") {
        const raw = canariesRes.value;
        const cList = Array.isArray(raw?.canaries)
          ? raw.canaries
          : Array.isArray(raw?.data?.canaries)
            ? raw.data.canaries
            : [];
        setCanaries(cList);
      }

      if (configRes.status === "fulfilled") {
        const raw = configRes.value;
        const cfg = raw?.data || raw;
        setConfig(cfg);
        setPolicyForm(cfg);
      }

      if (endpointsRes.status === "fulfilled") {
        const raw = endpointsRes.value;
        const eps = Array.isArray(raw?.endpoints)
          ? raw.endpoints
          : Array.isArray(raw?.data?.endpoints)
            ? raw.data.endpoints
            : [];
        setEndpoints(eps);
      }
    } catch (err) {
      setError(err.message || "Failed to load ransomware threat center data.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Derived Summary Counts
  const stats = useMemo(() => {
    const totalAlerts = alerts.length;
    const criticalAlerts = alerts.filter(
      (a) => String(a.severity).toLowerCase() === "critical"
    ).length;
    const highAlerts = alerts.filter(
      (a) => String(a.severity).toLowerCase() === "high"
    ).length;
    const activeCanaries = canaries.filter((c) => Boolean(c.enabled)).length;
    const totalCanaries = canaries.length;

    // Distinct hosts with alerts
    const affectedHosts = Array.from(
      new Set(alerts.map((a) => a.target_host).filter(Boolean))
    );

    // Latest alert timestamp
    const latestTime = alerts.length > 0 ? alerts[0].last_seen || alerts[0].first_seen : null;

    return {
      totalAlerts,
      criticalAlerts,
      highAlerts,
      activeCanaries,
      totalCanaries,
      affectedHosts,
      latestTime,
    };
  }, [alerts, canaries]);

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const matchSearch =
        alertSearch === "" ||
        (a.rule_id && a.rule_id.toLowerCase().includes(alertSearch.toLowerCase())) ||
        (a.rule_name && a.rule_name.toLowerCase().includes(alertSearch.toLowerCase())) ||
        (a.target_host && a.target_host.toLowerCase().includes(alertSearch.toLowerCase())) ||
        (a.summary && a.summary.toLowerCase().includes(alertSearch.toLowerCase())) ||
        (a.explanation && a.explanation.toLowerCase().includes(alertSearch.toLowerCase()));

      const matchSeverity =
        alertSeverityFilter === "all" ||
        String(a.severity).toLowerCase() === alertSeverityFilter.toLowerCase();

      const matchHost =
        alertHostFilter === "all" ||
        String(a.target_host).toLowerCase() === alertHostFilter.toLowerCase();

      return matchSearch && matchSeverity && matchHost;
    });
  }, [alerts, alertSearch, alertSeverityFilter, alertHostFilter]);

  // Filtered Canaries
  const filteredCanaries = useMemo(() => {
    return canaries.filter((c) => {
      return (
        canarySearch === "" ||
        (c.canary_id && c.canary_id.toLowerCase().includes(canarySearch.toLowerCase())) ||
        (c.file_path && c.file_path.toLowerCase().includes(canarySearch.toLowerCase())) ||
        (c.device_id && c.device_id.toLowerCase().includes(canarySearch.toLowerCase())) ||
        (c.description && c.description.toLowerCase().includes(canarySearch.toLowerCase()))
      );
    });
  }, [canaries, canarySearch]);

  // Handle Canary Form Open
  const handleOpenCanaryModal = (canary = null) => {
    if (canary) {
      setEditingCanary(canary);
      setCanaryId(canary.canary_id);
      setCanaryFilePath(canary.file_path);
      setCanaryDeviceId(canary.device_id || "");
      setCanarySeverity(canary.severity || "critical");
      setCanaryDesc(canary.description || "");
      setCanaryEnabled(Boolean(canary.enabled));
    } else {
      setEditingCanary(null);
      setCanaryId(`canary-${Math.random().toString(36).substring(2, 8)}`);
      setCanaryFilePath("");
      setCanaryDeviceId("");
      setCanarySeverity("critical");
      setCanaryDesc("");
      setCanaryEnabled(true);
    }
    setCanaryError(null);
    setShowCanaryModal(true);
  };

  // Submit Canary Form
  const handleSaveCanary = async (e) => {
    e.preventDefault();
    if (!canaryFilePath.trim()) {
      setCanaryError("File path is required.");
      return;
    }
    if (canaryFilePath.includes("\x00") || canaryFilePath.includes("..")) {
      setCanaryError("File path must not contain null bytes or '..' traversal sequences.");
      return;
    }

    setCanarySubmitting(true);
    setCanaryError(null);

    try {
      const payload = {
        canary_id: canaryId.trim(),
        file_path: canaryFilePath.trim(),
        device_id: canaryDeviceId.trim() || null,
        severity: canarySeverity,
        description: canaryDesc.trim(),
        enabled: canaryEnabled,
      };

      if (editingCanary) {
        await updateCanary(editingCanary.canary_id, payload);
      } else {
        await createCanary(payload);
      }

      setShowCanaryModal(false);
      await loadData();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setCanaryError(
        err.response?.data?.error || err.message || "Failed to save canary decoy definition."
      );
    } finally {
      setCanarySubmitting(false);
    }
  };

  // Toggle Canary Enabled
  const handleToggleCanary = async (canary) => {
    try {
      await updateCanary(canary.canary_id, { enabled: !canary.enabled });
      await loadData();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert(`Error toggling canary: ${err.message}`);
    }
  };

  // Delete Canary
  const handleDeleteCanary = async () => {
    if (!canaryDeleteTarget) return;
    try {
      await deleteCanary(canaryDeleteTarget.canary_id);
      setCanaryDeleteTarget(null);
      await loadData();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert(`Error deleting canary: ${err.message}`);
    }
  };

  // Policy Form Handlers
  const handlePolicyChange = (field, value) => {
    setPolicyForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleAddExtension = (e) => {
    e.preventDefault();
    const clean = newExtInput.trim().toLowerCase();
    if (!clean) return;
    const formatted = clean.startsWith(".") ? clean : `.${clean}`;
    const current = Array.isArray(policyForm?.suspicious_extensions)
      ? policyForm.suspicious_extensions
      : [];
    if (!current.includes(formatted)) {
      setPolicyForm((prev) => ({
        ...prev,
        suspicious_extensions: [...current, formatted],
      }));
    }
    setNewExtInput("");
  };

  const handleRemoveExtension = (ext) => {
    const current = Array.isArray(policyForm?.suspicious_extensions)
      ? policyForm.suspicious_extensions
      : [];
    setPolicyForm((prev) => ({
      ...prev,
      suspicious_extensions: current.filter((x) => x !== ext),
    }));
  };

  const handleSavePolicy = async (e) => {
    e.preventDefault();
    if (!policyForm) return;

    // Client-side range validation
    const numFields = [
      ["burst_window_seconds", 1, 300],
      ["burst_modify_threshold", 1, 10000],
      ["burst_rename_threshold", 1, 10000],
      ["burst_delete_threshold", 1, 10000],
      ["burst_combined_threshold", 1, 10000],
      ["correlation_window_seconds", 10, 7200],
      ["dedupe_gap_seconds", 10, 3600],
    ];

    for (const [key, min, max] of numFields) {
      const val = Number(policyForm[key]);
      if (isNaN(val) || val < min || val > max) {
        setPolicyFeedback({
          type: "danger",
          message: `Field '${key}' must be a number between ${min} and ${max}.`,
        });
        return;
      }
    }

    setPolicySubmitting(true);
    setPolicyFeedback(null);

    try {
      const payload = {
        burst_window_seconds: Number(policyForm.burst_window_seconds),
        burst_modify_threshold: Number(policyForm.burst_modify_threshold),
        burst_rename_threshold: Number(policyForm.burst_rename_threshold),
        burst_delete_threshold: Number(policyForm.burst_delete_threshold),
        burst_combined_threshold: Number(policyForm.burst_combined_threshold),
        correlation_window_seconds: Number(policyForm.correlation_window_seconds),
        dedupe_gap_seconds: Number(policyForm.dedupe_gap_seconds),
        suspicious_extensions: policyForm.suspicious_extensions,
        burst_enabled: Boolean(policyForm.burst_enabled),
        canary_enabled: Boolean(policyForm.canary_enabled),
        extension_enabled: Boolean(policyForm.extension_enabled),
      };

      const res = await updateRansomwareConfig(payload);
      const updated = res.data || res;
      setConfig(updated);
      setPolicyForm(updated);
      setPolicyFeedback({
        type: "success",
        message: "Ransomware detection policy and thresholds successfully synchronized.",
      });
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setPolicyFeedback({
        type: "danger",
        message: err.response?.data?.error || err.message || "Failed to update detection policy.",
      });
    } finally {
      setPolicySubmitting(false);
    }
  };

  // Run Manual Analysis
  const handleExecuteAnalysis = async () => {
    setAnalysisConfirm(false);
    setAnalysisRunning(true);
    setAnalysisError(null);
    setAnalysisResult(null);

    try {
      const res = await runRansomwareAnalysis(analysisDevice || null);
      const data = res.data || res;
      setAnalysisResult(data);
      await loadData();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setAnalysisError(
        err.response?.data?.error || err.message || "On-demand analysis execution failed."
      );
    } finally {
      setAnalysisRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Stat Cards */}
      <div className="rounded-xl border border-rose-500/30 bg-gradient-to-r from-rose-950/40 via-slate-900/80 to-slate-900/60 p-5 shadow-xl">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-rose-500/20 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-rose-500/20 text-rose-400 ring-1 ring-rose-500/40 shadow-lg shadow-rose-500/10">
              <FaBiohazard size={24} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Ransomware Behavioral Threat Center
                </h2>
                <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-mono font-bold text-rose-300 border border-rose-500/30 uppercase">
                  Phase 2/3 Live Engine
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Multi-indicator sliding burst analytics, canary honeyfiles, and extension mutation defenses
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setActiveSubTab("analysis")}
              className="inline-flex items-center gap-1.5 rounded-lg bg-rose-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-rose-600/30 hover:bg-rose-500 transition active:scale-95"
            >
              <FaPlay size={10} />
              <span>Run Analysis</span>
            </button>
            <button
              onClick={() => handleOpenCanaryModal()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600 bg-slate-800/90 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-accent hover:text-white transition"
            >
              <FaPlus size={10} className="text-accent" />
              <span>Add Canary</span>
            </button>
            <button
              onClick={() => loadData(true)}
              disabled={refreshing}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-500 hover:text-white transition disabled:opacity-50"
            >
              <FaRedo className={refreshing ? "animate-spin" : ""} size={10} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* 4 Overview Stat Cards */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 pt-4">
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Active Ransomware Alerts</span>
              <FaBiohazard className="text-rose-400" size={12} />
            </div>
            <div className="mt-1.5 font-mono text-xl font-bold text-white">
              {stats.totalAlerts}
            </div>
            <div className="mt-0.5 text-[11px] text-slate-400">
              <span className="font-semibold text-rose-400">{stats.criticalAlerts} Critical</span> • {stats.highAlerts} High
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Canary Decoys</span>
              <FaLock className="text-amber-400" size={12} />
            </div>
            <div className="mt-1.5 font-mono text-xl font-bold text-white">
              {stats.activeCanaries} <span className="text-xs text-slate-500 font-normal">/ {stats.totalCanaries}</span>
            </div>
            <div className="mt-0.5 text-[11px] text-emerald-400 font-medium">
              Active & Monitored
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Monitored Extensions</span>
              <FaFileCode className="text-purple-400" size={12} />
            </div>
            <div className="mt-1.5 font-mono text-xl font-bold text-white">
              {config?.suspicious_extensions?.length || 0}
            </div>
            <div className="mt-0.5 text-[11px] text-slate-400 font-mono truncate">
              {config?.suspicious_extensions?.slice(0, 3).join(", ") || "-"}...
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Impacted Endpoints</span>
              <FaServer className="text-emerald-400" size={12} />
            </div>
            <div className="mt-1.5 font-mono text-xl font-bold text-white">
              {stats.affectedHosts.length}
            </div>
            <div className="mt-0.5 text-[11px] text-slate-400 truncate">
              {stats.affectedHosts.length > 0 ? stats.affectedHosts.join(", ") : "All endpoints clean"}
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-700/80 pb-2">
        <button
          onClick={() => setActiveSubTab("overview")}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
            activeSubTab === "overview"
              ? "bg-rose-600 text-white shadow-md shadow-rose-600/30"
              : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
          }`}
        >
          <FaShieldAlt size={12} />
          <span>Ransomware Overview</span>
        </button>

        <button
          onClick={() => setActiveSubTab("alerts")}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
            activeSubTab === "alerts"
              ? "bg-rose-600 text-white shadow-md shadow-rose-600/30"
              : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
          }`}
        >
          <FaBiohazard size={12} />
          <span>Detections & Forensics</span>
          <span className="rounded-full bg-slate-900/60 px-2 py-0.5 text-[10px] font-mono">
            {alerts.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab("canaries")}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
            activeSubTab === "canaries"
              ? "bg-amber-600 text-white shadow-md shadow-amber-600/30"
              : "bg-slate-800/80 text-amber-300 hover:bg-slate-700 hover:text-white"
          }`}
        >
          <FaLock size={12} />
          <span>Canary Decoy Registry</span>
          <span className="rounded-full bg-slate-900/60 px-2 py-0.5 text-[10px] font-mono">
            {canaries.length}
          </span>
        </button>

        <button
          onClick={() => setActiveSubTab("policy")}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
            activeSubTab === "policy"
              ? "bg-purple-600 text-white shadow-md shadow-purple-600/30"
              : "bg-slate-800/80 text-purple-300 hover:bg-slate-700 hover:text-white"
          }`}
        >
          <FaSlidersH size={12} />
          <span>Detection Policy & Thresholds</span>
        </button>

        <button
          onClick={() => setActiveSubTab("analysis")}
          className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
            activeSubTab === "analysis"
              ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
              : "bg-slate-800/80 text-indigo-300 hover:bg-slate-700 hover:text-white"
          }`}
        >
          <FaPlay size={10} />
          <span>On-Demand Analysis</span>
        </button>
      </div>

      {/* Global Error Banner */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger">
          <div className="flex items-center gap-2">
            <FaExclamationTriangle size={14} />
            <span>{error}</span>
          </div>
          <button onClick={() => loadData(true)} className="underline font-semibold">
            Retry
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Overview */}
      {/* ========================================================================= */}
      {activeSubTab === "overview" && (
        <div className="space-y-6 animate-fadeIn">
          {/* Summary Status Panel */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-xl border border-slate-700/60 bg-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Threat Posture
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${
                    stats.criticalAlerts > 0
                      ? "bg-danger/20 text-danger border border-danger/40"
                      : stats.totalAlerts > 0
                        ? "bg-warning/20 text-warning border border-warning/40"
                        : "bg-success/20 text-success border border-success/40"
                  }`}
                >
                  {stats.criticalAlerts > 0
                    ? "CRITICAL INCIDENT"
                    : stats.totalAlerts > 0
                      ? "ELEVATED ACTIVITY"
                      : "DEFENSIVE BASELINE"}
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {stats.totalAlerts === 0
                  ? "Zero ransomware behavioral episodes currently active. Ingestion and honeypot collectors operating normally."
                  : `${stats.totalAlerts} ransomware indicator alerts identified across ${stats.affectedHosts.length} endpoint(s).`}
              </p>
              <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
                <span>Latest Indicator:</span>
                <span className="font-mono text-slate-300">
                  {stats.latestTime ? formatTimestamp(stats.latestTime) : "None recorded"}
                </span>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700/60 bg-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Canary Honeyfile Health
                </span>
                <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold text-emerald-300 border border-emerald-500/30">
                  {stats.activeCanaries} ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Decoy files placed in designated directories trigger instant critical severity alerts if tampered with or renamed.
              </p>
              <div className="pt-2 border-t border-slate-800 flex justify-between items-center text-[11px]">
                <button
                  onClick={() => setActiveSubTab("canaries")}
                  className="text-accent hover:underline font-semibold"
                >
                  Manage Canary Registry →
                </button>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700/60 bg-card p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Active Policy Engine
                </span>
                <span className="font-mono text-[10px] text-accent">
                  {config?.burst_window_seconds || 10}s Window
                </span>
              </div>
              <div className="space-y-1 text-xs text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-400">Modify Threshold:</span>
                  <span className="font-mono font-semibold">{config?.burst_modify_threshold || 50} files</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Rename Threshold:</span>
                  <span className="font-mono font-semibold">{config?.burst_rename_threshold || 50} files</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Delete Threshold:</span>
                  <span className="font-mono font-semibold">{config?.burst_delete_threshold || 50} files</span>
                </div>
              </div>
              <div className="pt-2 border-t border-slate-800 flex justify-between items-center text-[11px]">
                <button
                  onClick={() => setActiveSubTab("policy")}
                  className="text-purple-300 hover:underline font-semibold"
                >
                  Tune Engine Parameters →
                </button>
              </div>
            </div>
          </div>

          {/* Recent Ransomware Alerts Preview */}
          <div className="rounded-xl border border-slate-700/60 bg-card p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">Recent Ransomware Detections</h3>
                <p className="text-xs text-slate-400">
                  Forensic alerts correlating bursts, honeypot access, and malicious file mutations
                </p>
              </div>
              <button
                onClick={() => setActiveSubTab("alerts")}
                className="text-xs text-accent hover:underline font-semibold"
              >
                View All {alerts.length} Alerts →
              </button>
            </div>

            {alerts.length === 0 ? (
              <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-8 text-center text-xs text-slate-400">
                <FaShieldAlt className="mx-auto text-emerald-400 mb-2" size={24} />
                <p className="font-semibold text-slate-300">No active ransomware alerts.</p>
                <p className="mt-1 text-slate-500">
                  All endpoint file activity is within normal behavioral thresholds.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-slate-700/60">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400">
                    <tr>
                      <th className="px-3 py-2.5 font-mono">Alert ID</th>
                      <th className="px-3 py-2.5">Detected (UTC)</th>
                      <th className="px-3 py-2.5">Rule / Indicator</th>
                      <th className="px-3 py-2.5">Severity</th>
                      <th className="px-3 py-2.5">Host</th>
                      <th className="px-3 py-2.5">Affected Paths</th>
                      <th className="px-3 py-2.5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {alerts.slice(0, 5).map((a) => {
                      const settings = typeof a.settings === "object" ? (a.settings || {}) : {};
                      return (
                        <tr key={a.id} className="hover:bg-slate-800/50">
                          <td className="px-3 py-2.5 font-mono text-accent font-semibold">#{a.id}</td>
                          <td className="px-3 py-2.5 font-mono whitespace-nowrap text-slate-400">
                            {formatTimestamp(a.last_seen || a.first_seen)}
                          </td>
                          <td className="px-3 py-2.5">
                            <span className="font-semibold text-white">{a.rule_name || a.rule_id}</span>
                            <span className="ml-2 font-mono text-[10px] text-rose-300">({a.rule_id})</span>
                          </td>
                          <td className="px-3 py-2.5">
                            <SeverityBadge severity={a.severity} />
                          </td>
                          <td className="px-3 py-2.5 font-mono text-emerald-400 font-medium">
                            {a.target_host || "endpoint"}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-xs">
                            {settings.distinct_paths_count ? (
                              <span className="text-rose-300 font-semibold">
                                {settings.distinct_paths_count} paths ({settings.raw_event_count || "-"} events)
                              </span>
                            ) : (
                              <span className="text-slate-400">
                                {a.file_evidence?.length ? `${a.file_evidence.length} events` : "1 event"}
                              </span>
                            )}
                          </td>
                          <td className="px-3 py-2.5 text-right">
                            <button
                              onClick={() => onSelectAlert && onSelectAlert(a)}
                              className="rounded bg-accent/20 px-2.5 py-1 text-xs font-semibold text-accent border border-accent/30 hover:bg-accent hover:text-primary transition inline-flex items-center gap-1"
                            >
                              <span>Triage</span>
                              <FaExternalLinkAlt size={9} />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Detections & Forensics */}
      {/* ========================================================================= */}
      {activeSubTab === "alerts" && (
        <div className="space-y-4 animate-fadeIn">
          {/* Filter Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-700/60 bg-card p-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs" />
              <input
                type="text"
                value={alertSearch}
                onChange={(e) => setAlertSearch(e.target.value)}
                placeholder="Search alerts by rule, host, reason, or path..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900/80 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <div className="flex items-center gap-1.5">
                <FaFilter className="text-slate-500 text-xs" />
                <select
                  value={alertSeverityFilter}
                  onChange={(e) => setAlertSeverityFilter(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900/80 px-2.5 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
                >
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <FaServer className="text-slate-500 text-xs" />
                <select
                  value={alertHostFilter}
                  onChange={(e) => setAlertHostFilter(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-900/80 px-2.5 py-1.5 text-xs text-slate-300 focus:border-accent focus:outline-none"
                >
                  <option value="all">All Hosts</option>
                  {stats.affectedHosts.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Alerts Table */}
          <div className="rounded-xl border border-slate-700/60 bg-card overflow-hidden">
            {filteredAlerts.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                <p className="font-semibold text-slate-300">No ransomware alerts match current filters.</p>
                <p className="mt-1 text-slate-500">
                  Try clearing the search or severity filter to view historical records.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400">
                    <tr>
                      <th className="px-3.5 py-2.5 font-mono">ID</th>
                      <th className="px-3.5 py-2.5">Detected (UTC)</th>
                      <th className="px-3.5 py-2.5">Rule / Indicator</th>
                      <th className="px-3.5 py-2.5">Severity</th>
                      <th className="px-3.5 py-2.5">Target Host</th>
                      <th className="px-3.5 py-2.5">Detection Rationale</th>
                      <th className="px-3.5 py-2.5">Evidence</th>
                      <th className="px-3.5 py-2.5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {filteredAlerts.map((a) => {
                      const settings = typeof a.settings === "object" ? (a.settings || {}) : {};
                      const evCount = a.file_evidence?.length || 0;
                      return (
                        <tr key={a.id} className="hover:bg-slate-800/50">
                          <td className="px-3.5 py-2.5 font-mono text-accent font-semibold">#{a.id}</td>
                          <td className="px-3.5 py-2.5 font-mono whitespace-nowrap text-slate-400">
                            {formatTimestamp(a.last_seen || a.first_seen)}
                          </td>
                          <td className="px-3.5 py-2.5">
                            <span className="font-semibold text-white">{a.rule_name || a.rule_id}</span>
                            <div className="font-mono text-[10px] text-rose-300">{a.rule_id}</div>
                          </td>
                          <td className="px-3.5 py-2.5">
                            <SeverityBadge severity={a.severity} />
                          </td>
                          <td className="px-3.5 py-2.5 font-mono text-emerald-400 font-medium">
                            {a.target_host || "endpoint"}
                          </td>
                          <td className="px-3.5 py-2.5 max-w-sm truncate" title={a.explanation || a.summary}>
                            <span className="text-slate-300">{a.explanation || a.summary}</span>
                          </td>
                          <td className="px-3.5 py-2.5 whitespace-nowrap">
                            <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-mono font-semibold text-rose-300 border border-rose-500/30">
                              {settings.distinct_paths_count
                                ? `${settings.distinct_paths_count} paths`
                                : `${evCount} event${evCount === 1 ? "" : "s"}`}
                            </span>
                          </td>
                          <td className="px-3.5 py-2.5 text-right">
                            <button
                              onClick={() => onSelectAlert && onSelectAlert(a)}
                              className="rounded bg-accent/20 px-2.5 py-1 text-xs font-semibold text-accent border border-accent/30 hover:bg-accent hover:text-primary transition inline-flex items-center gap-1"
                            >
                              <span>Triage</span>
                              <FaExternalLinkAlt size={9} />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Canary Registry */}
      {/* ========================================================================= */}
      {activeSubTab === "canaries" && (
        <div className="space-y-4 animate-fadeIn">
          {/* Informational Guidance Notice */}
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-4 text-xs text-amber-200/90 space-y-1">
            <div className="flex items-center gap-2 font-bold text-amber-300">
              <FaInfoCircle size={14} />
              <span>Canary / Honeyfile Operational Guidance</span>
            </div>
            <p>
              Canary paths registered here are monitored by the backend detection engine for any creation, edit, rename, or deletion.
              <strong> Important:</strong> The ThreatLens Linux endpoint collector on target machines must already include the enclosing directory in its active watch path.
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 text-xs" />
              <input
                type="text"
                value={canarySearch}
                onChange={(e) => setCanarySearch(e.target.value)}
                placeholder="Search canaries by path, ID, device, or desc..."
                className="w-full rounded-lg border border-slate-700 bg-slate-900/80 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
              />
            </div>

            <button
              onClick={() => handleOpenCanaryModal()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-amber-600/30 hover:bg-amber-500 transition"
            >
              <FaPlus size={10} />
              <span>Register New Canary Decoy</span>
            </button>
          </div>

          {/* Canary Table */}
          <div className="rounded-xl border border-slate-700/60 bg-card overflow-hidden">
            {filteredCanaries.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-400">
                <FaLock className="mx-auto text-amber-400/60 mb-2" size={24} />
                <p className="font-semibold text-slate-300">No canary decoys currently registered.</p>
                <p className="mt-1 text-slate-500">
                  Register a decoy file path to establish early-warning ransomware triggers.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400">
                    <tr>
                      <th className="px-3.5 py-2.5 font-mono">Canary ID</th>
                      <th className="px-3.5 py-2.5">Decoy File Path</th>
                      <th className="px-3.5 py-2.5">Endpoint Scope</th>
                      <th className="px-3.5 py-2.5">Severity</th>
                      <th className="px-3.5 py-2.5">Description</th>
                      <th className="px-3.5 py-2.5">Status</th>
                      <th className="px-3.5 py-2.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {filteredCanaries.map((c) => (
                      <tr key={c.canary_id} className="hover:bg-slate-800/50">
                        <td className="px-3.5 py-2.5 font-mono text-amber-300 font-semibold">
                          {c.canary_id}
                        </td>
                        <td className="px-3.5 py-2.5 font-mono text-xs text-white max-w-xs truncate" title={c.file_path}>
                          {c.file_path}
                        </td>
                        <td className="px-3.5 py-2.5 font-mono text-emerald-400">
                          {c.device_id ? c.device_id : <span className="text-slate-500 italic">All Endpoints</span>}
                        </td>
                        <td className="px-3.5 py-2.5">
                          <SeverityBadge severity={c.severity} />
                        </td>
                        <td className="px-3.5 py-2.5 text-slate-400 max-w-xs truncate" title={c.description}>
                          {c.description || "-"}
                        </td>
                        <td className="px-3.5 py-2.5">
                          <button
                            onClick={() => handleToggleCanary(c)}
                            className={`rounded-full px-2.5 py-0.5 text-[10px] font-bold transition border ${
                              c.enabled
                                ? "bg-success/20 text-success border-success/40 hover:bg-success/30"
                                : "bg-slate-700 text-slate-400 border-slate-600 hover:bg-slate-600"
                            }`}
                          >
                            {c.enabled ? "Active" : "Disabled"}
                          </button>
                        </td>
                        <td className="px-3.5 py-2.5 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <button
                              onClick={() => handleOpenCanaryModal(c)}
                              title="Edit Canary"
                              className="rounded bg-slate-800 p-1 text-slate-300 hover:text-white hover:bg-slate-700 transition"
                            >
                              <FaEdit size={11} />
                            </button>
                            <button
                              onClick={() => setCanaryDeleteTarget(c)}
                              title="Delete Canary"
                              className="rounded bg-slate-800 p-1 text-rose-400 hover:text-rose-300 hover:bg-slate-700 transition"
                            >
                              <FaTrashAlt size={11} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: Policy & Thresholds */}
      {/* ========================================================================= */}
      {activeSubTab === "policy" && (
        <div className="space-y-6 animate-fadeIn">
          {policyFeedback && (
            <div
              className={`rounded-lg p-3 text-xs border ${
                policyFeedback.type === "success"
                  ? "bg-success/10 text-success border-success/40"
                  : "bg-danger/10 text-danger border-danger/40"
              }`}
            >
              {policyFeedback.message}
            </div>
          )}

          <form onSubmit={handleSavePolicy} className="rounded-xl border border-slate-700/60 bg-card p-6 space-y-6">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Ransomware Detection Policy & Threshold Tuning
              </h3>
              <p className="text-xs text-slate-400">
                Configure sliding time window thresholds, incident grouping periods, and monitored suspicious file extensions.
              </p>
            </div>

            {/* Enable/Disable Feature Toggles */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-4 rounded-lg bg-slate-900/60 border border-slate-800">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(policyForm?.burst_enabled)}
                  onChange={(e) => handlePolicyChange("burst_enabled", e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-rose-600 focus:ring-rose-500 h-4 w-4"
                />
                <div>
                  <div className="text-xs font-semibold text-white">Sliding Burst Detection</div>
                  <div className="text-[10px] text-slate-400">Rules RW-BURST-01..04</div>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(policyForm?.canary_enabled)}
                  onChange={(e) => handlePolicyChange("canary_enabled", e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-amber-600 focus:ring-amber-500 h-4 w-4"
                />
                <div>
                  <div className="text-xs font-semibold text-white">Canary Honeyfile Monitor</div>
                  <div className="text-[10px] text-slate-400">Rule RW-CANARY-01</div>
                </div>
              </label>

              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(policyForm?.extension_enabled)}
                  onChange={(e) => handlePolicyChange("extension_enabled", e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-purple-600 focus:ring-purple-500 h-4 w-4"
                />
                <div>
                  <div className="text-xs font-semibold text-white">Extension Mutation Defense</div>
                  <div className="text-[10px] text-slate-400">Rule RW-EXT-01</div>
                </div>
              </label>
            </div>

            {/* Threshold Sliders / Numbers */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Burst Window (Seconds)
                </label>
                <input
                  type="number"
                  min="1"
                  max="300"
                  value={policyForm?.burst_window_seconds ?? 10}
                  onChange={(e) => handlePolicyChange("burst_window_seconds", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Sliding evaluation episode window</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Modify Threshold (Distinct Paths)
                </label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={policyForm?.burst_modify_threshold ?? 50}
                  onChange={(e) => handlePolicyChange("burst_modify_threshold", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Triggers RW-BURST-01</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Rename Threshold (Distinct Paths)
                </label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={policyForm?.burst_rename_threshold ?? 50}
                  onChange={(e) => handlePolicyChange("burst_rename_threshold", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Triggers RW-BURST-02</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Delete Threshold (Distinct Paths)
                </label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={policyForm?.burst_delete_threshold ?? 50}
                  onChange={(e) => handlePolicyChange("burst_delete_threshold", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Triggers RW-BURST-03</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Combined Burst Threshold
                </label>
                <input
                  type="number"
                  min="1"
                  max="2000"
                  value={policyForm?.burst_combined_threshold ?? 80}
                  onChange={(e) => handlePolicyChange("burst_combined_threshold", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Triggers RW-BURST-04</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Incident Correlation Window (s)
                </label>
                <input
                  type="number"
                  min="10"
                  max="7200"
                  value={policyForm?.correlation_window_seconds ?? 600}
                  onChange={(e) => handlePolicyChange("correlation_window_seconds", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Correlates alerts into same incident</span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Alert Deduplication Gap (s)
                </label>
                <input
                  type="number"
                  min="10"
                  max="3600"
                  value={policyForm?.dedupe_gap_seconds ?? 300}
                  onChange={(e) => handlePolicyChange("dedupe_gap_seconds", e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs text-white focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">Prevents duplicate alerts on replay</span>
              </div>
            </div>

            {/* Suspicious Extension Tag Editor */}
            <div className="space-y-3 pt-3 border-t border-slate-800">
              <label className="block text-xs font-semibold text-slate-300">
                Monitored Suspicious Extensions (RW-EXT-01)
              </label>

              <div className="flex flex-wrap gap-2 items-center">
                {(policyForm?.suspicious_extensions || []).map((ext) => (
                  <span
                    key={ext}
                    className="inline-flex items-center gap-1.5 rounded bg-purple-950/40 border border-purple-500/30 px-2.5 py-1 text-xs font-mono text-purple-300"
                  >
                    <span>{ext}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveExtension(ext)}
                      className="text-purple-400 hover:text-white"
                      title="Remove extension"
                    >
                      <FaTimes size={10} />
                    </button>
                  </span>
                ))}
              </div>

              <div className="flex gap-2 max-w-sm pt-1">
                <input
                  type="text"
                  value={newExtInput}
                  onChange={(e) => setNewExtInput(e.target.value)}
                  placeholder="e.g. .locked, .wncry, .ransom"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1 text-xs text-white font-mono placeholder:text-slate-500 focus:border-accent focus:outline-none"
                />
                <button
                  type="button"
                  onClick={handleAddExtension}
                  className="rounded-lg bg-slate-800 border border-slate-600 px-3 py-1 text-xs font-semibold text-slate-200 hover:text-white hover:border-accent transition"
                >
                  Add
                </button>
              </div>
            </div>

            {/* Save Buttons */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setPolicyForm(config)}
                className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
              >
                Reset to Current
              </button>
              <button
                type="submit"
                disabled={policySubmitting}
                className="rounded-lg bg-purple-600 px-5 py-2 text-xs font-bold text-white shadow-md shadow-purple-600/30 hover:bg-purple-500 transition disabled:opacity-50"
              >
                {policySubmitting ? "Saving Changes..." : "Save Policy Configuration"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Tab: On-Demand Manual Analysis */}
      {/* ========================================================================= */}
      {activeSubTab === "analysis" && (
        <div className="space-y-6 animate-fadeIn">
          <div className="rounded-xl border border-slate-700/60 bg-card p-6 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                On-Demand Ransomware Telemetry Analysis
              </h3>
              <p className="text-xs text-slate-400">
                Trigger on-demand execution of the detection engine over stored file events to test correlation or verify endpoint telemetry.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-xl">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Target Endpoint Scope
                </label>
                <select
                  value={analysisDevice}
                  onChange={(e) => setAnalysisDevice(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-2 text-xs text-slate-200 focus:border-accent focus:outline-none"
                >
                  <option value="">All Registered Endpoints (Global)</option>
                  {endpoints.map((ep) => (
                    <option key={ep.device_id} value={ep.device_id}>
                      {ep.device_id} ({ep.hostname || "unknown"})
                    </option>
                  ))}
                </select>
                <span className="text-[10px] text-slate-500">
                  Select a specific host or evaluate all endpoint devices
                </span>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="button"
                disabled={analysisRunning}
                onClick={() => setAnalysisConfirm(true)}
                className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-xs font-bold text-white shadow-md shadow-indigo-600/30 hover:bg-indigo-500 transition disabled:opacity-50"
              >
                <FaPlay size={11} className={analysisRunning ? "animate-spin" : ""} />
                <span>{analysisRunning ? "Evaluating Telemetry..." : "Run Ransomware Analysis"}</span>
              </button>
            </div>
          </div>

          {/* Analysis Error */}
          {analysisError && (
            <div className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-xs text-danger">
              {analysisError}
            </div>
          )}

          {/* Analysis Results Display */}
          {analysisResult && (
            <div className="rounded-xl border border-indigo-500/30 bg-slate-900/60 p-6 space-y-4 animate-fadeIn">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <FaCheck className="text-emerald-400" size={14} />
                  <h4 className="text-sm font-bold text-white">Analysis Execution Completed</h4>
                </div>
                <span className="text-xs text-slate-400 font-mono">
                  {new Date().toLocaleTimeString()} UTC
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                  <div className="text-slate-400 text-[10px]">Events Evaluated</div>
                  <div className="font-mono text-lg font-bold text-white mt-0.5">
                    {analysisResult.events_evaluated || 0}
                  </div>
                </div>
                <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                  <div className="text-slate-400 text-[10px]">New Alerts Generated</div>
                  <div className="font-mono text-lg font-bold text-rose-400 mt-0.5">
                    {analysisResult.new_alerts_count || 0}
                  </div>
                </div>
                <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                  <div className="text-slate-400 text-[10px]">Alerts Deduplicated</div>
                  <div className="font-mono text-lg font-bold text-amber-400 mt-0.5">
                    {analysisResult.updated_alerts_count || 0}
                  </div>
                </div>
                <div className="rounded-lg bg-slate-900/80 p-3 border border-slate-800">
                  <div className="text-slate-400 text-[10px]">Incidents Escalated</div>
                  <div className="font-mono text-lg font-bold text-indigo-400 mt-0.5">
                    {(analysisResult.new_incidents_count || 0) + (analysisResult.updated_incidents_count || 0)}
                  </div>
                </div>
              </div>

              {analysisResult.new_alerts && analysisResult.new_alerts.length > 0 ? (
                <div className="space-y-2 pt-2">
                  <div className="text-xs font-semibold text-rose-300">
                    New Detection Indicators Flagged:
                  </div>
                  <div className="overflow-x-auto rounded border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900 text-slate-400">
                        <tr>
                          <th className="p-2">Rule</th>
                          <th className="p-2">Severity</th>
                          <th className="p-2">Target Host</th>
                          <th className="p-2">Rationale</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {analysisResult.new_alerts.map((na, idx) => (
                          <tr key={idx}>
                            <td className="p-2 font-mono text-rose-400">{na.rule_id}</td>
                            <td className="p-2"><SeverityBadge severity={na.severity} /></td>
                            <td className="p-2 font-mono text-emerald-400">{na.target_host}</td>
                            <td className="p-2 text-slate-300">{na.summary}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="rounded bg-slate-900/40 p-3 text-xs text-slate-400 text-center">
                  No new ransomware indicators detected across evaluated events.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* Modal: Register / Edit Canary */}
      {/* ========================================================================= */}
      {showCanaryModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-md rounded-2xl border border-slate-700 bg-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-700/80 pb-3">
              <div className="flex items-center gap-2">
                <FaLock className="text-amber-400" size={16} />
                <h3 className="text-sm font-bold text-white">
                  {editingCanary ? "Edit Canary Definition" : "Register Canary Honeyfile"}
                </h3>
              </div>
              <button
                onClick={() => setShowCanaryModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <FaTimes size={16} />
              </button>
            </div>

            {canaryError && (
              <div className="rounded bg-danger/10 border border-danger/40 p-2.5 text-xs text-danger">
                {canaryError}
              </div>
            )}

            <form onSubmit={handleSaveCanary} className="space-y-3.5 text-xs">
              <div>
                <label className="block font-semibold text-slate-300 mb-1">
                  Decoy File Path <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={canaryFilePath}
                  onChange={(e) => setCanaryFilePath(e.target.value)}
                  placeholder="e.g. /var/secrets/passwords.kdbx"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 font-mono text-white placeholder:text-slate-500 focus:border-accent focus:outline-none"
                />
                <span className="text-[10px] text-slate-500">
                  Exact normalized filesystem path watched by the endpoint collector.
                </span>
              </div>

              <div>
                <label className="block font-semibold text-slate-300 mb-1">Canary Identifier</label>
                <input
                  type="text"
                  disabled={Boolean(editingCanary)}
                  value={canaryId}
                  onChange={(e) => setCanaryId(e.target.value)}
                  placeholder="Unique ID e.g. canary-01"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 font-mono text-white placeholder:text-slate-500 focus:border-accent focus:outline-none disabled:opacity-60"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-semibold text-slate-300 mb-1">Endpoint Scope</label>
                  <select
                    value={canaryDeviceId}
                    onChange={(e) => setCanaryDeviceId(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-slate-200 focus:border-accent focus:outline-none"
                  >
                    <option value="">All Endpoints (Global)</option>
                    {endpoints.map((ep) => (
                      <option key={ep.device_id} value={ep.device_id}>
                        {ep.device_id}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block font-semibold text-slate-300 mb-1">Alert Severity</label>
                  <select
                    value={canarySeverity}
                    onChange={(e) => setCanarySeverity(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-slate-200 focus:border-accent focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-semibold text-slate-300 mb-1">Description</label>
                <input
                  type="text"
                  value={canaryDesc}
                  onChange={(e) => setCanaryDesc(e.target.value)}
                  placeholder="e.g. Executive payroll decoy spreadsheet"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-slate-200 placeholder:text-slate-500 focus:border-accent focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="canaryEnabledCheck"
                  checked={canaryEnabled}
                  onChange={(e) => setCanaryEnabled(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-amber-600 focus:ring-amber-500"
                />
                <label htmlFor="canaryEnabledCheck" className="text-slate-300 font-medium cursor-pointer">
                  Enable active monitoring for this decoy
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCanaryModal(false)}
                  className="rounded-lg border border-slate-700 px-3.5 py-1.5 font-semibold text-slate-300 hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={canarySubmitting}
                  className="rounded-lg bg-amber-600 px-4 py-1.5 font-bold text-white shadow hover:bg-amber-500 transition disabled:opacity-50"
                >
                  {canarySubmitting ? "Saving..." : editingCanary ? "Update Canary" : "Register Canary"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Modal: Confirm Canary Deletion */}
      {/* ========================================================================= */}
      {canaryDeleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-sm rounded-2xl border border-slate-700 bg-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <FaTrashAlt size={20} />
              <h3 className="text-sm font-bold text-white">Delete Canary Honeyfile?</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to remove canary <span className="font-mono text-rose-300">"{canaryDeleteTarget.canary_id}"</span>?
              The backend detection engine will no longer monitor path:
            </p>
            <div className="rounded bg-slate-900 p-2 font-mono text-[11px] text-slate-300 break-all border border-slate-800">
              {canaryDeleteTarget.file_path}
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setCanaryDeleteTarget(null)}
                className="rounded-lg border border-slate-700 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteCanary}
                className="rounded-lg bg-rose-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-rose-500 transition"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* Modal: Confirm Analysis Execution */}
      {/* ========================================================================= */}
      {analysisConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-md rounded-2xl border border-slate-700 bg-card p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-indigo-400">
              <FaPlay size={18} />
              <h3 className="text-sm font-bold text-white">Confirm On-Demand Analysis</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This will trigger an on-demand evaluation of file-system telemetry across all registered detection rules.
              Scope: <strong className="text-emerald-400">{analysisDevice || "All Endpoints (Global)"}</strong>.
            </p>
            <div className="text-[11px] text-slate-400 rounded bg-slate-900/60 p-2.5 border border-slate-800">
              <strong>Defensive Guarantee:</strong> This action evaluates stored database telemetry. It never modifies filesystem files, creates destructive simulations, or kills active processes.
            </div>
            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setAnalysisConfirm(false)}
                className="rounded-lg border border-slate-700 px-3.5 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleExecuteAnalysis}
                className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-bold text-white hover:bg-indigo-500 transition"
              >
                Run Analysis Now
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
