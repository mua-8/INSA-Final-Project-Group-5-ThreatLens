import React, { useState, useEffect } from "react";
import { FaTimes, FaDatabase, FaCheckCircle, FaExclamationTriangle, FaShieldAlt, FaSyncAlt, FaCloud, FaExternalLinkAlt, FaExchangeAlt } from "react-icons/fa";
import { getSystemHealth, getFirebaseDiagnostics, syncDataToFirebase, getBackendMode, setBackendMode } from "../services/api.js";
import { firebaseConfig } from "../services/firebase.js";

export default function DatabaseHealthModal({ onClose, onModeChange }) {
  const [healthData, setHealthData] = useState(null);
  const [firebaseStatus, setFirebaseStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState(null);
  const [currentMode, setCurrentMode] = useState(getBackendMode());

  const fetchHealth = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      getSystemHealth().catch((err) => ({ error: err.message })),
      getFirebaseDiagnostics().catch((err) => ({ error: err.message, connected: false }))
    ])
      .then(([health, fb]) => {
        setHealthData(health);
        setFirebaseStatus(fb);
      })
      .catch((err) => {
        setError(err.message || "Failed to query system telemetry");
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const handleSyncToFirebase = async () => {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const res = await syncDataToFirebase();
      setSyncMsg({ success: true, text: res.message || "Synced successfully to Firebase!" });
      fetchHealth();
    } catch (err) {
      setSyncMsg({
        success: false,
        text: err.message || "Failed to sync to Firebase. Ensure Firestore is enabled in Firebase Console."
      });
    } finally {
      setSyncing(false);
    }
  };

  const handleModeSwitch = (mode) => {
    setBackendMode(mode);
    setCurrentMode(mode);
    if (onModeChange) onModeChange(mode);
  };

  const db = healthData?.database || {};
  const isHealthy = healthData?.status === "healthy" && (db.integrity === "ok" || healthData?.firebase);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="relative flex max-h-[90vh] w-full max-w-2xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/40">
              <FaDatabase size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  Database & Backend Infrastructure
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                SQLite & Firebase Cloud Backend
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

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          
          {loading && (
            <div className="py-12 text-center text-sm text-slate-400">
              <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-slate-600 border-t-accent mb-3" />
              <div>Checking SQLite & Firebase Firestore connectivity...</div>
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
              {error}
            </div>
          )}

          {!loading && (
            <>
              {/* Firebase Cloud Backend Panel */}
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
                    <FaCloud size={16} />
                    <span>Firebase Cloud Integration ({firebaseConfig.projectId})</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    firebaseStatus?.connected ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40" : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                  }`}>
                    {firebaseStatus?.connected ? "Firestore Active" : "Configured"}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                    <span className="text-slate-400 block text-[10px]">Project ID</span>
                    <span className="font-mono text-slate-200 font-medium">{firebaseConfig.projectId}</span>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                    <span className="text-slate-400 block text-[10px]">Auth Domain</span>
                    <span className="font-mono text-slate-200 font-medium">{firebaseConfig.authDomain}</span>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                    <span className="text-slate-400 block text-[10px]">Storage Bucket</span>
                    <span className="font-mono text-slate-200 font-medium">{firebaseConfig.storageBucket}</span>
                  </div>
                  <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                    <span className="text-slate-400 block text-[10px]">App ID</span>
                    <span className="font-mono text-slate-200 font-medium truncate block">{firebaseConfig.appId}</span>
                  </div>
                </div>

                {firebaseStatus?.isNotEnabled && (
                  <div className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs text-warning space-y-2">
                    <p className="font-medium">
                      Firebase web configuration is loaded! To start writing cloud documents, activate Cloud Firestore in the Firebase Console:
                    </p>
                    <a
                      href={firebaseStatus.enableUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded bg-warning/20 px-3 py-1 font-semibold text-warning hover:bg-warning/30 transition"
                    >
                      <span>Enable Cloud Firestore in Console</span>
                      <FaExternalLinkAlt size={10} />
                    </a>
                  </div>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-amber-500/20 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">Active Backend:</span>
                    <button
                      onClick={() => handleModeSwitch("auto")}
                      className={`px-2 py-1 rounded text-xs font-semibold transition ${
                        currentMode === "auto" ? "bg-accent text-primary" : "bg-slate-800 text-slate-300 hover:text-white"
                      }`}
                    >
                      Auto Hybrid
                    </button>
                    <button
                      onClick={() => handleModeSwitch("firebase")}
                      className={`px-2 py-1 rounded text-xs font-semibold transition ${
                        currentMode === "firebase" ? "bg-amber-500 text-primary" : "bg-slate-800 text-slate-300 hover:text-white"
                      }`}
                    >
                      Firebase Mode
                    </button>
                    <button
                      onClick={() => handleModeSwitch("flask")}
                      className={`px-2 py-1 rounded text-xs font-semibold transition ${
                        currentMode === "flask" ? "bg-emerald-500 text-primary" : "bg-slate-800 text-slate-300 hover:text-white"
                      }`}
                    >
                      Local SQLite
                    </button>
                  </div>

                  <button
                    onClick={handleSyncToFirebase}
                    disabled={syncing}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                  >
                    <FaSyncAlt className={syncing ? "animate-spin" : ""} size={11} />
                    <span>{syncing ? "Syncing..." : "Sync DB to Firebase"}</span>
                  </button>
                </div>

                {syncMsg && (
                  <div className={`p-2.5 rounded text-xs ${syncMsg.success ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/30" : "bg-danger/10 text-danger border border-danger/30"}`}>
                    {syncMsg.text}
                  </div>
                )}
              </div>

              {/* SQLite Overall Status Banner */}
              <div
                className={`flex items-center justify-between rounded-xl border p-4 ${
                  isHealthy
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    : "border-warning/30 bg-warning/10 text-warning"
                }`}
              >
                <div className="flex items-center gap-3">
                  {isHealthy ? <FaCheckCircle size={22} className="text-emerald-400" /> : <FaExclamationTriangle size={22} />}
                  <div>
                    <h3 className="font-semibold text-white">
                      SQLite Engine: {db.integrity ? `Integrity ${db.integrity}` : "Operational"}
                    </h3>
                    <p className="text-xs text-slate-300">
                      Foreign Key Violations: <strong className="font-mono text-emerald-300">{db.foreign_key_violations ?? 0}</strong> • Mode: <strong className="font-mono text-accent">{db.journal_mode || "WAL"}</strong>
                    </p>
                  </div>
                </div>
                <button
                  onClick={fetchHealth}
                  className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                  title="Re-run diagnostics"
                >
                  <FaSyncAlt size={12} />
                </button>
              </div>

              {/* Table Records Count */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  SQLite Table Record Counts
                </h4>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                  {Object.entries(db.table_records || {}).map(([tbl, count]) => (
                    <div
                      key={tbl}
                      className="flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-900/60 px-3 py-2 text-xs"
                    >
                      <span className="font-mono text-slate-300">{tbl}</span>
                      <span className="font-mono font-bold text-accent">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Firebase: <span className="font-mono text-amber-300">{firebaseConfig.projectId}</span>
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
