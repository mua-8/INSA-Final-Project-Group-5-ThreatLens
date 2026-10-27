import React, { useState, useEffect } from "react";
import { FaTimes, FaDatabase, FaCheckCircle, FaExclamationTriangle, FaShieldAlt, FaSyncAlt } from "react-icons/fa";
import { getSystemHealth } from "../services/api.js";

export default function DatabaseHealthModal({ onClose }) {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHealth = () => {
    setLoading(true);
    setError(null);
    getSystemHealth()
      .then((data) => {
        setHealthData(data);
      })
      .catch((err) => {
        setError(err.message || "Failed to query /api/health");
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const db = healthData?.database || {};
  const isHealthy = healthData?.status === "healthy" && db.integrity === "ok";

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
                  Database Controls & Telemetry
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Storage Architecture & Integrity
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
              <div>Running PRAGMA integrity_check and querying database telemetry...</div>
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
              {error}
            </div>
          )}

          {!loading && healthData && (
            <>
              {/* Overall Status Banner */}
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
                      {isHealthy ? "Database Healthy & Protected" : "Database Attention Required"}
                    </h3>
                    <p className="text-xs text-slate-300">
                      PRAGMA integrity_check: <strong className="font-mono text-emerald-300">{db.integrity}</strong> • Foreign Key Violations: <strong className="font-mono text-emerald-300">{db.foreign_key_violations}</strong>
                    </p>
                  </div>
                </div>
                <button
                  onClick={fetchHealth}
                  className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                  title="Re-run health check"
                >
                  <FaSyncAlt size={12} />
                </button>
              </div>

              {/* Technical Specifications */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Storage Engine</div>
                  <div className="mt-1 font-mono text-xs font-bold text-white">SQLite 3</div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Journal Mode</div>
                  <div className="mt-1 font-mono text-xs font-bold text-accent uppercase">
                    {db.journal_mode || "WAL"}
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                  <div className="text-xs text-slate-400">Database Size</div>
                  <div className="mt-1 font-mono text-xs font-bold text-white">
                    {db.size_bytes ? `${(db.size_bytes / 1024).toFixed(1)} KB` : "N/A"}
                  </div>
                </div>
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

              {/* Architecture & Security Controls */}
              <div className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-4 space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Database Architecture & Security Controls
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  <li className="flex items-center gap-2">
                    <span className="text-emerald-400">✔</span>
                    <span><strong>Parameterized DB-API Queries:</strong> Protection against SQL injection through strictly parameterized queries.</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-emerald-400">✔</span>
                    <span><strong>Relational Integrity:</strong> Foreign key constraint enforcement (<code className="font-mono text-accent">PRAGMA foreign_keys = ON</code>).</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-emerald-400">✔</span>
                    <span><strong>Audit & Deduplication:</strong> SHA-256 deduplication guard on log files and ingested event line hashes.</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-emerald-400">✔</span>
                    <span><strong>Performance Optimization:</strong> Sliding window index (<code className="font-mono text-accent">idx_events_ip_time</code>) and WAL journal mode for concurrent reads.</span>
                  </li>
                </ul>
              </div>
            </>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Storage Engine: <span className="font-mono text-slate-300">SQLite 3 (WAL Mode)</span>
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
