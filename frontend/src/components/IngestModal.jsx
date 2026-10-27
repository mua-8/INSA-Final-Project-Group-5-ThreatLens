import React, { useState } from "react";
import { FaTimes, FaCloudUploadAlt, FaBolt, FaCheckCircle, FaExclamationTriangle, FaFileAlt } from "react-icons/fa";
import { ingestLog } from "../services/api.js";

const PRESET_ATTACKS = [
  {
    name: "SQL Injection Attack (SQLi)",
    rule: "DR-06",
    filename: "attack_sql_injection.log",
    description: "Hostile SQL injection control syntax (' OR 1=1, UNION SELECT, DROP TABLE) injected into authentication fields from 198.51.100.88.",
    sample: `Oct 24 14:00:00 web01 sshd[9501]: Failed password for invalid user ' OR '1'='1 from 198.51.100.88 port 42100 ssh2
Oct 24 14:00:15 web01 sshd[9502]: Failed password for invalid user admin'-- from 198.51.100.88 port 42101 ssh2
Oct 24 14:00:30 web01 sshd[9503]: Failed password for invalid user ' UNION SELECT null, username, password FROM users-- from 198.51.100.88 port 42102 ssh2
Oct 24 14:00:45 web01 sshd[9504]: Failed password for invalid user 1; DROP TABLE users;-- from 198.51.100.88 port 42103 ssh2`,
  },
  {
    name: "Brute Force SSH (10 attempts)",
    rule: "DR-01",
    filename: "attack_brute_force_10.log",
    description: "10 rapid failed password attempts from 192.168.1.105 targeting root and admin.",
    sample: `Oct 25 10:00:01 server sshd[1234]: Failed password for invalid user root from 192.168.1.105 port 54321 ssh2
Oct 25 10:00:03 server sshd[1235]: Failed password for invalid user admin from 192.168.1.105 port 54322 ssh2
Oct 25 10:00:05 server sshd[1236]: Failed password for invalid user test from 192.168.1.105 port 54323 ssh2
Oct 25 10:00:08 server sshd[1237]: Failed password for invalid user deploy from 192.168.1.105 port 54324 ssh2
Oct 25 10:00:10 server sshd[1238]: Failed password for invalid user ubuntu from 192.168.1.105 port 54325 ssh2
Oct 25 10:00:12 server sshd[1239]: Failed password for invalid user oracle from 192.168.1.105 port 54326 ssh2
Oct 25 10:00:14 server sshd[1240]: Failed password for invalid user postgres from 192.168.1.105 port 54327 ssh2
Oct 25 10:00:16 server sshd[1241]: Failed password for invalid user guest from 192.168.1.105 port 54328 ssh2
Oct 25 10:00:18 server sshd[1242]: Failed password for invalid user git from 192.168.1.105 port 54329 ssh2
Oct 25 10:00:20 server sshd[1243]: Failed password for invalid user support from 192.168.1.105 port 54330 ssh2`,
  },
  {
    name: "Direct Root Login Attempt",
    rule: "DR-05",
    filename: "attack_root_login.log",
    description: "High severity policy violation: Direct root login accepted from remote IP 203.0.113.77.",
    sample: `Oct 24 14:00:00 web01 sshd[9000]: Failed password for root from 203.0.113.77 port 45000 ssh2
Oct 24 14:00:30 web01 sshd[9001]: Failed password for root from 203.0.113.77 port 45001 ssh2
Oct 24 14:01:10 web01 sshd[9002]: Accepted password for root from 203.0.113.77 port 45002 ssh2`,
  },
  {
    name: "Password Spraying Campaign",
    rule: "DR-03",
    filename: "attack_password_spraying.log",
    description: "Attacker attempts 1 common password across multiple corporate accounts.",
    sample: `Oct 24 14:00:00 web01 sshd[7000]: Failed password for alice from 198.51.100.42 port 43000 ssh2
Oct 24 14:00:15 web01 sshd[7001]: Failed password for bob from 198.51.100.42 port 43001 ssh2
Oct 24 14:00:30 web01 sshd[7002]: Failed password for charlie from 198.51.100.42 port 43002 ssh2
Oct 24 14:00:45 web01 sshd[7003]: Failed password for dave from 198.51.100.42 port 43003 ssh2
Oct 24 14:01:00 web01 sshd[7004]: Failed password for eve from 198.51.100.42 port 43004 ssh2`,
  },
  {
    name: "Compromise (Success After Failures)",
    rule: "DR-04",
    filename: "attack_success_after_failures.log",
    description: "6 failed login attempts followed immediately by a successful breach.",
    sample: `Oct 24 14:00:00 web01 sshd[8000]: Failed password for svc_backup from 198.51.100.99 port 44000 ssh2
Oct 24 14:00:20 web01 sshd[8001]: Failed password for svc_backup from 198.51.100.99 port 44001 ssh2
Oct 24 14:00:40 web01 sshd[8002]: Failed password for svc_backup from 198.51.100.99 port 44002 ssh2
Oct 24 14:01:00 web01 sshd[8003]: Failed password for svc_backup from 198.51.100.99 port 44003 ssh2
Oct 24 14:01:20 web01 sshd[8004]: Failed password for svc_backup from 198.51.100.99 port 44004 ssh2
Oct 24 14:01:40 web01 sshd[8005]: Failed password for svc_backup from 198.51.100.99 port 44005 ssh2
Oct 24 14:03:20 web01 sshd[8100]: Accepted password for svc_backup from 198.51.100.99 port 44100 ssh2`,
  },
];

export default function IngestModal({ onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState("preset"); // 'preset' | 'custom'
  const [customText, setCustomText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleIngestPreset = async (preset) => {
    setLoading(true);
    setError(null);
    setResult(null);

    // Make filename unique with timestamp so duplicate guard doesn't block repeat testing
    const uniqueFilename = `${Date.now()}_${preset.filename}`;
    try {
      const res = await ingestLog(preset.sample, uniqueFilename);
      setResult(res);
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message || "Ingestion request failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleIngestCustom = async () => {
    if (!selectedFile && !customText.trim()) {
      setError("Please select a .log file or paste raw syslog lines.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let res;
      if (selectedFile) {
        res = await ingestLog(selectedFile, selectedFile.name);
      } else {
        const customFilename = `manual_entry_${Date.now()}.log`;
        res = await ingestLog(customText, customFilename);
      }
      setResult(res);
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message || "Failed to ingest custom log data.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="relative flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
              <FaCloudUploadAlt size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  Live Attack Injection
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Log Ingestion & Attack Simulator
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

        {/* Tab navigation */}
        <div className="flex border-b border-slate-700 bg-slate-900/40 px-6 pt-3">
          <button
            onClick={() => setActiveTab("preset")}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 mr-6 ${
              activeTab === "preset"
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            1-Click Preset Attack Scenarios
          </button>
          <button
            onClick={() => setActiveTab("custom")}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "custom"
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Custom File / Text Upload
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          
          {/* Result Alert */}
          {result && (
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4 animate-fadeIn">
              <div className="flex items-start gap-3">
                <FaCheckCircle className="text-emerald-400 mt-0.5 flex-shrink-0" size={18} />
                <div className="text-xs">
                  <h4 className="font-bold text-white text-sm">
                    {result.duplicate ? "Duplicate File Guard Activated" : "Log Ingested & Analyzed Successfully!"}
                  </h4>
                  {result.duplicate ? (
                    <p className="mt-1 text-slate-300">
                      SHA-256 deduplication guard detected this exact file in the <code className="text-accent font-mono">log_files</code> table. No redundant entries inserted.
                    </p>
                  ) : (
                    <div className="mt-2 grid grid-cols-2 gap-2 font-mono sm:grid-cols-4">
                      <div className="rounded bg-slate-900/60 p-2">
                        <span className="text-slate-400 text-[10px] block">Events Stored</span>
                        <span className="text-emerald-400 font-bold">{result.data?.events_stored ?? result.events_stored ?? 0}</span>
                      </div>
                      <div className="rounded bg-slate-900/60 p-2">
                        <span className="text-slate-400 text-[10px] block">New Alerts</span>
                        <span className="text-warning font-bold">{result.data?.new_alerts ?? result.new_alerts ?? 0}</span>
                      </div>
                      <div className="rounded bg-slate-900/60 p-2">
                        <span className="text-slate-400 text-[10px] block">Malformed Lines</span>
                        <span className="text-slate-300 font-bold">{result.data?.malformed_lines ?? result.malformed_lines ?? 0}</span>
                      </div>
                      <div className="rounded bg-slate-900/60 p-2">
                        <span className="text-slate-400 text-[10px] block">File ID</span>
                        <span className="text-accent font-bold">#{result.data?.log_file_id ?? result.log_file_id ?? "?"}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="rounded-xl border border-danger/40 bg-danger/10 p-4 text-xs text-danger flex items-center gap-3">
              <FaExclamationTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          {activeTab === "preset" ? (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Click any scenario below to trigger a live attack injection. The payload will be sent to <code className="font-mono text-accent">POST /api/ingest</code>, parsed, evaluated by the detection engine, and inserted into SQLite.
              </p>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {PRESET_ATTACKS.map((p) => (
                  <div
                    key={p.name}
                    className="flex flex-col justify-between rounded-xl border border-slate-700/70 bg-slate-900/40 p-4 transition hover:border-accent/60 hover:bg-slate-800/40"
                  >
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[10px] font-bold text-accent uppercase bg-accent/10 px-2 py-0.5 rounded">
                          {p.rule}
                        </span>
                        <span className="text-[11px] text-slate-500 font-mono">{p.filename}</span>
                      </div>
                      <h4 className="mt-2 text-sm font-semibold text-white">{p.name}</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">{p.description}</p>
                    </div>

                    <button
                      disabled={loading}
                      onClick={() => handleIngestPreset(p)}
                      className="mt-4 inline-flex items-center justify-center gap-2 rounded-lg bg-accent/20 px-3 py-2 text-xs font-semibold text-accent border border-accent/30 transition hover:bg-accent hover:text-primary disabled:opacity-50"
                    >
                      <FaBolt size={12} />
                      {loading ? "Simulating..." : "Inject Attack Scenario"}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* File upload picker */}
              <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/30 p-6 text-center">
                <input
                  type="file"
                  id="logFileInput"
                  accept=".log,.txt"
                  className="hidden"
                  onChange={(e) => setSelectedFile(e.target.files[0] || null)}
                />
                <label
                  htmlFor="logFileInput"
                  className="cursor-pointer flex flex-col items-center justify-center"
                >
                  <FaFileAlt className="text-slate-400 mb-2" size={28} />
                  <span className="text-sm font-semibold text-slate-200">
                    {selectedFile ? selectedFile.name : "Click to select a .log file from disk"}
                  </span>
                  <span className="text-xs text-slate-500 mt-1">
                    {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB` : "Supports OpenSSH syslog format (e.g. auth.log)"}
                  </span>
                </label>
              </div>

              {/* Raw text paste */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Or Paste Raw Syslog Lines:
                </label>
                <textarea
                  rows={5}
                  value={customText}
                  onChange={(e) => setCustomText(e.target.value)}
                  placeholder="Oct 25 12:00:01 server sshd[1234]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2..."
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-accent focus:outline-none"
                />
              </div>

              <button
                disabled={loading || (!selectedFile && !customText.trim())}
                onClick={handleIngestCustom}
                className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-bold text-primary transition hover:bg-sky-300 disabled:opacity-50"
              >
                <FaCloudUploadAlt size={16} />
                {loading ? "Uploading & Processing..." : "Upload & Ingest to SQLite"}
              </button>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Backend Endpoint: <span className="font-mono text-slate-300">POST /api/ingest</span>
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
