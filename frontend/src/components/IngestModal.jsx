import React, { useState } from "react";
import {
  FaTimes,
  FaCloudUploadAlt,
  FaBolt,
  FaCheckCircle,
  FaExclamationTriangle,
  FaFileAlt,
  FaTrash,
  FaChevronDown,
  FaChevronUp,
  FaSpinner,
  FaServer,
} from "react-icons/fa";
import { ingestLog } from "../services/api.js";

const PRESET_ATTACKS = [
  {
    name: "Brute Force SSH (10 attempts)",
    rule: "DR-01",
    filename: "scenario_brute_force_10.log",
    targetHost: "server",
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
    filename: "scenario_root_login.log",
    targetHost: "web01",
    description: "High severity policy violation: Direct root login attempted from remote IP 203.0.113.77.",
    sample: `Oct 24 14:00:00 web01 sshd[9000]: Failed password for root from 203.0.113.77 port 45000 ssh2
Oct 24 14:00:30 web01 sshd[9001]: Failed password for root from 203.0.113.77 port 45001 ssh2
Oct 24 14:01:10 web01 sshd[9002]: Accepted password for root from 203.0.113.77 port 45002 ssh2`,
  },
  {
    name: "Password Spraying Campaign",
    rule: "DR-03",
    filename: "scenario_password_spraying.log",
    targetHost: "web01",
    description: "Attacker attempts 1 common password across multiple distinct corporate accounts.",
    sample: `Oct 24 14:00:00 web01 sshd[7000]: Failed password for alice from 198.51.100.42 port 43000 ssh2
Oct 24 14:00:15 web01 sshd[7001]: Failed password for bob from 198.51.100.42 port 43001 ssh2
Oct 24 14:00:30 web01 sshd[7002]: Failed password for charlie from 198.51.100.42 port 43002 ssh2
Oct 24 14:00:45 web01 sshd[7003]: Failed password for dave from 198.51.100.42 port 43003 ssh2
Oct 24 14:01:00 web01 sshd[7004]: Failed password for eve from 198.51.100.42 port 43004 ssh2`,
  },
  {
    name: "Compromise (Success After Failures)",
    rule: "DR-04",
    filename: "scenario_success_after_failures.log",
    targetHost: "web01",
    description: "6 failed login attempts followed immediately by a successful authentication.",
    sample: `Oct 24 14:00:00 web01 sshd[8000]: Failed password for svc_backup from 198.51.100.99 port 44000 ssh2
Oct 24 14:00:20 web01 sshd[8001]: Failed password for svc_backup from 198.51.100.99 port 44001 ssh2
Oct 24 14:00:40 web01 sshd[8002]: Failed password for svc_backup from 198.51.100.99 port 44002 ssh2
Oct 24 14:01:00 web01 sshd[8003]: Failed password for svc_backup from 198.51.100.99 port 44003 ssh2
Oct 24 14:01:20 web01 sshd[8004]: Failed password for svc_backup from 198.51.100.99 port 44004 ssh2
Oct 24 14:01:40 web01 sshd[8005]: Failed password for svc_backup from 198.51.100.99 port 44005 ssh2
Oct 24 14:03:20 web01 sshd[8100]: Accepted password for svc_backup from 198.51.100.99 port 44100 ssh2`,
  },
];

const MONTH_NAMES = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/**
 * Format preset scenario log samples with current UTC timestamps so that:
 * 1. Detections fire inside the live real-time sliding window.
 * 2. Generated alerts appear immediately on the active dashboard.
 * 3. Each simulation run receives a unique SHA-256 hash to prevent duplicate collisions.
 */
function formatPresetPayload(sampleText) {
  const lines = sampleText.trim().split("\n");
  if (lines.length === 0) return sampleText;

  const timeRegex = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(.*)$/;
  const parsedDeltas = [];
  let baseSeconds = null;

  for (const line of lines) {
    const match = line.match(timeRegex);
    if (match) {
      const h = parseInt(match[3], 10);
      const m = parseInt(match[4], 10);
      const s = parseInt(match[5], 10);
      const totalSec = h * 3600 + m * 60 + s;
      if (baseSeconds === null) baseSeconds = totalSec;
      parsedDeltas.push({ delta: totalSec - baseSeconds, rest: match[6] });
    } else {
      parsedDeltas.push({ delta: 0, rest: " " + line });
    }
  }

  const maxDelta = parsedDeltas.length > 0 ? parsedDeltas[parsedDeltas.length - 1].delta : 0;
  const now = new Date();
  const startTime = new Date(now.getTime() - (maxDelta + 5) * 1000);

  const newLines = parsedDeltas.map((item) => {
    const eventTime = new Date(startTime.getTime() + item.delta * 1000);
    const month = MONTH_NAMES[eventTime.getUTCMonth()];
    const day = String(eventTime.getUTCDate()).padStart(2, " ");
    const hh = String(eventTime.getUTCHours()).padStart(2, "0");
    const mm = String(eventTime.getUTCMinutes()).padStart(2, "0");
    const ss = String(eventTime.getUTCSeconds()).padStart(2, "0");
    const tsStr = `${month} ${day} ${hh}:${mm}:${ss}`;
    return `${tsStr}${item.rest}`;
  });

  return newLines.join("\n");
}

export default function IngestModal({ onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState("preset"); // 'preset' | 'custom'
  const [customText, setCustomText] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [submittingPreset, setSubmittingPreset] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showErrorDetails, setShowErrorDetails] = useState(false);
  const [refreshedNotice, setRefreshedNotice] = useState(false);

  const handleIngestPreset = async (preset) => {
    if (loading) return; // Prevent duplicate concurrent clicks
    setLoading(true);
    setSubmittingPreset(preset.name);
    setError(null);
    setResult(null);
    setRefreshedNotice(false);

    try {
      // Dynamic timestamps guarantee live correlation in the current detection window
      const livePayload = formatPresetPayload(preset.sample);
      const uniqueFilename = `sim_${Date.now()}_${preset.filename}`;

      const res = await ingestLog(livePayload, uniqueFilename, { simulate: true });
      const payload = res.data || res;
      setResult(payload);

      if (onRefresh) {
        await onRefresh();
        setRefreshedNotice(true);
      }
    } catch (err) {
      let msg = err.response?.data?.error || err.message || "Preset simulation request failed.";
      if (err.message === "Network Error" && !err.response) {
        msg = "Network Error: Unable to reach the ThreatLens API at http://127.0.0.1:5000. Ensure the backend server is running.";
      }
      setError(msg);
      if (err.response?.data?.malformed_details) {
        setResult(err.response.data);
      }
    } finally {
      setLoading(false);
      setSubmittingPreset(null);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files?.[0] || null;
    setError(null);
    if (!file) {
      setSelectedFile(null);
      return;
    }

    // Validate file extension
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (ext !== ".log" && ext !== ".txt") {
      setError(`Unsupported file format "${ext}". Please select a plain-text .log or .txt file.`);
      setSelectedFile(null);
      e.target.value = "";
      return;
    }

    // Validate non-empty file
    if (file.size === 0) {
      setError("The selected file is empty (0 bytes). Please select a valid log file.");
      setSelectedFile(null);
      e.target.value = "";
      return;
    }

    setSelectedFile(file);
  };

  const handleClearFile = () => {
    setSelectedFile(null);
    setError(null);
    const fileInput = document.getElementById("logFileInput");
    if (fileInput) fileInput.value = "";
  };

  const handleUploadFile = async () => {
    if (!selectedFile) {
      setError("Please select a valid .log or .txt file first.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setRefreshedNotice(false);

    try {
      const res = await ingestLog(selectedFile, selectedFile.name);
      const payload = res.data || res;
      setResult(payload);

      if (onRefresh) {
        await onRefresh();
        setRefreshedNotice(true);
      }
    } catch (err) {
      let msg = err.response?.data?.error || err.message || "Failed to ingest log file.";
      if (err.message === "Network Error" && !err.response) {
        msg = "Network Error: Unable to reach the ThreatLens API at http://127.0.0.1:5000. Ensure the backend server is running.";
      }
      setError(msg);
      if (err.response?.data?.malformed_details) {
        setResult(err.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleIngestRawText = async () => {
    if (!customText.trim()) {
      setError("Please paste raw OpenSSH syslog lines into the textarea.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setRefreshedNotice(false);

    try {
      const customFilename = `manual_entry_${Date.now()}.log`;
      const res = await ingestLog(customText.trim(), customFilename);
      const payload = res.data || res;
      setResult(payload);

      if (onRefresh) {
        await onRefresh();
        setRefreshedNotice(true);
      }
    } catch (err) {
      let msg = err.response?.data?.error || err.message || "Failed to ingest raw syslog lines.";
      if (err.message === "Network Error" && !err.response) {
        msg = "Network Error: Unable to reach the ThreatLens API at http://127.0.0.1:5000. Ensure the backend server is running.";
      }
      setError(msg);
      if (err.response?.data?.malformed_details) {
        setResult(err.response.data);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-fadeIn">
      <div className="relative flex max-h-[92vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent/15 text-accent ring-1 ring-accent/40">
              <FaCloudUploadAlt size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  Telemetry Ingestion & Simulation
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Log Ingestion & Attack Scenarios
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
            onClick={() => { setActiveTab("preset"); setError(null); }}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 mr-6 ${
              activeTab === "preset"
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Preset Test Scenarios
          </button>
          <button
            onClick={() => { setActiveTab("custom"); setError(null); }}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "custom"
                ? "border-accent text-accent"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Custom Log & Syslog Input
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
          
          {/* Result Alert with Rich Metrics */}
          {result && (
            <div
              className={`rounded-xl border p-4 animate-fadeIn ${
                result.duplicate
                  ? "border-amber-500/40 bg-amber-500/10"
                  : (result.accepted_records ?? result.events_stored ?? 0) > 0
                  ? "border-emerald-500/40 bg-emerald-500/10"
                  : "border-rose-500/40 bg-rose-500/10"
              }`}
            >
              <div className="flex items-start gap-3">
                {result.duplicate ? (
                  <FaExclamationTriangle className="text-amber-400 mt-0.5 flex-shrink-0" size={18} />
                ) : (result.accepted_records ?? result.events_stored ?? 0) > 0 ? (
                  <FaCheckCircle className="text-emerald-400 mt-0.5 flex-shrink-0" size={18} />
                ) : (
                  <FaExclamationTriangle className="text-rose-400 mt-0.5 flex-shrink-0" size={18} />
                )}

                <div className="text-xs flex-1">
                  <div className="flex items-center justify-between">
                    <h4 className="font-bold text-white text-sm">
                      {result.duplicate
                        ? "Deduplication Guard Activated"
                        : (result.accepted_records ?? result.events_stored ?? 0) > 0
                        ? "Log Ingested & Evaluated Successfully"
                        : "No Valid Telemetry Events Extracted"}
                    </h4>
                    {refreshedNotice && (
                      <span className="font-mono text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">
                        Dashboard Updated
                      </span>
                    )}
                  </div>

                  <p className="mt-1 text-slate-300 leading-relaxed">
                    {result.message ||
                      (result.duplicate
                        ? "This exact content has already been ingested. No redundant records were inserted."
                        : `Ingested ${result.accepted_records ?? result.events_stored ?? 0} events.`)}
                  </p>

                  {/* 4-Card Transparent Metric Grid */}
                  <div className="mt-3 grid grid-cols-2 gap-2 font-mono sm:grid-cols-4">
                    <div className="rounded bg-slate-900/70 p-2.5 border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Submitted Lines</span>
                      <span className="text-slate-200 text-sm font-bold">
                        {result.submitted_lines ?? result.total_lines ?? 0}
                      </span>
                    </div>
                    <div className="rounded bg-slate-900/70 p-2.5 border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Accepted Records</span>
                      <span className="text-emerald-400 text-sm font-bold">
                        {result.accepted_records ?? result.events_stored ?? 0}
                      </span>
                    </div>
                    <div className="rounded bg-slate-900/70 p-2.5 border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Malformed / Rejected</span>
                      <span
                        className={`text-sm font-bold ${
                          (result.rejected_records ?? result.malformed_lines ?? 0) > 0
                            ? "text-rose-400"
                            : "text-slate-400"
                        }`}
                      >
                        {result.rejected_records ?? result.malformed_lines ?? 0}
                      </span>
                    </div>
                    <div className="rounded bg-slate-900/70 p-2.5 border border-slate-800">
                      <span className="text-slate-400 text-[10px] block uppercase">Generated Alerts</span>
                      <span className="text-warning text-sm font-bold">
                        {result.new_alerts ?? 0}
                      </span>
                    </div>
                  </div>

                  {/* Generated Alert Details */}
                  {result.alert_ids && result.alert_ids.length > 0 && (
                    <div className="mt-2.5 flex items-center gap-2 text-[11px] text-warning bg-warning/10 p-2 rounded border border-warning/20">
                      <FaBolt size={12} />
                      <span>
                        Triggered Correlation Alert ID(s):{" "}
                        <strong className="font-mono text-white">
                          {result.alert_ids.map((id) => `#${id}`).join(", ")}
                        </strong>
                      </span>
                    </div>
                  )}

                  {/* Malformed Lines Collapsible Details */}
                  {result.malformed_details && result.malformed_details.length > 0 && (
                    <div className="mt-3">
                      <button
                        onClick={() => setShowErrorDetails(!showErrorDetails)}
                        className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-rose-400 hover:text-rose-300 transition"
                      >
                        {showErrorDetails ? <FaChevronUp size={10} /> : <FaChevronDown size={10} />}
                        <span>
                          {showErrorDetails ? "Hide" : "View"} Malformed Diagnostics (
                          {result.malformed_details.length} samples)
                        </span>
                      </button>

                      {showErrorDetails && (
                        <div className="mt-2 max-h-40 overflow-y-auto rounded bg-slate-950 p-2 font-mono text-[11px] text-slate-300 space-y-1.5 border border-slate-800">
                          {result.malformed_details.map((m, idx) => (
                            <div key={idx} className="border-b border-slate-800/80 pb-1">
                              <span className="text-rose-400 font-bold">Line {m.line ?? idx + 1}:</span>{" "}
                              <span className="text-slate-400">{m.error}</span>
                              <div className="text-[10px] text-slate-500 truncate" title={m.raw}>
                                {m.raw}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                </div>
              </div>
            </div>
          )}

          {/* Standalone Error Notice */}
          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-xs text-rose-300 flex items-start gap-3">
              <FaExclamationTriangle size={16} className="text-rose-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1">
                <span className="font-bold block text-white">Ingestion Request Error</span>
                <span className="mt-0.5 block leading-relaxed">{error}</span>
              </div>
            </div>
          )}

          {/* Tab 1: Preset Attack Scenarios */}
          {activeTab === "preset" ? (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 leading-relaxed">
                Execute simulated authentication log scenarios through the live SIEM ingestion pipeline.
                Timestamps are dynamically synchronized to the current active window to trigger real-time detection rules.
              </p>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {PRESET_ATTACKS.map((p) => {
                  const isThisRunning = submittingPreset === p.name;
                  return (
                    <div
                      key={p.name}
                      className="flex flex-col justify-between rounded-xl border border-slate-700/70 bg-slate-900/40 p-4 transition hover:border-accent/60 hover:bg-slate-800/40"
                    >
                      <div>
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] font-bold text-accent uppercase bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                            {p.rule}
                          </span>
                          <span className="inline-flex items-center gap-1 text-[11px] text-slate-400 font-mono">
                            <FaServer size={10} className="text-slate-500" />
                            <span>{p.targetHost}</span>
                          </span>
                        </div>
                        <h4 className="mt-2 text-sm font-semibold text-white">{p.name}</h4>
                        <p className="mt-1 text-xs text-slate-400 leading-relaxed">{p.description}</p>
                      </div>

                      <button
                        disabled={loading}
                        onClick={() => handleIngestPreset(p)}
                        className={`mt-4 inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold border transition ${
                          isThisRunning
                            ? "bg-accent text-primary border-accent"
                            : "bg-accent/20 text-accent border-accent/30 hover:bg-accent hover:text-primary"
                        } disabled:opacity-50 disabled:cursor-not-allowed`}
                      >
                        {isThisRunning ? (
                          <>
                            <FaSpinner className="animate-spin" size={12} />
                            <span>Simulating Scenario...</span>
                          </>
                        ) : (
                          <>
                            <FaBolt size={12} />
                            <span>Run Test Scenario</span>
                          </>
                        )}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            /* Tab 2: Custom Log Upload & Syslog Input */
            <div className="space-y-5">

              {/* Option A: File Upload */}
              <div className="rounded-xl border border-slate-700/80 bg-slate-900/40 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Method 1: Upload Log File (.log, .txt)
                  </span>
                  {selectedFile && (
                    <button
                      onClick={handleClearFile}
                      className="inline-flex items-center gap-1 text-[11px] text-rose-400 hover:text-rose-300 transition"
                    >
                      <FaTrash size={10} />
                      <span>Remove File</span>
                    </button>
                  )}
                </div>

                <div className="rounded-xl border border-dashed border-slate-700 bg-slate-950/60 p-5 text-center transition hover:border-slate-500">
                  <input
                    type="file"
                    id="logFileInput"
                    accept=".log,.txt"
                    className="hidden"
                    onChange={handleFileSelect}
                  />
                  <label
                    htmlFor="logFileInput"
                    className="cursor-pointer flex flex-col items-center justify-center"
                  >
                    <FaFileAlt className="text-slate-400 mb-2" size={26} />
                    <span className="text-sm font-semibold text-slate-200">
                      {selectedFile ? selectedFile.name : "Click to select a .log or .txt file from disk"}
                    </span>
                    <span className="text-xs text-slate-500 mt-1">
                      {selectedFile
                        ? `${(selectedFile.size / 1024).toFixed(1)} KB • Ready for upload`
                        : "Supports OpenSSH BSD (RFC 3164) and ISO-8601 (RFC 5424) auth logs"}
                    </span>
                  </label>
                </div>

                <button
                  disabled={loading || !selectedFile}
                  onClick={handleUploadFile}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-bold text-primary transition hover:bg-sky-300 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading && selectedFile ? (
                    <>
                      <FaSpinner className="animate-spin" size={14} />
                      <span>Uploading & Processing File...</span>
                    </>
                  ) : (
                    <>
                      <FaCloudUploadAlt size={16} />
                      <span>Upload & Ingest Selected File</span>
                    </>
                  )}
                </button>
              </div>

              {/* Option B: Direct Raw Syslog Lines */}
              <div className="rounded-xl border border-slate-700/80 bg-slate-900/40 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Method 2: Paste Raw Syslog Lines
                  </span>
                  {customText.trim() && (
                    <button
                      onClick={() => setCustomText("")}
                      className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition"
                    >
                      <span>Clear Text</span>
                    </button>
                  )}
                </div>

                <textarea
                  rows={4}
                  value={customText}
                  onChange={(e) => setCustomText(e.target.value)}
                  placeholder="Oct 27 12:00:01 web01 sshd[1234]: Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2&#10;Oct 27 12:00:05 web01 sshd[1235]: Accepted password for root from 203.0.113.77 port 45000 ssh2"
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-accent focus:outline-none"
                />

                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>
                    {customText.trim() ? `${customText.trim().split("\n").length} line(s) entered` : "0 lines"}
                  </span>
                  <span>OpenSSH format required</span>
                </div>

                <button
                  disabled={loading || !customText.trim()}
                  onClick={handleIngestRawText}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-slate-800 border border-slate-600 px-4 py-2 text-xs font-bold text-white transition hover:bg-slate-700 hover:border-accent disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading && !selectedFile && customText.trim() ? (
                    <>
                      <FaSpinner className="animate-spin" size={14} />
                      <span>Parsing Raw Syslog Lines...</span>
                    </>
                  ) : (
                    <>
                      <FaBolt size={14} className="text-accent" />
                      <span>Ingest Pasted Syslog Lines</span>
                    </>
                  )}
                </button>
              </div>

            </div>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            ThreatLens Telemetry Pipeline Active
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
