import React, { useState } from "react";
import { FaTimes, FaTerminal, FaCopy, FaCheck, FaServer, FaUserShield, FaFingerprint } from "react-icons/fa";
import { formatTimestamp } from "../utils/normalize.js";

export default function EventDetailModal({ event, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!event) return null;

  const handleCopy = () => {
    if (event.rawLine) {
      navigator.clipboard.writeText(event.rawLine);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const isFailure = event.status?.toLowerCase().includes("fail") || event.eventType?.toLowerCase().includes("fail");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="relative flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
              <FaTerminal size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-accent uppercase tracking-wider">
                  AUTH EVENT #{event.id || "?"}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="font-mono text-xs text-slate-400">{event.host || "server"}</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                {event.eventType || "SSH Authentication Record"}
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
          
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Target Username</div>
              <div className="mt-1 font-mono text-xs font-bold text-white">
                {event.username || "-"}
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Source IP</div>
              <div className="mt-1 font-mono text-xs font-bold text-accent">
                {event.sourceIp || "-"}
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Outcome</div>
              <div className="mt-1">
                <span
                  className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                    isFailure
                      ? "bg-danger/15 text-danger ring-1 ring-danger/40"
                      : "bg-success/15 text-success ring-1 ring-success/40"
                  }`}
                >
                  {event.status || "recorded"}
                </span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
              <div className="text-xs text-slate-400">Port / Protocol</div>
              <div className="mt-1 font-mono text-xs text-slate-300">
                {event.port ? `Port ${event.port}` : "SSH2"}
              </div>
            </div>
          </div>

          {/* Timestamp Details */}
          <div className="rounded-lg border border-slate-700/60 bg-slate-900/30 px-4 py-3 text-xs text-slate-300">
            <span className="text-slate-400">Normalized ISO-8601 Timestamp:</span>{" "}
            <span className="font-mono font-medium text-white">{formatTimestamp(event.timestamp)}</span>{" "}
            <span className="text-slate-500 font-mono">({event.timestamp})</span>
          </div>

          {/* Raw Syslog Line with Copy */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Original Authentication Log Message
              </span>
              <button
                onClick={handleCopy}
                className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 text-xs text-slate-300 transition hover:bg-slate-700 hover:text-white"
              >
                {copied ? <FaCheck className="text-success" size={12} /> : <FaCopy size={12} />}
                {copied ? "Copied!" : "Copy Raw Line"}
              </button>
            </div>
            <pre className="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 p-4 font-mono text-xs text-emerald-400 leading-relaxed">
              {event.rawLine || "Raw log line unavailable in memory."}
            </pre>
          </div>

          {/* Security & Audit metadata */}
          <div className="flex items-center gap-2 rounded-lg border border-slate-700/60 bg-slate-900/40 p-3 text-xs text-slate-400">
            <FaFingerprint className="text-accent flex-shrink-0" size={16} />
            <div>
              <span className="text-white font-medium">Log Integrity:</span> This record is cryptographically indexed and preserved in its raw ingested format for forensic verification.
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Authentication Telemetry Record #{event.id || "?"}
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
