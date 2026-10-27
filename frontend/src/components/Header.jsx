import React, { useState, useEffect } from "react";
import {
  FaShieldAlt,
  FaSyncAlt,
  FaDatabase,
  FaBolt,
  FaVial,
  FaGlobe,
} from "react-icons/fa";
import { FiActivity, FiServer, FiLock, FiCpu } from "react-icons/fi";

export default function Header({
  lastUpdated,
  refreshing,
  onRefresh,
  offline,
  onOpenIngest,
  onOpenDbHealth,
  onOpenTesterCenter,
  onOpenDefenseCenter,
  onSwitchToVictim,
  defenseActive = true,
  blockedCount = 0,
}) {
  const [countdown, setCountdown] = useState(15);

  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown((c) => (c <= 1 ? 15 : c - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleManualRefresh = () => {
    setCountdown(15);
    if (onRefresh) onRefresh();
  };

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl shadow-2xl">
      {/* Top Ambient Operations Bar */}
      <div className="bg-slate-900/60 border-b border-slate-800/50 px-4 py-1 text-[11px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 font-mono text-emerald-400 font-bold">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
            SOC COCKPIT V2.4 • REAL-TIME ACTIVE DEFENSE
          </span>
          <span className="hidden md:inline text-slate-600">|</span>
          <span className="hidden md:inline text-slate-400">
            Engine: ThreatLens High-Throughput Correlation Matrix
          </span>
        </div>

        <div className="flex items-center gap-3 font-mono text-[10px]">
          <span className="text-slate-400">Telemetry Stream:</span>
          <span className="text-cyan-400 font-bold">ACTIVE (PORT 5000)</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-400">Next Poll:</span>
          <span className="text-amber-400 font-bold">{countdown}s</span>
        </div>
      </div>

      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        {/* Brand & Platform Identity */}
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/40 font-black">
            <FaShieldAlt size={22} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-black tracking-tight text-white flex items-center gap-1.5">
                ThreatLens
                <span className="text-cyan-400 font-mono text-xs font-normal">SIEM</span>
              </h1>
              <span className="rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider">
                Enterprise Cockpit
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Cross-Platform Threat Detection & Automated Response
            </p>
          </div>
        </div>

        {/* Action Controls & Operational Tools */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs font-semibold">
          
          {/* Target Public Website Button */}
          <button
            onClick={onSwitchToVictim}
            title="Open Apex Federal Trust Bank customer portal"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-3.5 py-2 text-white shadow-lg shadow-cyan-600/25 transition active:scale-95 border border-cyan-400/30"
          >
            <FaGlobe size={13} className="text-cyan-200" />
            <span>Apex Bank Portal</span>
          </button>

          {/* Active Defense & Quarantine Center */}
          <button
            onClick={onOpenDefenseCenter}
            title="Open Active Defense Center (Quarantines, Remediation & Auto-Defense Toggles)"
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-600/90 hover:bg-emerald-500 px-3.5 py-2 text-white shadow-lg shadow-emerald-600/20 transition active:scale-95 border border-emerald-400/40"
          >
            <FaShieldAlt size={13} className="text-emerald-200" />
            <span>Auto-Defense</span>
            {blockedCount > 0 && (
              <span className="rounded-full bg-rose-500 px-1.5 py-0.2 text-[10px] font-black text-white ml-0.5">
                {blockedCount}
              </span>
            )}
          </button>

          {/* Verification Suite Modal Trigger */}
          <button
            onClick={onOpenTesterCenter}
            title="Open Security Verification Suite & Fuzzer Explorer"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 px-3.5 py-2 text-white shadow-lg shadow-purple-600/25 transition hover:from-purple-500 hover:to-indigo-500 active:scale-95"
          >
            <FaVial size={13} className="text-purple-200" />
            <span className="hidden sm:inline">Verification Suite</span>
            <span className="sm:hidden">Suite</span>
          </button>

          {/* Ingest Logs Modal Trigger */}
          <button
            onClick={onOpenIngest}
            className="inline-flex items-center gap-2 rounded-xl bg-accent px-3.5 py-2 text-primary font-bold transition hover:bg-sky-300 shadow-lg shadow-accent/20 active:scale-95"
          >
            <FaBolt size={12} />
            <span>Ingest Logs</span>
          </button>

          {/* Database Health Badge */}
          <button
            onClick={onOpenDbHealth}
            title="Inspect SQLite Integrity & Firebase Cloud (cybergroup6)"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/90 px-3 py-2 text-slate-200 transition hover:border-accent hover:text-white"
          >
            <FaDatabase size={12} className="text-emerald-400" />
            <span className="hidden sm:inline">DB:</span>
            <span className="font-mono text-emerald-400 font-bold">WAL Active</span>
          </button>

          {/* Refresh Action with Spin Animation */}
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            aria-label="Refresh telemetry stream"
            title="Poll latest SIEM telemetry"
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-700 bg-slate-900 text-slate-300 transition hover:border-accent hover:text-accent focus:outline-none disabled:opacity-50 active:scale-95"
          >
            <FaSyncAlt className={refreshing ? "animate-spin text-accent" : ""} size={13} />
          </button>
        </div>
      </div>
    </header>
  );
}
