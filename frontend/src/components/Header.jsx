import React from "react";
import { FaShieldAlt, FaSyncAlt, FaDatabase, FaBolt, FaVial, FaGlobe } from "react-icons/fa";

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
  return (
    <header className="sticky top-0 z-20 border-b border-slate-700/60 bg-primary/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        
        {/* Logo and System title */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-accent/15 text-accent ring-1 ring-accent/40 shadow-lg shadow-accent/10">
            <FaShieldAlt size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold leading-tight text-white">
                ThreatLens
              </h1>
              <span className="rounded bg-accent/20 px-1.5 py-0.5 text-[10px] font-bold text-accent uppercase tracking-wider">
                Admin SOC Portal
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Active Defense Operations Center • Real-Time Attack Interception
            </p>
          </div>
        </div>

        {/* Action Controls & Telemetry */}
        <div className="flex flex-wrap items-center gap-2.5 text-sm">
          
          {/* Target Victim Website Switcher Button */}
          <button
            onClick={onSwitchToVictim}
            title="Open Target Public Website (Apex Financial Portal) to launch real attacks and verify automated prevention"
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 text-xs font-bold text-white shadow-lg shadow-cyan-600/25 transition active:scale-95 border border-cyan-400/30"
          >
            <FaGlobe size={12} className="text-cyan-200" />
            <span>Target Web Portal</span>
          </button>

          {/* Active Defense & Prevention Center Button */}
          <button
            onClick={onOpenDefenseCenter}
            title="Open Active Defense & Auto-Prevention Center (Quarantine, Attack Sim & Admin Guidance)"
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-600/90 hover:bg-emerald-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-lg shadow-emerald-600/20 transition active:scale-95 border border-emerald-400/40"
          >
            <FaShieldAlt size={12} className="text-emerald-200" />
            <span>Auto-Defense</span>
            {blockedCount > 0 && (
              <span className="rounded-full bg-red-500 px-1.5 py-0.2 text-[10px] font-black text-white ml-0.5">
                {blockedCount}
              </span>
            )}
          </button>

          {/* Module B Verification & Tester Center Button */}
          <button
            onClick={onOpenTesterCenter}
            title="Open Interactive Test Suite, SQLi Fuzzer, and API Explorer"
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 px-3 py-1.5 text-xs font-bold text-white shadow-lg shadow-purple-600/25 transition hover:from-purple-500 hover:to-indigo-500 active:scale-95"
          >
            <FaVial size={12} className="text-purple-200" />
            <span className="hidden sm:inline">Tester Center</span>
            <span className="sm:hidden">Tests</span>
          </button>

          {/* Ingest / Simulate Attack Button */}
          <button
            onClick={onOpenIngest}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 shadow-md shadow-accent/20 active:scale-95"
          >
            <FaBolt size={12} />
            <span>Ingest Logs</span>
          </button>


          {/* Database & Cloud Health Badge / Modal Trigger */}
          <button
            onClick={onOpenDbHealth}
            title="Inspect SQLite Integrity & Firebase Cloud (cybergroup6)"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-1.5 text-xs text-slate-200 transition hover:border-accent hover:text-white"
          >
            <FaDatabase size={12} className="text-emerald-400" />
            <span className="hidden sm:inline">DB:</span>
            <span className="font-mono text-emerald-400 font-semibold">WAL Active</span>
            <span className="h-3 w-px bg-slate-600 mx-0.5" />
            <span className="font-mono text-amber-400 font-semibold flex items-center gap-1">
              <span>Firebase</span>
            </span>
          </button>

          {/* Connection status indicator */}
          <div className="flex items-center gap-2 text-slate-300">
            <span className="relative flex h-2.5 w-2.5">
              {!offline && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-60" />}
              <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${offline ? "bg-danger" : "bg-success"}`} />
            </span>
            <span className="hidden md:inline text-xs">{offline ? "Disconnected" : "API Live"}</span>
          </div>

          {/* Last updated timestamp */}
          <div className="hidden sm:block text-right">
            <p className="text-[10px] text-slate-400">Last poll</p>
            <p className="font-mono text-xs text-slate-200">
              {lastUpdated ? lastUpdated.toLocaleTimeString() : "--:--:--"}
            </p>
          </div>

          {/* Refresh button */}
          <button
            onClick={onRefresh}
            disabled={refreshing}
            aria-label="Refresh data"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-600 text-slate-300 transition hover:border-accent hover:text-accent focus:outline-none disabled:opacity-50"
          >
            <FaSyncAlt className={refreshing ? "animate-spin" : ""} size={12} />
          </button>

        </div>
      </div>
    </header>
  );
}
