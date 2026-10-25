import React from "react";
import { FaShieldAlt, FaSyncAlt, FaDatabase, FaBolt, FaVial } from "react-icons/fa";

export default function Header({
  lastUpdated,
  refreshing,
  onRefresh,
  offline,
  onOpenIngest,
  onOpenDbHealth,
  onOpenTesterCenter,
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
                SOC Core
              </span>
            </div>
            <p className="text-xs text-slate-400">
              SSH Attack Monitoring • Module B Backend (SQLite WAL)
            </p>
          </div>
        </div>

        {/* Action Controls & Telemetry */}
        <div className="flex flex-wrap items-center gap-3 text-sm">
          
          {/* Module B Verification & Tester Center Button */}
          <button
            onClick={onOpenTesterCenter}
            title="Open Interactive Test Suite, SQLi Fuzzer, and API Explorer"
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-lg shadow-purple-600/25 transition hover:from-purple-500 hover:to-indigo-500 active:scale-95"
          >
            <FaVial size={12} className="text-purple-200" />
            <span>Tester Center (81 Tests & SQLi)</span>
          </button>

          {/* Ingest / Simulate Attack Button */}
          <button
            onClick={onOpenIngest}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 shadow-md shadow-accent/20 active:scale-95"
          >
            <FaBolt size={12} />
            <span>Ingest / Attack Sim</span>
          </button>

          {/* Database Health Badge / Modal Trigger */}
          <button
            onClick={onOpenDbHealth}
            title="Inspect Module B SQLite Database Integrity & WAL Mode"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800/80 px-3 py-1.5 text-xs text-slate-200 transition hover:border-accent hover:text-white"
          >
            <FaDatabase size={12} className="text-emerald-400" />
            <span className="hidden sm:inline">DB:</span>
            <span className="font-mono text-emerald-400 font-semibold">WAL Active</span>
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
