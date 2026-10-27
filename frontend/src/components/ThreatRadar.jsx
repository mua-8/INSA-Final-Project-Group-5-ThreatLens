import React, { useState } from "react";
import {
  FiShield,
  FiAlertTriangle,
  FiActivity,
  FiZap,
  FiGlobe,
  FiTerminal,
  FiRadio,
  FiCrosshair,
  FiCheckCircle,
} from "react-icons/fi";

export default function ThreatRadar({
  alerts = [],
  events = [],
  quarantinedCount = 0,
  onTriggerScan,
  scanning = false,
  onSelectIp,
}) {
  const [selectedTarget, setSelectedTarget] = useState(null);

  // Derive live stream entries directly from real recent events
  const liveLogs = events.slice(0, 5).map((e, idx) => ({
    id: e.id || idx,
    time: e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "Live",
    source: e.host || "siem-core",
    message: `${e.event_type || "auth.attempt"} from ${e.source_ip || "127.0.0.1"} (user: ${e.username || "anonymous"}) - ${e.outcome || "processed"}`,
    level: e.outcome === "failed" ? "danger" : "info",
  }));

  // Fallback if no events loaded yet
  const displayLogs = liveLogs.length > 0 ? liveLogs : [
    {
      id: "init-1",
      time: "Live",
      source: "WAF Core",
      message: "Continuous deep packet inspection active on monitored web gateways.",
      level: "info",
    },
    {
      id: "init-2",
      time: "Live",
      source: "Ingestion Engine",
      message: "SIEM event queue operational. Sliding window 5m evaluator armed.",
      level: "info",
    },
  ];

  // Derive radar target points directly from active real alerts
  const targets = alerts.slice(0, 8).map((a, i) => {
    const angle = ((i * 47 + 25) % 360) * (Math.PI / 180);
    const radius = 32 + (i * 11) % 48;
    const x = 50 + radius * Math.cos(angle);
    const y = 50 + radius * Math.sin(angle);
    return {
      id: a.id || i,
      ip: a.source_ip || "198.51.100.42",
      rule: a.rule_name || a.rule_id,
      severity: a.severity || "HIGH",
      x,
      y,
      alert: a,
    };
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 rounded-3xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl backdrop-blur-xl relative overflow-hidden">
      {/* Ambient background glow */}
      <div className="absolute left-1/4 top-1/2 -mt-32 -ml-32 h-64 w-64 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
      <div className="absolute right-10 bottom-0 h-48 w-48 rounded-full bg-rose-500/10 blur-3xl pointer-events-none" />

      {/* LEFT: Radar Scanner Canvas (5 cols) */}
      <div className="lg:col-span-5 flex flex-col items-center justify-between border-b lg:border-b-0 lg:border-r border-slate-800/80 pb-5 lg:pb-0 lg:pr-5">
        <div className="w-full flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="flex h-2.5 w-2.5 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
            </span>
            <h3 className="text-xs font-black uppercase tracking-wider text-white flex items-center gap-1.5">
              <FiCrosshair className="text-cyan-400" />
              Live Threat Intercept Radar
            </h3>
          </div>

          <span className="text-[10px] font-mono bg-slate-800/80 text-cyan-400 border border-slate-700 px-2 py-0.5 rounded-full font-bold">
            360° Real-Time Scan
          </span>
        </div>

        {/* Radar Graphic Container */}
        <div className="relative w-64 h-64 sm:w-72 sm:h-72 rounded-full border-2 border-cyan-500/30 bg-slate-950/90 shadow-inner flex items-center justify-center overflow-hidden my-2">
          {/* Concentric grid rings */}
          <div className="absolute w-3/4 h-3/4 rounded-full border border-cyan-500/20" />
          <div className="absolute w-1/2 h-1/2 rounded-full border border-cyan-500/20" />
          <div className="absolute w-1/4 h-1/4 rounded-full border border-cyan-500/20" />

          {/* Crosshairs */}
          <div className="absolute w-full h-[1px] bg-cyan-500/20" />
          <div className="absolute h-full w-[1px] bg-cyan-500/20" />

          {/* Rotating radar beam */}
          <div
            className="absolute inset-0 origin-center pointer-events-none"
            style={{
              background:
                "conic-gradient(from 0deg, transparent 0deg, rgba(6, 182, 212, 0.4) 60deg, transparent 65deg)",
              animation: "spin 4s linear infinite",
            }}
          />

          {/* Center Hub */}
          <div className="absolute h-3 w-3 rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/80 ring-4 ring-cyan-500/20" />

          {/* Threat Target Blips */}
          {targets.map((t) => {
            const isCritical =
              t.severity === "CRITICAL" || t.severity === "HIGH";
            return (
              <button
                key={t.id}
                onClick={() => {
                  setSelectedTarget(t);
                  if (onSelectIp) onSelectIp(t.ip);
                }}
                title={`Host: ${t.ip} (${t.rule})`}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 group cursor-pointer z-20 focus:outline-none"
                style={{ left: `${t.x}%`, top: `${t.y}%` }}
              >
                <span className="relative flex h-3.5 w-3.5">
                  <span
                    className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                      isCritical ? "bg-rose-400" : "bg-amber-400"
                    }`}
                  />
                  <span
                    className={`relative inline-flex rounded-full h-3.5 w-3.5 border-2 border-white shadow-md ${
                      isCritical ? "bg-rose-600" : "bg-amber-500"
                    }`}
                  />
                </span>

                {/* Hover Tooltip */}
                <div className="hidden group-hover:block absolute left-4 top-0 bg-slate-900 border border-slate-700 text-[10px] text-white p-2 rounded-lg shadow-2xl whitespace-nowrap z-30 font-mono">
                  <span className="font-bold text-cyan-300 block">{t.ip}</span>
                  <span className="text-slate-300 block">{t.rule}</span>
                  <span
                    className={`font-bold uppercase ${
                      isCritical ? "text-rose-400" : "text-amber-400"
                    }`}
                  >
                    {t.severity}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Radar Legend Footer */}
        <div className="w-full flex items-center justify-between text-[11px] font-mono text-slate-400 pt-2">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-rose-500" />
            <span>Active Threat Vectors ({alerts.length})</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span>SIEM Core (Protected)</span>
          </div>
        </div>
      </div>

      {/* RIGHT: Live Cyber Operations Center & Real-Time Feed (7 cols) */}
      <div className="lg:col-span-7 flex flex-col justify-between space-y-4">
        {/* Dynamic Status Ribbon */}
        <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-950/80 p-3.5 rounded-2xl border border-slate-800">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/15 text-amber-400 border border-amber-500/30">
              <FiRadio size={18} className="animate-pulse" />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                Threat Posture
              </span>
              <div className="flex items-center gap-2">
                <span className="text-sm font-black text-amber-300 font-mono">
                  DEFCON 3: ELEVATED MONITORING
                </span>
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-ping" />
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="text-right">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
                Active Quarantines
              </span>
              <span className="text-base font-black text-rose-400 font-mono">
                {quarantinedCount} Attacker IPs
              </span>
            </div>

            {/* Run Security Verification Scan */}
            <button
              onClick={onTriggerScan}
              disabled={scanning}
              className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold px-3.5 py-2 rounded-xl text-xs shadow-lg shadow-cyan-900/30 transition active:scale-95 disabled:opacity-60"
              title="Run a real-time security verification scan on the monitored assets"
            >
              <FiZap className={scanning ? "animate-spin" : ""} size={14} />
              <span>{scanning ? "Evaluating Assets..." : "Run Security Scan"}</span>
            </button>
          </div>
        </div>

        {/* Selected Target Inspection Box */}
        {selectedTarget ? (
          <div className="bg-slate-950/90 border border-cyan-500/40 p-3.5 rounded-2xl text-xs space-y-2 animate-in fade-in">
            <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
              <div className="flex items-center gap-2 font-mono">
                <span className="text-slate-400">Target Selected:</span>
                <span className="text-cyan-300 font-bold">{selectedTarget.ip}</span>
              </div>
              <button
                onClick={() => setSelectedTarget(null)}
                className="text-slate-400 hover:text-white text-xs"
              >
                Clear
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
              <div>
                <span className="text-slate-400">Triggered Detection:</span>
                <span className="text-white block font-sans font-semibold">
                  {selectedTarget.rule}
                </span>
              </div>
              <div>
                <span className="text-slate-400">Severity Assessment:</span>
                <span className="text-rose-400 font-bold block">
                  {selectedTarget.severity}
                </span>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-slate-950/50 border border-slate-800/80 p-3.5 rounded-2xl text-xs text-slate-400 flex items-center justify-between">
            <span className="italic">
              Click any blip on the radar scanner to inspect live target telemetry.
            </span>
            <span className="font-mono text-cyan-400 text-[11px]">
              Active Intercept Ready
            </span>
          </div>
        )}

        {/* Real-time Rolling Telemetry Activity Stream Log */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold uppercase tracking-wider text-slate-400 text-[10px] flex items-center gap-1.5">
              <FiTerminal className="text-cyan-400" />
              Live Telemetry Activity Stream
            </span>
            <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Stream Connected
            </span>
          </div>

          <div className="bg-slate-950 rounded-2xl border border-slate-800 p-3 font-mono text-[11px] space-y-1.5 max-h-36 overflow-y-auto">
            {displayLogs.map((log) => (
              <div
                key={log.id}
                className="flex items-start gap-2 text-slate-300 hover:text-white transition"
              >
                <span className="text-slate-500 text-[10px] shrink-0">
                  {log.time}
                </span>
                <span className="text-cyan-400 font-bold shrink-0">
                  [{log.source}]
                </span>
                <span className="text-slate-300 break-all">{log.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
