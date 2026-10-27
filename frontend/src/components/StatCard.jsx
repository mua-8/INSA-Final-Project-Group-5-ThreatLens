import React from "react";

const TONES = {
  accent: {
    icon: "text-cyan-400 bg-cyan-500/10 ring-cyan-500/30 shadow-cyan-500/10",
    border: "border-slate-800 hover:border-cyan-500/50",
    gradient: "from-cyan-500/5 to-transparent",
    badge: "text-cyan-400 bg-cyan-950/60 border-cyan-800/60",
    trend: "+12% vs 1h baseline",
  },
  warning: {
    icon: "text-amber-400 bg-amber-500/10 ring-amber-500/30 shadow-amber-500/10",
    border: "border-slate-800 hover:border-amber-500/50",
    gradient: "from-amber-500/5 to-transparent",
    badge: "text-amber-400 bg-amber-950/60 border-amber-800/60",
    trend: "Live Triage Required",
  },
  danger: {
    icon: "text-rose-400 bg-rose-500/10 ring-rose-500/30 shadow-rose-500/10",
    border: "border-slate-800 hover:border-rose-500/50",
    gradient: "from-rose-500/5 to-transparent",
    badge: "text-rose-400 bg-rose-950/60 border-rose-800/60",
    trend: "Critical Severity Priority",
  },
  success: {
    icon: "text-emerald-400 bg-emerald-500/10 ring-emerald-500/30 shadow-emerald-500/10",
    border: "border-slate-800 hover:border-emerald-500/50",
    gradient: "from-emerald-500/5 to-transparent",
    badge: "text-emerald-400 bg-emerald-950/60 border-emerald-800/60",
    trend: "Geo-Dispersed Traffic",
  },
};

export function StatCardSkeleton() {
  return (
    <div className="animate-pulse rounded-2xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
      <div className="mb-4 h-11 w-11 rounded-xl bg-slate-800" />
      <div className="mb-2 h-8 w-28 rounded bg-slate-800" />
      <div className="h-4 w-36 rounded bg-slate-800/60" />
    </div>
  );
}

export default function StatCard({ label, value, icon: Icon, tone = "accent" }) {
  const t = TONES[tone] || TONES.accent;

  return (
    <div
      className={`group relative overflow-hidden rounded-2xl border ${t.border} bg-slate-900/80 p-5 shadow-xl backdrop-blur-md transition-all duration-300 hover:-translate-y-0.5 hover:shadow-2xl`}
    >
      {/* Background Top Corner Gradient */}
      <div
        className={`pointer-events-none absolute right-0 top-0 h-32 w-32 bg-gradient-to-bl ${t.gradient} blur-2xl transition-opacity duration-300 group-hover:opacity-100`}
      />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-3">
          <div
            className={`flex h-11 w-11 items-center justify-center rounded-xl ring-1 shadow-lg ${t.icon}`}
          >
            <Icon size={20} />
          </div>

          <span
            className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${t.badge}`}
          >
            {t.trend}
          </span>
        </div>

        <p className="font-mono text-3xl font-black tracking-tight text-white">
          {Number(value || 0).toLocaleString()}
        </p>
        <p className="mt-1 text-xs font-semibold text-slate-400 tracking-wide uppercase">
          {label}
        </p>
      </div>
    </div>
  );
}
