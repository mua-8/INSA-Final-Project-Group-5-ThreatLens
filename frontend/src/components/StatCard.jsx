const TONES = {
  accent: "text-accent bg-accent/10 ring-accent/30",
  warning: "text-warning bg-warning/10 ring-warning/30",
  danger: "text-danger bg-danger/10 ring-danger/30",
  success: "text-success bg-success/10 ring-success/30",
};

export function StatCardSkeleton() {
  return (
    <div className="animate-pulse rounded-xl border border-slate-700/60 bg-card p-5">
      <div className="mb-4 h-10 w-10 rounded-lg bg-slate-700" />
      <div className="mb-2 h-7 w-24 rounded bg-slate-700" />
      <div className="h-3 w-32 rounded bg-slate-700/70" />
    </div>
  );
}

export default function StatCard({ label, value, icon: Icon, tone = "accent" }) {
  return (
    <div className="rounded-xl border border-slate-700/60 bg-card p-5 shadow-lg shadow-black/20">
      <div className={`mb-4 flex h-10 w-10 items-center justify-center rounded-lg ring-1 ${TONES[tone]}`}>
        <Icon size={18} />
      </div>
      <p className="font-mono text-3xl font-semibold text-white">{Number(value || 0).toLocaleString()}</p>
      <p className="mt-1 text-sm text-slate-400">{label}</p>
    </div>
  );
}
