import { FaShieldAlt, FaSyncAlt } from "react-icons/fa";

export default function Header({ lastUpdated, refreshing, onRefresh, offline }) {
  return (
    <header className="sticky top-0 z-20 border-b border-slate-700/60 bg-primary/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
            <FaShieldAlt size={20} />
          </div>
          <div>
            <h1 className="text-lg font-semibold leading-tight text-white">
              ThreatLens <span className="font-normal text-slate-400">SSH Attack Monitoring</span>
            </h1>
            <p className="text-xs text-slate-400">Security Operations Dashboard</p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2 text-slate-300">
            <span className="relative flex h-2.5 w-2.5">
              {!offline && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-60" />}
              <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${offline ? "bg-danger" : "bg-success"}`} />
            </span>
            <span className="hidden sm:inline">{offline ? "Disconnected" : "Live"}</span>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-400">Last updated</p>
            <p className="font-mono text-xs text-slate-200">
              {lastUpdated ? lastUpdated.toLocaleTimeString() : "--:--:--"}
            </p>
          </div>
          <button
            onClick={onRefresh}
            disabled={refreshing}
            aria-label="Refresh data"
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-600 text-slate-300 transition hover:border-accent hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
          >
            <FaSyncAlt className={refreshing ? "animate-spin" : ""} size={14} />
          </button>
        </div>
      </div>
    </header>
  );
}
