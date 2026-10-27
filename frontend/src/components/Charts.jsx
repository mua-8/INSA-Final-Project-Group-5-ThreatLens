import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend,
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid,
} from "recharts";

const SEVERITY_COLORS = { Critical: "#ef4444", High: "#f97316", Medium: "#facc15", Low: "#22c55e" };
const FALLBACK = ["#38bdf8", "#a78bfa", "#f59e0b", "#94a3b8"];

const axis = { stroke: "#64748b", fontSize: 11, tickLine: false, axisLine: { stroke: "#334155" } };
const tooltipStyle = {
  contentStyle: { background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "#cbd5e1" },
  itemStyle: { color: "#e2e8f0" },
};

export function ChartSkeleton() {
  return (
    <div className="animate-pulse rounded-xl border border-slate-700/60 bg-card p-5">
      <div className="mb-4 h-4 w-40 rounded bg-slate-700" />
      <div className="h-52 rounded bg-slate-700/50" />
    </div>
  );
}

function ChartCard({ title, empty, children }) {
  return (
    <section className="rounded-xl border border-slate-700/60 bg-card p-4 shadow-lg shadow-black/20">
      <h2 className="mb-3 font-semibold text-white text-sm">{title}</h2>
      <div className="h-52">
        {empty ? (
          <div className="flex h-full items-center justify-center text-sm text-slate-500">No data available yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">{children}</ResponsiveContainer>
        )}
      </div>
    </section>
  );
}

export default function Charts({ severity, eventsTimeline, alertTrend, topIps }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ChartCard title="Alerts by Severity" empty={!severity.length}>
        <PieChart>
          <Pie data={severity} dataKey="count" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3} stroke="none">
            {severity.map((s, i) => (
              <Cell key={s.name} fill={SEVERITY_COLORS[s.name] || FALLBACK[i % FALLBACK.length]} />
            ))}
          </Pie>
          <Tooltip {...tooltipStyle} />
          <Legend wrapperStyle={{ fontSize: 12, color: "#cbd5e1" }} />
        </PieChart>
      </ChartCard>

      <ChartCard title="Events Timeline (UTC)" empty={!eventsTimeline.length}>
        <LineChart data={eventsTimeline} margin={{ left: -15, right: 8, top: 8 }}>
          <CartesianGrid stroke="#334155" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="label" {...axis} />
          <YAxis allowDecimals={false} {...axis} />
          <Tooltip {...tooltipStyle} />
          <Line type="linear" dataKey="count" name="Events" stroke="#38bdf8" strokeWidth={2.5} dot={{ r: 3, fill: "#38bdf8" }} activeDot={{ r: 5 }} />
        </LineChart>
      </ChartCard>

      <ChartCard title="Alert Trend (UTC)" empty={!alertTrend.length}>
        <AreaChart data={alertTrend} margin={{ left: -15, right: 8, top: 8 }}>
          <defs>
            <linearGradient id="alertFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#334155" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="label" {...axis} />
          <YAxis allowDecimals={false} {...axis} />
          <Tooltip {...tooltipStyle} />
          <Area type="linear" dataKey="count" name="Alerts" stroke="#f59e0b" strokeWidth={2.5} fill="url(#alertFill)" />
        </AreaChart>
      </ChartCard>

      <ChartCard title="Top Attacking IPs" empty={!topIps.length}>
        <BarChart data={topIps} layout="vertical" margin={{ left: 20, right: 12, top: 8 }}>
          <CartesianGrid stroke="#334155" strokeDasharray="3 3" horizontal={false} />
          <XAxis type="number" allowDecimals={false} {...axis} />
          <YAxis type="category" dataKey="ip" width={110} {...axis} />
          <Tooltip {...tooltipStyle} cursor={{ fill: "rgba(148,163,184,0.1)" }} />
          <Bar dataKey="count" name="Hits" fill="#ef4444" radius={[0, 4, 4, 0]} barSize={16} />
        </BarChart>
      </ChartCard>
    </div>
  );
}
