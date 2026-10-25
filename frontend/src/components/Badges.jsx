const SEVERITY = {
  critical: "bg-danger/15 text-danger ring-danger/40",
  high: "bg-orange-500/15 text-orange-400 ring-orange-500/40",
  medium: "bg-yellow-400/15 text-yellow-300 ring-yellow-400/40",
  low: "bg-success/15 text-success ring-success/40",
};

export function SeverityBadge({ severity }) {
  const cls = SEVERITY[String(severity).toLowerCase()] || "bg-slate-500/15 text-slate-300 ring-slate-500/40";
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${cls}`}>
      {severity || "Unknown"}
    </span>
  );
}

export function StatusBadge({ status }) {
  const s = String(status).toLowerCase();
  let cls = "bg-accent/15 text-accent ring-accent/40";
  if (/(success|accept|resolved|closed|ok)/.test(s)) cls = "bg-success/15 text-success ring-success/40";
  else if (/(fail|invalid|denied|reject|blocked|error)/.test(s)) cls = "bg-danger/15 text-danger ring-danger/40";
  else if (/(open|new|pending|investigat)/.test(s)) cls = "bg-warning/15 text-warning ring-warning/40";
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${cls}`}>
      {status || "-"}
    </span>
  );
}
