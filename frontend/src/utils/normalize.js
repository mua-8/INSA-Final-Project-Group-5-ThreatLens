// The dashboard tolerates several response shapes from the Flask API and
// derives anything missing (charts, totals) from the raw events and alerts.

const pick = (obj, keys, fallback = undefined) => {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  }
  return fallback;
};

export const unwrapList = (data, keys) => {
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object") {
    for (const k of [...keys, "data", "items", "results"]) {
      if (Array.isArray(data[k])) return data[k];
    }
  }
  return [];
};

const capitalize = (s) => {
  const str = String(s ?? "").trim();
  return str ? str[0].toUpperCase() + str.slice(1).toLowerCase() : "";
};

export const normalizeAlert = (a = {}) => ({
  id: a.id,
  ruleId: a.rule_id || a.ruleId || "",
  timestamp: pick(a, ["first_seen", "timestamp", "time", "created_at", "detected_at", "datetime"], ""),
  type: pick(a, ["rule_name", "alert_type", "type", "rule", "name", "message"], "Security Alert"),
  severity: capitalize(pick(a, ["severity", "level", "priority"], "low")),
  sourceIp: pick(a, ["source_ip", "src_ip", "ip", "ip_address", "attacker_ip"], "-"),
  status: capitalize(pick(a, ["status", "state"], "new")),
  summary: a.summary || "",
  explanation: a.explanation || "",
  firstSeen: a.first_seen || "",
  lastSeen: a.last_seen || "",
});

export const normalizeEvent = (e = {}) => ({
  id: e.id,
  timestamp: pick(e, ["timestamp", "time", "created_at", "datetime"], ""),
  username: pick(e, ["username", "user", "account"], "-"),
  eventType: pick(e, ["event_type", "type", "event", "action"], "Unknown"),
  sourceIp: pick(e, ["source_ip", "src_ip", "ip", "ip_address"], "-"),
  status: pick(e, ["outcome", "status", "result"], "-"),
  rawLine: e.raw_line || "",
  method: e.method || "",
  port: e.port || "",
  host: e.host || "web01",
});


export const toTime = (ts) => {
  const t = new Date(ts).getTime();
  return Number.isNaN(t) ? null : t;
};

export const formatTimestamp = (ts) => {
  const t = toTime(ts);
  return t === null ? String(ts || "-") : new Date(t).toLocaleString();
};

export const sortRecent = (rows) =>
  [...rows].sort((a, b) => (toTime(b.timestamp) ?? 0) - (toTime(a.timestamp) ?? 0));

// Group rows into time buckets sized to the data's time range.
const bucketize = (rows) => {
  const times = rows.map((r) => toTime(r.timestamp)).filter((t) => t !== null);
  if (!times.length) return [];
  const min = Math.min(...times);
  const max = Math.max(...times);
  const range = max - min;
  const MIN = 60000, HOUR = 3600000, DAY = 86400000;
  const size = range <= 2 * HOUR ? 5 * MIN : range <= 2 * DAY ? HOUR : DAY;
  const counts = new Map();
  times.forEach((t) => {
    const k = Math.floor(t / size) * size;
    counts.set(k, (counts.get(k) || 0) + 1);
  });
  return [...counts.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([k, count]) => {
      const d = new Date(k);
      const label =
        size === DAY
          ? d.toLocaleDateString([], { month: "short", day: "numeric" })
          : size === HOUR && range > DAY
          ? d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
          : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      return { label, count };
    });
};

const toCountList = (value, labelKey) => {
  if (Array.isArray(value)) {
    return value.map((v) => ({
      [labelKey]: String(pick(v, [labelKey, "name", "label", "ip", "source_ip", "severity"], "?")),
      count: Number(pick(v, ["count", "value", "total", "attempts"], 0)),
    }));
  }
  if (value && typeof value === "object") {
    return Object.entries(value).map(([k, v]) => ({ [labelKey]: k, count: Number(v) || 0 }));
  }
  return null;
};

export const buildDashboardModel = (rawStats, rawEvents, rawAlerts) => {
  const stats = rawStats && typeof rawStats === "object" ? rawStats : {};
  const events = sortRecent(unwrapList(rawEvents, ["events"]).map(normalizeEvent));
  const alerts = sortRecent(unwrapList(rawAlerts, ["alerts"]).map(normalizeAlert));

  // Severity distribution
  let severity = toCountList(
    pick(stats, ["alerts_by_severity", "severity_distribution", "severity_counts", "by_severity"]),
    "name"
  );
  if (!severity) {
    const c = {};
    alerts.forEach((a) => { c[a.severity] = (c[a.severity] || 0) + 1; });
    severity = Object.entries(c).map(([name, count]) => ({ name, count }));
  }
  severity = severity.map((s) => ({ ...s, name: capitalize(s.name) })).filter((s) => s.count > 0);

  // Top attacking IPs
  let topIps = toCountList(
    pick(stats, ["top_ips", "top_attacking_ips", "top_source_ips", "top_attackers"]),
    "ip"
  );
  if (!topIps) {
    const c = {};
    [...events, ...alerts].forEach((r) => {
      if (r.sourceIp && r.sourceIp !== "-") c[r.sourceIp] = (c[r.sourceIp] || 0) + 1;
    });
    topIps = Object.entries(c).map(([ip, count]) => ({ ip, count }));
  }
  topIps = topIps.sort((a, b) => b.count - a.count).slice(0, 8);

  const uniqueIps = new Set(
    [...events, ...alerts].map((r) => r.sourceIp).filter((ip) => ip && ip !== "-")
  ).size;

  const highCount = alerts.filter((a) => ["High", "Critical"].includes(a.severity)).length;
  const sevHigh = severity
    .filter((s) => ["High", "Critical"].includes(s.name))
    .reduce((n, s) => n + s.count, 0);

  const summary = {
    totalEvents: Number(pick(stats, ["total_events", "events_total", "event_count"], events.length)),
    totalAlerts: Number(pick(stats, ["total_alerts", "alerts_total", "alert_count"], alerts.length)),
    highSeverity: Number(
      pick(stats, ["high_severity_alerts", "high_severity", "high_alerts"], sevHigh || highCount)
    ),
    uniqueIps: Number(
      pick(stats, ["unique_source_ips", "unique_ips", "unique_sources", "unique_ip_count"], uniqueIps)
    ),
  };

  return {
    summary,
    severity,
    topIps,
    eventsTimeline: bucketize(events),
    alertTrend: bucketize(alerts),
    alerts: alerts.slice(0, 10),
    events: events.slice(0, 10),
  };
};
