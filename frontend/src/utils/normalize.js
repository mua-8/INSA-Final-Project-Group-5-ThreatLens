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
  targetHost: pick(a, ["target_host", "targetHost", "host"], "server"),
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

export const formatUtcTimestamp = (ts) => {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  const pad = (n) => String(n).padStart(2, "0");
  const year = d.getUTCFullYear();
  const month = pad(d.getUTCMonth() + 1);
  const day = pad(d.getUTCDate());
  const hours = pad(d.getUTCHours());
  const minutes = pad(d.getUTCMinutes());
  const seconds = pad(d.getUTCSeconds());
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
};

export const formatTimestamp = (ts) => formatUtcTimestamp(ts);

export const sortRecent = (rows) =>
  [...rows].sort((a, b) => (toTime(b.timestamp) ?? 0) - (toTime(a.timestamp) ?? 0));

// Group rows into zero-filled continuous time buckets sized to the data's range.
const bucketize = (rows) => {
  const times = rows.map((r) => toTime(r.timestamp)).filter((t) => t !== null);
  if (!times.length) return [];
  const min = Math.min(...times);
  const max = Math.max(...times);
  const range = Math.max(max - min, 3600000); // at least 1h
  const MIN = 60000, HOUR = 3600000, DAY = 86400000;
  const size = range <= 2 * HOUR ? 5 * MIN : range <= 2 * DAY ? 2 * HOUR : DAY;

  const start = Math.floor(min / size) * size;
  const end = Math.floor(max / size) * size;

  const counts = new Map();
  // Fill all buckets with 0 so inactive periods clearly show zero activity
  for (let t = start; t <= end; t += size) {
    counts.set(t, 0);
  }
  times.forEach((t) => {
    const k = Math.floor(t / size) * size;
    counts.set(k, (counts.get(k) || 0) + 1);
  });

  const pad = (n) => String(n).padStart(2, "0");
  return [...counts.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([k, count]) => {
      const d = new Date(k);
      const label =
        size >= DAY
          ? `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} UTC`
          : `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
      return { label, count, timestamp: d.toISOString() };
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

  const criticalOnly = alerts.filter((a) => a.severity === "Critical").length;
  const highOnly = alerts.filter((a) => a.severity === "High").length;
  const openCount = alerts.filter((a) => !["Resolved", "Closed", "False Positive", "False_positive"].includes(a.status)).length;
  const resolvedCount = alerts.filter((a) => ["Resolved", "Closed", "False Positive", "False_positive"].includes(a.status)).length;

  const summary = {
    totalEvents: Number(pick(stats, ["total_events", "events_total", "event_count"], events.length)),
    totalAlerts: Number(pick(stats, ["total_alerts", "alerts_total", "alert_count"], alerts.length)),
    openAlerts: Number(pick(stats, ["open_alerts"], openCount)),
    resolvedAlerts: Number(pick(stats, ["resolved_alerts"], resolvedCount)),
    criticalAlerts: Number(pick(stats, ["critical_alerts"], criticalOnly)),
    highAlerts: Number(pick(stats, ["high_alerts"], highOnly)),
    highSeverity: Number(
      pick(stats, ["high_and_critical_alerts", "high_severity_alerts", "high_severity", "high_alerts"], sevHigh || highCount)
    ),
    uniqueIps: Number(
      pick(stats, ["unique_source_ips", "unique_ips", "unique_sources", "unique_ip_count"], uniqueIps)
    ),
  };

  // Prioritize server-side zero-filled timeseries across the whole dataset
  let eventsTimeline = [];
  if (Array.isArray(stats.events_timeline) && stats.events_timeline.length > 0) {
    eventsTimeline = stats.events_timeline.map((b) => ({
      label: b.label,
      count: b.count,
      timestamp: b.iso,
    }));
  } else {
    eventsTimeline = bucketize(events);
  }

  let alertTrend = [];
  if (Array.isArray(stats.alert_trend) && stats.alert_trend.length > 0) {
    alertTrend = stats.alert_trend.map((b) => ({
      label: b.label,
      count: b.count,
      timestamp: b.iso,
    }));
  } else if (Array.isArray(stats.alerts_timeline) && stats.alerts_timeline.length > 0) {
    alertTrend = stats.alerts_timeline.map((b) => ({
      label: b.label,
      count: b.count,
      timestamp: b.iso,
    }));
  } else {
    alertTrend = bucketize(alerts);
  }

  return {
    summary,
    severity,
    topIps,
    eventsTimeline,
    alertTrend,
    alerts,
    events,
  };
};
