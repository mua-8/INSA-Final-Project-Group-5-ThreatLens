import axios from "axios";
import {
  checkFirebaseConnection,
  getFirebaseEvents,
  getFirebaseAlerts,
  updateFirebaseAlertStatus,
  getFirebaseStatistics,
  syncLocalToFirebase
} from "./firebaseBackend.js";
import { firebaseConfig } from "./firebase.js";

const BASE_URL = "http://127.0.0.1:5000";

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { Accept: "application/json" },
});

// Backend Mode: 'auto' | 'firebase' | 'flask'
let activeBackendMode = localStorage.getItem("threatlens_backend_mode") || "auto";

export const getBackendMode = () => activeBackendMode;
export const setBackendMode = (mode) => {
  activeBackendMode = mode;
  localStorage.setItem("threatlens_backend_mode", mode);
};

export const getFirebaseDiagnostics = async () => {
  return await checkFirebaseConnection();
};

export const syncDataToFirebase = async () => {
  const [stats, eventsRes, alertsRes] = await Promise.all([
    client.get("/api/statistics").then(r => r.data).catch(() => null),
    client.get("/api/events?limit=50").then(r => r.data.data?.events || r.data.events || []).catch(() => []),
    client.get("/api/alerts?limit=50").then(r => r.data.data?.alerts || r.data.alerts || []).catch(() => [])
  ]);
  return await syncLocalToFirebase(eventsRes, alertsRes, stats);
};

export const getStatistics = async () => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseStatistics();
    } catch (err) {
      console.warn("Firebase stats error, falling back to Flask:", err);
    }
  }
  try {
    return (await client.get("/api/statistics")).data;
  } catch (err) {
    if (activeBackendMode === "auto") {
      try {
        return await getFirebaseStatistics();
      } catch (fbErr) {
        throw err;
      }
    }
    throw err;
  }
};

export const getEvents = async (params = {}) => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseEvents(params);
    } catch (err) {
      console.warn("Firebase events error, falling back to Flask:", err);
    }
  }
  try {
    const res = await client.get("/api/events", { params });
    return res.data;
  } catch (err) {
    if (activeBackendMode === "auto") {
      try {
        return await getFirebaseEvents(params);
      } catch (fbErr) {
        throw err;
      }
    }
    throw err;
  }
};

export const getEventDetails = async (id) => {
  const res = await client.get(`/api/events/${id}`);
  return res.data;
};

export const getAlerts = async (params = {}) => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseAlerts(params);
    } catch (err) {
      console.warn("Firebase alerts error, falling back to Flask:", err);
    }
  }
  try {
    const res = await client.get("/api/alerts", { params });
    return res.data;
  } catch (err) {
    if (activeBackendMode === "auto") {
      try {
        return await getFirebaseAlerts(params);
      } catch (fbErr) {
        throw err;
      }
    }
    throw err;
  }
};

export const getAlertDetails = async (id) => {
  const res = await client.get(`/api/alerts/${id}`);
  return res.data;
};

export const updateAlertStatus = async (id, status) => {
  if (activeBackendMode === "firebase") {
    try {
      return await updateFirebaseAlertStatus(id, status);
    } catch (err) {
      console.warn("Firebase update alert error:", err);
    }
  }
  const res = await client.patch(`/api/alerts/${id}/status`, { status });
  return res.data;
};

export const getSystemHealth = async () => {
  try {
    const res = await client.get("/api/health");
    return {
      ...res.data,
      firebase: {
        projectId: firebaseConfig.projectId,
        authDomain: firebaseConfig.authDomain,
        storageBucket: firebaseConfig.storageBucket,
        configured: true
      }
    };
  } catch (err) {
    const fbCheck = await checkFirebaseConnection();
    return {
      status: fbCheck.connected ? "healthy" : "degraded",
      service: "ThreatLens SOC Firebase Backend",
      firebase: fbCheck
    };
  }
};

export const ingestLog = async (logData, filename = "upload.log") => {
  if (logData instanceof File) {
    const formData = new FormData();
    formData.append("file", logData);
    const res = await client.post("/api/ingest", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return res.data;
  }
  const res = await client.post("/api/ingest", logData, {
    headers: {
      "Content-Type": "text/plain",
      "X-Filename": filename,
    },
  });
  return res.data;
};

export const getIncidents = async () => {
  const res = await client.get("/api/incidents");
  return res.data;
};

export const createIncident = async (payload) => {
  const res = await client.post("/api/incidents", payload);
  return res.data;
};

export const updateIncidentStatus = async (id, status) => {
  const res = await client.patch(`/api/incidents/${id}/status`, { status });
  return res.data;
};

export const addIncidentNote = async (id, note, author = "Adnan (Lead Analyst)") => {
  const res = await client.post(`/api/incidents/${id}/notes`, { note, author });
  return res.data;
};

export const getIncidentNotes = async (id) => {
  const res = await client.get(`/api/incidents/${id}/notes`);
  return res.data;
};

// Module B Interactive Verification Endpoints
export const runSystemTests = async () => {
  const res = await client.post("/api/system/tests/run");
  return res.data;
};

export const runSqliFuzz = async (payload, target = "source_ip") => {
  const res = await client.post("/api/system/sqli-fuzz", { payload, target });
  return res.data;
};

export const callRawEndpoint = async (method, path, body = null) => {
  const start = performance.now();
  let res;
  if (method === "GET") {
    res = await client.get(path);
  } else if (method === "POST") {
    res = await client.post(path, body);
  } else if (method === "PATCH") {
    res = await client.patch(path, body);
  } else {
    res = await client.request({ method, url: path, data: body });
  }
  const duration = Math.round(performance.now() - start);
  return {
    status: res.status,
    durationMs: duration,
    data: res.data,
  };
};

// --------------------------------------------------------------------------
// Active Defense & Prevention Endpoints
// --------------------------------------------------------------------------

export const getDefenseStatus = async () => {
  const res = await client.get("/api/defense/status");
  return res.data?.data || res.data;
};

export const toggleAutoDefense = async (enabled) => {
  const res = await client.post("/api/defense/toggle", { enabled });
  return res.data?.data || res.data;
};

export const blockIp = async (ip, reason = "Manual Administrator Quarantine", severity = "high") => {
  const res = await client.post("/api/defense/block", { ip, reason, severity });
  return res.data?.data || res.data;
};

export const unblockIp = async (ip) => {
  const res = await client.post("/api/defense/unblock", { ip });
  return res.data?.data || res.data;
};

export const getDefenseRecommendations = async () => {
  const res = await client.get("/api/defense/recommendations");
  return res.data?.data?.recommendations || [];
};

export const simulateAttack = async (attackType, ip = null) => {
  const payload = { attack_type: attackType };
  if (ip) payload.ip = ip;
  const res = await client.post("/api/defense/simulate-attack", payload);
  return res.data?.data || res.data;
};

// --------------------------------------------------------------------------
// Target Victim Website (Enterprise Portal) API
// --------------------------------------------------------------------------

export const getVictimStatus = async (ip = "") => {
  const headers = ip ? { "X-Simulated-IP": ip } : {};
  const res = await client.get(`/api/victim/status${ip ? `?ip=${encodeURIComponent(ip)}` : ""}`, { headers });
  return res.data?.data || res.data;
};

export const submitVictimLogin = async ({ username, password, client_ip, simulate_count = 1 }) => {
  const headers = client_ip ? { "X-Simulated-IP": client_ip } : {};
  try {
    const res = await client.post(
      "/api/victim/login",
      { username, password, client_ip, simulate_count },
      { headers }
    );
    return res.data?.data || res.data;
  } catch (err) {
    if (err.response?.status === 403) {
      return {
        blocked: true,
        quarantined: true,
        ...err.response.data,
      };
    }
    if (err.response?.data) {
      return err.response.data;
    }
    throw err;
  }
};

export const submitVictimSearch = async ({ query, client_ip }) => {
  const headers = client_ip ? { "X-Simulated-IP": client_ip } : {};
  try {
    const res = await client.post(
      "/api/victim/search",
      { query, client_ip },
      { headers }
    );
    return res.data?.data || res.data;
  } catch (err) {
    if (err.response?.status === 403) {
      return {
        blocked: true,
        quarantined: true,
        ...err.response.data,
      };
    }
    if (err.response?.data) {
      return err.response.data;
    }
    throw err;
  }
};

export const resetVictimIp = async (ip_address) => {
  const res = await client.post("/api/victim/reset-ip", { ip_address });
  return res.data?.data || res.data;
};

