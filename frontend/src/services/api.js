import axios from "axios";
import { localEngine } from "./localEngine.js";
import {
  checkFirebaseConnection,
  getFirebaseEvents,
  getFirebaseAlerts,
  updateFirebaseAlertStatus,
  getFirebaseStatistics,
  syncLocalToFirebase,
} from "./firebaseBackend.js";
import { firebaseConfig } from "./firebase.js";

const BASE_URL = "http://127.0.0.1:5000";

// Client with a fast timeout (2500ms) so web users don't hang if Flask is offline
const client = axios.create({
  baseURL: BASE_URL,
  timeout: 2500,
  headers: { Accept: "application/json" },
});

// Backend Mode: 'auto' | 'local' | 'flask' | 'firebase'
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
  try {
    const [stats, eventsRes, alertsRes] = await Promise.all([
      client.get("/api/statistics").then((r) => r.data).catch(() => localEngine.getStatistics()),
      client.get("/api/events?limit=50").then((r) => r.data.data?.events || r.data.events || []).catch(() => localEngine.getEvents({ limit: 50 }).events),
      client.get("/api/alerts?limit=50").then((r) => r.data.data?.alerts || r.data.alerts || []).catch(() => localEngine.getAlerts({ limit: 50 }).alerts),
    ]);
    return await syncLocalToFirebase(eventsRes, alertsRes, stats);
  } catch (err) {
    return { status: "error", error: err.message };
  }
};

export const getStatistics = async () => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseStatistics();
    } catch {
      // Fall through
    }
  }

  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/statistics");
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getStatistics();
};

export const getEvents = async (params = {}) => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseEvents(params);
    } catch {
      // Fall through
    }
  }

  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/events", { params });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getEvents(params);
};

export const getEventDetails = async (id) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get(`/api/events/${id}`);
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getEventDetails(id);
};

export const getAlerts = async (params = {}) => {
  if (activeBackendMode === "firebase") {
    try {
      return await getFirebaseAlerts(params);
    } catch {
      // Fall through
    }
  }

  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/alerts", { params });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getAlerts(params);
};

export const getAlertDetails = async (id) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get(`/api/alerts/${id}`);
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getAlertDetails(id);
};

export const updateAlertStatus = async (id, status) => {
  if (activeBackendMode === "firebase") {
    try {
      return await updateFirebaseAlertStatus(id, status);
    } catch {
      // Fall through
    }
  }

  if (activeBackendMode !== "local") {
    try {
      const res = await client.patch(`/api/alerts/${id}/status`, { status });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.updateAlertStatus(id, status);
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
        configured: true,
      },
    };
  } catch {
    return localEngine.getSystemHealth();
  }
};

export const ingestLog = async (logData, filename = "upload.log") => {
  if (activeBackendMode !== "local") {
    try {
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
    } catch {
      // Offline fallback
    }
  }

  return localEngine.ingestLog(logData, filename);
};

export const getIncidents = async () => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/incidents");
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getIncidents();
};

export const createIncident = async (payload) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/incidents", payload);
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.createIncident(payload);
};

export const updateIncidentStatus = async (id, status) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.patch(`/api/incidents/${id}/status`, { status });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.updateIncidentStatus(id, status);
};

export const addIncidentNote = async (id, note, author = "Adnan (Lead Analyst)") => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post(`/api/incidents/${id}/notes`, { note, author });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.addIncidentNote(id, note, author);
};

export const getIncidentNotes = async (id) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get(`/api/incidents/${id}/notes`);
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getIncidentNotes(id);
};

// Module B Interactive Verification Endpoints
export const runSystemTests = async () => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/system/tests/run");
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.runSystemTests();
};

export const runSqliFuzz = async (payload, target = "source_ip") => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/system/sqli-fuzz", { payload, target });
      if (res.data) return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.runSqliFuzz(payload, target);
};

export const callRawEndpoint = async (method, path, body = null) => {
  const start = performance.now();
  try {
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
  } catch {
    const duration = Math.round(performance.now() - start);
    return {
      status: 200,
      durationMs: duration,
      data: { message: "Simulated endpoint response via in-browser SIEM engine", path, method },
    };
  }
};

// --------------------------------------------------------------------------
// Active Defense & Prevention Endpoints
// --------------------------------------------------------------------------

export const getDefenseStatus = async () => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/defense/status");
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getDefenseStatus().data;
};

export const toggleAutoDefense = async (enabled) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/defense/toggle", { enabled });
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.toggleAutoDefense(enabled).data;
};

export const blockIp = async (ip, reason = "Manual Administrator Quarantine", severity = "high") => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/defense/block", { ip, reason, severity });
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.blockIp(ip, reason, severity).data;
};

export const unblockIp = async (ip) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/defense/unblock", { ip });
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.unblockIp(ip).data;
};

export const getDefenseRecommendations = async () => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/defense/recommendations");
      return res.data?.data?.recommendations || [];
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getDefenseRecommendations();
};

export const simulateAttack = async (attackType, ip = null) => {
  if (activeBackendMode !== "local") {
    try {
      const payload = { attack_type: attackType };
      if (ip) payload.ip = ip;
      const res = await client.post("/api/defense/simulate-attack", payload);
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.simulateAttack(attackType, ip);
};

// --------------------------------------------------------------------------
// Target Victim Website (Enterprise Portal) API
// --------------------------------------------------------------------------

export const getVictimStatus = async (ip = "") => {
  if (activeBackendMode !== "local") {
    try {
      const headers = ip ? { "X-Simulated-IP": ip } : {};
      const res = await client.get(`/api/victim/status${ip ? `?ip=${encodeURIComponent(ip)}` : ""}`, { headers });
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getVictimStatus(ip || "198.51.100.42");
};

export const submitVictimLogin = async ({ username, password, client_ip, simulate_count = 1 }) => {
  if (activeBackendMode !== "local") {
    try {
      const headers = client_ip ? { "X-Simulated-IP": client_ip } : {};
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
      // If network failure / connection refused, fallback to local engine
    }
  }

  return localEngine.submitVictimLogin({ username, password, client_ip, simulate_count });
};

export const submitVictimSearch = async ({ query, client_ip }) => {
  if (activeBackendMode !== "local") {
    try {
      const headers = client_ip ? { "X-Simulated-IP": client_ip } : {};
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
      // If network failure / connection refused, fallback to local engine
    }
  }

  return localEngine.submitVictimSearch({ query, client_ip });
};

export const resetVictimIp = async (ip_address) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.post("/api/victim/reset-ip", { ip_address });
      return res.data?.data || res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.resetVictimIp(ip_address);
};

// Endpoint Agent Telemetry
export const getEndpointEvents = async (params = {}) => {
  if (activeBackendMode !== "local") {
    try {
      const res = await client.get("/api/v1/events", { params });
      return res.data;
    } catch {
      // Offline fallback
    }
  }

  return localEngine.getEndpointEvents(params);
};
