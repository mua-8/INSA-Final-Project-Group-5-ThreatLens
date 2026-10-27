import axios from "axios";

const BASE_URL = "http://127.0.0.1:5000";

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { Accept: "application/json" },
});

export const getStatistics = async () => (await client.get("/api/statistics")).data;

export const getEvents = async (params = {}) => {
  const res = await client.get("/api/events", { params });
  return res.data;
};

export const getEventDetails = async (id) => {
  const res = await client.get(`/api/events/${id}`);
  return res.data;
};

export const getAlerts = async (params = {}) => {
  const res = await client.get("/api/alerts", { params });
  return res.data;
};

export const getAlertDetails = async (id) => {
  const res = await client.get(`/api/alerts/${id}`);
  return res.data;
};

export const updateAlertStatus = async (id, status, actor = "SOC Analyst", reason = "") => {
  const res = await client.patch(`/api/alerts/${id}/status`, { status, actor, reason });
  return res.data;
};

export const updateAlertAssignee = async (id, assignee, actor = "SOC Analyst") => {
  const res = await client.patch(`/api/alerts/${id}/assign`, { assignee, actor });
  return res.data;
};

export const addAlertNote = async (id, note, author = "SOC Analyst") => {
  const res = await client.post(`/api/alerts/${id}/notes`, { note, author });
  return res.data;
};

export const getAlertNotes = async (id) => {
  const res = await client.get(`/api/alerts/${id}/notes`);
  return res.data;
};

export const getAlertHistory = async (id) => {
  const res = await client.get(`/api/alerts/${id}/history`);
  return res.data;
};

export const getSystemHealth = async () => {
  const res = await client.get("/api/health");
  return res.data;
};

export const ingestLog = async (logData, filename = "upload.log", options = {}) => {
  const params = {};
  if (options.simulate) params.simulate = "true";
  if (options.force) params.force = "true";

  if (logData instanceof File) {
    const formData = new FormData();
    formData.append("file", logData);

    const res = await client.post("/api/ingest", formData, {
      params,
    });
    return res.data;
  }

  const headers = {
    "Content-Type": "text/plain",
    "X-Filename": filename,
  };

  const res = await client.post("/api/ingest", logData, {
    params,
    headers,
  });
  return res.data;
};

export const getIncidents = async (params = {}) => {
  const res = await client.get("/api/incidents", { params });
  return res.data;
};

export const getIncidentDetails = async (id) => {
  const res = await client.get(`/api/incidents/${id}`);
  return res.data;
};

export const createIncident = async (payload) => {
  const res = await client.post("/api/incidents", payload);
  return res.data;
};

export const updateIncident = async (id, payload) => {
  const res = await client.patch(`/api/incidents/${id}`, payload);
  return res.data;
};

export const updateIncidentStatus = async (id, status, closeReason = "") => {
  const res = await client.patch(`/api/incidents/${id}/status`, { status, close_reason: closeReason });
  return res.data;
};

export const unlinkAlertFromIncident = async (incidentId, alertId) => {
  const res = await client.delete(`/api/incidents/${incidentId}/alerts/${alertId}`);
  return res.data;
};

export const addIncidentNote = async (id, note, author = "SOC Analyst") => {
  const res = await client.post(`/api/incidents/${id}/notes`, { note, author });
  return res.data;
};

export const getIncidentNotes = async (id) => {
  const res = await client.get(`/api/incidents/${id}/notes`);
  return res.data;
};

// Detection Rules CRUD & Management
export const getDetectionRules = async (params = {}) => {
  const res = await client.get("/api/rules", { params });
  return res.data;
};

export const getDetectionRule = async (ruleId) => {
  const res = await client.get(`/api/rules/${ruleId}`);
  return res.data;
};

export const createDetectionRule = async (payload) => {
  const res = await client.post("/api/rules", payload);
  return res.data;
};

export const updateDetectionRule = async (ruleId, payload) => {
  const res = await client.patch(`/api/rules/${ruleId}`, payload);
  return res.data;
};

export const toggleDetectionRule = async (ruleId, enabled, changedBy = "SOC Analyst") => {
  const res = await client.patch(`/api/rules/${ruleId}/toggle`, { enabled, changed_by: changedBy });
  return res.data;
};

export const getRuleAuditLogs = async (ruleId) => {
  const res = await client.get(`/api/rules/${ruleId}/audit`);
  return res.data;
};

// Endpoints Fleet Management
export const getEndpoints = async (params = {}) => {
  const res = await client.get("/api/endpoints", { params });
  return res.data;
};

export const getEndpointDetails = async (deviceId) => {
  const res = await client.get(`/api/endpoints/${deviceId}`);
  return res.data;
};

export const enrollEndpoint = async (payload) => {
  const res = await client.post("/api/endpoints", payload);
  return res.data;
};

export const updateEndpoint = async (deviceId, payload) => {
  const res = await client.patch(`/api/endpoints/${deviceId}`, payload);
  return res.data;
};

export const updateEndpointStatus = async (deviceId, status) => {
  const res = await client.patch(`/api/endpoints/${deviceId}/status`, { status });
  return res.data;
};

// Interactive Diagnostic & Security Verification Endpoints
export const getSystemRoutes = async () => {
  const res = await client.get("/api/system/routes");
  return res.data;
};

export const runSystemTests = async (target = "all") => {
  const res = await client.post("/api/system/tests/run", { target });
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
// Endpoint Agent Telemetry
export const getEndpointEvents = async (params = {}) => {
  const res = await client.get("/api/v1/events", { params });
  return res.data;
};
