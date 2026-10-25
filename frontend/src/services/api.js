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

export const updateAlertStatus = async (id, status) => {
  const res = await client.patch(`/api/alerts/${id}/status`, { status });
  return res.data;
};

export const getSystemHealth = async () => {
  const res = await client.get("/api/health");
  return res.data;
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
