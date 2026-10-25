import axios from "axios";

const BASE_URL = "http://127.0.0.1:5000";

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
  headers: { Accept: "application/json" },
});

export const getStatistics = async () => (await client.get("/api/statistics")).data;
export const getEvents = async () => (await client.get("/api/events")).data;
export const getAlerts = async () => (await client.get("/api/alerts")).data;
