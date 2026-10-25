import { useCallback, useEffect, useRef, useState } from "react";
import { getStatistics, getEvents, getAlerts } from "../services/api.js";
import { buildDashboardModel } from "../utils/normalize.js";

const REFRESH_MS = 15000;

export default function useDashboardData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const mounted = useRef(true);

  const fetchAll = useCallback(async ({ manual = false } = {}) => {
    if (manual) setRefreshing(true);
    try {
      const [stats, events, alerts] = await Promise.all([getStatistics(), getEvents(), getAlerts()]);
      if (!mounted.current) return;
      setData(buildDashboardModel(stats, events, alerts));
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      if (!mounted.current) return;
      setError(
        !err.response
          ? "Cannot reach the ThreatLens API at http://127.0.0.1:5000. Make sure the Flask server is running and CORS is enabled."
          : `The API returned an error (${err.response.status}). Check the Flask server logs.`
      );
    } finally {
      if (mounted.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    fetchAll();
    const id = setInterval(() => fetchAll(), REFRESH_MS);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, [fetchAll]);

  const retry = useCallback(() => fetchAll({ manual: true }), [fetchAll]);

  return { data, loading, refreshing, error, lastUpdated, retry };
}
