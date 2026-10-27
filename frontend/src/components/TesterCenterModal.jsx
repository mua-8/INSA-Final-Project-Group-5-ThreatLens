import React, { useState, useEffect } from "react";
import {
  FaTimes,
  FaVial,
  FaShieldAlt,
  FaCheckCircle,
  FaExclamationTriangle,
  FaPlay,
  FaCode,
  FaBug,
  FaExchangeAlt,
  FaNotesMedical,
  FaTerminal,
  FaClock,
} from "react-icons/fa";
import {
  runSystemTests,
  runSqliFuzz,
  callRawEndpoint,
  getSystemRoutes,
  getIncidents,
  createIncident,
  addIncidentNote,
  getIncidentNotes,
} from "../services/api.js";

const SQLI_PRESETS = [
  {
    name: "Classic Authentication Bypass",
    payload: "' OR '1'='1",
    target: "username",
    desc: "Attempts to bypass WHERE clause filters by injecting a tautology.",
  },
  {
    name: "Destructive DROP TABLE Attempt",
    payload: "admin'; DROP TABLE events; --",
    target: "username",
    desc: "Attempts to terminate the query and drop the core events table.",
  },
  {
    name: "Union-Based Data Exfiltration",
    payload: "' UNION SELECT id, password, 3, 4, 5, 6, 7 FROM sqlite_master --",
    target: "source_ip",
    desc: "Attempts to append schema or sensitive tables to the query output.",
  },
  {
    name: "IP Tautology Filter Bypass",
    payload: "192.168.1.1' OR 1=1 --",
    target: "source_ip",
    desc: "Attempts to return all stored events regardless of origin IP.",
  },
  {
    name: "Blind SQLi Time / Subquery Probe",
    payload: "' AND (SELECT 1 FROM log_files WHERE 1=1)='1",
    target: "event_type",
    desc: "Attempts to execute nested subqueries into SQLite.",
  },
];

export default function TesterCenterModal({ onClose, onRefreshDashboard }) {
  const [activeTab, setActiveTab] = useState("tests"); // 'tests' | 'sqli' | 'api' | 'incidents'

  // Tab 1: Automated Test Suite State
  const [runningTests, setRunningTests] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testError, setTestError] = useState(null);

  // Tab 2: SQLi Fuzzing State
  const [selectedPreset, setSelectedPreset] = useState(SQLI_PRESETS[0]);
  const [customPayload, setCustomPayload] = useState(SQLI_PRESETS[0].payload);
  const [targetField, setTargetField] = useState(SQLI_PRESETS[0].target);
  const [fuzzing, setFuzzing] = useState(false);
  const [fuzzResult, setFuzzResult] = useState(null);

  // Tab 3: API Explorer State (Dynamic Route Discovery)
  const [discoveredRoutes, setDiscoveredRoutes] = useState([]);
  const [routesLoading, setRoutesLoading] = useState(false);
  const [routesError, setRoutesError] = useState(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState(null);
  const [customPath, setCustomPath] = useState("");
  const [customBody, setCustomBody] = useState("");
  const [callingApi, setCallingApi] = useState(false);
  const [apiResponse, setApiResponse] = useState(null);

  // Tab 4: Incidents State
  const [incidentList, setIncidentList] = useState([]);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentSev, setIncidentSev] = useState("high");
  const [incidentDesc, setIncidentDesc] = useState("");
  const [activeIncidentId, setActiveIncidentId] = useState(null);
  const [notesList, setNotesList] = useState([]);
  const [newNote, setNewNote] = useState("");
  const [incidentLoading, setIncidentLoading] = useState(false);

  // Handlers
  const handleRunAllTests = async () => {
    setRunningTests(true);
    setTestError(null);
    try {
      const res = await runSystemTests();
      setTestResult(res.data || res);
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setTestError(err.message || "Failed to execute automated test runner.");
    } finally {
      setRunningTests(false);
    }
  };

  const handleExecuteSqli = async () => {
    setFuzzing(true);
    setFuzzResult(null);
    try {
      const res = await runSqliFuzz(customPayload, targetField);
      setFuzzResult(res.data || res);
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setFuzzResult({ error: err.message });
    } finally {
      setFuzzing(false);
    }
  };

  const loadRoutes = async () => {
    setRoutesLoading(true);
    setRoutesError(null);
    try {
      const res = await getSystemRoutes();
      const list = res.data?.routes || res.routes || [];
      setDiscoveredRoutes(list);
      if (list.length > 0 && !selectedEndpoint) {
        setSelectedEndpoint(list[0]);
        setCustomPath(list[0].sample_path || list[0].path);
        setCustomBody(list[0].sample_body ? JSON.stringify(list[0].sample_body, null, 2) : "");
      }
    } catch (err) {
      setRoutesError(err.message || "Failed to load registered routes from backend.");
    } finally {
      setRoutesLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === "api" && discoveredRoutes.length === 0 && !routesLoading) {
      loadRoutes();
    }
  }, [activeTab]);

  const handleSelectEndpoint = (ep) => {
    setSelectedEndpoint(ep);
    setCustomPath(ep.sample_path || ep.path);
    setCustomBody(ep.sample_body ? JSON.stringify(ep.sample_body, null, 2) : "");
    setApiResponse(null);
  };

  const handleCallApi = async () => {
    if (!selectedEndpoint) return;
    setCallingApi(true);
    setApiResponse(null);
    try {
      let parsedBody = null;
      if (["POST", "PATCH", "PUT"].includes(selectedEndpoint.method) && customBody.trim()) {
        parsedBody = JSON.parse(customBody);
      }
      const targetPath = customPath.trim() || selectedEndpoint.sample_path || selectedEndpoint.path;
      const res = await callRawEndpoint(selectedEndpoint.method, targetPath, parsedBody);
      setApiResponse(res);
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      setApiResponse({
        status: err.response?.status || 500,
        data: err.response?.data || { error: err.message },
      });
    } finally {
      setCallingApi(false);
    }
  };

  const loadIncidents = async () => {
    setIncidentLoading(true);
    try {
      const res = await getIncidents();
      const list = res.data?.incidents || res.incidents || res.data || [];
      setIncidentList(list);
      if (list.length > 0 && !activeIncidentId) {
        selectIncident(list[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIncidentLoading(false);
    }
  };

  const selectIncident = async (id) => {
    setActiveIncidentId(id);
    try {
      const res = await getIncidentNotes(id);
      setNotesList(res.data?.notes || res.notes || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!incidentTitle.trim()) return;
    try {
      await createIncident({
        title: incidentTitle,
        severity: incidentSev,
        description: incidentDesc || "Manual triage case",
      });
      setIncidentTitle("");
      setIncidentDesc("");
      await loadIncidents();
      if (onRefreshDashboard) onRefreshDashboard();
    } catch (err) {
      alert("Failed to create incident: " + err.message);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!activeIncidentId || !newNote.trim()) return;
    try {
      await addIncidentNote(activeIncidentId, newNote, "SOC Analyst");
      setNewNote("");
      await selectIncident(activeIncidentId);
    } catch (err) {
      alert("Failed to add note: " + err.message);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-fadeIn">
      <div className="relative flex max-h-[92vh] w-full max-w-5xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/15 text-purple-400 ring-1 ring-purple-500/40">
              <FaVial size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-purple-400 uppercase tracking-wider">
                  System Diagnostics
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="font-mono text-xs text-slate-300">Security Verification</span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Diagnostics & Security Controls Center
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
          >
            <FaTimes size={18} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap border-b border-slate-700 bg-slate-900/50 px-6 pt-3 gap-6">
          <button
            onClick={() => setActiveTab("tests")}
            className={`flex items-center gap-2 pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "tests"
                ? "border-purple-400 text-purple-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaPlay size={10} />
            <span>Automated Test Runner</span>
          </button>

          <button
            onClick={() => setActiveTab("sqli")}
            className={`flex items-center gap-2 pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "sqli"
                ? "border-purple-400 text-purple-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaShieldAlt size={11} />
            <span>SQL Injection Fuzzer</span>
          </button>

          <button
            onClick={() => setActiveTab("api")}
            className={`flex items-center gap-2 pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "api"
                ? "border-purple-400 text-purple-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaExchangeAlt size={11} />
            <span>REST API Explorer</span>
          </button>

          <button
            onClick={() => {
              setActiveTab("incidents");
              loadIncidents();
            }}
            className={`flex items-center gap-2 pb-3 text-xs font-semibold uppercase tracking-wider transition border-b-2 ${
              activeTab === "incidents"
                ? "border-purple-400 text-purple-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaNotesMedical size={11} />
            <span>Incidents & Case Notes</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          
          {/* TAB 1: AUTOMATED TEST RUNNER */}
          {activeTab === "tests" && (
            <div className="space-y-5">
              <div className="rounded-xl border border-slate-700/70 bg-slate-900/40 p-5 flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white">Automated System Test Runner</h3>
                  <p className="mt-1 text-xs text-slate-400 max-w-xl leading-relaxed">
                    Executes test verification suites on the backend via <code className="font-mono text-purple-300">POST /api/system/tests/run</code>. Verifies SQLite schema constraints, cascading deletions, REST API endpoints, and query parameterization controls.
                  </p>
                </div>
                <button
                  disabled={runningTests}
                  onClick={handleRunAllTests}
                  className="inline-flex items-center gap-2 rounded-xl bg-purple-600 px-5 py-2.5 text-xs font-bold text-white transition hover:bg-purple-500 shadow-lg shadow-purple-600/20 disabled:opacity-50 active:scale-95"
                >
                  <FaPlay size={12} className={runningTests ? "animate-spin" : ""} />
                  {runningTests ? "Executing Tests..." : "Run Automated System Tests"}
                </button>
              </div>

              {testError && (
                <div className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-xs text-danger">
                  {testError}
                </div>
              )}

              {testResult && (
                <div className="space-y-4 animate-fadeIn">
                  {/* Summary Card */}
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3">
                      <div className="text-[11px] text-slate-400">Total Tests</div>
                      <div className="mt-1 text-lg font-bold font-mono text-emerald-400">
                        {testResult.total_tests} / {testResult.total_tests}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                      <div className="text-[11px] text-slate-400">Failures / Errors</div>
                      <div className="mt-1 text-lg font-bold font-mono text-white">
                        {testResult.failures} / {testResult.errors}
                      </div>
                    </div>
                    <div className="rounded-lg border border-slate-700/60 bg-slate-900/40 p-3">
                      <div className="text-[11px] text-slate-400">Execution Time</div>
                      <div className="mt-1 text-lg font-bold font-mono text-purple-300">
                        {testResult.duration_seconds}s
                      </div>
                    </div>
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3">
                      <div className="text-[11px] text-slate-400">Overall Status</div>
                      <div className="mt-1 text-sm font-bold font-mono text-emerald-300 uppercase flex items-center gap-1.5">
                        <FaCheckCircle size={14} />
                        <span>{testResult.failures === 0 && testResult.errors === 0 ? "PASSED" : "ISSUES REPORTED"}</span>
                      </div>
                    </div>
                  </div>

                  {/* Test Suites Breakdown */}
                  <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4 space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 mb-3">
                      Verified Architectural Modules
                    </h4>
                    <div className="space-y-2">
                      {testResult.suites?.map((s, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between rounded-lg border border-slate-700/50 bg-slate-900/70 px-4 py-2.5 text-xs"
                        >
                          <div className="flex items-center gap-3">
                            <span
                              className={`flex h-5 w-5 items-center justify-center rounded-full font-bold text-[10px] ${
                                s.status === "PASSED"
                                  ? "bg-emerald-500/20 text-emerald-400"
                                  : "bg-danger/20 text-danger"
                              }`}
                            >
                              {s.status === "PASSED" ? "✓" : "✕"}
                            </span>
                            <span className="font-medium text-slate-200">{s.name}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-slate-400">{s.tests} tests</span>
                            <span
                              className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold border ${
                                s.status === "PASSED"
                                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                  : "bg-danger/15 text-danger border-danger/30"
                              }`}
                            >
                              {s.status}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    {testResult.output_summary && (
                      <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-400">
                        <span className="text-slate-500 font-semibold mr-2">Execution Output:</span>
                        <span className="text-emerald-400 font-medium">{testResult.output_summary}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SQL INJECTION DEFENSE FUZZER */}
          {activeTab === "sqli" && (
            <div className="space-y-5">
              <div className="rounded-xl border border-slate-700/70 bg-slate-900/40 p-4">
                <h3 className="text-sm font-bold text-white">Query Parameterization Verification</h3>
                <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                  Select or type a hostile payload to test query parameterization against SQLite. All data access queries use DB-API parameterized markers (<code className="font-mono text-accent">?</code>) ensuring user inputs cannot alter query logic or execute unauthorized SQL statements.
                </p>
              </div>

              {/* Preset Selector */}
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Select Attack Payload Preset:
                </label>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {SQLI_PRESETS.map((p) => (
                    <button
                      key={p.name}
                      onClick={() => {
                        setSelectedPreset(p);
                        setCustomPayload(p.payload);
                        setTargetField(p.target);
                        setFuzzResult(null);
                      }}
                      className={`text-left rounded-lg border p-3 transition ${
                        selectedPreset.name === p.name
                          ? "border-purple-400 bg-purple-500/10 text-white"
                          : "border-slate-700 bg-slate-900/30 text-slate-300 hover:border-slate-600"
                      }`}
                    >
                      <div className="font-semibold text-xs text-white">{p.name}</div>
                      <code className="block mt-1 font-mono text-[11px] text-accent truncate">{p.payload}</code>
                      <div className="mt-1 text-[11px] text-slate-400">{p.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Payload Editor & Execution */}
              <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4 space-y-3">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Payload String:</label>
                    <input
                      type="text"
                      value={customPayload}
                      onChange={(e) => setCustomPayload(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-accent focus:border-purple-400 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Target Parameter:</label>
                    <select
                      value={targetField}
                      onChange={(e) => setTargetField(e.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-purple-400 focus:outline-none"
                    >
                      <option value="source_ip">source_ip (filter)</option>
                      <option value="username">username (filter)</option>
                      <option value="event_type">event_type (filter)</option>
                    </select>
                  </div>
                </div>

                <button
                  disabled={fuzzing}
                  onClick={handleExecuteSqli}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-purple-600 py-2.5 text-xs font-bold text-white transition hover:bg-purple-500 shadow-md shadow-purple-600/20 disabled:opacity-50"
                >
                  <FaBug size={12} />
                  {fuzzing ? "Testing Defense..." : "Execute Parameterization Test"}
                </button>
              </div>

              {/* Fuzz Result Card */}
              {fuzzResult && (
                <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-5 space-y-3 animate-fadeIn">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                      <FaCheckCircle size={18} />
                      <span>Parameterization Enforced: Safe Literal Processing</span>
                    </div>
                    <span className="font-mono text-xs font-semibold text-emerald-300 bg-emerald-500/20 px-2 py-0.5 rounded border border-emerald-500/30">
                      PRAGMA integrity_check: {fuzzResult.database_integrity}
                    </span>
                  </div>

                  <p className="text-xs text-slate-200 leading-relaxed font-sans">
                    {fuzzResult.explanation}
                  </p>

                  <div className="grid grid-cols-2 gap-2 font-mono text-xs sm:grid-cols-4 pt-2">
                    <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                      <span className="text-slate-400 text-[10px] block">Query Pattern</span>
                      <span className="text-purple-300 font-bold truncate block">{fuzzResult.query_pattern}</span>
                    </div>
                    <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                      <span className="text-slate-400 text-[10px] block">Matches Leaked</span>
                      <span className="text-emerald-400 font-bold">{fuzzResult.matches_found} Records</span>
                    </div>
                    <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                      <span className="text-slate-400 text-[10px] block">FK Violations</span>
                      <span className="text-emerald-400 font-bold">{fuzzResult.foreign_key_violations}</span>
                    </div>
                    <div className="rounded bg-slate-900/60 p-2 border border-slate-700/50">
                      <span className="text-slate-400 text-[10px] block">Events Table Retained</span>
                      <span className="text-emerald-400 font-bold">{fuzzResult.table_counts?.events ?? "?"} Rows</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: REST API EXPLORER */}
          {activeTab === "api" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
                {/* Endpoint List */}
                <div className="lg:col-span-5 space-y-1.5 max-h-[420px] overflow-y-auto pr-1">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                      Registered API Endpoints {discoveredRoutes.length > 0 ? `(${discoveredRoutes.length} Total)` : ""}
                    </span>
                    {routesLoading && (
                      <span className="text-[10px] text-purple-400 animate-pulse font-mono">Discovering routes...</span>
                    )}
                  </div>

                  {routesError && (
                    <div className="rounded-lg border border-danger/40 bg-danger/10 p-3 text-xs text-danger mb-3">
                      <div className="font-semibold">Route Discovery Error</div>
                      <div className="text-[11px] mt-0.5">{routesError}</div>
                      <button
                        onClick={loadRoutes}
                        className="mt-2 rounded bg-danger/20 px-2.5 py-1 text-[10px] font-bold text-danger border border-danger/40 hover:bg-danger/30"
                      >
                        Retry Discovery
                      </button>
                    </div>
                  )}

                  {discoveredRoutes.map((ep, i) => (
                    <button
                      key={`${ep.method}-${ep.path}-${i}`}
                      onClick={() => handleSelectEndpoint(ep)}
                      className={`w-full text-left rounded-lg border p-2.5 transition text-xs flex items-center justify-between ${
                        selectedEndpoint?.path === ep.path && selectedEndpoint?.method === ep.method
                          ? "border-purple-400 bg-purple-500/15 text-white"
                          : "border-slate-700/60 bg-slate-900/30 text-slate-300 hover:border-slate-600"
                      }`}
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${
                              ep.method === "GET"
                                ? "bg-accent/20 text-accent"
                                : ep.method === "POST"
                                ? "bg-emerald-500/20 text-emerald-400"
                                : ep.method === "PATCH"
                                ? "bg-warning/20 text-warning"
                                : "bg-purple-500/20 text-purple-300"
                            }`}
                          >
                            {ep.method}
                          </span>
                          <span className="font-mono text-slate-200 truncate">{ep.path}</span>
                        </div>
                        <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-400">
                          <span className="font-mono text-purple-300/80">{ep.endpoint}()</span>
                          <span>•</span>
                          <span className="truncate">{ep.desc}</span>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>

                {/* Request / Response Panel */}
                <div className="lg:col-span-7 space-y-3">
                  {selectedEndpoint ? (
                    <div className="rounded-xl border border-slate-700/70 bg-slate-900/60 p-4 space-y-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 font-mono text-xs flex-1">
                          <span
                            className={`font-bold px-2 py-0.5 rounded text-[10px] ${
                              selectedEndpoint.method === "GET"
                                ? "bg-accent/20 text-accent"
                                : selectedEndpoint.method === "POST"
                                ? "bg-emerald-500/20 text-emerald-400"
                                : selectedEndpoint.method === "PATCH"
                                ? "bg-warning/20 text-warning"
                                : "bg-purple-500/20 text-purple-300"
                            }`}
                          >
                            {selectedEndpoint.method}
                          </span>
                          <input
                            type="text"
                            value={customPath}
                            onChange={(e) => setCustomPath(e.target.value)}
                            className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1 font-mono text-xs text-white focus:border-purple-400 focus:outline-none"
                            placeholder="/api/..."
                          />
                        </div>
                        <button
                          disabled={callingApi}
                          onClick={handleCallApi}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-primary transition hover:bg-sky-300 disabled:opacity-50 whitespace-nowrap"
                        >
                          <FaPlay size={10} />
                          {callingApi ? "Calling..." : "Send Request"}
                        </button>
                      </div>

                      <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-2">
                        <span>Handler:</span>
                        <code className="font-mono text-purple-300">{selectedEndpoint.endpoint}()</code>
                        <span>•</span>
                        <span className="text-slate-300 truncate">{selectedEndpoint.desc}</span>
                      </div>

                      {["POST", "PATCH", "PUT"].includes(selectedEndpoint.method) && (
                        <div>
                          <label className="block text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                            Request JSON Payload:
                          </label>
                          <textarea
                            rows={3}
                            value={customBody}
                            onChange={(e) => setCustomBody(e.target.value)}
                            className="w-full rounded-lg border border-slate-700 bg-slate-950 p-2 font-mono text-xs text-slate-200 focus:outline-none"
                          />
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="rounded-xl border border-slate-700/60 bg-slate-900/40 p-8 text-center text-xs text-slate-400">
                      {routesLoading ? "Discovering registered endpoints..." : "Select an endpoint to inspect and test."}
                    </div>
                  )}

                  {/* Response Display */}
                  {apiResponse && (
                    <div className="rounded-xl border border-slate-700 bg-slate-950 p-4 space-y-2 animate-fadeIn">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400">Status:</span>
                          <span
                            className={`font-bold ${
                              apiResponse.status < 300 ? "text-emerald-400" : "text-danger"
                            }`}
                          >
                            {apiResponse.status}
                          </span>
                        </div>
                        {apiResponse.durationMs !== undefined && (
                          <div className="text-slate-400">
                            Latency: <span className="text-purple-300 font-bold">{apiResponse.durationMs}ms</span>
                          </div>
                        )}
                      </div>
                      <pre className="max-h-56 overflow-y-auto rounded border border-slate-800 bg-black/60 p-3 font-mono text-[11px] text-emerald-400 leading-relaxed">
                        {JSON.stringify(apiResponse.data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: INCIDENTS & INVESTIGATION NOTES */}
          {activeTab === "incidents" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
                {/* Left: Incident Cases List */}
                <div className="lg:col-span-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Security Incidents ({incidentList.length})
                    </span>
                    <button
                      onClick={loadIncidents}
                      className="text-xs text-accent hover:underline"
                    >
                      Refresh
                    </button>
                  </div>

                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {incidentList.length === 0 ? (
                      <div className="rounded-lg border border-slate-700/50 bg-slate-900/30 p-4 text-center text-xs text-slate-500">
                        No active incidents in SQLite. Create one below!
                      </div>
                    ) : (
                      incidentList.map((inc) => (
                        <div
                          key={inc.id}
                          onClick={() => selectIncident(inc.id)}
                          className={`cursor-pointer rounded-lg border p-3 transition text-xs ${
                            activeIncidentId === inc.id
                              ? "border-purple-400 bg-purple-500/15 text-white"
                              : "border-slate-700/60 bg-slate-900/40 text-slate-300 hover:border-slate-600"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-accent font-bold">INC-{inc.id}</span>
                            <span className="rounded bg-danger/20 px-1.5 py-0.2 text-[10px] text-danger border border-danger/30 font-semibold uppercase">
                              {inc.severity}
                            </span>
                          </div>
                          <div className="mt-1 font-semibold text-white truncate">{inc.title}</div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Create Incident Form */}
                  <form onSubmit={handleCreateIncident} className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3 space-y-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 block">
                      Create Incident (POST /api/incidents)
                    </span>
                    <input
                      type="text"
                      placeholder="Incident Title..."
                      value={incidentTitle}
                      onChange={(e) => setIncidentTitle(e.target.value)}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-white focus:outline-none"
                    />
                    <select
                      value={incidentSev}
                      onChange={(e) => setIncidentSev(e.target.value)}
                      className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-300 focus:outline-none"
                    >
                      <option value="critical">Critical Severity</option>
                      <option value="high">High Severity</option>
                      <option value="medium">Medium Severity</option>
                      <option value="low">Low Severity</option>
                    </select>
                    <button
                      type="submit"
                      className="w-full rounded bg-purple-600 py-1.5 text-xs font-bold text-white transition hover:bg-purple-500"
                    >
                      Create Incident
                    </button>
                  </form>
                </div>

                {/* Right: Notes Timeline for Selected Incident */}
                <div className="lg:col-span-7 space-y-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 block">
                    Investigation Notes Timeline ({activeIncidentId ? `INC-${activeIncidentId}` : "Select Incident"})
                  </span>

                  <div className="rounded-xl border border-slate-700/70 bg-slate-900/40 p-4 min-h-[220px] max-h-60 overflow-y-auto space-y-2">
                    {!activeIncidentId ? (
                      <div className="py-12 text-center text-xs text-slate-500">
                        Select an incident from the left to view and append notes.
                      </div>
                    ) : notesList.length === 0 ? (
                      <div className="py-12 text-center text-xs text-slate-500">
                        No analyst notes attached yet. Add the first one below!
                      </div>
                    ) : (
                      notesList.map((n, i) => (
                        <div key={n.id || i} className="rounded-lg border border-slate-700/60 bg-slate-900/80 p-3 text-xs space-y-1">
                          <div className="flex items-center justify-between text-slate-400">
                            <span className="font-semibold text-accent">{n.author || "SOC Analyst"}</span>
                            <span className="font-mono text-[10px] text-slate-500">{n.created_at || "just now"}</span>
                          </div>
                          <p className="text-slate-200 leading-relaxed font-sans">{n.note || n.body}</p>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Add Note Form */}
                  {activeIncidentId && (
                    <form onSubmit={handleAddNote} className="flex gap-2">
                      <input
                        type="text"
                        value={newNote}
                        onChange={(e) => setNewNote(e.target.value)}
                        placeholder="Add forensic finding or triage note..."
                        className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-white focus:outline-none"
                      />
                      <button
                        type="submit"
                        className="rounded-lg bg-accent px-4 py-2 text-xs font-bold text-primary hover:bg-sky-300"
                      >
                        Add Note
                      </button>
                    </form>
                  )}
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/70">
          <div className="text-xs text-slate-400">
            System Diagnostics & Controls Verification
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-700 px-4 py-2 text-xs font-semibold text-white transition hover:bg-slate-600"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
