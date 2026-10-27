import React, { useState, useEffect } from "react";
import {
  FiShield,
  FiAlertTriangle,
  FiLock,
  FiUser,
  FiSearch,
  FiZap,
  FiCheckCircle,
  FiRefreshCw,
  FiArrowRight,
  FiDatabase,
  FiServer,
  FiGlobe,
  FiActivity
} from "react-icons/fi";
import {
  getVictimStatus,
  submitVictimLogin,
  submitVictimSearch,
  resetVictimIp
} from "../services/api.js";

const DEFAULT_ATTACK_IPS = [
  { label: "External Attacker IP", ip: "198.51.100.42" },
  { label: "Malicious Botnet Node", ip: "203.0.113.19" },
  { label: "Internal Rogue Host", ip: "192.168.1.105" },
];

export default function VictimWebsite({ onSwitchToAdmin }) {
  const [selectedIp, setSelectedIp] = useState("198.51.100.42");
  const [customIp, setCustomIp] = useState("");
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [quarantineInfo, setQuarantineInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  // Login form state
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginResponse, setLoginResponse] = useState(null);

  // Search form state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searchResponse, setSearchResponse] = useState(null);

  const activeIp = customIp.trim() || selectedIp;

  // Fetch status of the current active IP
  const checkStatus = async () => {
    try {
      const res = await getVictimStatus(activeIp);
      setIsQuarantined(res?.is_quarantined || false);
      setQuarantineInfo(res?.quarantine_info || null);
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    checkStatus();
  }, [activeIp]);

  // Handle Login submission
  const handleLogin = async (e, forcedCount = 1) => {
    if (e) e.preventDefault();
    setLoading(true);
    setLoginResponse(null);
    try {
      const res = await submitVictimLogin({
        username: loginUsername,
        password: loginPassword,
        client_ip: activeIp,
        simulate_count: forcedCount
      });
      setLoginResponse(res);
      await checkStatus();
    } catch (err) {
      setLoginResponse({
        error: err.message || "Request failed",
        status: "error"
      });
    } finally {
      setLoading(false);
    }
  };

  // Handle Search submission
  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    setSearchResponse(null);
    setSearchResults(null);
    try {
      const res = await submitVictimSearch({
        query: searchQuery,
        client_ip: activeIp
      });
      setSearchResponse(res);
      if (res?.results) {
        setSearchResults(res.results);
      }
      await checkStatus();
    } catch (err) {
      setSearchResponse({
        error: err.message || "Request failed",
        status: "error"
      });
    } finally {
      setLoading(false);
    }
  };

  // Reset / Unblock current IP
  const handleResetIp = async () => {
    setLoading(true);
    try {
      await resetVictimIp(activeIp);
      setLoginResponse(null);
      setSearchResponse(null);
      await checkStatus();
    } catch {
      // Ignored
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Banner: Attacker IP Simulation & SOC Switcher */}
      <div className="bg-slate-900 border-b border-slate-800 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </span>
          <span className="font-semibold text-slate-300 uppercase tracking-wider">
            Target Public Website:
          </span>
          <span className="text-cyan-400 font-mono font-medium">
            Apex Financial Enterprise Portal
          </span>
          <span className="hidden md:inline text-slate-500">|</span>
          <span className="hidden md:flex items-center gap-1.5 text-slate-400">
            <FiShield className="text-emerald-400" />
            Protected by <strong className="text-slate-200">ThreatLens Active Defense WAF</strong>
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* IP Persona Selector */}
          <div className="flex items-center gap-2 bg-slate-950/80 px-2.5 py-1 rounded border border-slate-700">
            <span className="text-slate-400">Attacker IP Persona:</span>
            <select
              value={selectedIp}
              onChange={(e) => {
                setSelectedIp(e.target.value);
                setCustomIp("");
              }}
              className="bg-slate-900 text-cyan-300 font-mono text-xs rounded border border-slate-700 px-2 py-0.5 outline-none"
            >
              {DEFAULT_ATTACK_IPS.map((item) => (
                <option key={item.ip} value={item.ip}>
                  {item.ip} ({item.label})
                </option>
              ))}
            </select>
          </div>

          {/* Quarantine Badge */}
          {isQuarantined ? (
            <div className="flex items-center gap-1.5 bg-red-950/80 text-red-300 border border-red-700/60 px-2.5 py-1 rounded font-semibold animate-pulse">
              <FiAlertTriangle className="text-red-400" />
              QUARANTINED (403)
            </div>
          ) : (
            <div className="flex items-center gap-1.5 bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 px-2.5 py-1 rounded font-medium">
              <FiCheckCircle className="text-emerald-400" />
              CLEAN / NORMAL
            </div>
          )}

          {/* Reset IP Button */}
          <button
            onClick={handleResetIp}
            disabled={loading}
            className="flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 transition"
            title="Remove this IP from ThreatLens quarantine"
          >
            <FiRefreshCw className={loading ? "animate-spin" : ""} />
            Reset IP
          </button>

          {/* Switch to Admin SOC Button */}
          <button
            onClick={onSwitchToAdmin}
            className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold px-3 py-1 rounded shadow-md shadow-cyan-900/40 transition"
          >
            <FiShield className="text-sm" />
            Switch to Admin SOC
            <FiArrowRight className="text-xs" />
          </button>
        </div>
      </div>

      {/* Corporate Public Header */}
      <header className="bg-slate-900/60 backdrop-blur border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20 font-bold text-xl">
            A
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              Apex Financial Portal
              <span className="text-[10px] uppercase font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 px-1.5 py-0.5 rounded">
                Live Target App
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Corporate Banking & Cloud Escrow Gateway
            </p>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-6 text-sm text-slate-300 font-medium">
          <span className="hover:text-white cursor-pointer transition">Accounts</span>
          <span className="hover:text-white cursor-pointer transition">Corporate Escrow</span>
          <span className="hover:text-white cursor-pointer transition">Developer API</span>
          <span className="hover:text-white cursor-pointer transition">Security Center</span>
        </nav>
      </header>

      {/* Main Target App Body */}
      <main className="flex-1 max-w-6xl w-full mx-auto p-6 space-y-6">
        {/* If the current host is Quarantined by ThreatLens, show the Active WAF Block Screen */}
        {isQuarantined && (
          <div className="bg-red-950/70 border-2 border-red-600 rounded-xl p-6 shadow-2xl shadow-red-950/80 space-y-4">
            <div className="flex items-start gap-4">
              <div className="h-12 w-12 rounded-full bg-red-600/20 border border-red-500 flex items-center justify-center text-red-400 shrink-0 text-2xl">
                <FiShield />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold bg-red-900 text-red-200 px-2 py-0.5 rounded uppercase">
                    HTTP 403 Forbidden
                  </span>
                  <span className="text-xs text-red-300">
                    ThreatLens Active Defense Firewall
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white mt-1">
                  Access Denied: Your IP ({activeIp}) Has Been Quarantined
                </h2>
                <p className="text-sm text-red-200 mt-1">
                  {quarantineInfo?.reason ||
                    "Malicious security attack payload detected from this IP address."}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 text-xs font-mono bg-slate-950/80 p-3 rounded-lg border border-red-900/60">
                  <div>
                    <span className="text-slate-400 block">Quarantined Host:</span>
                    <span className="text-cyan-400 font-bold">{activeIp}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Triggered Rule:</span>
                    <span className="text-amber-300 font-bold">
                      {quarantineInfo?.rule_id || "DR-06 / SQL Injection Attack"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Automated Mitigation:</span>
                    <span className="text-emerald-400 font-bold">
                      Connection Terminated (Dropped)
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3 mt-4">
                  <button
                    onClick={onSwitchToAdmin}
                    className="flex items-center gap-1.5 bg-red-600 hover:bg-red-500 text-white font-semibold px-4 py-2 rounded shadow transition text-xs"
                  >
                    <FiShield />
                    Inspect Alert & Recommendations in Admin SOC
                  </button>
                  <button
                    onClick={handleResetIp}
                    className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-2 rounded border border-slate-700 transition text-xs"
                  >
                    <FiRefreshCw />
                    Clear Quarantine for this IP
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Attack Surface Row: Login & Search */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Surface 1: Customer Authentication Gateway */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <FiLock className="text-cyan-400 text-lg" />
                  <h3 className="font-bold text-white text-sm">
                    Attack Surface 1: Customer Login Gateway
                  </h3>
                </div>
                <span className="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                  POST /api/victim/login
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4">
                Test SQL injection authentication bypass payloads, rapid multi-password brute force guessing, or policy violations against this gateway.
              </p>

              {/* 1-Click Attack Presets */}
              <div className="space-y-1.5 mb-4">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1">
                  <FiZap className="text-amber-400" />
                  Quick Attack Presets:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      setLoginUsername("admin' OR '1'='1");
                      setLoginPassword("any_password");
                    }}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-amber-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ SQLi: ' OR '1'='1
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setLoginUsername("admin'--");
                      setLoginPassword("ignored");
                    }}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-amber-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ SQLi: admin'--
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      setLoginUsername("finance_lead");
                      setLoginPassword("wrongpass123");
                      handleLogin(e, 5);
                    }}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-red-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ Brute Force (5 rapid tries)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setLoginUsername("root");
                      setLoginPassword("rootpass");
                    }}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-purple-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ Root Login Policy Violation
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setLoginUsername("demo_user");
                      setLoginPassword("ApexSecure2026!");
                    }}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-emerald-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ✓ Valid User Login
                  </button>
                </div>
              </div>

              {/* Login Form */}
              <form onSubmit={handleLogin} className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Username / Account ID
                  </label>
                  <div className="relative">
                    <FiUser className="absolute left-3 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      placeholder="e.g. admin' OR '1'='1"
                      className="w-full bg-slate-950 text-white pl-9 pr-3 py-1.5 rounded border border-slate-700 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Password
                  </label>
                  <div className="relative">
                    <FiLock className="absolute left-3 top-2.5 text-slate-500" />
                    <input
                      type="password"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="Enter password..."
                      className="w-full bg-slate-950 text-white pl-9 pr-3 py-1.5 rounded border border-slate-700 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold py-2 rounded text-xs transition shadow-md shadow-cyan-900/30 flex items-center justify-center gap-1.5"
                >
                  {loading ? (
                    <FiRefreshCw className="animate-spin text-sm" />
                  ) : (
                    <FiArrowRight className="text-sm" />
                  )}
                  Submit Authentication Request
                </button>
              </form>
            </div>

            {/* Login Result Container */}
            {loginResponse && (
              <div className="mt-4 pt-3 border-t border-slate-800">
                {loginResponse.status === "attack_detected" || loginResponse.blocked ? (
                  <div className="bg-red-950/60 border border-red-700/60 rounded p-3 text-xs space-y-1.5">
                    <div className="flex items-center gap-1.5 text-red-300 font-bold">
                      <FiAlertTriangle className="text-red-400" />
                      ThreatLens Active Defense Intercepted Malicious Attack!
                    </div>
                    <p className="text-slate-300 font-mono text-[11px]">
                      {loginResponse.message || loginResponse.error}
                    </p>
                    {loginResponse.alert && (
                      <div className="bg-slate-950/80 p-2 rounded border border-red-900/40 text-[11px] font-mono text-amber-300">
                        <strong>Rule Fired:</strong> {loginResponse.alert.rule_name} ({loginResponse.alert.rule_id}) | Severity: {loginResponse.alert.severity}
                      </div>
                    )}
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline font-semibold mt-1"
                    >
                      Inspect in Admin SOC Dashboard &rarr;
                    </button>
                  </div>
                ) : loginResponse.status === "authenticated" ? (
                  <div className="bg-emerald-950/60 border border-emerald-700/60 rounded p-3 text-xs space-y-1">
                    <div className="flex items-center gap-1.5 text-emerald-300 font-bold">
                      <FiCheckCircle className="text-emerald-400" />
                      Legitimate Authentication Accepted
                    </div>
                    <p className="text-slate-300 text-[11px]">
                      Welcome, <strong>{loginResponse.user?.name}</strong> ({loginResponse.user?.role}).
                    </p>
                    <div className="text-[11px] font-mono text-cyan-400">
                      Balance: {loginResponse.user?.balance}
                    </div>
                  </div>
                ) : (
                  <div className="bg-amber-950/40 border border-amber-700/40 rounded p-2.5 text-xs text-amber-300">
                    {loginResponse.error || "Authentication failed: Invalid credentials"}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Surface 2: Customer Account Search & Transactions */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <FiDatabase className="text-blue-400 text-lg" />
                  <h3 className="font-bold text-white text-sm">
                    Attack Surface 2: Database Account Search
                  </h3>
                </div>
                <span className="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                  POST /api/victim/search
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4">
                Test SQL injection payloads inside query parameters (UNION SELECT, comment tricks, tautologies) against internal database queries.
              </p>

              {/* 1-Click Attack Presets */}
              <div className="space-y-1.5 mb-4">
                <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1">
                  <FiZap className="text-amber-400" />
                  Quick Query Presets:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => setSearchQuery("1001' OR 1=1 --")}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-amber-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ SQLi: 1001' OR 1=1 --
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setSearchQuery("' UNION SELECT username, password FROM users --")
                    }
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-amber-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ⚡ SQLi Union: UNION SELECT
                  </button>
                  <button
                    type="button"
                    onClick={() => setSearchQuery("ACC-49102")}
                    className="text-xs bg-slate-800 hover:bg-slate-700 text-emerald-300 font-mono px-2 py-1 rounded border border-slate-700 transition"
                  >
                    ✓ Clean Query: ACC-49102
                  </button>
                </div>
              </div>

              {/* Search Form */}
              <form onSubmit={handleSearch} className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Account / Query Parameter
                  </label>
                  <div className="relative">
                    <FiSearch className="absolute left-3 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="e.g. 1001' OR 1=1 --"
                      className="w-full bg-slate-950 text-white pl-9 pr-3 py-1.5 rounded border border-slate-700 font-mono text-xs focus:border-blue-500 focus:outline-none"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold py-2 rounded text-xs transition shadow-md shadow-blue-900/30 flex items-center justify-center gap-1.5"
                >
                  {loading ? (
                    <FiRefreshCw className="animate-spin text-sm" />
                  ) : (
                    <FiSearch className="text-sm" />
                  )}
                  Execute Database Query
                </button>
              </form>
            </div>

            {/* Search Result Container */}
            {searchResponse && (
              <div className="mt-4 pt-3 border-t border-slate-800">
                {searchResponse.status === "attack_detected" || searchResponse.blocked ? (
                  <div className="bg-red-950/60 border border-red-700/60 rounded p-3 text-xs space-y-1.5">
                    <div className="flex items-center gap-1.5 text-red-300 font-bold">
                      <FiAlertTriangle className="text-red-400" />
                      ThreatLens WAF Dropped SQL Injection Query!
                    </div>
                    <p className="text-slate-300 font-mono text-[11px]">
                      {searchResponse.message || searchResponse.error}
                    </p>
                    <div className="text-[11px] font-mono text-cyan-300">
                      Query Neutralized: <code>{searchResponse.query}</code>
                    </div>
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline font-semibold mt-1"
                    >
                      View Mitigation in Admin SOC &rarr;
                    </button>
                  </div>
                ) : searchResults ? (
                  <div className="space-y-2">
                    <span className="text-xs text-slate-400 font-medium">
                      Query Results ({searchResults.length} Records):
                    </span>
                    <div className="space-y-1.5">
                      {searchResults.map((item, idx) => (
                        <div
                          key={idx}
                          className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs flex justify-between items-center"
                        >
                          <div>
                            <div className="font-semibold text-white">{item.name}</div>
                            <div className="text-[11px] font-mono text-slate-500">
                              {item.id} &bull; {item.type}
                            </div>
                          </div>
                          <div className="text-emerald-400 font-mono font-bold">
                            {item.balance}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </div>

        {/* Live Architecture Explainer Card */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 text-xs text-slate-300">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
            <h4 className="font-bold text-white flex items-center gap-2">
              <FiActivity className="text-cyan-400" />
              How Real-World Protection Works on this Website
            </h4>
            <span className="bg-slate-800 text-slate-400 font-mono px-2 py-0.5 rounded text-[10px]">
              Full Stack End-to-End
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-1 bg-slate-950/60 p-3 rounded border border-slate-800/80">
              <strong className="text-cyan-300 block font-mono text-[11px]">
                1. Real Ingestion & Attack Parsing
              </strong>
              <p className="text-slate-400">
                Hostile input payloads (such as SQL injection tautologies or password stuffing) submitted on this website trigger real authentication events that are logged and correlated in ThreatLens.
              </p>
            </div>

            <div className="space-y-1 bg-slate-950/60 p-3 rounded border border-slate-800/80">
              <strong className="text-amber-300 block font-mono text-[11px]">
                2. Automated Prevention & Drop
              </strong>
              <p className="text-slate-400">
                ThreatLens Active Defense immediately quarantines the attacker's IP in the firewall blocklist. Any subsequent request from this host is dropped with <strong>HTTP 403 Forbidden</strong>.
              </p>
            </div>

            <div className="space-y-1 bg-slate-950/60 p-3 rounded border border-slate-800/80">
              <strong className="text-emerald-300 block font-mono text-[11px]">
                3. Admin SOC & Hardening Plan
              </strong>
              <p className="text-slate-400">
                In the Admin SOC Portal, the security administrator monitors live telemetry, manages quarantined IPs, and accesses step-by-step system hardening configurations (sshd, WAF, DB prepared statements).
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
