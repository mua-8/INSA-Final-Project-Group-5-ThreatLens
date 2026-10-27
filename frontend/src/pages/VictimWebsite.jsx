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
  FiDollarSign,
  FiCreditCard,
  FiSend,
  FiEye,
  FiEyeOff,
  FiChevronRight,
  FiExternalLink,
  FiSliders,
  FiX,
  FiTerminal,
  FiKey
} from "react-icons/fi";
import {
  getVictimStatus,
  submitVictimLogin,
  submitVictimSearch,
  resetVictimIp
} from "../services/api.js";

const DEFAULT_ATTACK_IPS = [
  { label: "External Threat Actor (APT-41)", ip: "198.51.100.42" },
  { label: "Compromised Tor Exit Node", ip: "203.0.113.19" },
  { label: "Rogue Insider Workstation", ip: "192.168.1.105" },
];

const INITIAL_TRANSACTIONS = [
  {
    id: "TXN-998241",
    date: "Today, 09:42 AM",
    description: "Sovereign Asset Liquidity Wire Inbound",
    account: "Checking ****8841",
    amount: "+$125,000.00",
    status: "Completed",
    type: "credit",
  },
  {
    id: "TXN-998239",
    date: "Today, 08:15 AM",
    description: "Amazon Web Services Enterprise Infrastructure",
    account: "Escrow ****1092",
    amount: "-$14,820.50",
    status: "Cleared",
    type: "debit",
  },
  {
    id: "TXN-998190",
    date: "Yesterday",
    description: "Global Custody Treasury Dividend Yield (5.12%)",
    account: "Checking ****8841",
    amount: "+$8,410.22",
    status: "Completed",
    type: "credit",
  },
  {
    id: "TXN-997840",
    date: "25 Oct 2026",
    description: "Payroll Direct Deposit Batch #4112",
    account: "Escrow ****1092",
    amount: "-$84,500.00",
    status: "Cleared",
    type: "debit",
  },
];

export default function VictimWebsite({ onSwitchToAdmin }) {
  const [selectedIp, setSelectedIp] = useState("198.51.100.42");
  const [customIp, setCustomIp] = useState("");
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [quarantineInfo, setQuarantineInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  // Red Team Audit drawer state
  const [showAuditDrawer, setShowAuditDrawer] = useState(true);

  // Customer portal interactive state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showBalance, setShowBalance] = useState(true);
  const [transactions, setTransactions] = useState(INITIAL_TRANSACTIONS);

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
  const handleLogin = async (e, forcedUsername = null, forcedPassword = null, forcedCount = 1) => {
    if (e && e.preventDefault) e.preventDefault();
    const u = forcedUsername !== null ? forcedUsername : loginUsername;
    const p = forcedPassword !== null ? forcedPassword : loginPassword;

    setLoading(true);
    setLoginResponse(null);
    try {
      const res = await submitVictimLogin({
        username: u,
        password: p,
        client_ip: activeIp,
        simulate_count: forcedCount
      });
      setLoginResponse(res);
      await checkStatus();

      if (res?.status === "authenticated" || res?.token) {
        setIsAuthenticated(true);
      }
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
  const handleSearch = async (e, forcedQuery = null) => {
    if (e && e.preventDefault) e.preventDefault();
    const q = forcedQuery !== null ? forcedQuery : searchQuery;

    setLoading(true);
    setSearchResponse(null);
    setSearchResults(null);
    try {
      const res = await submitVictimSearch({
        query: q,
        client_ip: activeIp
      });
      setSearchResponse(res);
      if (res?.results) {
        setSearchResults(res.results);
      }
      await checkStatus();
    } catch (err) {
      setSearchResponse({
        error: err.message || "Search request failed",
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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-amber-400 selection:text-slate-950">
      
      {/* Institutional Top Trust Bar */}
      <div className="bg-slate-900/90 border-b border-slate-800 text-[11px] text-slate-400 px-4 py-1.5 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1 text-emerald-400 font-medium">
            <FiShield className="text-xs" /> 256-Bit TLS Bank-Grade Encryption
          </span>
          <span className="hidden sm:inline text-slate-600">|</span>
          <span className="hidden sm:inline text-slate-400">FDIC Certificate #34190 • Equal Housing Lender</span>
        </div>
        
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAuditDrawer(!showAuditDrawer)}
            className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 font-semibold transition"
          >
            <FiSliders className="text-xs" />
            <span>Red Team Exploit Harness:</span>
            <span className={`h-1.5 w-1.5 rounded-full ${showAuditDrawer ? "bg-cyan-400 animate-ping" : "bg-slate-500"}`} />
            <span className="font-mono">{showAuditDrawer ? "OPEN" : "HIDDEN"}</span>
          </button>

          <button
            onClick={onSwitchToAdmin}
            className="flex items-center gap-1 font-bold text-sky-400 hover:text-sky-300 transition"
          >
            <span>Admin SOC Portal</span>
            <FiArrowRight className="text-xs" />
          </button>
        </div>
      </div>

      {/* Primary Financial Institution Header */}
      <header className="sticky top-0 z-30 bg-slate-900/95 backdrop-blur-md border-b border-slate-800/80 shadow-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-amber-400 via-amber-500 to-amber-700 flex items-center justify-center text-slate-950 font-black text-xl shadow-lg shadow-amber-500/20 ring-1 ring-amber-300/40">
              A
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-extrabold tracking-tight text-white">
                  APEX FEDERAL
                </h1>
                <span className="text-[10px] font-bold uppercase tracking-wider bg-amber-500/15 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded-full">
                  Trust & Private Bank
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Institutional Wealth Management & Commercial Treasury Portal
              </p>
            </div>
          </div>

          <nav className="hidden lg:flex items-center gap-7 text-xs font-semibold text-slate-300">
            <a href="#accounts" className="hover:text-amber-400 transition">Cash & Treasury</a>
            <a href="#wires" className="hover:text-amber-400 transition">Global Wire Services</a>
            <a href="#custody" className="hover:text-amber-400 transition">Asset Custody</a>
            <a href="#compliance" className="hover:text-amber-400 transition">Compliance & Security</a>
          </nav>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <div className="flex items-center gap-2 bg-slate-800/80 border border-slate-700 px-3 py-1.5 rounded-lg text-xs">
                <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-slate-300 font-medium">Logged in as:</span>
                <span className="font-mono font-bold text-amber-300">{loginUsername || "Corporate Lead"}</span>
                <button
                  onClick={() => setIsAuthenticated(false)}
                  className="ml-2 text-slate-400 hover:text-white underline text-[11px]"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <a
                href="#login-section"
                className="inline-flex items-center gap-1.5 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs shadow-lg shadow-amber-500/20 transition active:scale-95"
              >
                <FiLock className="text-sm" />
                <span>Client Access</span>
              </a>
            )}
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">

        {/* 403 Forbidden Shield Screen if Attacking IP is Quarantined */}
        {isQuarantined && (
          <div className="rounded-2xl border-2 border-red-500 bg-gradient-to-br from-red-950/90 via-slate-900 to-red-950/80 p-6 sm:p-8 shadow-2xl shadow-red-950/90 backdrop-blur-xl animate-in fade-in zoom-in-95 duration-200">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-red-500/30">
              <div className="flex items-center gap-4">
                <div className="h-16 w-16 rounded-2xl bg-red-600/20 border-2 border-red-500 flex items-center justify-center text-red-400 text-3xl shadow-lg shadow-red-600/30">
                  <FiAlertTriangle />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-black bg-red-600 text-white px-2.5 py-0.5 rounded uppercase tracking-wider">
                      HTTP 403 FORBIDDEN
                    </span>
                    <span className="text-xs text-red-300 font-semibold tracking-wide">
                      ThreatLens Active Defense WAF
                    </span>
                  </div>
                  <h2 className="text-2xl font-black text-white mt-1 tracking-tight">
                    Access Denied: Host Quarantined & Blocked
                  </h2>
                  <p className="text-xs text-red-200/90 mt-0.5 max-w-xl">
                    {quarantineInfo?.reason || "An automated security violation was detected. Your IP has been immediately isolated to protect client treasury assets."}
                  </p>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <button
                  onClick={onSwitchToAdmin}
                  className="flex items-center gap-2 bg-red-600 hover:bg-red-500 text-white font-bold px-4 py-2.5 rounded-xl text-xs shadow-lg shadow-red-600/30 transition active:scale-95"
                >
                  <FiShield size={14} />
                  <span>Inspect in Admin SOC Portal</span>
                </button>
                <button
                  onClick={handleResetIp}
                  disabled={loading}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-4 py-2.5 rounded-xl border border-slate-700 text-xs transition active:scale-95"
                >
                  <FiRefreshCw className={loading ? "animate-spin" : ""} size={14} />
                  <span>Clear IP Quarantine</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mt-6 text-xs font-mono">
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Quarantined IP:</span>
                <span className="text-cyan-400 font-bold text-sm">{activeIp}</span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Triggered Security Rule:</span>
                <span className="text-amber-400 font-bold text-sm">
                  {quarantineInfo?.rule_id || "DR-06 / SQL Injection Attack"}
                </span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Automated SOC Action:</span>
                <span className="text-emerald-400 font-bold text-sm">DROP Connection / WAF Shield</span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Ray Incident ID:</span>
                <span className="text-slate-300 font-bold text-sm">THREAT-WAF-{Math.abs(activeIp.split('.').reduce((a,b)=>a*31+parseInt(b), 0)).toString(16).toUpperCase()}</span>
              </div>
            </div>
          </div>
        )}

        {/* Hero Banner: Institutional Banking */}
        <section className="relative overflow-hidden rounded-3xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900/95 to-slate-950 p-8 sm:p-10 shadow-2xl">
          <div className="absolute right-0 top-0 -mt-12 -mr-12 h-96 w-96 rounded-full bg-amber-500/5 blur-3xl pointer-events-none" />
          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-bold text-amber-400">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
              Next-Gen Liquidity Escrow & Institutional Custody
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
              Institutional Asset Management for High-Growth Enterprises
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              Apex Federal provides frictionless commercial treasury, automated wire clearances, and programmatic liquidity. Backed by real-time ThreatLens active intrusion defense.
            </p>
            <div className="flex flex-wrap items-center gap-4 pt-2">
              <a
                href="#login-section"
                className="inline-flex items-center gap-2 rounded-xl bg-amber-500 px-5 py-2.5 text-xs font-bold text-slate-950 shadow-lg shadow-amber-500/25 transition hover:bg-amber-400 active:scale-95"
              >
                <span>Launch Client Sign-In</span>
                <FiChevronRight />
              </a>
              <a
                href="#wire-search-section"
                className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/80 px-5 py-2.5 text-xs font-bold text-slate-200 transition hover:border-slate-500 hover:text-white"
              >
                <FiSearch />
                <span>Search Wire Ledger</span>
              </a>
            </div>
          </div>
        </section>

        {/* Customer Accounts & Financial Status Dashboard */}
        <section id="accounts" className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white tracking-wide">
                Corporate Asset Portfolios
              </h3>
              <span className="text-xs text-slate-400">Live Balances</span>
            </div>
            <button
              onClick={() => setShowBalance(!showBalance)}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white font-medium"
            >
              {showBalance ? <FiEyeOff /> : <FiEye />}
              <span>{showBalance ? "Hide Balances" : "Reveal Balances"}</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                <span>Primary Commercial Checking</span>
                <span className="font-mono text-[10px] bg-slate-800 px-2 py-0.5 rounded text-amber-300">**** 8841</span>
              </div>
              <div className="text-2xl font-black text-white font-mono tracking-tight">
                {showBalance ? "$428,950.00" : "••••••••••"}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] text-emerald-400 mt-2 font-medium">
                <span>+4.85% APY High Yield Active</span>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                <span>Corporate Treasury Escrow</span>
                <span className="font-mono text-[10px] bg-slate-800 px-2 py-0.5 rounded text-cyan-300">**** 1092</span>
              </div>
              <div className="text-2xl font-black text-white font-mono tracking-tight">
                {showBalance ? "$2,500,000.00" : "••••••••••"}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] text-cyan-400 mt-2 font-medium">
                <span>Overnight Federal Reserve Repo</span>
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 shadow-lg relative overflow-hidden">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                <span>Corporate Visa Infinite Credit</span>
                <span className="font-mono text-[10px] bg-slate-800 px-2 py-0.5 rounded text-purple-300">**** 4402</span>
              </div>
              <div className="text-2xl font-black text-white font-mono tracking-tight">
                {showBalance ? "$48,120.50 Available" : "••••••••••"}
              </div>
              <div className="flex items-center gap-1.5 text-[11px] text-purple-400 mt-2 font-medium">
                <span>Limit: $250,000.00 • 0% Fraud Liability</span>
              </div>
            </div>
          </div>
        </section>

        {/* Live Attack Surface Area: Interactive Customer Login & Wire Lookup */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Surface 1: Real Customer Authentication Gateway */}
          <section id="login-section" className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <FiKey className="text-amber-400 text-lg" />
                  <h3 className="font-bold text-white text-sm">
                    Client Secure Sign-In Gateway
                  </h3>
                </div>
                <span className="text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
                  Target Endpoint: POST /api/victim/login
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Sign into your Apex Federal commercial account. Real-time active defense monitors this gateway for SQL injection auth bypass, brute force, and credential stuffing.
              </p>

              {/* Real Login Form */}
              <form onSubmit={handleLogin} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Client Account ID / Username
                  </label>
                  <div className="relative">
                    <FiUser className="absolute left-3.5 top-3 text-slate-500" />
                    <input
                      type="text"
                      value={loginUsername}
                      onChange={(e) => setLoginUsername(e.target.value)}
                      placeholder="e.g. corporate_lead or admin' OR '1'='1"
                      className="w-full bg-slate-950 text-white pl-10 pr-4 py-2 rounded-xl border border-slate-700 font-mono text-xs focus:border-amber-400 focus:outline-none transition shadow-inner"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Secret Security Password
                  </label>
                  <div className="relative">
                    <FiLock className="absolute left-3.5 top-3 text-slate-500" />
                    <input
                      type="password"
                      value={loginPassword}
                      onChange={(e) => setLoginPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full bg-slate-950 text-white pl-10 pr-4 py-2 rounded-xl border border-slate-700 font-mono text-xs focus:border-amber-400 focus:outline-none transition shadow-inner"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs pt-1">
                  <label className="flex items-center gap-2 text-slate-400 cursor-pointer">
                    <input type="checkbox" defaultChecked className="rounded bg-slate-950 border-slate-700 text-amber-500" />
                    <span>Remember Client Device</span>
                  </label>
                  <span className="text-slate-500 text-[11px]">Forgot Credentials?</span>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold py-2.5 rounded-xl text-xs transition shadow-lg shadow-amber-500/20 flex items-center justify-center gap-2 active:scale-95"
                >
                  {loading ? (
                    <FiRefreshCw className="animate-spin text-sm" />
                  ) : (
                    <FiLock className="text-sm" />
                  )}
                  <span>Authenticate to Secure Treasury</span>
                </button>
              </form>
            </div>

            {/* Response Banner */}
            {loginResponse && (
              <div className="mt-4 pt-3 border-t border-slate-800">
                {loginResponse.status === "attack_detected" || loginResponse.blocked ? (
                  <div className="bg-red-950/70 border border-red-700/70 rounded-xl p-3.5 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-red-300 font-bold">
                      <FiAlertTriangle className="text-red-400 text-base" />
                      <span>ThreatLens Active Defense Intercepted Intrusion!</span>
                    </div>
                    <p className="text-slate-200 font-mono text-[11px]">
                      {loginResponse.message || loginResponse.error}
                    </p>
                    {loginResponse.alert && (
                      <div className="bg-slate-950/90 p-2.5 rounded-lg border border-red-900/50 text-[11px] font-mono text-amber-300 flex items-center justify-between">
                        <span><strong>Rule:</strong> {loginResponse.alert.rule_name}</span>
                        <span className="bg-red-900/80 text-white px-2 py-0.5 rounded text-[10px] font-bold">
                          {loginResponse.alert.severity}
                        </span>
                      </div>
                    )}
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:underline font-bold mt-1"
                    >
                      <FiShield size={12} />
                      <span>View Defense Action & Mitigation in SOC Portal</span>
                    </button>
                  </div>
                ) : (
                  <div className="bg-emerald-950/60 border border-emerald-700/60 rounded-xl p-3 text-xs text-emerald-300 flex items-center gap-2">
                    <FiCheckCircle className="text-emerald-400 text-base" />
                    <div>
                      <span className="font-bold">Authentication Accepted:</span> {loginResponse.message || "Session initiated successfully."}
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* Surface 2: Wire Ledger & Transaction Search API */}
          <section id="wire-search-section" className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <FiSearch className="text-cyan-400 text-lg" />
                  <h3 className="font-bold text-white text-sm">
                    Wire Transfer & Transaction Lookup API
                  </h3>
                </div>
                <span className="text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
                  Target Endpoint: POST /api/victim/search
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Query enterprise wire batches, settlement IDs, or counterparties. This search input queries the underlying database and is defended against SQL injection fuzzer queries.
              </p>

              {/* Search Form */}
              <form onSubmit={handleSearch} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 mb-1">
                    Wire Reference / Counterparty Query
                  </label>
                  <div className="relative">
                    <FiSearch className="absolute left-3.5 top-3 text-slate-500" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="e.g. Amazon or ' UNION SELECT username, password FROM users--"
                      className="w-full bg-slate-950 text-white pl-10 pr-4 py-2 rounded-xl border border-slate-700 font-mono text-xs focus:border-cyan-400 focus:outline-none transition shadow-inner"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2.5 rounded-xl text-xs transition shadow-lg shadow-cyan-600/20 flex items-center justify-center gap-2 active:scale-95"
                >
                  {loading ? (
                    <FiRefreshCw className="animate-spin text-sm" />
                  ) : (
                    <FiSearch className="text-sm" />
                  )}
                  <span>Query Transaction Ledger</span>
                </button>
              </form>
            </div>

            {/* Search Results / Attack Response Container */}
            {searchResponse && (
              <div className="mt-4 pt-3 border-t border-slate-800">
                {searchResponse.status === "attack_detected" || searchResponse.blocked ? (
                  <div className="bg-red-950/70 border border-red-700/70 rounded-xl p-3.5 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-red-300 font-bold">
                      <FiAlertTriangle className="text-red-400 text-base" />
                      <span>SQL Injection Attack Blocked by WAF!</span>
                    </div>
                    <p className="text-slate-200 font-mono text-[11px]">
                      {searchResponse.message}
                    </p>
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:underline font-bold mt-1"
                    >
                      <FiShield size={12} />
                      <span>Review SQLi Attack Vector in SOC Dashboard</span>
                    </button>
                  </div>
                ) : (
                  <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-xs space-y-2">
                    <div className="text-slate-400 font-medium">
                      Found {searchResults?.length || 0} matching transaction records:
                    </div>
                    {searchResults && searchResults.length > 0 ? (
                      <div className="space-y-1.5 max-h-36 overflow-y-auto font-mono text-[11px]">
                        {searchResults.map((r, i) => (
                          <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
                            <span className="text-white font-bold">{r.description || r.title || "Transaction Item"}</span>
                            <span className="text-amber-400">{r.amount || "$0.00"}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-slate-500 italic text-[11px]">
                        No matching transactions found for query.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </section>
        </div>

        {/* Recent Financial Wire Ledger Table */}
        <section className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">
                Live Transaction & Settlement Ledger
              </h3>
              <p className="text-xs text-slate-400">
                Institutional escrow clearances and domestic wire settlements
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2.5 py-1 rounded-lg border border-slate-700">
              Fedwire Protocol Active
            </span>
          </div>

          <div className="overflow-x-auto mt-4">
            <table className="w-full text-left text-xs">
              <thead className="text-[11px] font-bold text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="pb-3 font-semibold">REFERENCE ID</th>
                  <th className="pb-3 font-semibold">TIMESTAMP</th>
                  <th className="pb-3 font-semibold">DESCRIPTION</th>
                  <th className="pb-3 font-semibold">PORTFOLIO</th>
                  <th className="pb-3 font-semibold text-right">SETTLEMENT</th>
                  <th className="pb-3 font-semibold text-center">STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {transactions.map((tx) => (
                  <tr key={tx.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 text-cyan-400 font-bold">{tx.id}</td>
                    <td className="py-3 text-slate-400">{tx.date}</td>
                    <td className="py-3 text-slate-200 font-sans font-medium">{tx.description}</td>
                    <td className="py-3 text-slate-400">{tx.account}</td>
                    <td className={`py-3 text-right font-bold ${tx.type === "credit" ? "text-emerald-400" : "text-slate-200"}`}>
                      {tx.amount}
                    </td>
                    <td className="py-3 text-center">
                      <span className="bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 px-2 py-0.5 rounded-full text-[10px] font-bold">
                        {tx.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {/* Floating Red Team Security Penetration Drawer / Dock */}
      {showAuditDrawer && (
        <aside className="fixed bottom-6 right-6 z-40 w-96 max-w-[calc(100vw-2rem)] rounded-2xl border border-cyan-500/40 bg-slate-900/95 p-5 shadow-2xl shadow-cyan-950/80 backdrop-blur-xl animate-in slide-in-from-bottom-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
              </span>
              <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                <FiTerminal size={14} /> Red Team Exploit Harness
              </h4>
            </div>
            <button
              onClick={() => setShowAuditDrawer(false)}
              className="text-slate-400 hover:text-white transition"
              title="Minimize exploit harness"
            >
              <FiX size={16} />
            </button>
          </div>

          <p className="text-[11px] text-slate-300 mb-3 leading-normal">
            Inject real-world attack vectors into Apex Federal Bank to test <strong>ThreatLens automated prevention</strong> and <strong>real-time quarantine</strong>.
          </p>

          {/* Attacker IP Persona Selector */}
          <div className="space-y-1.5 mb-3 text-xs">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
              Attacker IP Persona:
            </label>
            <select
              value={selectedIp}
              onChange={(e) => {
                setSelectedIp(e.target.value);
                setCustomIp("");
              }}
              className="w-full bg-slate-950 text-cyan-300 font-mono text-xs rounded-lg border border-slate-700 px-2.5 py-1.5 outline-none focus:border-cyan-500"
            >
              {DEFAULT_ATTACK_IPS.map((item) => (
                <option key={item.ip} value={item.ip}>
                  {item.ip} ({item.label})
                </option>
              ))}
            </select>
          </div>

          {/* 1-Click Exploit Buttons */}
          <div className="space-y-2 text-xs">
            <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
              Quick Exploit Presets (1-Click Inject):
            </label>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                type="button"
                onClick={(e) => {
                  setLoginUsername("admin' OR '1'='1");
                  setLoginPassword("any_password");
                  handleLogin(e, "admin' OR '1'='1", "any_password");
                }}
                className="text-[11px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono p-2 rounded-lg text-left transition font-semibold"
              >
                ⚡ SQLi: ' OR '1'='1
              </button>

              <button
                type="button"
                onClick={(e) => {
                  setLoginUsername("admin'--");
                  setLoginPassword("ignored");
                  handleLogin(e, "admin'--", "ignored");
                }}
                className="text-[11px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono p-2 rounded-lg text-left transition font-semibold"
              >
                ⚡ SQLi: admin'--
              </button>

              <button
                type="button"
                onClick={(e) => {
                  setLoginUsername("finance_lead");
                  setLoginPassword("badpass");
                  handleLogin(e, "finance_lead", "badpass", 5);
                }}
                className="text-[11px] bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 font-mono p-2 rounded-lg text-left transition font-semibold"
              >
                ⚡ Brute Force (x5)
              </button>

              <button
                type="button"
                onClick={(e) => {
                  setSearchQuery("' UNION SELECT username, password FROM users--");
                  handleSearch(e, "' UNION SELECT username, password FROM users--");
                }}
                className="text-[11px] bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono p-2 rounded-lg text-left transition font-semibold"
              >
                ⚡ Wire SQLi Injection
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between pt-3 mt-3 border-t border-slate-800 text-xs">
            <button
              onClick={handleResetIp}
              disabled={loading}
              className="text-slate-400 hover:text-white underline text-[11px] flex items-center gap-1"
            >
              <FiRefreshCw className={loading ? "animate-spin" : ""} size={10} />
              Reset Attacker IP
            </button>
            <button
              onClick={onSwitchToAdmin}
              className="bg-sky-600 hover:bg-sky-500 text-white font-bold px-3 py-1 rounded-lg text-[11px] shadow transition"
            >
              Go to SOC Portal →
            </button>
          </div>
        </aside>
      )}

      {/* Institutional Footer */}
      <footer className="bg-slate-950 border-t border-slate-800/80 px-6 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-400">Apex Federal Trust Bank N.A.</span>
            <span>•</span>
            <span>Member FDIC</span>
            <span>•</span>
            <span>Equal Housing Lender</span>
          </div>
          <div className="text-[11px] text-slate-400 flex items-center gap-2">
            <span>ThreatLens Active Defense Monitoring Active</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          </div>
        </div>
      </footer>
    </div>
  );
}
