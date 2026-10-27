import React, { useState, useEffect } from "react";
import {
  FiShield,
  FiAlertTriangle,
  FiLock,
  FiUser,
  FiSearch,
  FiCheckCircle,
  FiRefreshCw,
  FiArrowRight,
  FiDollarSign,
  FiCreditCard,
  FiEye,
  FiEyeOff,
  FiChevronRight,
  FiKey
} from "react-icons/fi";
import {
  getVictimStatus,
  submitVictimLogin,
  submitVictimSearch,
  resetVictimIp
} from "../services/api.js";

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
  const [activeIp] = useState("198.51.100.42");
  const [isQuarantined, setIsQuarantined] = useState(false);
  const [quarantineInfo, setQuarantineInfo] = useState(null);
  const [loading, setLoading] = useState(false);

  // Customer portal interactive state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [showBalance, setShowBalance] = useState(true);
  const [transactions] = useState(INITIAL_TRANSACTIONS);

  // Login form state
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginResponse, setLoginResponse] = useState(null);

  // Search form state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searchResponse, setSearchResponse] = useState(null);

  // Fetch status of the current client IP from WAF
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
  const handleLogin = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!loginUsername.trim()) return;

    setLoading(true);
    setLoginResponse(null);
    try {
      const res = await submitVictimLogin({
        username: loginUsername,
        password: loginPassword,
        client_ip: activeIp,
        simulate_count: 1
      });
      setLoginResponse(res);
      await checkStatus();

      if (res?.status === "authenticated" || res?.token) {
        setIsAuthenticated(true);
      }
    } catch (err) {
      setLoginResponse({
        error: err.message || "Authentication gateway unavailable.",
        status: "error"
      });
    } finally {
      setLoading(false);
    }
  };

  // Handle Search submission
  const handleSearch = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!searchQuery.trim()) return;

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
        error: err.message || "Query failed.",
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
          <span className="text-slate-400">Federal Reserve ABA Routing: <strong className="text-slate-200">021000021</strong></span>
          <span className="text-slate-600">|</span>
          <button
            onClick={onSwitchToAdmin}
            className="flex items-center gap-1 font-semibold text-cyan-400 hover:text-cyan-300 transition"
          >
            <span>SOC Security Gateway</span>
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
            <a href="#compliance" className="hover:text-amber-400 transition">Compliance & Disclosures</a>
          </nav>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <div className="flex items-center gap-2 bg-slate-800/80 border border-slate-700 px-3 py-1.5 rounded-lg text-xs">
                <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-slate-300 font-medium">Account:</span>
                <span className="font-mono font-bold text-amber-300">{loginUsername || "Corporate Officer"}</span>
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

        {/* 403 Forbidden Shield Screen if Host IP is Quarantined by WAF */}
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
                      Apex Security Shield • Web Application Firewall
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
                  <span>Inspect in SOC Security Operations</span>
                </button>
                <button
                  onClick={handleResetIp}
                  disabled={loading}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-4 py-2.5 rounded-xl border border-slate-700 text-xs transition active:scale-95"
                >
                  <FiRefreshCw className={loading ? "animate-spin" : ""} size={14} />
                  <span>Request Firewall Unblock</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 mt-6 text-xs font-mono">
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Client Origin:</span>
                <span className="text-cyan-400 font-bold text-sm">{activeIp}</span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Firewall Rule Violation:</span>
                <span className="text-amber-400 font-bold text-sm">
                  {quarantineInfo?.rule_id || "DR-06 / SQL Injection Exploit"}
                </span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">WAF Disposition:</span>
                <span className="text-emerald-400 font-bold text-sm">CONNECTION DROPPED</span>
              </div>
              <div className="bg-slate-950/80 p-3 rounded-xl border border-red-900/50">
                <span className="text-slate-400 block text-[10px] uppercase">Incident Ray ID:</span>
                <span className="text-slate-300 font-bold text-sm">WAF-RAY-9908F41A</span>
              </div>
            </div>
          </div>
        )}

        {/* Hero Section */}
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
              Apex Federal provides frictionless commercial treasury, automated wire clearances, and programmatic liquidity. Backed by real-time automated intrusion defense.
            </p>
            <div className="flex flex-wrap items-center gap-4 pt-2">
              <a
                href="#login-section"
                className="inline-flex items-center gap-2 rounded-xl bg-amber-500 px-5 py-2.5 text-xs font-bold text-slate-950 shadow-lg shadow-amber-500/25 transition hover:bg-amber-400 active:scale-95"
              >
                <span>Client Sign-In</span>
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

        {/* Live Authentication & Transaction Search */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Real Customer Authentication Gateway */}
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
                  Protected by Active WAF
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Sign into your Apex Federal commercial account. Secure multi-factor session validation is enforced.
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
                      placeholder="corporate_treasury_lead"
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
                  <span className="text-slate-500 text-[11px] cursor-pointer hover:underline">Forgot Credentials?</span>
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
                      <span>Security Violation Intercepted by WAF</span>
                    </div>
                    <p className="text-slate-200 font-mono text-[11px]">
                      {loginResponse.message || loginResponse.error}
                    </p>
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:underline font-bold mt-1"
                    >
                      <FiShield size={12} />
                      <span>Review Security Disposition in SOC Portal</span>
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

          {/* Wire Ledger & Transaction Search API */}
          <section id="wire-search-section" className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <FiSearch className="text-cyan-400 text-lg" />
                  <h3 className="font-bold text-white text-sm">
                    Wire Transfer & Transaction Lookup
                  </h3>
                </div>
                <span className="text-[10px] font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded border border-slate-700">
                  Fedwire Query API
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                Query enterprise wire batches, settlement IDs, or counterparties across the clearing network.
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
                      placeholder="e.g. Amazon or Sovereign Liquidity"
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

            {/* Search Results */}
            {searchResponse && (
              <div className="mt-4 pt-3 border-t border-slate-800">
                {searchResponse.status === "attack_detected" || searchResponse.blocked ? (
                  <div className="bg-red-950/70 border border-red-700/70 rounded-xl p-3.5 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-red-300 font-bold">
                      <FiAlertTriangle className="text-red-400 text-base" />
                      <span>Security Violation Intercepted by WAF</span>
                    </div>
                    <p className="text-slate-200 font-mono text-[11px]">
                      {searchResponse.message}
                    </p>
                    <button
                      onClick={onSwitchToAdmin}
                      className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:underline font-bold mt-1"
                    >
                      <FiShield size={12} />
                      <span>Review Incident in SOC Dashboard</span>
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
          <div className="text-[11px] text-slate-400 flex items-center gap-3">
            <span>Automated Active Defense Protected</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            <button
              onClick={onSwitchToAdmin}
              className="text-slate-400 hover:text-white underline"
            >
              Security Operations Console
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
