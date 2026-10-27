import React, { useState, useEffect } from "react";
import {
  FaTimes,
  FaShieldAlt,
  FaLock,
  FaUnlock,
  FaBolt,
  FaTerminal,
  FaCheckCircle,
  FaExclamationTriangle,
  FaBan,
  FaHistory,
  FaList,
  FaCopy
} from "react-icons/fa";
import {
  getDefenseStatus,
  toggleAutoDefense,
  blockIp,
  unblockIp,
  getDefenseRecommendations,
  simulateAttack
} from "../services/api.js";

export default function DefenseCenterModal({ onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState("quarantine"); // 'quarantine' | 'simulate' | 'audit' | 'recommendations'
  const [statusData, setStatusData] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionFeedback, setActionFeedback] = useState("");
  const [copiedCmd, setCopiedCmd] = useState(null);

  // Manual Block IP Form state
  const [manualIp, setManualIp] = useState("");
  const [manualReason, setManualReason] = useState("");
  const [submittingBlock, setSubmittingBlock] = useState(false);

  // Attack Simulation State
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, recsRes] = await Promise.all([
        getDefenseStatus(),
        getDefenseRecommendations()
      ]);
      setStatusData(statusRes);
      setRecommendations(recsRes || []);
    } catch (err) {
      setError(err.message || "Failed to load defense telemetry.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleAuto = async () => {
    const currentState = statusData?.summary?.auto_defense_enabled ?? true;
    try {
      const res = await toggleAutoDefense(!currentState);
      setActionFeedback(`Auto-Defense ${res.auto_defense_enabled ? "ENABLED" : "DISABLED"}`);
      loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(`Failed to toggle auto defense: ${err.message}`);
    }
  };

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!manualIp.trim()) return;
    setSubmittingBlock(true);
    setActionFeedback("");
    try {
      await blockIp(manualIp, manualReason || "Manual Administrator Quarantine");
      setManualIp("");
      setManualReason("");
      setActionFeedback(`Successfully quarantined IP ${manualIp}`);
      loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message || "Failed to block IP.");
    } finally {
      setSubmittingBlock(false);
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await unblockIp(ip);
      setActionFeedback(`Removed quarantine from IP ${ip}`);
      loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(`Failed to unblock: ${err.message}`);
    }
  };

  const handleSimulateAttack = async (type) => {
    setSimulating(true);
    setSimResult(null);
    setActionFeedback("");
    try {
      const res = await simulateAttack(type);
      setSimResult(res);
      setActionFeedback(`Live Attack Injected: ${res.scenario}. Auto-prevention triggered!`);
      loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message || "Simulation failed.");
    } finally {
      setSimulating(false);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const isAutoEnabled = statusData?.summary?.auto_defense_enabled ?? true;
  const blockedList = statusData?.blocked_ips || [];
  const actionsList = statusData?.recent_actions || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-fadeIn">
      <div className="relative flex max-h-[92vh] w-full max-w-5xl flex-col rounded-2xl border border-slate-700 bg-card shadow-2xl overflow-hidden">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-700/80 px-6 py-4 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/40 shadow-lg shadow-emerald-500/10">
              <FaShieldAlt size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                  ThreatLens Active Defense
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                  isAutoEnabled ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-warning/20 text-warning border border-warning/30"
                }`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${isAutoEnabled ? "bg-emerald-400 animate-pulse" : "bg-warning"}`} />
                  {isAutoEnabled ? "Auto-Prevention Active" : "Monitoring Only"}
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                SOC Defense & Prevention Center
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleToggleAuto}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                isAutoEnabled
                  ? "bg-slate-700 hover:bg-slate-600 text-slate-200"
                  : "bg-emerald-600 hover:bg-emerald-500 text-white"
              }`}
            >
              {isAutoEnabled ? <FaLock size={11} /> : <FaUnlock size={11} />}
              {isAutoEnabled ? "Disable Auto-Defense" : "Enable Auto-Defense"}
            </button>
            <button
              onClick={onClose}
              aria-label="Close modal"
              className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 transition hover:bg-slate-700 hover:text-white"
            >
              <FaTimes size={18} />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-700 bg-slate-900/40 px-6">
          <button
            onClick={() => setActiveTab("quarantine")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 text-xs font-semibold transition ${
              activeTab === "quarantine"
                ? "border-emerald-400 text-emerald-400 bg-emerald-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaBan size={12} />
            Quarantine List ({blockedList.filter(b => b.status === "active").length})
          </button>
          <button
            onClick={() => setActiveTab("simulate")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 text-xs font-semibold transition ${
              activeTab === "simulate"
                ? "border-accent text-accent bg-accent/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaBolt size={12} />
            Real-World Attack Simulator
          </button>
          <button
            onClick={() => setActiveTab("audit")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 text-xs font-semibold transition ${
              activeTab === "audit"
                ? "border-purple-400 text-purple-400 bg-purple-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaHistory size={12} />
            Defense Actions Audit ({actionsList.length})
          </button>
          <button
            onClick={() => setActiveTab("recommendations")}
            className={`flex items-center gap-2 border-b-2 py-3 px-4 text-xs font-semibold transition ${
              activeTab === "recommendations"
                ? "border-amber-400 text-amber-400 bg-amber-500/5"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FaList size={12} />
            Admin Hardening Guidance
          </button>
        </div>

        {/* Feedback & Alerts */}
        {actionFeedback && (
          <div className="mx-6 mt-4 flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-400 font-medium animate-fadeIn">
            <FaCheckCircle size={14} />
            <span>{actionFeedback}</span>
          </div>
        )}
        {error && (
          <div className="mx-6 mt-4 flex items-center gap-2 rounded-lg border border-danger/40 bg-danger/10 px-4 py-2.5 text-xs text-danger font-medium animate-fadeIn">
            <FaExclamationTriangle size={14} />
            <span>{error}</span>
          </div>
        )}

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* TAB 1: Quarantine & Blocked IPs */}
          {activeTab === "quarantine" && (
            <div className="space-y-6">
              {/* Manual Block Form */}
              <div className="rounded-xl border border-slate-700/80 bg-slate-900/50 p-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                  <FaBan className="text-danger" /> Quarantine an Attacker IP Address
                </h3>
                <form onSubmit={handleManualBlock} className="flex flex-wrap gap-3">
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.88"
                    value={manualIp}
                    onChange={(e) => setManualIp(e.target.value)}
                    className="flex-1 min-w-[200px] rounded-lg border border-slate-700 bg-slate-800/90 px-3.5 py-2 font-mono text-xs text-white placeholder-slate-500 focus:border-emerald-400 focus:outline-none"
                    required
                  />
                  <input
                    type="text"
                    placeholder="Reason (e.g. Repeated SQLi probes / SSH brute force)"
                    value={manualReason}
                    onChange={(e) => setManualReason(e.target.value)}
                    className="flex-[2] min-w-[260px] rounded-lg border border-slate-700 bg-slate-800/90 px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:border-emerald-400 focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={submittingBlock}
                    className="rounded-lg bg-danger/80 hover:bg-danger px-4 py-2 text-xs font-bold text-white transition disabled:opacity-50"
                  >
                    {submittingBlock ? "Quarantining..." : "Block IP"}
                  </button>
                </form>
              </div>

              {/* Blocked IPs Table */}
              <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 overflow-hidden">
                <div className="border-b border-slate-700 px-4 py-3 flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Active Firewall & Application Quarantine
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    Enforced at HTTP/Flask Filter & SQLite
                  </span>
                </div>

                {blockedList.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-400">
                    No IPs currently quarantined. When attacks occur or thresholds are met, attacker IPs appear here automatically.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-700 bg-slate-900/80 text-slate-400 font-mono">
                        <tr>
                          <th className="px-4 py-2.5">Target IP</th>
                          <th className="px-4 py-2.5">Reason</th>
                          <th className="px-4 py-2.5">Rule</th>
                          <th className="px-4 py-2.5">Blocked At</th>
                          <th className="px-4 py-2.5">Status</th>
                          <th className="px-4 py-2.5 text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {blockedList.map((row) => (
                          <tr key={row.id} className="hover:bg-slate-800/40">
                            <td className="px-4 py-2.5 font-mono text-white font-semibold">
                              {row.ip_address}
                            </td>
                            <td className="px-4 py-2.5 text-slate-300">
                              {row.reason}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-accent">
                              {row.rule_id || "-"}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-slate-400">
                              {row.blocked_at?.slice(0, 19).replace("T", " ")}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                                row.status === "active"
                                  ? "bg-danger/20 text-danger border border-danger/40"
                                  : "bg-slate-700 text-slate-300 border border-slate-600"
                              }`}>
                                {row.status}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-right">
                              {row.status === "active" ? (
                                <button
                                  onClick={() => handleUnblock(row.ip_address)}
                                  className="rounded bg-slate-700 hover:bg-slate-600 px-2.5 py-1 text-[11px] font-semibold text-slate-200 transition"
                                >
                                  Unblock
                                </button>
                              ) : (
                                <button
                                  onClick={() => blockIp(row.ip_address, "Re-quarantined by admin").then(() => loadData())}
                                  className="rounded bg-danger/20 hover:bg-danger/30 px-2.5 py-1 text-[11px] font-semibold text-danger border border-danger/40 transition"
                                >
                                  Re-block
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: Real-World Attack Simulator */}
          {activeTab === "simulate" && (
            <div className="space-y-6">
              <div className="rounded-xl border border-slate-700/80 bg-slate-900/50 p-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-accent mb-2">
                  Real-World Attack Injection & Instant Auto-Defense Verification
                </h3>
                <p className="text-xs text-slate-400 mb-4">
                  Trigger authentic attack vectors against this system. ThreatLens parses the live log stream, evaluates the detection rules, automatically quarantines the attacking IP, logs the mitigation, and presents administrator remediation instructions.
                </p>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {/* SQL Injection */}
                  <div className="rounded-lg border border-red-500/30 bg-slate-800/80 p-3.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-red-400">DR-06</span>
                        <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-bold text-red-400">HIGH</span>
                      </div>
                      <h4 className="mt-1 font-bold text-white text-sm">SQL Injection (SQLi)</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                        Injects quote escapes, boolean tautologies (<code>' OR '1'='1</code>), and UNION queries.
                      </p>
                    </div>
                    <button
                      disabled={simulating}
                      onClick={() => handleSimulateAttack("sqli")}
                      className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                    >
                      <FaBolt size={10} /> Test SQL Injection Attack
                    </button>
                  </div>

                  {/* SSH Brute Force */}
                  <div className="rounded-lg border border-amber-500/30 bg-slate-800/80 p-3.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-amber-400">DR-01</span>
                        <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-bold text-amber-400">MEDIUM</span>
                      </div>
                      <h4 className="mt-1 font-bold text-white text-sm">Multiple Password Try (Brute Force)</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                        10 rapid failed password attempts in under 2 minutes from 192.168.1.105.
                      </p>
                    </div>
                    <button
                      disabled={simulating}
                      onClick={() => handleSimulateAttack("brute_force")}
                      className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                    >
                      <FaBolt size={10} /> Test Brute Force Attack
                    </button>
                  </div>

                  {/* Password Spraying */}
                  <div className="rounded-lg border border-orange-500/30 bg-slate-800/80 p-3.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-orange-400">DR-03</span>
                        <span className="rounded bg-orange-500/20 px-1.5 py-0.5 text-[10px] font-bold text-orange-400">HIGH</span>
                      </div>
                      <h4 className="mt-1 font-bold text-white text-sm">Password Spraying Campaign</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                        Attempts 1 common password across 6 corporate accounts from 198.51.100.42.
                      </p>
                    </div>
                    <button
                      disabled={simulating}
                      onClick={() => handleSimulateAttack("spray")}
                      className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-orange-600 hover:bg-orange-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                    >
                      <FaBolt size={10} /> Test Password Spraying
                    </button>
                  </div>

                  {/* Direct Root Breach */}
                  <div className="rounded-lg border border-purple-500/30 bg-slate-800/80 p-3.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-purple-400">DR-05</span>
                        <span className="rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] font-bold text-purple-400">HIGH</span>
                      </div>
                      <h4 className="mt-1 font-bold text-white text-sm">Direct Root Login Breach</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                        Privileged root login accepted directly from external IP 203.0.113.77.
                      </p>
                    </div>
                    <button
                      disabled={simulating}
                      onClick={() => handleSimulateAttack("root")}
                      className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                    >
                      <FaBolt size={10} /> Test Root Breach Attack
                    </button>
                  </div>

                  {/* Compromise */}
                  <div className="rounded-lg border border-rose-500/30 bg-slate-800/80 p-3.5 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-rose-400">DR-04</span>
                        <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] font-bold text-rose-400">CRITICAL</span>
                      </div>
                      <h4 className="mt-1 font-bold text-white text-sm">Success After Failures</h4>
                      <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                        6 failed attempts followed by password guess breakthrough.
                      </p>
                    </div>
                    <button
                      disabled={simulating}
                      onClick={() => handleSimulateAttack("compromise")}
                      className="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 px-3 py-1.5 text-xs font-bold text-white transition disabled:opacity-50"
                    >
                      <FaBolt size={10} /> Test Compromise Attack
                    </button>
                  </div>
                </div>
              </div>

              {/* Simulation Result Presentation */}
              {simResult && (
                <div className="rounded-xl border border-emerald-500/50 bg-slate-900/90 p-5 space-y-4 animate-fadeIn">
                  <div className="flex items-center justify-between border-b border-slate-700 pb-3">
                    <div className="flex items-center gap-2">
                      <FaCheckCircle className="text-emerald-400" size={16} />
                      <h4 className="font-bold text-white text-sm">
                        Live Attack Injected: {simResult.scenario}
                      </h4>
                    </div>
                    <span className="font-mono text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      Auto-Quarantine Executed
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
                    <div className="rounded bg-slate-800/80 p-2.5 border border-slate-700">
                      <div className="text-slate-400">Attacker IP</div>
                      <div className="font-mono font-bold text-white mt-0.5">{simResult.attacker_ip}</div>
                    </div>
                    <div className="rounded bg-slate-800/80 p-2.5 border border-slate-700">
                      <div className="text-slate-400">Events Logged</div>
                      <div className="font-mono font-bold text-accent mt-0.5">{simResult.events_logged}</div>
                    </div>
                    <div className="rounded bg-slate-800/80 p-2.5 border border-slate-700">
                      <div className="text-slate-400">Alerts Generated</div>
                      <div className="font-mono font-bold text-warning mt-0.5">{simResult.alerts_generated}</div>
                    </div>
                    <div className="rounded bg-slate-800/80 p-2.5 border border-slate-700">
                      <div className="text-slate-400">Firewall Action</div>
                      <div className="font-mono font-bold text-emerald-400 mt-0.5">BLOCKED (403)</div>
                    </div>
                  </div>

                  {/* Immediate Remediation Recommendations */}
                  {simResult.recommendations && (
                    <div className="rounded-lg bg-slate-800/60 p-4 border border-slate-700 space-y-3">
                      <h5 className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-2">
                        <FaTerminal /> Recommended Admin Actions for {simResult.recommendations.attack_name}
                      </h5>
                      
                      <div className="space-y-1.5 text-xs text-slate-300">
                        {simResult.recommendations.immediate_actions.map((act, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className="text-emerald-400 font-bold">•</span>
                            <span>{act}</span>
                          </div>
                        ))}
                      </div>

                      {simResult.recommendations.auto_prevention_method?.iptables_rule && (
                        <div className="mt-2 rounded bg-slate-950 p-2.5 font-mono text-xs text-slate-200 border border-slate-800 flex items-center justify-between">
                          <span>{simResult.recommendations.auto_prevention_method.iptables_rule}</span>
                          <button
                            onClick={() => handleCopy(simResult.recommendations.auto_prevention_method.iptables_rule, "sim-cmd")}
                            className="text-slate-400 hover:text-accent ml-2"
                            title="Copy command"
                          >
                            {copiedCmd === "sim-cmd" ? "Copied!" : <FaCopy />}
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: Defense Actions Audit Log */}
          {activeTab === "audit" && (
            <div className="rounded-xl border border-slate-700/80 bg-slate-900/60 overflow-hidden">
              <div className="border-b border-slate-700 px-4 py-3 flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Automated & Manual Defense Audit Trail
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  table: defense_actions
                </span>
              </div>

              {actionsList.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-400">
                  No defense actions logged yet.
                </div>
              ) : (
                <div className="overflow-x-auto max-h-96 overflow-y-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-700 bg-slate-900/90 text-slate-400 font-mono sticky top-0">
                      <tr>
                        <th className="px-4 py-2.5">Timestamp</th>
                        <th className="px-4 py-2.5">Action Type</th>
                        <th className="px-4 py-2.5">Target IP</th>
                        <th className="px-4 py-2.5">Rule</th>
                        <th className="px-4 py-2.5">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      {actionsList.map((act) => (
                        <tr key={act.id} className="hover:bg-slate-800/40">
                          <td className="px-4 py-2 font-mono whitespace-nowrap text-slate-400">
                            {act.timestamp?.slice(0, 19).replace("T", " ")}
                          </td>
                          <td className="px-4 py-2 whitespace-nowrap">
                            <span className="rounded bg-purple-500/20 px-2 py-0.5 text-[10px] font-mono font-bold text-purple-300 border border-purple-500/30 uppercase">
                              {act.action_type}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-white font-semibold">
                            {act.target_ip}
                          </td>
                          <td className="px-4 py-2 font-mono text-accent">
                            {act.rule_id || "-"}
                          </td>
                          <td className="px-4 py-2 text-slate-300 text-[11px]">
                            {act.details}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Admin Hardening Guidance */}
          {activeTab === "recommendations" && (
            <div className="space-y-4">
              <div className="text-xs text-slate-400 mb-2">
                Standard Operating Procedures (SOP) and security hardening guidelines for all RSD and Web cyber attacks:
              </div>

              <div className="space-y-4">
                {recommendations.map((rec) => (
                  <div key={rec.rule_id} className="rounded-xl border border-slate-700/80 bg-slate-900/60 p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-700/60 pb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-accent bg-accent/10 px-2 py-0.5 rounded border border-accent/20">
                          {rec.rule_id}
                        </span>
                        <h4 className="font-bold text-white text-sm">
                          {rec.attack_name}
                        </h4>
                      </div>
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                        rec.threat_level === "Critical"
                          ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                          : rec.threat_level === "High"
                          ? "bg-red-500/20 text-red-400 border border-red-500/40"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                      }`}>
                        {rec.threat_level} Severity
                      </span>
                    </div>

                    <p className="text-xs text-slate-300">{rec.summary}</p>

                    {/* Automated Prevention */}
                    <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/30 p-3">
                      <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block mb-1">
                        Automated ThreatLens Prevention
                      </span>
                      <p className="text-xs text-slate-300">
                        {rec.auto_prevention_method?.description}
                      </p>
                    </div>

                    {/* System Hardening Checklist */}
                    {rec.system_hardening && rec.system_hardening.length > 0 && (
                      <div className="space-y-2 pt-1">
                        <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">
                          Hardening & Protection Checklist
                        </span>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          {rec.system_hardening.map((hard, idx) => (
                            <div key={idx} className="rounded-lg bg-slate-800/70 border border-slate-700/70 p-3 text-xs space-y-1.5">
                              <div className="font-semibold text-white">{hard.title}</div>
                              <div className="text-slate-400 text-[11px] leading-relaxed">{hard.detail}</div>
                              {hard.command && (
                                <div className="rounded bg-slate-950 p-2 font-mono text-[10px] text-accent flex items-center justify-between border border-slate-800">
                                  <span className="truncate">{hard.command}</span>
                                  <button
                                    onClick={() => handleCopy(hard.command, `${rec.rule_id}-${idx}`)}
                                    className="text-slate-400 hover:text-white ml-2 flex-shrink-0"
                                    title="Copy command"
                                  >
                                    {copiedCmd === `${rec.rule_id}-${idx}` ? "Copied!" : <FaCopy />}
                                  </button>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between border-t border-slate-700/80 px-6 py-3 bg-slate-900/60">
          <div className="text-xs text-slate-400">
            Active Protection Status: <span className="font-mono text-emerald-400 font-semibold">{isAutoEnabled ? "Auto-Quarantine Active" : "Disabled"}</span>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-700 px-4 py-2 text-xs font-semibold text-white transition hover:bg-slate-600"
          >
            Close Defense Center
          </button>
        </div>

      </div>
    </div>
  );
}
