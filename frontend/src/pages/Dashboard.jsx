import React, { useState } from "react";
import {
  FaListUl,
  FaBell,
  FaExclamationTriangle,
  FaNetworkWired,
  FaPlug,
  FaRedo,
  FaShieldAlt,
  FaBan,
  FaBolt,
  FaGlobe,
  FaDesktop,
  FaLayerGroup,
  FaChartPie,
} from "react-icons/fa";
import Header from "../components/Header.jsx";
import StatCard, { StatCardSkeleton } from "../components/StatCard.jsx";
import Charts, { ChartSkeleton } from "../components/Charts.jsx";
import AlertsTable from "../components/AlertsTable.jsx";
import EventsTable from "../components/EventsTable.jsx";
import EndpointTelemetryTable from "../components/EndpointTelemetryTable.jsx";
import ThreatRadar from "../components/ThreatRadar.jsx";

import AlertDetailModal from "../components/AlertDetailModal.jsx";
import EventDetailModal from "../components/EventDetailModal.jsx";
import IngestModal from "../components/IngestModal.jsx";
import DatabaseHealthModal from "../components/DatabaseHealthModal.jsx";
import TesterCenterModal from "../components/TesterCenterModal.jsx";
import DefenseCenterModal from "../components/DefenseCenterModal.jsx";
import useDashboardData from "../hooks/useDashboardData.js";
import { simulateAttack } from "../services/api.js";

function LoadingState() {
  return (
    <div className="space-y-6" aria-busy="true">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-600 border-t-accent" />
        Connecting to ThreatLens SIEM Backend...
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <StatCardSkeleton key={i} />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <ChartSkeleton key={i} />
        ))}
      </div>
    </div>
  );
}

function ErrorState({ message, onRetry, retrying }) {
  return (
    <div
      role="alert"
      className="mx-auto mt-16 max-w-lg rounded-2xl border border-danger/40 bg-slate-900/90 p-8 text-center shadow-2xl backdrop-blur-md"
    >
      <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-danger/15 text-danger ring-1 ring-danger/40 shadow-lg shadow-danger/10">
        <FaPlug size={24} />
      </div>

      <h2 className="text-xl font-bold text-white tracking-tight">
        SIEM API Connection Disrupted
      </h2>

      <p className="mt-2 text-xs text-slate-400 leading-relaxed">{message}</p>

      <button
        onClick={onRetry}
        disabled={retrying}
        className="mt-6 inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-xs font-bold text-primary transition hover:bg-sky-300 focus:outline-none disabled:opacity-60 shadow-lg shadow-accent/20"
      >
        <FaRedo className={retrying ? "animate-spin" : ""} size={12} />
        {retrying ? "Reconnecting..." : "Retry Connection"}
      </button>
    </div>
  );
}

export default function Dashboard({ onSwitchToVictim }) {
  const {
    data,
    endpointEvents,
    endpointLoading,
    endpointError,
    loading,
    refreshing,
    error,
    lastUpdated,
    retry,
  } = useDashboardData();

  // Active SOC tab view
  const [activeTab, setActiveTab] = useState("all");
  const [simulating, setSimulating] = useState(false);

  // Interactive modal states
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [showDbHealthModal, setShowDbHealthModal] = useState(false);
  const [showTesterCenter, setShowTesterCenter] = useState(false);
  const [showDefenseCenter, setShowDefenseCenter] = useState(false);

  const defense = data?.defense || {
    auto_defense_enabled: true,
    active_quarantined_ips: 0,
    total_defense_actions: 0,
  };

  const handleTriggerScan = async () => {
    setSimulating(true);
    try {
      await simulateAttack("brute_force", "198.51.100.42");
      await retry();
    } catch {
      // Ignored
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 pb-20 selection:bg-cyan-500 selection:text-black">
      <Header
        lastUpdated={lastUpdated}
        refreshing={refreshing}
        onRefresh={retry}
        offline={!!error}
        onOpenIngest={() => setShowIngestModal(true)}
        onOpenDbHealth={() => setShowDbHealthModal(true)}
        onOpenTesterCenter={() => setShowTesterCenter(true)}
        onOpenDefenseCenter={() => setShowDefenseCenter(true)}
        onSwitchToVictim={onSwitchToVictim}
        defenseActive={defense.auto_defense_enabled}
        blockedCount={defense.active_quarantined_ips}
      />

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {loading && !data && <LoadingState />}

        {error && !data && !loading && (
          <ErrorState
            message={error}
            onRetry={retry}
            retrying={refreshing}
          />
        )}

        {data && (
          <>
            {error && (
              <div
                role="alert"
                className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-xs text-warning shadow-lg backdrop-blur-md"
              >
                <span>
                  Connection lost to telemetry ingestion daemon. Showing cached database snapshots. Retrying automatically.
                </span>
                <button
                  onClick={retry}
                  className="font-bold underline underline-offset-2 hover:text-white"
                >
                  Retry Now
                </button>
              </div>
            )}

            {/* Active Defense & Live Auto-Prevention Operations Banner */}
            <section className="relative overflow-hidden rounded-2xl border border-emerald-500/40 bg-gradient-to-r from-slate-900 via-slate-900/95 to-emerald-950/40 p-5 shadow-2xl backdrop-blur-md">
              <div className="absolute right-0 top-0 -mt-10 -mr-10 h-64 w-64 rounded-full bg-emerald-500/10 blur-3xl pointer-events-none" />
              
              <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5">
                <div className="flex items-start sm:items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/40 shadow-lg shadow-emerald-500/20 shrink-0">
                    <FaShieldAlt size={24} />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2.5">
                      <h2 className="text-base font-extrabold text-white tracking-tight">
                        Active Threat Prevention & Automated Intrusion Quarantine
                      </h2>
                      <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10px] font-extrabold uppercase tracking-wider ${
                        defense.auto_defense_enabled
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-warning/20 text-warning border border-warning/40"
                      }`}>
                        <span className={`h-2 w-2 rounded-full ${defense.auto_defense_enabled ? "bg-emerald-400 animate-pulse" : "bg-warning"}`} />
                        {defense.auto_defense_enabled ? "Auto-Prevention Armed" : "Monitoring Only"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
                      Continuous real-time correlation against SSH brute force (DR-01), password spraying (DR-04), unauthorized root logins (DR-03), and Web SQL injection (DR-06). Malicious client IPs are automatically quarantined with a 403 WAF shield.
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5 shrink-0 w-full lg:w-auto justify-start lg:justify-end">
                  <div className="flex items-center gap-2 rounded-xl bg-slate-950/80 px-3.5 py-2 border border-slate-700/80 text-xs">
                    <FaBan className="text-rose-500" size={13} />
                    <span className="text-slate-400">Quarantined Hosts:</span>
                    <span className="font-mono font-black text-rose-400 text-sm">
                      {defense.active_quarantined_ips}
                    </span>
                  </div>

                  <button
                    onClick={onSwitchToVictim}
                    title="Open monitored Apex Federal Bank asset in new view"
                    className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-cyan-600/30 transition active:scale-95"
                  >
                    <FaGlobe size={13} />
                    <span>Apex Bank Asset</span>
                  </button>

                  <button
                    onClick={() => setShowDefenseCenter(true)}
                    className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-xs font-bold text-white shadow-lg shadow-emerald-600/30 transition active:scale-95"
                  >
                    <FaShieldAlt size={13} />
                    <span>Defense Center</span>
                  </button>

                  <button
                    onClick={() => setShowDefenseCenter(true)}
                    className="inline-flex items-center gap-2 rounded-xl border border-accent/40 bg-accent/10 hover:bg-accent/20 px-3.5 py-2 text-xs font-bold text-accent transition active:scale-95"
                  >
                    <FaBolt size={12} />
                    <span>Security Policy</span>
                  </button>
                </div>
              </div>
            </section>

            {/* LIVE DYNAMIC THREAT RADAR & TELEMETRY STREAM */}
            <ThreatRadar
              alerts={data.alerts || []}
              events={data.events || []}
              quarantinedCount={defense.active_quarantined_ips}
              onTriggerScan={handleTriggerScan}
              scanning={simulating}
            />

            {/* SOC Metric KPI Cards */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Total Telemetry Events"
                value={data.summary.totalEvents}
                icon={FaListUl}
                tone="accent"
              />
              <StatCard
                label="Correlated Security Alerts"
                value={data.summary.totalAlerts}
                icon={FaBell}
                tone="warning"
              />
              <StatCard
                label="High / Critical Severity"
                value={data.summary.highSeverity}
                icon={FaExclamationTriangle}
                tone="danger"
              />
              <StatCard
                label="Unique Threat Actor IPs"
                value={data.summary.uniqueIps}
                icon={FaNetworkWired}
                tone="success"
              />
            </div>

            {/* SOC Operational View Selector Tabs */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2 pt-2">
              <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-900 border border-slate-800 text-xs">
                <button
                  onClick={() => setActiveTab("all")}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-bold transition ${
                    activeTab === "all"
                      ? "bg-slate-800 text-white shadow-sm border border-slate-700"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FaLayerGroup size={12} />
                  <span>Master Command Board</span>
                </button>
                <button
                  onClick={() => setActiveTab("alerts")}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-bold transition ${
                    activeTab === "alerts"
                      ? "bg-slate-800 text-amber-300 shadow-sm border border-slate-700"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FaBell size={12} />
                  <span>Alert Triage ({data.alerts?.length || 0})</span>
                </button>
                <button
                  onClick={() => setActiveTab("endpoint")}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-bold transition ${
                    activeTab === "endpoint"
                      ? "bg-slate-800 text-cyan-300 shadow-sm border border-slate-700"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FaDesktop size={12} />
                  <span>EDR Endpoint Fleet ({endpointEvents?.length || 0})</span>
                </button>
                <button
                  onClick={() => setActiveTab("events")}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-bold transition ${
                    activeTab === "events"
                      ? "bg-slate-800 text-slate-200 shadow-sm border border-slate-700"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FaListUl size={12} />
                  <span>SSH Event Stream</span>
                </button>
                <button
                  onClick={() => setActiveTab("charts")}
                  className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg font-bold transition ${
                    activeTab === "charts"
                      ? "bg-slate-800 text-purple-300 shadow-sm border border-slate-700"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FaChartPie size={12} />
                  <span>Threat Visualizer</span>
                </button>
              </div>

              <div className="text-[11px] font-mono text-slate-400">
                ThreatLens SIEM Engine • Database WAL Mode Enabled
              </div>
            </div>

            {/* TAB CONTENT: Master Board or Specific Views */}

            {(activeTab === "all" || activeTab === "charts") && (
              <Charts
                severity={data.severity}
                eventsTimeline={data.eventsTimeline}
                alertTrend={data.alertTrend}
                topIps={data.topIps}
              />
            )}

            {(activeTab === "all" || activeTab === "alerts") && (
              <AlertsTable
                alerts={data.alerts}
                onSelectAlert={(alert) => setSelectedAlert(alert)}
              />
            )}

            {(activeTab === "all" || activeTab === "endpoint") && (
              <>
                {endpointError && (
                  <div
                    role="status"
                    className="rounded-xl border border-warning/40 bg-warning/10 px-4 py-3 text-xs text-warning shadow"
                  >
                    {endpointError} Existing SSH events and alerts are unaffected.
                  </div>
                )}
                <EndpointTelemetryTable
                  events={endpointEvents}
                  loading={endpointLoading}
                />
              </>
            )}

            {(activeTab === "all" || activeTab === "events") && (
              <EventsTable
                events={data.events}
                onSelectEvent={(event) => setSelectedEvent(event)}
              />
            )}
          </>
        )}
      </main>

      {/* Interactive alert details modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={retry}
        />
      )}

      {/* Interactive SSH event details modal */}
      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {/* Log ingestion modal */}
      {showIngestModal && (
        <IngestModal
          onClose={() => setShowIngestModal(false)}
          onRefresh={retry}
        />
      )}

      {/* Database health modal */}
      {showDbHealthModal && (
        <DatabaseHealthModal
          onClose={() => setShowDbHealthModal(false)}
        />
      )}

      {/* Tester center modal */}
      {showTesterCenter && (
        <TesterCenterModal
          onClose={() => setShowTesterCenter(false)}
          onRefreshDashboard={retry}
        />
      )}

      {/* Active defense center modal */}
      {showDefenseCenter && (
        <DefenseCenterModal
          onClose={() => setShowDefenseCenter(false)}
          onRefresh={retry}
        />
      )}
    </div>
  );
}
