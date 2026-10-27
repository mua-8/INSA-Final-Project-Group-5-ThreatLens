import React, { useState } from "react";
import { FaListUl, FaBell, FaExclamationTriangle, FaNetworkWired, FaPlug, FaRedo, FaShieldAlt, FaBan, FaBolt, FaGlobe } from "react-icons/fa";
import Header from "../components/Header.jsx";
import StatCard, { StatCardSkeleton } from "../components/StatCard.jsx";
import Charts, { ChartSkeleton } from "../components/Charts.jsx";
import AlertsTable from "../components/AlertsTable.jsx";
import EventsTable from "../components/EventsTable.jsx";
import AlertDetailModal from "../components/AlertDetailModal.jsx";
import EventDetailModal from "../components/EventDetailModal.jsx";
import IngestModal from "../components/IngestModal.jsx";
import DatabaseHealthModal from "../components/DatabaseHealthModal.jsx";
import TesterCenterModal from "../components/TesterCenterModal.jsx";
import DefenseCenterModal from "../components/DefenseCenterModal.jsx";
import useDashboardData from "../hooks/useDashboardData.js";

function LoadingState() {
  return (
    <div className="space-y-6" aria-busy="true">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-600 border-t-accent" />
        Connecting to ThreatLens API...
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => <StatCardSkeleton key={i} />)}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {Array.from({ length: 4 }).map((_, i) => <ChartSkeleton key={i} />)}
      </div>
    </div>
  );
}

function ErrorState({ message, onRetry, retrying }) {
  return (
    <div role="alert" className="mx-auto mt-16 max-w-lg rounded-xl border border-danger/40 bg-card p-8 text-center shadow-lg">
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-danger/15 text-danger">
        <FaPlug size={20} />
      </div>
      <h2 className="text-lg font-semibold text-white">API connection failed</h2>
      <p className="mt-2 text-sm text-slate-400">{message}</p>
      <button
        onClick={onRetry}
        disabled={retrying}
        className="mt-6 inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-primary transition hover:bg-sky-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-card disabled:opacity-60"
      >
        <FaRedo className={retrying ? "animate-spin" : ""} size={12} />
        {retrying ? "Retrying..." : "Retry connection"}
      </button>
    </div>
  );
}

export default function Dashboard({ onSwitchToVictim }) {
  const { data, loading, refreshing, error, lastUpdated, retry } = useDashboardData();
  
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

  return (
    <div className="min-h-screen bg-primary pb-16">
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

        {error && !data && !loading && <ErrorState message={error} onRetry={retry} retrying={refreshing} />}

        {data && (
          <>
            {error && (
              <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning">
                <span>Connection lost. Showing the last data received. Retrying every 15 seconds.</span>
                <button onClick={retry} className="font-semibold underline underline-offset-2">Retry now</button>
              </div>
            )}

            {/* Active Defense & Live Auto-Prevention Status Banner */}
            <div className="rounded-2xl border border-emerald-500/40 bg-gradient-to-r from-slate-900 via-slate-900/95 to-emerald-950/40 p-4 shadow-xl backdrop-blur-md">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3.5">
                  <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/40 shadow-lg shadow-emerald-500/10">
                    <FaShieldAlt size={22} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-sm font-bold text-white tracking-wide">
                        Automated Threat Prevention & Active Defense
                      </h2>
                      <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                        defense.auto_defense_enabled
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-warning/20 text-warning border border-warning/30"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${defense.auto_defense_enabled ? "bg-emerald-400 animate-pulse" : "bg-warning"}`} />
                        {defense.auto_defense_enabled ? "Auto-Prevention Active" : "Monitoring Only"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 mt-0.5">
                      Identifies SSH brute force, SQL injection, spraying, and account breaches in real time. Automatically quarantines attacker IPs and recommends SOC remediation.
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  <div className="flex items-center gap-2 rounded-lg bg-slate-800/80 px-3 py-1.5 border border-slate-700 text-xs">
                    <FaBan className="text-danger" size={12} />
                    <span className="text-slate-400">Quarantined IPs:</span>
                    <span className="font-mono font-bold text-white">{defense.active_quarantined_ips}</span>
                  </div>

                  <button
                    onClick={onSwitchToVictim}
                    title="Launch the target public website to test attacks directly on it"
                    className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-cyan-600/25 transition active:scale-95"
                  >
                    <FaGlobe size={12} />
                    <span>Launch Target Website</span>
                  </button>

                  <button
                    onClick={() => setShowDefenseCenter(true)}
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3.5 py-1.5 text-xs font-bold text-white shadow-md shadow-emerald-600/25 transition active:scale-95"
                  >
                    <FaShieldAlt size={12} />
                    <span>Defense Center</span>
                  </button>

                  <button
                    onClick={() => {
                      setShowDefenseCenter(true);
                    }}
                    className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 hover:bg-accent/20 px-3 py-1.5 text-xs font-bold text-accent transition active:scale-95"
                  >
                    <FaBolt size={12} />
                    <span>⚡ Attack Sim</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Stat Cards */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard label="Total Events" value={data.summary.totalEvents} icon={FaListUl} tone="accent" />
              <StatCard label="Total Alerts" value={data.summary.totalAlerts} icon={FaBell} tone="warning" />
              <StatCard label="High Severity Alerts" value={data.summary.highSeverity} icon={FaExclamationTriangle} tone="danger" />
              <StatCard label="Unique Source IPs" value={data.summary.uniqueIps} icon={FaNetworkWired} tone="success" />
            </div>

            {/* Analytics & Distribution Charts */}
            <Charts
              severity={data.severity}
              eventsTimeline={data.eventsTimeline}
              alertTrend={data.alertTrend}
              topIps={data.topIps}
            />

            {/* Ingested Alerts Table with Click Triage */}
            <AlertsTable
              alerts={data.alerts}
              onSelectAlert={(alert) => setSelectedAlert(alert)}
            />

            {/* Ingested Events Table with Click Raw Syslog Inspection */}
            <EventsTable
              events={data.events}
              onSelectEvent={(event) => setSelectedEvent(event)}
            />
          </>
        )}
      </main>

      {/* Interactive Modals */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={retry}
        />
      )}

      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {showIngestModal && (
        <IngestModal
          onClose={() => setShowIngestModal(false)}
          onRefresh={retry}
        />
      )}

      {showDbHealthModal && (
        <DatabaseHealthModal
          onClose={() => setShowDbHealthModal(false)}
        />
      )}

      {showTesterCenter && (
        <TesterCenterModal
          onClose={() => setShowTesterCenter(false)}
          onRefreshDashboard={retry}
        />
      )}

      {showDefenseCenter && (
        <DefenseCenterModal
          onClose={() => setShowDefenseCenter(false)}
          onRefresh={retry}
        />
      )}
    </div>
  );
}

