
import React, { useState } from "react";
import {
  FaListUl,
  FaBell,
  FaExclamationTriangle,
  FaNetworkWired,
  FaPlug,
  FaRedo,
  FaChartBar,
  FaFolderOpen,
  FaDesktop,
  FaSlidersH,
  FaServer,
} from "react-icons/fa";

import Header from "../components/Header.jsx";
import StatCard, { StatCardSkeleton } from "../components/StatCard.jsx";
import Charts, { ChartSkeleton } from "../components/Charts.jsx";
import AlertsTable from "../components/AlertsTable.jsx";
import EventsTable from "../components/EventsTable.jsx";
import EndpointTelemetryTable from "../components/EndpointTelemetryTable.jsx";
import IncidentsView from "../components/IncidentsView.jsx";
import DetectionRulesView from "../components/DetectionRulesView.jsx";
import EndpointsView from "../components/EndpointsView.jsx";

import AlertDetailModal from "../components/AlertDetailModal.jsx";
import EventDetailModal from "../components/EventDetailModal.jsx";
import IngestModal from "../components/IngestModal.jsx";
import DatabaseHealthModal from "../components/DatabaseHealthModal.jsx";
import TesterCenterModal from "../components/TesterCenterModal.jsx";

import useDashboardData from "../hooks/useDashboardData.js";

function LoadingState() {
  return (
    <div className="space-y-6" aria-busy="true">
      <div className="flex items-center gap-3 text-sm text-slate-400">
        <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-600 border-t-accent" />
        Connecting to ThreatLens API...
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
      className="mx-auto mt-16 max-w-lg rounded-xl border border-danger/40 bg-card p-8 text-center shadow-lg"
    >
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-danger/15 text-danger">
        <FaPlug size={20} />
      </div>

      <h2 className="text-lg font-semibold text-white">
        API connection failed
      </h2>

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

export default function Dashboard() {
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

  // Existing interactive modal states
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [showDbHealthModal, setShowDbHealthModal] = useState(false);
  const [showTesterCenter, setShowTesterCenter] = useState(false);

  // Tabbed view navigation
  const [activeTab, setActiveTab] = useState("overview"); // "overview" | "alerts" | "incidents" | "events" | "telemetry"

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
                className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning"
              >
                <span>
                  Connection lost. Showing the last data received. Retrying
                  every 15 seconds.
                </span>
                <button
                  onClick={retry}
                  className="font-semibold underline underline-offset-2"
                >
                  Retry now
                </button>
              </div>
            )}

            {/* Dashboard statistics */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Total Events"
                value={data.summary.totalEvents}
                icon={FaListUl}
                tone="accent"
                sublabel={`${data.summary.uniqueIps} Sources`}
              />
              <StatCard
                label="Total Alerts"
                value={data.summary.totalAlerts}
                icon={FaBell}
                tone="warning"
                sublabel={`${data.summary.openAlerts || 0} Open`}
              />
              <StatCard
                label="High & Critical Alerts"
                value={data.summary.highSeverity}
                icon={FaExclamationTriangle}
                tone="danger"
                sublabel={`Crit: ${data.summary.criticalAlerts || 0} • High: ${data.summary.highAlerts || 0}`}
              />
              <StatCard
                label="Unique Source IPs"
                value={data.summary.uniqueIps}
                icon={FaNetworkWired}
                tone="success"
              />
            </div>

            {/* View Navigation Tabs */}
            <nav className="flex flex-wrap items-center gap-2 border-b border-slate-700/80 pb-3 pt-1" aria-label="Dashboard views">
              <button
                type="button"
                onClick={() => setActiveTab("overview")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "overview"
                    ? "bg-accent text-slate-900 shadow-md shadow-accent/20"
                    : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaChartBar size={12} />
                <span>SOC Overview</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("alerts")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "alerts"
                    ? "bg-accent text-slate-900 shadow-md shadow-accent/20"
                    : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaBell size={12} />
                <span>Security Alerts</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-mono ${
                  activeTab === "alerts" ? "bg-slate-900/40 text-slate-900 font-bold" : "bg-slate-700 text-slate-300"
                }`}>
                  {data.alerts?.length || 0}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("incidents")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "incidents"
                    ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
                    : "bg-slate-800/80 text-indigo-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaFolderOpen size={12} />
                <span>Incident Cases</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("rules")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "rules"
                    ? "bg-amber-600 text-white shadow-md shadow-amber-600/30"
                    : "bg-slate-800/80 text-amber-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaSlidersH size={12} />
                <span>Detection Rules</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("endpoints")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "endpoints"
                    ? "bg-emerald-600 text-white shadow-md shadow-emerald-600/30"
                    : "bg-slate-800/80 text-emerald-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaServer size={12} />
                <span>Endpoint Fleet</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("events")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "events"
                    ? "bg-accent text-slate-900 shadow-md shadow-accent/20"
                    : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaListUl size={12} />
                <span>SSH Events</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-mono ${
                  activeTab === "events" ? "bg-slate-900/40 text-slate-900 font-bold" : "bg-slate-700 text-slate-300"
                }`}>
                  {data.events?.length || 0}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("telemetry")}
                className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition ${
                  activeTab === "telemetry"
                    ? "bg-accent text-slate-900 shadow-md shadow-accent/20"
                    : "bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white"
                }`}
              >
                <FaDesktop size={12} />
                <span>Endpoint Telemetry</span>
                <span className={`rounded-full px-2 py-0.5 text-[10px] font-mono ${
                  activeTab === "telemetry" ? "bg-slate-900/40 text-slate-900 font-bold" : "bg-slate-700 text-slate-300"
                }`}>
                  {endpointEvents?.length || 0}
                </span>
              </button>
            </nav>

            {/* Tab 1: SOC Overview */}
            {activeTab === "overview" && (
              <div className="space-y-6 animate-fadeIn">
                <Charts
                  severity={data.severity}
                  eventsTimeline={data.eventsTimeline}
                  alertTrend={data.alertTrend}
                  topIps={data.topIps}
                />
                <AlertsTable
                  alerts={data.alerts}
                  onSelectAlert={(alert) => setSelectedAlert(alert)}
                />
              </div>
            )}

            {/* Tab 2: Security Alerts Dedicated View */}
            {activeTab === "alerts" && (
              <div className="space-y-4 animate-fadeIn">
                <AlertsTable
                  alerts={data.alerts}
                  onSelectAlert={(alert) => setSelectedAlert(alert)}
                />
              </div>
            )}

            {/* Tab 3: Incident Management View */}
            {activeTab === "incidents" && (
              <div className="space-y-4 animate-fadeIn">
                <IncidentsView onRefreshDashboard={retry} />
              </div>
            )}

            {/* Tab 4: Detection Rules Management View */}
            {activeTab === "rules" && (
              <div className="space-y-4 animate-fadeIn">
                <DetectionRulesView />
              </div>
            )}

            {/* Tab 5: Endpoint Fleet Management View */}
            {activeTab === "endpoints" && (
              <div className="space-y-4 animate-fadeIn">
                <EndpointsView />
              </div>
            )}

            {/* Tab 6: SSH Authentication Events */}
            {activeTab === "events" && (
              <div className="space-y-4 animate-fadeIn">
                <EventsTable
                  events={data.events}
                  onSelectEvent={(event) => setSelectedEvent(event)}
                />
              </div>
            )}

            {/* Tab 7: Endpoint Agent Telemetry */}
            {activeTab === "telemetry" && (
              <div className="space-y-4 animate-fadeIn">
                {endpointError && (
                  <div
                    role="status"
                    className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-3 text-sm text-warning"
                  >
                    {endpointError} Existing SSH events and alerts are unaffected.
                  </div>
                )}
                <EndpointTelemetryTable
                  events={endpointEvents}
                  loading={endpointLoading}
                />
              </div>
            )}
          </>
        )}
      </main>

      {/* Existing alert details modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={retry}
        />
      )}

      {/* Existing SSH event details modal */}
      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {/* Existing log ingestion modal */}
      {showIngestModal && (
        <IngestModal
          onClose={() => setShowIngestModal(false)}
          onRefresh={retry}
        />
      )}

      {/* Existing database health modal */}
      {showDbHealthModal && (
        <DatabaseHealthModal
          onClose={() => setShowDbHealthModal(false)}
        />
      )}

      {/* Existing tester center modal */}
      {showTesterCenter && (
        <TesterCenterModal
          onClose={() => setShowTesterCenter(false)}
          onRefreshDashboard={retry}
        />
      )}
    </div>
  );
}
