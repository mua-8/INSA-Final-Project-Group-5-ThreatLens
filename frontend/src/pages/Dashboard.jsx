import React, { useState } from "react";
import { FaListUl, FaBell, FaExclamationTriangle, FaNetworkWired, FaPlug, FaRedo } from "react-icons/fa";
import Header from "../components/Header.jsx";
import StatCard, { StatCardSkeleton } from "../components/StatCard.jsx";
import Charts, { ChartSkeleton } from "../components/Charts.jsx";
import AlertsTable from "../components/AlertsTable.jsx";
import EventsTable from "../components/EventsTable.jsx";
import AlertDetailModal from "../components/AlertDetailModal.jsx";
import EventDetailModal from "../components/EventDetailModal.jsx";
import IngestModal from "../components/IngestModal.jsx";
import DatabaseHealthModal from "../components/DatabaseHealthModal.jsx";
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

export default function Dashboard() {
  const { data, loading, refreshing, error, lastUpdated, retry } = useDashboardData();
  
  // Interactive modal states
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [showDbHealthModal, setShowDbHealthModal] = useState(false);

  return (
    <div className="min-h-screen bg-primary pb-16">
      <Header
        lastUpdated={lastUpdated}
        refreshing={refreshing}
        onRefresh={retry}
        offline={!!error}
        onOpenIngest={() => setShowIngestModal(true)}
        onOpenDbHealth={() => setShowDbHealthModal(true)}
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
    </div>
  );
}
