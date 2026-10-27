import React, { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard.jsx";
import VictimWebsite from "./pages/VictimWebsite.jsx";
import { FaShieldAlt, FaGlobe } from "react-icons/fa";

export default function App() {
  const [currentView, setCurrentView] = useState(() => {
    return window.location.hash === "#victim" ? "victim" : "admin";
  });

  useEffect(() => {
    const handleHashChange = () => {
      if (window.location.hash === "#victim") {
        setCurrentView("victim");
      } else if (window.location.hash === "#admin") {
        setCurrentView("admin");
      }
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const switchView = (view) => {
    setCurrentView(view);
    window.location.hash = view === "victim" ? "#victim" : "#admin";
  };

  return (
    <div className="relative">
      {/* Top Floating View Switcher Dock */}
      <div className="fixed bottom-4 right-4 z-50 flex items-center bg-slate-900/95 backdrop-blur-md border border-slate-700/80 rounded-full p-1 shadow-2xl shadow-black/80">
        <button
          onClick={() => switchView("admin")}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold transition ${
            currentView === "admin"
              ? "bg-accent text-primary shadow-md shadow-accent/25"
              : "text-slate-400 hover:text-white"
          }`}
          title="Switch to Admin SOC Portal to view live attacks, auto-defense, and recommendations"
        >
          <FaShieldAlt size={12} />
          <span>Admin SOC</span>
        </button>
        <button
          onClick={() => switchView("victim")}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold transition ${
            currentView === "victim"
              ? "bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/25"
              : "text-slate-400 hover:text-white"
          }`}
          title="Switch to Target Public Website (Apex Financial Portal) where attacks happen"
        >
          <FaGlobe size={12} />
          <span>Target Website</span>
        </button>
      </div>

      {/* Render Active View */}
      {currentView === "victim" ? (
        <VictimWebsite onSwitchToAdmin={() => switchView("admin")} />
      ) : (
        <Dashboard onSwitchToVictim={() => switchView("victim")} />
      )}
    </div>
  );
}
