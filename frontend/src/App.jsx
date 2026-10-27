import React, { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard.jsx";
import VictimWebsite from "./pages/VictimWebsite.jsx";

export default function App() {
  const [currentView, setCurrentView] = useState(() => {
    return window.location.hash === "#victim" ? "victim" : "admin";
  });

  useEffect(() => {
    const handleHashChange = () => {
      if (window.location.hash === "#victim") {
        setCurrentView("victim");
      } else {
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
    <div className="relative min-h-screen bg-slate-950">
      {/* Render Active View */}
      {currentView === "victim" ? (
        <VictimWebsite onSwitchToAdmin={() => switchView("admin")} />
      ) : (
        <Dashboard onSwitchToVictim={() => switchView("victim")} />
      )}
    </div>
  );
}
