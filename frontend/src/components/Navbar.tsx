import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { RefreshCw, Shield, Sparkles, Laptop } from 'lucide-react';

export const Navbar: React.FC = () => {
  const { isSampleMode, toggleSampleMode, platform, threatScore, triggerRefresh, activeView } = useApp();
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    triggerRefresh();
    setTimeout(() => setIsRefreshing(false), 600);
  };

  // Determine threat badge color
  let scoreColor = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  let scoreLabel = 'Normal Baseline';
  if (threatScore <= 40) {
    scoreColor = 'text-rose-400 border-rose-500/40 bg-rose-500/15 animate-pulse';
    scoreLabel = 'High Threat';
  } else if (threatScore <= 70) {
    scoreColor = 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    scoreLabel = 'Elevated Risk';
  }

  const viewTitles: Record<string, string> = {
    overview: 'SOC Situational Overview',
    events: 'Live Telemetry Stream',
    incidents: 'Threat Incident Investigation',
    processes: 'Endpoint Process Explorer',
    fim: 'File Integrity Monitoring (SHA-256)',
    network: 'Vayu Network Intelligence',
    rules: 'Detection Rules Catalog',
    persistence: 'Startup & Persistence Audit',
    reports: 'Security Intelligence Reports',
    audit: 'Immutable System Audit Logs',
    settings: 'Platform Settings & AI Configuration',
    diagnostics: 'Host Diagnostics & About Agni',
  };

  return (
    <header className="h-16 bg-[#0f172a] border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Title & View Description */}
      <div>
        <h1 className="text-base font-semibold text-slate-100 flex items-center gap-2">
          {viewTitles[activeView] || 'Security Operations Center'}
        </h1>
        <p className="text-[11px] text-slate-400 font-mono">
          Local Endpoint Monitor • 127.0.0.1:8000
        </p>
      </div>

      {/* Action Controls & Indicators */}
      <div className="flex items-center gap-3">
        {/* Threat Score Badge */}
        <div className={`hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono font-medium ${scoreColor}`}>
          <Shield className="w-3.5 h-3.5" />
          <span>Posture: {threatScore}/100 ({scoreLabel})</span>
        </div>

        {/* Host OS Pill */}
        <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 text-xs font-mono">
          <Laptop className="w-3.5 h-3.5 text-cyan-400" />
          <span>{platform}</span>
        </div>

        {/* Demo Mode Toggle */}
        <button
          onClick={() => toggleSampleMode()}
          title="Toggle between Live Host Telemetry and Simulated APT Threat Scenarios"
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
            isSampleMode
              ? 'bg-purple-950/80 border-purple-500/50 text-purple-300 hover:bg-purple-900/90'
              : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <Sparkles className={`w-3.5 h-3.5 ${isSampleMode ? 'text-purple-400' : 'text-slate-400'}`} />
          <span>{isSampleMode ? 'Demo Mode' : 'Live Host'}</span>
        </button>

        {/* Manual Refresh / Poll Now */}
        <button
          onClick={handleRefresh}
          title="Poll telemetry sensors immediately"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Poll Now</span>
        </button>
      </div>
    </header>
  );
};
