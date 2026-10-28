import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { IncidentRead, SensorHealthStatus, TelemetryOverviewRead } from '../types/api';
import { SeverityBadge } from '../components/SeverityBadge';
import {
  ShieldAlert,
  Activity,
  Cpu,
  RefreshCw,
  Clock,
  ExternalLink,
  ChevronRight,
  Radio,
} from 'lucide-react';

export const OverviewView: React.FC = () => {
  const { setActiveView, setIncidentSeverityFilter, setThreatScore, refreshTrigger } = useApp();
  const [overview, setOverview] = useState<TelemetryOverviewRead | null>(null);
  const [sensors, setSensors] = useState<SensorHealthStatus[]>([]);
  const [triageIncidents, setTriageIncidents] = useState<IncidentRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    Promise.all([
      api.getOverview(),
      api.getSensorStatus(),
      api.getIncidents({ limit: 5 }),
    ])
      .then(([ov, sens, incResp]) => {
        if (!mounted) return;
        setOverview(ov);
        setSensors(sens);
        setTriageIncidents(incResp.items || []);
        setThreatScore(ov.threat_posture_score);
        setLoading(false);
      })
      .catch(() => {
        if (mounted) setLoading(false);
      });

    return () => {
      mounted = false;
    };
  }, [refreshTrigger, setThreatScore]);

  const handleFilterIncident = (sev: string) => {
    setIncidentSeverityFilter(sev);
    setActiveView('incidents');
  };

  if (loading && !overview) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2">
        <RefreshCw className="w-5 h-5 animate-spin text-cyan-400" />
        <span>Loading SOC Overview Telemetry...</span>
      </div>
    );
  }

  const score = overview?.threat_posture_score ?? 55;
  let scoreClass = 'text-emerald-400 stroke-emerald-400';
  let scoreCategory = 'Optimal Security Baseline';
  let scoreDesc = 'All active host processes and telemetry are operating within established security thresholds.';

  if (score <= 40) {
    scoreClass = 'text-rose-400 stroke-rose-400';
    scoreCategory = 'Critical Threat Level';
    scoreDesc = 'Active adversary indicators or ransomware preparation commands detected on host.';
  } else if (score <= 70) {
    scoreClass = 'text-amber-400 stroke-amber-400';
    scoreCategory = 'Elevated Risk State';
    scoreDesc = 'Anomalous network activity or unauthorized file integrity modifications detected.';
  }

  return (
    <div className="space-y-6">
      {/* Top Threat Posture & KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Threat Posture Card */}
        <div className="md:col-span-1 bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Threat Posture</span>
            <span className="flex items-center gap-1 text-[11px] font-mono text-cyan-400">
              <Radio className="w-3 h-3 animate-pulse" /> Real-time
            </span>
          </div>

          <div className="flex items-center gap-4 my-2">
            <div className="relative w-20 h-20 flex-shrink-0 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800 stroke-current"
                  strokeWidth="3.5"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`${scoreClass} stroke-current transition-all duration-1000`}
                  strokeDasharray={`${score}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
                <span className="text-xl font-bold text-slate-100">{score}</span>
                <span className="text-[9px] text-slate-500">/ 100</span>
              </div>
            </div>

            <div>
              <div className="text-xs font-bold text-slate-200">{scoreCategory}</div>
              <p className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                {scoreDesc}
              </p>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Evaluation Window</span>
            <span className="font-mono text-slate-300">Last 300s</span>
          </div>
        </div>

        {/* Active Incidents Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Incidents</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-bold font-mono text-slate-100">
              {overview?.active_incidents ?? 3}
            </div>
            <p className="text-xs text-slate-400 mt-1">Requiring immediate analyst triage</p>
          </div>
          <div className="pt-2 border-t border-slate-800 flex items-center gap-2">
            <button
              onClick={() => handleFilterIncident('Critical')}
              className="text-[10px] px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 font-mono transition"
            >
              1 Critical
            </button>
            <button
              onClick={() => handleFilterIncident('High')}
              className="text-[10px] px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/30 hover:bg-orange-500/20 font-mono transition"
            >
              1 High
            </button>
            <button
              onClick={() => handleFilterIncident('Medium')}
              className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 font-mono transition"
            >
              1 Medium
            </button>
          </div>
        </div>

        {/* 24h Normalized Events Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Normalized Events (24h)</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-bold font-mono text-cyan-400">
              {(overview?.total_events_24h ?? 1248).toLocaleString()}
            </div>
            <p className="text-xs text-slate-400 mt-1">Ingested and evaluated via Varuna AST</p>
          </div>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
            <button
              onClick={() => setActiveView('events')}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition text-xs"
            >
              Open Live Stream <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Monitored Host Entities Card */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col justify-between shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Host Inventory</span>
            <Cpu className="w-4 h-4 text-blue-400" />
          </div>
          <div className="grid grid-cols-2 gap-2 my-2">
            <div>
              <div className="text-xl font-bold font-mono text-slate-200">
                {overview?.monitored_processes ?? 184}
              </div>
              <div className="text-[11px] text-slate-400">Processes</div>
            </div>
            <div>
              <div className="text-xl font-bold font-mono text-slate-200">
                {overview?.active_sockets ?? 62}
              </div>
              <div className="text-[11px] text-slate-400">Active Sockets</div>
            </div>
            <div>
              <div className="text-xl font-bold font-mono text-slate-200">
                {overview?.fim_monitored_files ?? 48}
              </div>
              <div className="text-[11px] text-slate-400">FIM Files</div>
            </div>
            <div>
              <div className="text-xl font-bold font-mono text-slate-200">
                {overview?.network_devices_count ?? 9}
              </div>
              <div className="text-[11px] text-slate-400">ARP Devices</div>
            </div>
          </div>
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>OS: {overview?.platform ?? 'Windows'}</span>
            <span className="text-emerald-400">Sensor OK</span>
          </div>
        </div>
      </div>

      {/* Sensor Operational Health Grid */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> Sensor Engine Health Telemetry
          </h2>
          <span className="text-xs text-slate-400 font-mono">Latency Bounded &lt; 20ms</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {sensors.map((s, idx) => (
            <div
              key={idx}
              className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col justify-between shadow-sm"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">{s.sensor_name}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  {s.status}
                </span>
              </div>
              <div className="my-3 space-y-1 text-xs font-mono text-slate-400">
                <div className="flex justify-between">
                  <span>Collected:</span>
                  <span className="text-slate-200">{s.items_collected} items</span>
                </div>
                <div className="flex justify-between">
                  <span>Latency:</span>
                  <span className="text-cyan-400">{s.latency_ms} ms</span>
                </div>
                <div className="flex justify-between">
                  <span>Errors:</span>
                  <span className={s.error_count === 0 ? 'text-slate-400' : 'text-rose-400'}>
                    {s.error_count}
                  </span>
                </div>
              </div>
              <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800/80 truncate">
                {s.message || 'Operational'}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Urgent Incident Triage Queue */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" /> Critical Incident Triage Queue
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Top correlated threat events awaiting analyst disposition</p>
          </div>
          <button
            onClick={() => setActiveView('incidents')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition"
          >
            View All Incidents <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/80 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Incident Title</th>
                <th className="py-2.5 px-3">Trigger Rule</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Alerts</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {triageIncidents.length > 0 ? (
                triageIncidents.map((inc) => {
                  let statusBg = 'bg-slate-500/10 text-slate-400 border-slate-500/30';
                  if (inc.status === 'New') statusBg = 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
                  else if (inc.status === 'Triaged') statusBg = 'bg-sky-500/10 text-sky-400 border-sky-500/30';
                  else if (inc.status === 'In Progress') statusBg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
                  else if (inc.status === 'Resolved') statusBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';

                  return (
                    <tr key={inc.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-3">
                        <SeverityBadge severity={inc.severity} size="sm" />
                      </td>
                      <td className="py-3 px-3 font-sans font-medium text-slate-200">
                        {inc.title}
                      </td>
                      <td className="py-3 px-3 text-cyan-400">{inc.rule_id}</td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] ${statusBg}`}>
                          {inc.status}
                        </span>
                      </td>
                      <td className="py-3 px-3">{inc.alert_count} correlated</td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => {
                            setIncidentSeverityFilter(inc.severity);
                            setActiveView('incidents');
                          }}
                          className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-[11px] font-sans font-medium transition"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500 font-sans">
                    No active triage incidents detected. Host operating within normal baseline.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Telemetry Alerts Stream Ticker */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-100">Recent Real-Time Telemetry Events</h2>
          </div>
          <button
            onClick={() => setActiveView('events')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition"
          >
            Explore All Events <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-2">
          {overview?.recent_events?.slice(0, 5).map(ev => (
            <div
              key={ev.id}
              className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs"
            >
              <div className="flex items-center gap-3">
                <SeverityBadge severity={ev.severity} size="sm" />
                <span className="font-mono text-cyan-300 font-semibold">{ev.action}</span>
                <span className="text-slate-300 font-sans">
                  {ev.actor_name ? `${ev.actor_name} (PID: ${ev.actor_pid})` : ev.target_identifier}
                </span>
                {ev.is_sample && (
                  <span className="px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px] font-mono">
                    SAMPLE
                  </span>
                )}
              </div>
              <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3 text-slate-500" />
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
                <button
                  onClick={() => setActiveView('events')}
                  className="text-cyan-400 hover:text-cyan-300 underline"
                >
                  Inspect
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
