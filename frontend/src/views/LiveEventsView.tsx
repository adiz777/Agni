import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { TelemetryEventRead } from '../types/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { Drawer } from '../components/Drawer';
import {
  Play,
  Pause,
  Search,
  Download,
  Copy,
  Check,
  Filter,
  ExternalLink,
  Clock,
  Radio,
  RefreshCw,
} from 'lucide-react';

export const LiveEventsView: React.FC = () => {
  const { setActiveView, addToast, refreshTrigger } = useApp();
  const [events, setEvents] = useState<TelemetryEventRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [pollInterval, setPollInterval] = useState<number>(3000);
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<TelemetryEventRead | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchEvents = () => {
    api.getEvents({ limit: 100 })
      .then(res => {
        setEvents(res.items);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchEvents();
  }, [refreshTrigger]);

  // Real-time polling stream effect
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(() => {
      fetchEvents();
    }, pollInterval);
    return () => clearInterval(interval);
  }, [isStreaming, pollInterval]);

  const handleCopyJson = (obj: unknown) => {
    navigator.clipboard.writeText(JSON.stringify(obj, null, 2))
      .then(() => {
        setCopied(true);
        addToast('Event JSON copied to clipboard', 'success');
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {
        addToast('Clipboard write access blocked', 'warning');
      });
  };

  const handleExportFiltered = (format: 'json' | 'csv') => {
    const dataToExport = filteredEvents;
    let content = '';
    let mimeType = 'text/plain';

    if (format === 'json') {
      mimeType = 'application/json';
      content = JSON.stringify(dataToExport, null, 2);
    } else {
      mimeType = 'text/csv';
      content = 'ID,Timestamp,Severity,Category,Action,Actor,Target,Details\n' +
        dataToExport.map(e => `"${e.id}","${e.timestamp}","${e.severity}","${e.category}","${e.action}","${e.actor_name || ''}","${e.target_identifier || ''}","${JSON.stringify(e.details || {}).replace(/"/g, '""')}"`).join('\n');
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agni-events-${Date.now()}.${format}`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
    addToast(`Exported ${dataToExport.length} events as ${format.toUpperCase()}`, 'success');
  };

  const filteredEvents = events.filter(e => {
    if (severityFilter !== 'All' && e.severity.toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    if (categoryFilter !== 'All' && e.category.toLowerCase() !== categoryFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchActor = e.actor_name?.toLowerCase().includes(q) || false;
      const matchPath = e.actor_path?.toLowerCase().includes(q) || false;
      const matchCmd = e.actor_cmdline?.toLowerCase().includes(q) || false;
      const matchTarget = e.target_identifier?.toLowerCase().includes(q) || false;
      const matchAction = e.action.toLowerCase().includes(q);
      const matchPid = e.actor_pid ? String(e.actor_pid).includes(q) : false;
      return matchActor || matchPath || matchCmd || matchTarget || matchAction || matchPid;
    }
    return true;
  });

  if (loading && events.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Connecting to Live Event Stream...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stream Controls & Filter Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Stream Status Toggle & Rate */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
                isStreaming
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/20'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-400 hover:bg-amber-500/20'
              }`}
            >
              {isStreaming ? (
                <>
                  <Radio className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
                  <span>Streaming Active</span>
                  <Pause className="w-3 h-3 ml-1 text-slate-400" />
                </>
              ) : (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Stream Paused</span>
                  <Play className="w-3 h-3 ml-1 text-slate-400" />
                </>
              )}
            </button>

            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <span>Rate:</span>
              <select
                value={pollInterval}
                onChange={e => setPollInterval(Number(e.target.value))}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value={1000}>1s</option>
                <option value={3000}>3s (Default)</option>
                <option value={5000}>5s</option>
                <option value={10000}>10s</option>
              </select>
            </div>
          </div>

          {/* Export Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExportFiltered('json')}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => handleExportFiltered('csv')}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Severity & Category Filter Pills */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-500 flex items-center gap-1 mr-1">
              <Filter className="w-3 h-3" /> Severity:
            </span>
            {['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition ${
                  severityFilter === sev
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}

            <span className="text-slate-600 mx-1">|</span>
            <span className="text-xs text-slate-500 mr-1">Category:</span>
            {['All', 'process', 'network', 'fim', 'persistence'].map(cat => (
              <button
                key={cat}
                onClick={() => setCategoryFilter(cat)}
                className={`px-2.5 py-1 rounded text-xs font-mono uppercase transition ${
                  categoryFilter === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by PID, process, IP..."
              className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Events Stream Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Category</th>
                <th className="py-3 px-3">Action</th>
                <th className="py-3 px-4">Actor / Entity</th>
                <th className="py-3 px-4">Target / Summary</th>
                <th className="py-3 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No telemetry events matching active filters.
                  </td>
                </tr>
              ) : (
                filteredEvents.map(e => (
                  <tr
                    key={e.id}
                    onClick={() => setSelectedEvent(e)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3">
                      <SeverityBadge severity={e.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 uppercase text-[10px] text-cyan-400">
                      {e.category}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-200">
                      {e.action}
                    </td>
                    <td className="py-2.5 px-4 font-sans text-slate-300 truncate max-w-xs">
                      {e.actor_name ? (
                        <span>
                          {e.actor_name} <span className="font-mono text-slate-500">({e.actor_pid})</span>
                        </span>
                      ) : (
                        <span className="text-slate-500">System</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-sans text-slate-400 truncate max-w-sm">
                      {e.target_identifier || (e.details?.technique as string) || 'Normal telemetry record'}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(ev) => {
                          ev.stopPropagation();
                          setSelectedEvent(e);
                        }}
                        className="px-2 py-0.5 rounded text-[11px] text-cyan-400 hover:text-cyan-300 font-sans hover:underline"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Drawer */}
      <Drawer
        isOpen={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent ? `${selectedEvent.action} (${selectedEvent.category.toUpperCase()})` : 'Event Detail'}
        subtitle={selectedEvent ? `Event ID: ${selectedEvent.id}` : ''}
        width="xl"
      >
        {selectedEvent && (
          <div className="space-y-5">
            {/* Severity & Timestamps */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={selectedEvent.severity} />
                <span className="text-xs text-slate-400 font-mono">
                  Source: {selectedEvent.source}
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <Clock className="w-3.5 h-3.5" />
                {new Date(selectedEvent.timestamp).toISOString()}
              </div>
            </div>

            {/* Normalized Attributes Grid */}
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Normalized Attributes
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                <div className="text-slate-400">Actor Process:</div>
                <div className="text-slate-200">{selectedEvent.actor_name || 'N/A'}</div>

                <div className="text-slate-400">Actor PID:</div>
                <div className="text-cyan-400">{selectedEvent.actor_pid || 'N/A'}</div>

                <div className="text-slate-400">Actor User:</div>
                <div className="text-slate-200">{selectedEvent.actor_user || 'N/A'}</div>

                <div className="text-slate-400">Actor Path:</div>
                <div className="text-slate-300 break-all">{selectedEvent.actor_path || 'N/A'}</div>

                <div className="text-slate-400">Target Type:</div>
                <div className="text-slate-200">{selectedEvent.target_type || 'N/A'}</div>

                <div className="text-slate-400">Target Identifier:</div>
                <div className="text-cyan-400 break-all">{selectedEvent.target_identifier || 'N/A'}</div>
              </div>
            </div>

            {/* Command Line / Arguments if present */}
            {selectedEvent.actor_cmdline && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Observed Command Line
                </h4>
                <div className="p-3 bg-black/60 rounded-lg border border-slate-800 font-mono text-xs text-cyan-300 break-all leading-relaxed">
                  {selectedEvent.actor_cmdline}
                </div>
              </div>
            )}

            {/* Quick Actions */}
            <div className="pt-2 border-t border-slate-800 flex flex-wrap gap-2">
              <button
                onClick={() => {
                  setSearchQuery(selectedEvent.actor_name || String(selectedEvent.actor_pid || ''));
                  setSelectedEvent(null);
                  addToast('Applied filter to live stream', 'info');
                }}
                className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition"
              >
                Filter Like This
              </button>
              {selectedEvent.actor_pid && (
                <button
                  onClick={() => {
                    setSelectedEvent(null);
                    setActiveView('processes');
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 transition flex items-center gap-1"
                >
                  Jump to Process in Explorer <ExternalLink className="w-3 h-3" />
                </button>
              )}
              <button
                onClick={() => handleCopyJson(selectedEvent)}
                className="px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition flex items-center gap-1 ml-auto"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy JSON'}</span>
              </button>
            </div>

            {/* Raw JSON Preview */}
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Raw Event JSON
              </h4>
              <pre className="p-3 bg-black/80 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-60 leading-relaxed">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
