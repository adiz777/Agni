import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { PersistenceRead } from '../types/api';
import { Modal } from '../components/Modal';
import { PlatformCapabilityBanner } from '../components/Banners';
import {
  Power,
  Key,
  AlertTriangle,
  Copy,
  Check,
  Search,
  RefreshCw,
} from 'lucide-react';

export const PersistenceView: React.FC = () => {
  const { addToast, refreshTrigger } = useApp();
  const [entries, setEntries] = useState<PersistenceRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedEntry, setSelectedEntry] = useState<PersistenceRead | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [activeCategoryTab, setActiveCategoryTab] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    api.getPersistence()
      .then(res => {
        setEntries(res);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [refreshTrigger]);

  const copyPath = (path: string) => {
    navigator.clipboard.writeText(path)
      .then(() => {
        setCopied(true);
        addToast('Target path copied to clipboard', 'success');
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {
        addToast('Clipboard write access blocked', 'warning');
      });
  };

  const categories = ['All', 'Registry Run Key', 'Windows Service', 'Scheduled Task', 'Systemd Unit', 'LaunchAgent'];

  const filteredEntries = entries.filter(e => {
    if (activeCategoryTab !== 'All' && e.location_type !== activeCategoryTab) {
      return false;
    }
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchName = e.name.toLowerCase().includes(q);
      const matchPath = (e.target_path || '').toLowerCase().includes(q);
      const matchLoc = e.location_type.toLowerCase().includes(q);
      return matchName || matchPath || matchLoc;
    }
    return true;
  });

  if (loading && entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Auditing Host Startup & Persistence Hooks...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Platform Banner */}
      <PlatformCapabilityBanner featureName="Startup & Persistence Locations Audit" />

      {/* Persistence Controls */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Power className="w-4 h-4 text-cyan-400" /> Host Startup &amp; Persistence Inventory
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Read-only visibility into autostart hooks across registry hives, services, and scheduled tasks
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>Entries Monitored: {entries.length}</span>
          </div>
        </div>

        {/* Categories Tab Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1.5">
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setActiveCategoryTab(cat)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  activeCategoryTab === cat
                    ? 'bg-cyan-600/30 text-cyan-300 font-semibold border border-cyan-500/40 shadow-sm'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search entry name, path..."
              className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Persistence Entries Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Entry Name</th>
                <th className="py-3 px-3">Location Type</th>
                <th className="py-3 px-4">Target Executable / Command</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-4 font-sans">Suspicious Indicators</th>
                <th className="py-3 px-3 text-right font-sans">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEntries.map(entry => {
                const isSusp = entry.suspicious_indicators && entry.suspicious_indicators.length > 0;
                return (
                  <tr
                    key={entry.entry_id}
                    onClick={() => setSelectedEntry(entry)}
                    className={`hover:bg-slate-800/50 cursor-pointer transition ${isSusp ? 'bg-amber-950/20' : ''}`}
                  >
                    <td className="py-3 px-4 font-sans font-semibold text-slate-200 flex items-center gap-2">
                      {isSusp ? (
                        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                      ) : (
                        <Key className="w-4 h-4 text-slate-500 flex-shrink-0" />
                      )}
                      <span>{entry.name}</span>
                    </td>
                    <td className="py-3 px-3 text-cyan-400">{entry.location_type}</td>
                    <td className="py-3 px-4 text-slate-300 truncate max-w-sm">
                      {entry.target_path || 'Embedded Service / Command'}
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        {entry.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans">
                      {isSusp ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold">
                          {entry.suspicious_indicators[0]}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Normal Baseline</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEntry(entry);
                        }}
                        className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Entry Inspection Modal */}
      <Modal
        isOpen={Boolean(selectedEntry)}
        onClose={() => setSelectedEntry(null)}
        title={selectedEntry ? `Persistence Entry — ${selectedEntry.name}` : 'Inspect Persistence'}
        subtitle={selectedEntry ? selectedEntry.location_type : ''}
        maxWidth="lg"
      >
        {selectedEntry && (
          <div className="space-y-4 text-xs font-mono">
            {/* Suspicious Alert Header if present */}
            {selectedEntry.suspicious_indicators && selectedEntry.suspicious_indicators.length > 0 && (
              <div className="p-3 bg-amber-950/70 border border-amber-800/80 rounded-lg text-amber-200 space-y-1 font-sans">
                <div className="font-semibold flex items-center gap-1.5 text-amber-300">
                  <AlertTriangle className="w-4 h-4" /> Suspicious Persistence Indicator Flagged:
                </div>
                <ul className="list-disc list-inside space-y-0.5 text-xs text-amber-200/90">
                  {selectedEntry.suspicious_indicators.map((ind, i) => (
                    <li key={i}>{ind}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* General Info */}
            <div className="space-y-2 p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <div className="flex justify-between">
                <span className="text-slate-500">Location Type:</span>
                <span className="text-cyan-400">{selectedEntry.location_type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Location Detail:</span>
                <span className="text-slate-300 break-all">{selectedEntry.location_detail || 'Standard Path'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Execution Arguments:</span>
                <span className="text-slate-300">{selectedEntry.arguments || 'None'}</span>
              </div>
            </div>

            {/* Target Path with Copy */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300 font-sans">Target Executable Path:</span>
                {selectedEntry.target_path && (
                  <button
                    onClick={() => copyPath(selectedEntry.target_path!)}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 text-[11px] font-sans"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy Path'}</span>
                  </button>
                )}
              </div>
              <div className="p-3 bg-black/60 rounded-lg border border-slate-800 text-cyan-300 break-all leading-relaxed">
                {selectedEntry.target_path || 'N/A'}
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
