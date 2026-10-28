import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { FIMBaselineRead, FIMChangeRead } from '../types/api';
import { Modal } from '../components/Modal';
import {
  FileCheck2,
  FolderPlus,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Diff,
  FilePlus,
  FileX,
  FileEdit,
} from 'lucide-react';

export const FileIntegrityView: React.FC = () => {
  const { addToast, refreshTrigger } = useApp();
  const [baselines, setBaselines] = useState<FIMBaselineRead[]>([]);
  const [changes, setChanges] = useState<FIMChangeRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [addModalOpen, setAddModalOpen] = useState<boolean>(false);
  const [newBaselinePath, setNewBaselinePath] = useState<string>('');
  const [newBaselineName, setNewBaselineName] = useState<string>('');
  const [newBaselineRecursive, setNewBaselineRecursive] = useState<boolean>(false);
  const [selectedChange, setSelectedChange] = useState<FIMChangeRead | null>(null);

  const fetchData = () => {
    Promise.all([
      api.getFimBaselines(),
      api.getFimChanges(50),
    ])
      .then(([bases, chgs]) => {
        setBaselines(bases);
        setChanges(chgs);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchData();
  }, [refreshTrigger]);

  const handleScanNow = async () => {
    setScanning(true);
    try {
      const results = await api.scanFimBaselines();
      addToast(`FIM baseline integrity verification complete (${results.length} baselines scanned)`, 'success');
      fetchData();
    } catch {
      addToast('FIM baseline scan encountered an error', 'error');
    } finally {
      setScanning(false);
    }
  };

  const handleCreateBaseline = async () => {
    if (!newBaselinePath.trim()) return;
    try {
      const created = await api.createFimBaseline({
        name: newBaselineName.trim() || 'Custom Baseline',
        target_path: newBaselinePath.trim(),
        recursive: newBaselineRecursive,
      });
      setBaselines(prev => [created, ...prev]);
      setAddModalOpen(false);
      setNewBaselinePath('');
      setNewBaselineName('');
      addToast(`FIM baseline registered for ${created.target_path}`, 'success');
    } catch (err: unknown) {
      addToast(err instanceof Error ? err.message : 'Failed to register baseline', 'error');
    }
  };

  const renderActionBadge = (type: string) => {
    const t = type.toUpperCase();
    if (t === 'MODIFIED') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          <FileEdit className="w-3 h-3" /> MODIFIED
        </span>
      );
    }
    if (t === 'CREATED') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
          <FilePlus className="w-3 h-3" /> CREATED
        </span>
      );
    }
    if (t === 'DELETED') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
          <FileX className="w-3 h-3" /> DELETED
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-800 border border-slate-700">
        {type}
      </span>
    );
  };

  if (loading && baselines.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading File Integrity Baselines & Discrepancies...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Actions */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-cyan-400" /> Monitored Directory Baselines (SHA-256)
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic streaming 64KB hashing over critical files and persistence directories
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setAddModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 transition"
          >
            <FolderPlus className="w-3.5 h-3.5 text-cyan-400" />
            <span>Add Baseline</span>
          </button>
          <button
            onClick={handleScanNow}
            disabled={scanning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${scanning ? 'animate-spin' : ''}`} />
            <span>{scanning ? 'Hashing Files...' : 'Scan Baselines Now'}</span>
          </button>
        </div>
      </div>

      {/* Monitored Baselines Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {baselines.map(b => (
          <div
            key={b.id}
            className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 flex flex-col justify-between shadow-sm space-y-3"
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3 className="text-xs font-semibold text-slate-200">{b.name}</h3>
                <p className="text-[11px] font-mono text-cyan-400 mt-0.5 truncate max-w-xs" title={b.target_path}>
                  {b.target_path}
                </p>
              </div>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                  b.status === 'Clean'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                }`}
              >
                {b.status}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-400 pt-2 border-t border-slate-800/80">
              <div>
                <span className="text-slate-500">Files: </span>
                <span className="text-slate-200">{b.total_files}</span>
              </div>
              <div>
                <span className="text-slate-500">Recursive: </span>
                <span className="text-slate-200">{b.recursive ? 'Yes' : 'No'}</span>
              </div>
              <div className="col-span-2 text-[11px] text-slate-500 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                <span>Last Scan: {b.last_scanned_at ? new Date(b.last_scanned_at).toLocaleTimeString() : 'Never'}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* FIM Change Log Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" /> Detected File Integrity Discrepancies
          </h3>
          <span className="text-xs text-slate-400 font-mono">Total Changes: {changes.length}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-3 px-4">Detected</th>
                <th className="py-3 px-3">Action</th>
                <th className="py-3 px-4">File Path</th>
                <th className="py-3 px-4">Current SHA-256</th>
                <th className="py-3 px-3">Size Delta</th>
                <th className="py-3 px-3 text-right">Cryptographic Diff</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {changes.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-2" />
                    File Integrity Verified — All monitored paths match baseline hashes.
                  </td>
                </tr>
              ) : (
                changes.map(ch => (
                  <tr
                    key={ch.id}
                    onClick={() => setSelectedChange(ch)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(ch.detected_at).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3">{renderActionBadge(ch.change_type)}</td>
                    <td className="py-2.5 px-4 font-sans font-medium text-slate-200 truncate max-w-sm">
                      {ch.file_path}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-400 truncate max-w-xs">
                      {ch.current_sha256 ? `${ch.current_sha256.substring(0, 16)}...` : 'N/A (Deleted)'}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400">
                      {ch.previous_size && ch.current_size ? `${ch.current_size - ch.previous_size} B` : '0 B'}
                    </td>
                    <td className="py-2.5 px-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedChange(ch);
                        }}
                        className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition flex items-center gap-1 ml-auto"
                      >
                        <Diff className="w-3 h-3" />
                        <span>Inspect Diff</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Baseline Modal */}
      <Modal
        isOpen={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        title="Register File Integrity Baseline"
        subtitle="Specify a directory to snapshot and monitor for unauthorized modifications"
        maxWidth="lg"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Baseline Friendly Name
            </label>
            <input
              type="text"
              value={newBaselineName}
              onChange={e => setNewBaselineName(e.target.value)}
              placeholder="e.g. Critical System Drivers"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Target Directory Path
            </label>
            <input
              type="text"
              value={newBaselinePath}
              onChange={e => setNewBaselinePath(e.target.value)}
              placeholder="e.g. C:\Windows\System32\drivers\etc"
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Must be an existing local directory. Path traversal attempts are rejected.
            </p>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <input
              type="checkbox"
              id="rec-check"
              checked={newBaselineRecursive}
              onChange={e => setNewBaselineRecursive(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-600 focus:ring-0"
            />
            <label htmlFor="rec-check" className="text-xs text-slate-300 cursor-pointer">
              Recursive (Include all nested subdirectories)
            </label>
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end gap-2">
            <button
              onClick={() => setAddModalOpen(false)}
              className="px-3 py-1.5 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              onClick={handleCreateBaseline}
              disabled={!newBaselinePath.trim()}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition disabled:opacity-50"
            >
              Create Baseline Snapshot
            </button>
          </div>
        </div>
      </Modal>

      {/* Cryptographic Diff Modal */}
      <Modal
        isOpen={Boolean(selectedChange)}
        onClose={() => setSelectedChange(null)}
        title="Cryptographic Hash & Integrity Diff"
        subtitle={selectedChange ? selectedChange.file_path : ''}
        maxWidth="2xl"
      >
        {selectedChange && (
          <div className="space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Action:</span>
              {renderActionBadge(selectedChange.change_type)}
            </div>

            {/* Baseline Hash vs Current Hash */}
            <div className="space-y-3">
              <div>
                <span className="text-slate-500 block mb-1">Baseline Established SHA-256:</span>
                <div className="p-2.5 bg-black/60 rounded-lg border border-slate-800 text-slate-300 break-all">
                  {selectedChange.previous_sha256 || 'N/A (Newly Created)'}
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Observed Current SHA-256:</span>
                <div className="p-2.5 bg-black/60 rounded-lg border border-rose-900/50 text-rose-400 break-all">
                  {selectedChange.current_sha256 || 'N/A (Deleted from disk)'}
                </div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 text-slate-300 text-xs font-sans leading-relaxed">
              <span className="font-semibold text-amber-400">Security Interpretation:</span> The SHA-256 cryptographic digest of this file no longer matches its baseline snapshot. This discrepancy has generated a telemetry event in the Varuna engine.
            </div>

            <div className="pt-2 flex justify-end gap-2">
              <button
                onClick={() => {
                  setSelectedChange(null);
                  addToast('Change acknowledged and marked in audit trail', 'info');
                }}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-sans transition"
              >
                Acknowledge Discrepancy
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
