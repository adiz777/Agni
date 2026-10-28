import React, { useEffect, useState, useMemo } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { ProcessRead, SocketRead } from '../types/api';
import { Modal } from '../components/Modal';
import { PlatformCapabilityBanner } from '../components/Banners';
import {
  Search,
  Copy,
  Check,
  FolderTree,
  Table as TableIcon,
  ShieldCheck,
  AlertTriangle,
  Network,
  RefreshCw,
  CornerDownRight,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

export interface ProcessTreeNode {
  process: ProcessRead;
  depth: number;
  children: ProcessTreeNode[];
}

export interface FlatTreeItem {
  process: ProcessRead;
  depth: number;
  hasChildren: boolean;
  isCollapsed: boolean;
}

export function buildProcessTree(procs: ProcessRead[]): ProcessTreeNode[] {
  const byPid = new Map<number, ProcessRead>();
  const childrenMap = new Map<number, ProcessRead[]>();

  for (const p of procs) {
    byPid.set(p.pid, p);
  }

  for (const p of procs) {
    if (p.ppid && byPid.has(p.ppid) && p.ppid !== p.pid) {
      const list = childrenMap.get(p.ppid) || [];
      list.push(p);
      childrenMap.set(p.ppid, list);
    }
  }

  const roots: ProcessRead[] = [];
  for (const p of procs) {
    if (!p.ppid || !byPid.has(p.ppid) || p.ppid === p.pid) {
      roots.push(p);
    }
  }

  const visited = new Set<number>();

  function createNode(p: ProcessRead, depth: number): ProcessTreeNode {
    visited.add(p.pid);
    const rawChildren = childrenMap.get(p.pid) || [];
    const children: ProcessTreeNode[] = [];
    for (const child of rawChildren) {
      if (!visited.has(child.pid)) {
        children.push(createNode(child, depth + 1));
      }
    }
    return { process: p, depth, children };
  }

  const result: ProcessTreeNode[] = roots.map(r => createNode(r, 0));

  for (const p of procs) {
    if (!visited.has(p.pid)) {
      result.push(createNode(p, 0));
    }
  }

  return result;
}

export function flattenProcessTree(
  nodes: ProcessTreeNode[],
  collapsedPids: Set<number>
): FlatTreeItem[] {
  const result: FlatTreeItem[] = [];

  function walk(node: ProcessTreeNode) {
    const hasChildren = node.children.length > 0;
    const isCollapsed = collapsedPids.has(node.process.pid);
    result.push({
      process: node.process,
      depth: node.depth,
      hasChildren,
      isCollapsed,
    });
    if (hasChildren && !isCollapsed) {
      for (const child of node.children) {
        walk(child);
      }
    }
  }

  for (const root of nodes) {
    walk(root);
  }

  return result;
}

export const ProcessExplorerView: React.FC = () => {
  const { addToast, refreshTrigger } = useApp();
  const [processes, setProcesses] = useState<ProcessRead[]>([]);
  const [sockets, setSockets] = useState<SocketRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [viewMode, setViewMode] = useState<'table' | 'tree'>('table');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [suspiciousOnly, setSuspiciousOnly] = useState<boolean>(false);
  const [selectedProcess, setSelectedProcess] = useState<ProcessRead | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [collapsedPids, setCollapsedPids] = useState<Set<number>>(new Set());

  useEffect(() => {
    Promise.all([
      api.getProcesses(300),
      api.getNetworkConnections(500),
    ])
      .then(([procs, socks]) => {
        setProcesses(procs);
        setSockets(socks);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [refreshTrigger]);

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text)
      .then(() => {
        setCopiedKey(key);
        addToast(`${label} copied to clipboard`, 'success');
        setTimeout(() => setCopiedKey(null), 2000);
      })
      .catch(() => {
        addToast('Clipboard write access blocked', 'warning');
      });
  };

  const isSuspiciousProcess = (p: ProcessRead): boolean => {
    const exe = (p.exe || '').toLowerCase();
    const cmd = (p.cmdline || '').toLowerCase();
    const name = p.name.toLowerCase();
    if (exe.includes('\\public\\') || exe.includes('/tmp/') || exe.includes('\\temp\\') || exe.includes('\\appdata\\local\\temp\\')) return true;
    if (cmd.includes('-enc') || cmd.includes('delete shadows') || cmd.includes('-urlcache')) return true;
    if (name === 'vssadmin.exe' || name === 'certutil.exe') return true;
    return false;
  };

  const filteredProcesses = useMemo(() => {
    return processes.filter(p => {
      if (suspiciousOnly && !isSuspiciousProcess(p)) return false;
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const matchName = p.name.toLowerCase().includes(q);
        const matchPid = String(p.pid).includes(q);
        const matchPpid = String(p.ppid).includes(q);
        const matchExe = (p.exe || '').toLowerCase().includes(q);
        const matchUser = (p.username || '').toLowerCase().includes(q);
        return matchName || matchPid || matchPpid || matchExe || matchUser;
      }
      return true;
    });
  }, [processes, suspiciousOnly, searchQuery]);

  const treeNodes = useMemo(() => buildProcessTree(filteredProcesses), [filteredProcesses]);
  const flatTreeItems = useMemo(() => flattenProcessTree(treeNodes, collapsedPids), [treeNodes, collapsedPids]);

  const toggleCollapse = (pid: number) => {
    setCollapsedPids(prev => {
      const next = new Set(prev);
      if (next.has(pid)) {
        next.delete(pid);
      } else {
        next.add(pid);
      }
      return next;
    });
  };

  const handleExpandAll = () => setCollapsedPids(new Set());
  const handleCollapseAll = () => {
    const pidsWithKids = new Set<number>();
    for (const p of filteredProcesses) {
      if (filteredProcesses.some(c => c.ppid === p.pid && c.pid !== p.pid)) {
        pidsWithKids.add(p.pid);
      }
    }
    setCollapsedPids(pidsWithKids);
  };

  const getProcessSockets = (pid: number) => {
    return sockets.filter(s => s.pid === pid);
  };

  if (loading && processes.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Enumerating Host Process Inventory & Trees...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Platform Banner */}
      <PlatformCapabilityBanner featureName="Process Lineage & Memory Allocation" />

      {/* Control Toolbar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* View Mode Toggle */}
          <div className="flex items-center bg-slate-900 border border-slate-700 rounded-lg p-1">
            <button
              onClick={() => setViewMode('table')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
                viewMode === 'table' ? 'bg-cyan-600/30 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5" />
              <span>Flat Table</span>
            </button>
            <button
              onClick={() => setViewMode('tree')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
                viewMode === 'tree' ? 'bg-cyan-600/30 text-cyan-300 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FolderTree className="w-3.5 h-3.5" />
              <span>Lineage Hierarchy</span>
            </button>
          </div>

          {/* Suspicious Only Filter */}
          <button
            onClick={() => setSuspiciousOnly(!suspiciousOnly)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition ${
              suspiciousOnly
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            <span>Suspicious Indicators Only</span>
          </button>

          {/* Tree Expansion Controls (Only in Tree Mode) */}
          {viewMode === 'tree' && (
            <div className="flex items-center gap-2 border-l border-slate-700 pl-3">
              <button
                onClick={handleExpandAll}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono transition"
              >
                Expand All
              </button>
              <button
                onClick={handleCollapseAll}
                className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded text-[11px] font-mono transition"
              >
                Collapse All
              </button>
            </div>
          )}
        </div>

        {/* Search Input */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search PID, name, path..."
            className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>
      </div>

      {/* Process Table or Tree View */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          {viewMode === 'tree' ? (
            /* Hierarchical Lineage Tree Table */
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-3 px-4">Lineage Hierarchy & Process Name</th>
                  <th className="py-3 px-3">PID</th>
                  <th className="py-3 px-3">PPID</th>
                  <th className="py-3 px-3">CPU %</th>
                  <th className="py-3 px-3">RAM (RSS)</th>
                  <th className="py-3 px-4">User Scope</th>
                  <th className="py-3 px-4">Executable Path</th>
                  <th className="py-3 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {flatTreeItems.map(item => {
                  const p = item.process;
                  const isSusp = isSuspiciousProcess(p);
                  const memMb = p.memory_rss ? (p.memory_rss / (1024 * 1024)).toFixed(1) : '0';
                  return (
                    <tr
                      key={p.pid}
                      data-testid="process-tree-node"
                      data-pid={p.pid}
                      data-depth={item.depth}
                      onClick={() => setSelectedProcess(p)}
                      className={`hover:bg-slate-800/50 cursor-pointer transition ${isSusp ? 'bg-amber-950/20' : ''}`}
                    >
                      <td className="py-2.5 px-4 font-mono">
                        <div
                          className="flex items-center gap-2"
                          style={{ paddingLeft: `${item.depth * 24}px` }}
                        >
                          {item.depth > 0 && (
                            <CornerDownRight className="w-3.5 h-3.5 text-cyan-400/80 flex-shrink-0" />
                          )}
                          {item.hasChildren ? (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleCollapse(p.pid);
                              }}
                              className="p-0.5 hover:bg-slate-700 rounded text-cyan-400 hover:text-cyan-300 transition flex-shrink-0"
                              title={item.isCollapsed ? 'Expand Children' : 'Collapse Children'}
                              aria-label={item.isCollapsed ? `Expand PID ${p.pid}` : `Collapse PID ${p.pid}`}
                            >
                              {item.isCollapsed ? (
                                <ChevronRight className="w-3.5 h-3.5" />
                              ) : (
                                <ChevronDown className="w-3.5 h-3.5" />
                              )}
                            </button>
                          ) : (
                            <span className="w-3.5 h-3.5 inline-flex items-center justify-center text-slate-600 text-xs flex-shrink-0">•</span>
                          )}
                          <span className="font-sans font-medium text-slate-200">
                            {p.name}
                          </span>
                          {item.depth === 0 ? (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                              Root
                            </span>
                          ) : (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/50 text-cyan-300 border border-cyan-800/40">
                              PPID: {p.ppid}
                            </span>
                          )}
                          {isSusp && (
                            <span className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                              <AlertTriangle className="w-3 h-3 text-amber-400" /> Suspicious
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-bold text-cyan-400" data-testid={`tree-node-pid-${p.pid}`}>
                        <span>{p.pid}</span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500">{p.ppid}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className="w-10 text-right">{p.cpu_percent ? p.cpu_percent.toFixed(1) : 0.0}%</span>
                          <div className="w-12 bg-slate-800 h-1.5 rounded overflow-hidden">
                            <div
                              className="bg-cyan-500 h-full"
                              style={{ width: `${Math.min(100, (p.cpu_percent || 0) * 4)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{memMb} MB</td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs font-sans">
                        {p.username || 'SYSTEM'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-sm">
                        {p.exe || 'System Process'}
                      </td>
                      <td className="py-2.5 px-3 text-right font-sans">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedProcess(p);
                          }}
                          className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {flatTreeItems.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-6 text-center text-slate-500 font-sans">
                      No processes match the active filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          ) : (
            /* Flat Process Table */
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-3 px-4">PID</th>
                  <th className="py-3 px-3">PPID</th>
                  <th className="py-3 px-4">Process Name</th>
                  <th className="py-3 px-3">CPU %</th>
                  <th className="py-3 px-3">RAM (RSS)</th>
                  <th className="py-3 px-4">User Scope</th>
                  <th className="py-3 px-4">Executable Path</th>
                  <th className="py-3 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredProcesses.map(p => {
                  const isSusp = isSuspiciousProcess(p);
                  const memMb = p.memory_rss ? (p.memory_rss / (1024 * 1024)).toFixed(1) : '0';
                  return (
                    <tr
                      key={p.pid}
                      onClick={() => setSelectedProcess(p)}
                      className={`hover:bg-slate-800/50 cursor-pointer transition ${isSusp ? 'bg-amber-950/20' : ''}`}
                    >
                      <td className="py-2.5 px-4 font-bold text-cyan-400 flex items-center gap-1.5">
                        {isSusp && <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />}
                        <span>{p.pid}</span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500">{p.ppid}</td>
                      <td className="py-2.5 px-4 font-sans font-medium text-slate-200">
                        {p.name}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <span className="w-10 text-right">{p.cpu_percent ? p.cpu_percent.toFixed(1) : 0.0}%</span>
                          <div className="w-12 bg-slate-800 h-1.5 rounded overflow-hidden">
                            <div
                              className="bg-cyan-500 h-full"
                              style={{ width: `${Math.min(100, (p.cpu_percent || 0) * 4)}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{memMb} MB</td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs font-sans">
                        {p.username || 'SYSTEM'}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-sm">
                        {p.exe || 'System Process'}
                      </td>
                      <td className="py-2.5 px-3 text-right font-sans">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedProcess(p);
                          }}
                          className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {filteredProcesses.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-6 text-center text-slate-500 font-sans">
                      No processes match the active filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Process Inspection Modal */}
      <Modal
        isOpen={Boolean(selectedProcess)}
        onClose={() => setSelectedProcess(null)}
        title={selectedProcess ? `Process Inspector — ${selectedProcess.name} (PID: ${selectedProcess.pid})` : 'Inspect Process'}
        subtitle="Forensic Endpoint Metadata & Socket Bindings"
        maxWidth="2xl"
      >
        {selectedProcess && (
          <div className="space-y-4">
            {/* Safety Notice */}
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <span>
                Read-Only Monitoring: Agni operates under strict non-destructive principles and does not terminate processes or modify memory.
              </span>
            </div>

            {/* General Info Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-500">PID / PPID: </span>
                <span className="text-cyan-400">{selectedProcess.pid}</span> / <span className="text-slate-400">{selectedProcess.ppid}</span>
              </div>
              <div>
                <span className="text-slate-500">User Scope: </span>
                <span className="text-slate-200">{selectedProcess.username || 'NT AUTHORITY\\SYSTEM'}</span>
              </div>
              <div>
                <span className="text-slate-500">CPU Usage: </span>
                <span className="text-slate-200">{selectedProcess.cpu_percent ? selectedProcess.cpu_percent.toFixed(1) : 0}%</span>
              </div>
              <div>
                <span className="text-slate-500">Resident Memory: </span>
                <span className="text-slate-200">
                  {selectedProcess.memory_rss ? (selectedProcess.memory_rss / (1024 * 1024)).toFixed(1) : 0} MB
                </span>
              </div>
            </div>

            {/* Executable Path & SHA-256 */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300">Executable Path:</span>
                {selectedProcess.exe && (
                  <button
                    onClick={() => copyToClipboard(selectedProcess.exe!, 'exe', 'Executable path')}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 text-[11px]"
                  >
                    {copiedKey === 'exe' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'exe' ? 'Copied' : 'Copy Path'}</span>
                  </button>
                )}
              </div>
              <div className="p-2.5 bg-black/60 rounded-lg border border-slate-800 font-mono text-cyan-300 break-all">
                {selectedProcess.exe || 'N/A'}
              </div>
            </div>

            {/* Sanitized Command Line */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300">Sanitized Command Line:</span>
                {selectedProcess.cmdline && (
                  <button
                    onClick={() => copyToClipboard(selectedProcess.cmdline!, 'cmd', 'Command line')}
                    className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 text-[11px]"
                  >
                    {copiedKey === 'cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'cmd' ? 'Copied' : 'Copy Command'}</span>
                  </button>
                )}
              </div>
              <div className="p-2.5 bg-black/60 rounded-lg border border-slate-800 font-mono text-slate-300 break-all leading-relaxed max-h-36 overflow-y-auto">
                {selectedProcess.cmdline || selectedProcess.exe || 'N/A'}
              </div>
            </div>

            {/* Associated Network Sockets */}
            <div className="space-y-2 text-xs">
              <span className="font-semibold text-slate-300 flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" /> Active Network Sockets for PID {selectedProcess.pid}
              </span>
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left font-mono text-[11px]">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">Protocol</th>
                      <th className="py-2 px-3">Local Address</th>
                      <th className="py-2 px-3">Remote Address</th>
                      <th className="py-2 px-3">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {getProcessSockets(selectedProcess.pid).map((s, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40">
                        <td className="py-1.5 px-3 text-cyan-400">{s.protocol}</td>
                        <td className="py-1.5 px-3">{s.local_address}:{s.local_port}</td>
                        <td className="py-1.5 px-3 text-slate-400">{s.remote_address ? `${s.remote_address}:${s.remote_port}` : '*:*'}</td>
                        <td className="py-1.5 px-3 text-emerald-400">{s.status || 'CONNECTED'}</td>
                      </tr>
                    ))}
                    {getProcessSockets(selectedProcess.pid).length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-3 text-center text-slate-500 font-sans">
                          No active socket connections bound to this PID.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
