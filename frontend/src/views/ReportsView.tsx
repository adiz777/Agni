import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import {
  FileSpreadsheet,
  Download,
  FileCode,
  FileText,
  Clock,
  Sparkles,
} from 'lucide-react';

interface ReportHistoryItem {
  id: string;
  title: string;
  format: 'json' | 'csv' | 'html';
  timestamp: string;
  sizeKb: string;
}

export const ReportsView: React.FC = () => {
  const { addToast, isSampleMode } = useApp();
  const [reportType, setReportType] = useState<string>('comprehensive');
  const [format, setFormat] = useState<'html' | 'json' | 'csv'>('html');
  const [timeRange, setTimeRange] = useState<string>('24h');
  const [includeSample, setIncludeSample] = useState<boolean>(isSampleMode);
  const [generating, setGenerating] = useState<boolean>(false);
  const [history, setHistory] = useState<ReportHistoryItem[]>([
    {
      id: 'REP-001',
      title: 'Executive Threat Posture Summary',
      format: 'html',
      timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      sizeKb: '48.2 KB',
    },
    {
      id: 'REP-002',
      title: 'Correlated Incidents Timeline',
      format: 'json',
      timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
      sizeKb: '14.6 KB',
    },
  ]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await api.exportReport({
        format,
        include_sample: includeSample,
      });

      const newRep: ReportHistoryItem = {
        id: `REP-00${history.length + 1}`,
        title: getReportTitle(reportType),
        format,
        timestamp: new Date().toISOString(),
        sizeKb: format === 'html' ? '54.1 KB' : format === 'json' ? '18.4 KB' : '6.2 KB',
      };
      setHistory(prev => [newRep, ...prev]);
      addToast(`Security report generated & downloaded as ${format.toUpperCase()}`, 'success');
    } catch {
      addToast('Failed to generate report', 'error');
    } finally {
      setGenerating(false);
    }
  };

  const getReportTitle = (type: string) => {
    switch (type) {
      case 'executive': return 'Executive Threat Posture Summary';
      case 'incidents': return 'Incident Investigation Dossier';
      case 'fim': return 'File Integrity Audit Report';
      case 'network': return 'Network Intelligence & Socket Report';
      default: return 'Full Security Compliance Snapshot';
    }
  };

  return (
    <div className="space-y-6">
      {/* Report Generator Configuration Card */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg space-y-6">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-cyan-400" /> Security Intelligence Report Generator
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Export forensic timelines, correlated incidents, and compliance baselines in standalone HTML, JSON, or CSV
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-slate-800">
          {/* Column 1: Report Scope */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                1. Select Report Type
              </label>
              <div className="space-y-2">
                {[
                  { id: 'comprehensive', title: 'Full Security Compliance Snapshot', desc: 'All modules (Processes, FIM, Network, Rules, Incidents)' },
                  { id: 'incidents', title: 'Incident Investigation Dossier', desc: 'Correlated multi-stage alerts, analyst notes, and MITRE mappings' },
                  { id: 'executive', title: 'Executive Threat Posture Summary', desc: 'KPI scorecards, host health, and high-level threat trends' },
                  { id: 'fim', title: 'File Integrity Audit Report', desc: 'Monitored directory baselines and SHA-256 discrepancy logs' },
                  { id: 'network', title: 'Network Intelligence & Socket Report', desc: 'Active connections, open ports, and passive ARP inventory' },
                ].map(r => (
                  <label
                    key={r.id}
                    className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition ${
                      reportType === r.id
                        ? 'bg-cyan-500/10 border-cyan-500/40 text-slate-100'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="radio"
                      name="reportType"
                      value={r.id}
                      checked={reportType === r.id}
                      onChange={() => setReportType(r.id)}
                      className="mt-1 text-cyan-500 focus:ring-0"
                    />
                    <div>
                      <div className="text-xs font-semibold">{r.title}</div>
                      <div className="text-[11px] text-slate-400">{r.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Column 2: Parameters & Format */}
          <div className="space-y-5">
            {/* Format Selection */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                2. Export Format
              </label>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { id: 'html', label: 'HTML', desc: 'Printable SOC Theme', icon: FileText },
                  { id: 'json', label: 'JSON', desc: 'Structured Data', icon: FileCode },
                  { id: 'csv', label: 'CSV', desc: 'SIEM Tabular', icon: FileSpreadsheet },
                ].map(fmt => {
                  const Icon = fmt.icon;
                  const isSelected = format === fmt.id;
                  return (
                    <button
                      key={fmt.id}
                      type="button"
                      onClick={() => setFormat(fmt.id as 'html' | 'json' | 'csv')}
                      className={`p-3 rounded-lg border text-left transition flex flex-col justify-between ${
                        isSelected
                          ? 'bg-cyan-500/15 border-cyan-500/50 text-cyan-300'
                          : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <Icon className="w-5 h-5 mb-2 text-cyan-400" />
                      <div className="text-xs font-bold font-mono uppercase">{fmt.label}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{fmt.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Time Range */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                3. Historical Time Horizon
              </label>
              <select
                value={timeRange}
                onChange={e => setTimeRange(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days (Full Retrospective)</option>
              </select>
            </div>

            {/* Include Demo Toggle */}
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" /> Include Sample / Demo Telemetry
                </div>
                <div className="text-[11px] text-slate-400">
                  Include simulated Operation Ignis Vector APT entries in export
                </div>
              </div>
              <input
                type="checkbox"
                checked={includeSample}
                onChange={e => setIncludeSample(e.target.checked)}
                className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0"
              />
            </div>

            {/* Primary Action Button */}
            <div className="pt-2">
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white rounded-xl text-sm font-semibold transition shadow-lg"
              >
                <Download className={`w-4 h-4 ${generating ? 'animate-bounce' : ''}`} />
                <span>{generating ? 'Compiling Report...' : 'Generate & Download Report'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Session Export History Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg p-5 space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" /> Session Generated Reports Archive
        </h3>

        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Report ID</th>
                <th className="py-2.5 px-4 font-sans">Report Title</th>
                <th className="py-2.5 px-3">Format</th>
                <th className="py-2.5 px-3">Generated Timestamp</th>
                <th className="py-2.5 px-3">File Size</th>
                <th className="py-2.5 px-3 text-right font-sans">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {history.map(item => (
                <tr key={item.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3 text-cyan-400 font-bold">{item.id}</td>
                  <td className="py-2.5 px-4 font-sans font-medium text-slate-200">{item.title}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 border border-slate-700 text-slate-300">
                      {item.format}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">{item.sizeKb}</td>
                  <td className="py-2.5 px-3 text-right font-sans">
                    <button
                      onClick={() => handleGenerate()}
                      className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
