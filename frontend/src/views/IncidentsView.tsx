import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { IncidentDetailRead, IncidentStatus } from '../types/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { Drawer } from '../components/Drawer';
import {
  Kanban,
  Table as TableIcon,
  MessageSquare,
  Send,
  Copy,
  Check,
  Clock,
  RefreshCw,
} from 'lucide-react';

export const IncidentsView: React.FC = () => {
  const { incidentSeverityFilter, setIncidentSeverityFilter, addToast, refreshTrigger } = useApp();
  const [incidents, setIncidents] = useState<IncidentDetailRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [viewMode, setViewMode] = useState<'table' | 'kanban'>('kanban');
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetailRead | null>(null);
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchIncidents = () => {
    api.getIncidents({ limit: 50 })
      .then(async res => {
        // Fetch full details for the incidents to populate notes & alerts
        const details = await Promise.all(
          res.items.map(item => api.getIncidentDetail(item.id).catch(() => item as IncidentDetailRead))
        );
        setIncidents(details);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchIncidents();
  }, [refreshTrigger]);

  const handleStatusChange = async (incidentId: string, newStatus: IncidentStatus) => {
    try {
      const updated = await api.updateIncidentStatus(
        incidentId,
        newStatus,
        `Status transitioned to ${newStatus} via SOC web console.`,
        'local_analyst'
      );
      setIncidents(prev => prev.map(inc => inc.id === incidentId ? updated : inc));
      if (selectedIncident?.id === incidentId) {
        setSelectedIncident(updated);
      }
      addToast(`Incident ${incidentId} transitioned to ${newStatus}`, 'success');
    } catch {
      addToast('Failed to transition incident status', 'error');
    }
  };

  const handleAddNote = async () => {
    if (!selectedIncident || !newNoteText.trim()) return;
    setSubmittingNote(true);
    try {
      const added = await api.addIncidentNote(selectedIncident.id, newNoteText.trim(), 'local_analyst');
      const updatedNotes = [...(selectedIncident.notes || []), added];
      const updated: IncidentDetailRead = { ...selectedIncident, notes: updatedNotes };
      setSelectedIncident(updated);
      setIncidents(prev => prev.map(i => i.id === selectedIncident.id ? updated : i));
      setNewNoteText('');
      addToast('Investigation note saved', 'success');
    } catch {
      addToast('Failed to save note', 'error');
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleCopySummary = (inc: IncidentDetailRead) => {
    const summary = `[${inc.id}] ${inc.title}
Severity: ${inc.severity} | Priority: ${inc.priority} | Status: ${inc.status}
Trigger Rule: ${inc.rule_id}
Alerts Count: ${inc.alert_count}
First Seen: ${inc.first_seen}
Last Seen: ${inc.last_seen}
Notes:
${(inc.notes || []).map(n => `- [${n.author} @ ${new Date(n.created_at).toLocaleString()}]: ${n.content}`).join('\n')}`;

    navigator.clipboard.writeText(summary)
      .then(() => {
        setCopied(true);
        addToast('Incident summary copied to clipboard', 'success');
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {
        addToast('Clipboard write access blocked', 'warning');
      });
  };

  const statuses: IncidentStatus[] = ['New', 'Triaged', 'In Progress', 'Resolved', 'False Positive'];

  const filteredIncidents = incidents.filter(i => {
    if (incidentSeverityFilter && incidentSeverityFilter !== 'All') {
      return i.severity.toLowerCase() === incidentSeverityFilter.toLowerCase();
    }
    return true;
  });

  if (loading && incidents.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Incident Investigation Dossiers...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header & View Mode Switcher */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center bg-slate-900 border border-slate-700 rounded-lg p-1">
            <button
              onClick={() => setViewMode('kanban')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
                viewMode === 'kanban'
                  ? 'bg-cyan-600/30 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Kanban className="w-3.5 h-3.5" />
              <span>Kanban Board</span>
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition ${
                viewMode === 'table'
                  ? 'bg-cyan-600/30 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5" />
              <span>Table Grid</span>
            </button>
          </div>

          {/* Active Filter Notification */}
          {incidentSeverityFilter && (
            <div className="flex items-center gap-2 text-xs text-slate-300 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-700">
              <span>Filter:</span>
              <SeverityBadge severity={incidentSeverityFilter} size="sm" />
              <button
                onClick={() => setIncidentSeverityFilter(null)}
                className="text-slate-400 hover:text-slate-100 ml-1 font-bold"
              >
                ×
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span>Total Incidents: {filteredIncidents.length}</span>
        </div>
      </div>

      {/* Kanban Board Mode */}
      {viewMode === 'kanban' ? (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {statuses.map(st => {
            const inStatus = filteredIncidents.filter(i => i.status === st);
            return (
              <div
                key={st}
                className="bg-[#0f172a] border border-slate-800 rounded-xl p-3 flex flex-col min-h-[500px] shadow-sm"
              >
                {/* Column Header */}
                <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800 text-xs font-semibold text-slate-300">
                  <span>{st}</span>
                  <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 font-mono text-slate-400">
                    {inStatus.length}
                  </span>
                </div>

                {/* Cards List */}
                <div className="space-y-3 flex-1 overflow-y-auto">
                  {inStatus.map(inc => (
                    <div
                      key={inc.id}
                      onClick={() => setSelectedIncident(inc)}
                      className="p-3 bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 rounded-lg cursor-pointer transition shadow hover:border-slate-700 space-y-2.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11px] font-bold text-cyan-400">
                          {inc.id}
                        </span>
                        <SeverityBadge severity={inc.severity} size="sm" />
                      </div>

                      <h4 className="text-xs font-semibold text-slate-200 line-clamp-2 leading-snug">
                        {inc.title}
                      </h4>

                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/80 font-mono">
                        <span>{inc.rule_id}</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-500" />
                          {inc.alert_count} alerts
                        </span>
                      </div>
                    </div>
                  ))}
                  {inStatus.length === 0 && (
                    <div className="h-24 flex items-center justify-center text-[11px] text-slate-600 border border-dashed border-slate-800/80 rounded-lg">
                      No incidents
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Table Mode */
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Priority</th>
                <th className="py-3 px-4">Incident Title</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Rule</th>
                <th className="py-3 px-3">Alerts</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredIncidents.map(inc => (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className="hover:bg-slate-800/50 cursor-pointer transition"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">{inc.id}</td>
                  <td className="py-3 px-3"><SeverityBadge severity={inc.severity} size="sm" /></td>
                  <td className="py-3 px-3 text-slate-400">{inc.priority}</td>
                  <td className="py-3 px-4 font-sans font-medium text-slate-200">{inc.title}</td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {inc.status}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-cyan-400">{inc.rule_id}</td>
                  <td className="py-3 px-3">{inc.alert_count}</td>
                  <td className="py-3 px-4 text-right font-sans">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedIncident(inc);
                      }}
                      className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Incident Detail & Investigation Drawer */}
      <Drawer
        isOpen={Boolean(selectedIncident)}
        onClose={() => setSelectedIncident(null)}
        title={selectedIncident ? `${selectedIncident.id} — ${selectedIncident.title}` : 'Incident Investigation'}
        subtitle="Threat Evidence & Triage Dossier"
        width="2xl"
      >
        {selectedIncident && (
          <div className="space-y-6">
            {/* Status Transition Control Bar */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300">Investigation Lifecycle Status:</span>
                <select
                  value={selectedIncident.status}
                  onChange={e => handleStatusChange(selectedIncident.id, e.target.value as IncidentStatus)}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-cyan-300 font-mono font-semibold focus:outline-none focus:border-cyan-500 cursor-pointer"
                >
                  {statuses.map(st => (
                    <option key={st} value={st}>{st}</option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-2 pt-2 border-t border-slate-800 text-xs">
                <button
                  onClick={() => handleStatusChange(selectedIncident.id, 'False Positive')}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                >
                  Mark False Positive
                </button>
                <button
                  onClick={() => handleStatusChange(selectedIncident.id, 'Resolved')}
                  className="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded transition"
                >
                  Resolve Incident
                </button>
                <button
                  onClick={() => handleCopySummary(selectedIncident)}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition flex items-center gap-1 ml-auto"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy Summary'}</span>
                </button>
              </div>
            </div>

            {/* Incident Metadata Key-Value */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-slate-900/60 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-500">Severity: </span>
                <SeverityBadge severity={selectedIncident.severity} size="sm" />
              </div>
              <div>
                <span className="text-slate-500">Priority: </span>
                <span className="text-slate-200">{selectedIncident.priority}</span>
              </div>
              <div>
                <span className="text-slate-500">Trigger Rule: </span>
                <span className="text-cyan-400">{selectedIncident.rule_id}</span>
              </div>
              <div>
                <span className="text-slate-500">Target Entity: </span>
                <span className="text-slate-300">{selectedIncident.entity_key}</span>
              </div>
              <div>
                <span className="text-slate-500">First Seen: </span>
                <span className="text-slate-300">{new Date(selectedIncident.first_seen).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-500">Last Seen: </span>
                <span className="text-slate-300">{new Date(selectedIncident.last_seen).toLocaleString()}</span>
              </div>
            </div>

            {/* Correlated Detection Alerts Timeline */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" /> Correlated Alerts Evidence Chain ({selectedIncident.alerts?.length || 0})
              </h4>
              <div className="space-y-3">
                {selectedIncident.alerts?.map(alert => (
                  <div
                    key={alert.id}
                    className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-xs text-slate-200">{alert.title}</span>
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </div>
                    {alert.explanation && (
                      <p className="text-xs text-slate-400 leading-relaxed font-sans">
                        {alert.explanation}
                      </p>
                    )}
                    <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                      <span>Rule: {alert.rule_id}</span>
                      <span>Event Ref: {alert.event_id}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Investigation Notes Section */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                <MessageSquare className="w-4 h-4 text-cyan-400" /> Analyst Investigation Notes
              </h4>

              {/* Existing Notes Timeline */}
              <div className="space-y-2 mb-3">
                {selectedIncident.notes?.map(note => (
                  <div
                    key={note.id}
                    className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
                      <span className="text-cyan-400 font-semibold">{note.author}</span>
                      <span>{new Date(note.created_at).toLocaleString()}</span>
                    </div>
                    <p className="text-slate-200 leading-relaxed">{note.content}</p>
                  </div>
                ))}
                {(!selectedIncident.notes || selectedIncident.notes.length === 0) && (
                  <div className="text-xs text-slate-500 italic p-2">
                    No notes recorded yet for this incident.
                  </div>
                )}
              </div>

              {/* Add Note Input Form */}
              <div className="space-y-2">
                <textarea
                  value={newNoteText}
                  onChange={e => setNewNoteText(e.target.value)}
                  placeholder="Record forensic findings, triage observations, or remediation steps..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 min-h-[80px]"
                />
                <div className="flex justify-end">
                  <button
                    onClick={handleAddNote}
                    disabled={submittingNote || !newNoteText.trim()}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Save Analyst Note</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
