import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { DetectionRuleRead } from '../types/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { Modal } from '../components/Modal';
import {
  Sliders,
  Search,
  Play,
  RefreshCw,
} from 'lucide-react';

export const DetectionRulesView: React.FC = () => {
  const { addToast, refreshTrigger } = useApp();
  const [rules, setRules] = useState<DetectionRuleRead[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedRule, setSelectedRule] = useState<DetectionRuleRead | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [testingRule, setTestingRule] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<{ matched: boolean; evaluation_time_ms: number } | null>(null);

  const fetchRules = () => {
    api.getRules()
      .then(res => {
        setRules(res);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchRules();
  }, [refreshTrigger]);

  const handleToggle = async (ruleId: string, currentEnabled: boolean) => {
    const nextState = !currentEnabled;
    try {
      const updated = await api.toggleRule(ruleId, nextState);
      setRules(prev => prev.map(r => r.id === ruleId ? updated : r));
      if (selectedRule?.id === ruleId) {
        setSelectedRule(updated);
      }
      addToast(`Rule ${ruleId} ${nextState ? 'Enabled' : 'Disabled'}`, nextState ? 'success' : 'warning');
    } catch {
      addToast('Failed to toggle detection rule', 'error');
    }
  };

  const handleTestRule = async () => {
    if (!selectedRule) return;
    setTestingRule(true);
    try {
      const sampleEvent = {
        category: selectedRule.category,
        action: 'PROCESS_EXEC',
        actor: { name: 'powershell.exe', cmdline: '-enc SQBFAFgA' },
        target: { identifier: 'C:\\Windows\\System32\\drivers\\etc\\hosts' },
      };
      const res = await api.testRule(selectedRule, sampleEvent);
      setTestResult(res);
      addToast(`Rule AST dry-run evaluated in ${res.evaluation_time_ms}ms`, 'info');
    } catch {
      addToast('Failed to execute rule dry-run', 'error');
    } finally {
      setTestingRule(false);
    }
  };

  const filteredRules = rules.filter(r => {
    if (severityFilter !== 'All' && r.severity.toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    if (categoryFilter !== 'All' && r.category.toLowerCase() !== categoryFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchId = r.id.toLowerCase().includes(q);
      const matchName = r.name.toLowerCase().includes(q);
      const matchDesc = r.description.toLowerCase().includes(q);
      const matchMitre = (r.mitre_attack || '').toLowerCase().includes(q);
      return matchId || matchName || matchDesc || matchMitre;
    }
    return true;
  });

  if (loading && rules.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Detection Rules Catalog...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Catalog Stats & Filter Toolbar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" /> Varuna Detection Rules Catalog
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              18 pre-tuned defensive rules mapped to MITRE ATT&amp;CK techniques with correlation windows
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>Active Rules: {rules.filter(r => r.enabled).length} / {rules.length}</span>
          </div>
        </div>

        {/* Filters & Search */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-500 mr-1">Severity:</span>
            {['All', 'Critical', 'High', 'Medium'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition ${
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

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search rule ID, technique, name..."
              className="w-full bg-slate-900/90 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Rules Catalog Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="text-[11px] uppercase tracking-wider text-slate-400 bg-slate-900/90 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Rule ID</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Category</th>
                <th className="py-3 px-4 font-sans">Rule Name &amp; Description</th>
                <th className="py-3 px-3">MITRE ATT&amp;CK</th>
                <th className="py-3 px-3">Window</th>
                <th className="py-3 px-3 text-center">Status</th>
                <th className="py-3 px-3 text-right font-sans">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRules.map(rule => (
                <tr
                  key={rule.id}
                  onClick={() => {
                    setSelectedRule(rule);
                    setTestResult(null);
                  }}
                  className="hover:bg-slate-800/50 cursor-pointer transition"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">{rule.id}</td>
                  <td className="py-3 px-3">
                    <SeverityBadge severity={rule.severity} size="sm" />
                  </td>
                  <td className="py-3 px-3 uppercase text-[10px] text-slate-400">
                    {rule.category}
                  </td>
                  <td className="py-3 px-4 font-sans">
                    <div className="font-semibold text-slate-200">{rule.name}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{rule.description}</div>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 text-[10px]">
                      {rule.mitre_attack || 'T1059'}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400">{rule.correlation_window}s</td>
                  <td className="py-3 px-3 text-center font-sans">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleToggle(rule.id, rule.enabled);
                      }}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition border ${
                        rule.enabled
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                          : 'bg-slate-800 text-slate-500 border-slate-700 hover:text-slate-300'
                      }`}
                    >
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="py-3 px-3 text-right font-sans">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRule(rule);
                        setTestResult(null);
                      }}
                      className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 rounded text-xs transition"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule Inspection Modal */}
      <Modal
        isOpen={Boolean(selectedRule)}
        onClose={() => {
          setSelectedRule(null);
          setTestResult(null);
        }}
        title={selectedRule ? `${selectedRule.id} — ${selectedRule.name}` : 'Rule Details'}
        subtitle="Detection AST Specification & Correlation Parameters"
        maxWidth="2xl"
      >
        {selectedRule && (
          <div className="space-y-4 text-xs font-mono">
            {/* Header Meta */}
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-slate-900 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-3">
                <SeverityBadge severity={selectedRule.severity} />
                <span className="text-slate-400">MITRE ATT&amp;CK: {selectedRule.mitre_attack}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-500">State:</span>
                <button
                  onClick={() => handleToggle(selectedRule.id, selectedRule.enabled)}
                  className={`px-2.5 py-1 rounded font-sans font-semibold text-xs border transition ${
                    selectedRule.enabled
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-slate-800 text-slate-500 border-slate-700'
                  }`}
                >
                  {selectedRule.enabled ? 'Enabled (Active)' : 'Disabled'}
                </button>
              </div>
            </div>

            {/* Threat Rationale & Explanation */}
            <div>
              <span className="font-semibold text-slate-300 font-sans block mb-1">
                Threat Rationale &amp; Attack Explanation:
              </span>
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 font-sans text-slate-300 leading-relaxed text-xs">
                {selectedRule.explanation || selectedRule.description}
              </div>
            </div>

            {/* Match Condition AST */}
            <div>
              <span className="font-semibold text-slate-300 font-sans block mb-1 flex items-center justify-between">
                <span>Declarative Match Conditions AST:</span>
                <span className="text-[11px] text-slate-500">Window: {selectedRule.correlation_window}s | Threshold: {selectedRule.threshold}</span>
              </span>
              <pre className="p-3 bg-black/80 rounded-lg border border-slate-800 text-cyan-300 overflow-x-auto text-[11px] leading-relaxed max-h-48">
                {JSON.stringify(selectedRule.match_conditions, null, 2)}
              </pre>
            </div>

            {/* Recommended Investigation Steps */}
            {selectedRule.investigation_steps && selectedRule.investigation_steps.length > 0 && (
              <div>
                <span className="font-semibold text-slate-300 font-sans block mb-1">
                  SOC Analyst Investigation Steps:
                </span>
                <ol className="p-3 bg-slate-900/70 rounded-lg border border-slate-800 font-sans text-slate-300 space-y-1.5 list-decimal list-inside text-xs">
                  {selectedRule.investigation_steps.map((st, i) => (
                    <li key={i}>{st}</li>
                  ))}
                </ol>
              </div>
            )}

            {/* Dry-run Evaluation Result if triggered */}
            {testResult && (
              <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-200 flex items-center justify-between font-sans">
                <div>
                  <span className="font-semibold">Test Evaluation: </span>
                  {testResult.matched ? 'MATCHED synthetic threat event' : 'NO MATCH against sample payload'}
                </div>
                <div className="font-mono text-xs text-cyan-400">
                  Latency: {testResult.evaluation_time_ms} ms
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="pt-2 border-t border-slate-800 flex justify-end gap-2 font-sans">
              <button
                onClick={handleTestRule}
                disabled={testingRule}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{testingRule ? 'Evaluating AST...' : 'Dry-Run Test Rule'}</span>
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
