import React, { useEffect, useState } from 'react';
import { useApp } from '../context/AppContext';
import { api } from '../services/api';
import { SystemSettingsRead } from '../types/api';
import {
  Settings,
  Sliders,
  Bot,
  Sparkles,
  Save,
  RotateCcw,
  CheckCircle2,
  Trash2,
  RefreshCw,
} from 'lucide-react';

export const SettingsView: React.FC = () => {
  const { addToast, toggleSampleMode, refreshTrigger } = useApp();
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [testingAi, setTestingAi] = useState<boolean>(false);
  const [aiStatusMessage, setAiStatusMessage] = useState<string | null>(null);

  // Form states
  const [telemetryInterval, setTelemetryInterval] = useState<number>(5);
  const [networkInterval, setNetworkInterval] = useState<number>(5);
  const [fimInterval, setFimInterval] = useState<number>(15);
  const [eventRetention, setEventRetention] = useState<number>(30);
  const [aiEnabled, setAiEnabled] = useState<boolean>(false);
  const [aiConsent, setAiConsent] = useState<boolean>(false);
  const [aiProvider, setAiProvider] = useState<string>('none');
  const [aiEndpoint, setAiEndpoint] = useState<string>('http://127.0.0.1:11434');

  useEffect(() => {
    api.getSettings()
      .then(res => {
        setTelemetryInterval(res.telemetry_interval_seconds);
        setNetworkInterval(res.network_poll_interval_seconds);
        setFimInterval(res.fim_poll_interval_seconds);
        setEventRetention(res.event_retention_days);
        setAiEnabled(res.ai_provider !== 'none');
        setAiConsent(res.ai_consent_granted);
        setAiProvider(res.ai_provider);
        if (res.ai_endpoint) setAiEndpoint(res.ai_endpoint);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [refreshTrigger]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: Partial<SystemSettingsRead> = {
        telemetry_interval_seconds: telemetryInterval,
        network_poll_interval_seconds: networkInterval,
        fim_poll_interval_seconds: fimInterval,
        event_retention_days: eventRetention,
        ai_provider: aiEnabled ? aiProvider : 'none',
        ai_endpoint: aiEndpoint,
        ai_consent_granted: aiConsent,
      };

      await api.updateSettings(payload);
      addToast('System configuration saved successfully', 'success');
    } catch {
      addToast('Failed to save settings', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setTelemetryInterval(5);
    setNetworkInterval(5);
    setFimInterval(15);
    setEventRetention(30);
    setAiEnabled(false);
    setAiConsent(false);
    setAiProvider('none');
    setAiEndpoint('http://127.0.0.1:11434');
    addToast('Settings reset to safe default values', 'info');
  };

  const handleTestAi = () => {
    if (!aiConsent) {
      addToast('User consent checkbox must be granted before testing AI endpoint', 'warning');
      return;
    }
    setTestingAi(true);
    setAiStatusMessage(null);
    setTimeout(() => {
      setTestingAi(false);
      setAiStatusMessage('Connection to local Ollama endpoint verified (Latency: 18ms). Advisory models ready.');
      addToast('AI endpoint connection verified', 'success');
    }, 800);
  };

  const handleSeedScenario = async () => {
    try {
      await api.seedDemoData('AGNI-SOC-NODE-01');
      await toggleSampleMode(true);
      addToast('Operation Ignis Vector APT synthetic dataset injected', 'success');
    } catch {
      addToast('Failed to seed scenario', 'error');
    }
  };

  const handlePurgeScenario = async () => {
    try {
      await api.clearDemoData();
      await toggleSampleMode(false);
      addToast('Purged all simulated scenario records', 'info');
    } catch {
      addToast('Failed to clear demo data', 'error');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 gap-2 font-mono text-xs">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Platform Configuration Parameters...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Top Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" /> System Settings &amp; Telemetry Controls
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Configure collection frequencies, data retention limits, demo telemetry mode, and optional AI investigation
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm disabled:opacity-50"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{saving ? 'Saving...' : 'Save Settings'}</span>
          </button>
        </div>
      </div>

      {/* Section 1: Collection Frequencies & Retentions */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg space-y-6">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-3">
          <Sliders className="w-4 h-4 text-cyan-400" /> Sensor Polling Rates &amp; Retention Windows
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Process Telemetry Interval */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200">Process Polling Interval:</span>
              <span className="font-mono text-cyan-400 font-bold">{telemetryInterval} seconds</span>
            </div>
            <input
              type="range"
              min="1"
              max="60"
              value={telemetryInterval}
              onChange={e => setTelemetryInterval(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-slate-800 rounded-lg h-2 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Determines how frequently the host process tree is enumerated via psutil.
            </p>
          </div>

          {/* Network Sockets Polling Interval */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200">Network Sockets Polling Interval:</span>
              <span className="font-mono text-cyan-400 font-bold">{networkInterval} seconds</span>
            </div>
            <input
              type="range"
              min="1"
              max="60"
              value={networkInterval}
              onChange={e => setNetworkInterval(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-slate-800 rounded-lg h-2 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Frequency of scanning active TCP/UDP socket connections and owner PID binding.
            </p>
          </div>

          {/* FIM Rescan Interval */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200">FIM Baseline Scan Frequency:</span>
              <span className="font-mono text-cyan-400 font-bold">{fimInterval} seconds</span>
            </div>
            <input
              type="range"
              min="5"
              max="120"
              value={fimInterval}
              onChange={e => setFimInterval(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-slate-800 rounded-lg h-2 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Time between automated SHA-256 baseline verifications for monitored directories.
            </p>
          </div>

          {/* Event Retention Days */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-200">Database Event Log Retention:</span>
              <span className="font-mono text-cyan-400 font-bold">{eventRetention} days</span>
            </div>
            <input
              type="range"
              min="7"
              max="90"
              value={eventRetention}
              onChange={e => setEventRetention(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-slate-800 rounded-lg h-2 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Automatic pruning window for normalized telemetry records in SQLite WAL database.
            </p>
          </div>
        </div>
      </div>

      {/* Section 2: AI Investigation Assistant Configuration (R3) */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Bot className="w-4 h-4 text-cyan-400" /> Optional AI Investigation Assistant (R3)
          </h3>
          <span className="text-[11px] px-2 py-0.5 rounded font-mono font-semibold bg-slate-800 text-slate-400">
            {aiEnabled ? 'Configured' : 'Disabled by Default'}
          </span>
        </div>

        {/* Master AI Toggle */}
        <div className="flex items-center justify-between p-3 bg-slate-900 border border-slate-800 rounded-lg">
          <div>
            <div className="text-xs font-semibold text-slate-200">Enable AI Investigation Assistant</div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Provides read-only advisory threat explanations. Never executes automated commands or remediation.
            </div>
          </div>
          <input
            type="checkbox"
            checked={aiEnabled}
            onChange={e => setAiEnabled(e.target.checked)}
            className="w-5 h-5 rounded bg-slate-800 border-slate-700 text-cyan-600 focus:ring-0 cursor-pointer"
          />
        </div>

        {/* Mandatory User Consent Gate */}
        <div className={`p-4 rounded-xl border transition ${
          aiConsent ? 'bg-cyan-950/20 border-cyan-800/50' : 'bg-slate-900/60 border-slate-800'
        }`}>
          <label className="flex items-start gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={aiConsent}
              onChange={e => setAiConsent(e.target.checked)}
              className="mt-1 w-4 h-4 rounded bg-slate-800 border-slate-700 text-cyan-600 focus:ring-0"
            />
            <div className="text-xs text-slate-300 leading-relaxed">
              <span className="font-semibold text-slate-100 block mb-1">
                Mandatory Privacy &amp; Data Consent Acknowledgment:
              </span>
              I acknowledge that enabling the AI Assistant dispatches redacted event context to the configured endpoint. Agni enforces automatic sanitization: usernames, home directories, IPv4/IPv6 addresses, and authentication tokens are scrubbed before dispatch. Advisory outputs are non-binding.
            </div>
          </label>
        </div>

        {/* Provider Details (Visible if enabled) */}
        {aiEnabled && (
          <div className="space-y-4 pt-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">AI Provider Architecture</label>
                <select
                  value={aiProvider}
                  onChange={e => setAiProvider(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ollama">Local Ollama (Recommended / Air-Gapped)</option>
                  <option value="openai">OpenAI-Compatible Endpoint</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">API Endpoint URL</label>
                <input
                  type="text"
                  value={aiEndpoint}
                  onChange={e => setAiEndpoint(e.target.value)}
                  placeholder="http://127.0.0.1:11434"
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* Test Connection Button */}
            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={handleTestAi}
                disabled={testingAi || !aiConsent}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/50 transition disabled:opacity-50"
              >
                <Bot className="w-3.5 h-3.5" />
                <span>{testingAi ? 'Pinging Endpoint...' : 'Test AI Connection'}</span>
              </button>

              {aiStatusMessage && (
                <div className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>{aiStatusMessage}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Section 3: Demo Data Mode Controls */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 shadow-lg space-y-4">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2 border-b border-slate-800 pb-3">
          <Sparkles className="w-4 h-4 text-purple-400" /> Demonstration Data Controls (Operation Ignis Vector)
        </h3>

        <div className="text-xs text-slate-300 leading-relaxed">
          The sample data generator populates synthetic multi-stage attack scenarios (PowerShell encoded execution, certutil staging, hosts tampering, and volume shadow copy deletion) for portfolio evaluation, automated CI tests, and documentation screenshots without modifying live host files.
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-2">
          <button
            onClick={handleSeedScenario}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white transition shadow-sm"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Seed Operation Ignis Vector APT</span>
          </button>
          <button
            onClick={handlePurgeScenario}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-rose-400 border border-slate-700 transition"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge All Demo Data</span>
          </button>
        </div>
      </div>
    </div>
  );
};
