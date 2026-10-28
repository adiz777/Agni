import React from 'react';
import { useApp } from '../context/AppContext';
import { ShieldAlert, Sparkles, Terminal } from 'lucide-react';

export const SampleModeBanner: React.FC = () => {
  const { isSampleMode, toggleSampleMode } = useApp();

  if (!isSampleMode) return null;

  return (
    <aside 
      aria-label="Sample Demonstration Mode Notice"
      className="bg-gradient-to-r from-purple-950/90 via-slate-900/90 to-purple-950/90 border-b border-purple-700/50 px-4 py-2 text-xs text-purple-200 flex flex-wrap items-center justify-between gap-3 shadow-md backdrop-blur-sm"
    >
      <div className="flex items-center gap-2.5">
        <span className="flex items-center justify-center p-1 bg-purple-500/20 text-purple-400 rounded border border-purple-500/30">
          <Sparkles className="w-3.5 h-3.5" />
        </span>
        <div className="flex items-center gap-2">
          <span className="font-bold uppercase tracking-wider text-purple-300">
            DEMO MODE ACTIVE:
          </span>
          <span>
            Displaying simulated enterprise intrusion scenario (Operation Ignis Vector: Encoded PowerShell, Certutil staging, Hosts tampering, C2 beaconing).
          </span>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={() => toggleSampleMode(false)}
          className="px-2.5 py-1 text-[11px] font-semibold bg-purple-600 hover:bg-purple-500 text-white rounded transition shadow-sm hover:shadow"
        >
          Switch to Live Host Telemetry
        </button>
      </div>
    </aside>
  );
};

interface PlatformBannerProps {
  featureName?: string;
  className?: string;
}

export const PlatformCapabilityBanner: React.FC<PlatformBannerProps> = ({
  featureName = 'System Telemetry',
  className = '',
}) => {
  const { platform } = useApp();

  return (
    <div 
      className={`bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs text-slate-300 flex items-start gap-3 ${className}`}
    >
      <Terminal className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
      <div className="space-y-1 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-200">
            Platform Environment:
          </span>
          <span className="px-1.5 py-0.2 rounded bg-slate-800 border border-slate-700 text-cyan-300 font-mono text-[11px]">
            {platform}
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">
            Feature: {featureName}
          </span>
        </div>
        <p className="text-slate-400 text-[11px] leading-relaxed">
          Operating in user-level telemetry mode. Read-only inspection is active across processes, active TCP/UDP sockets, FIM hashes, and autorun locations. Administrative/root permissions may be required for full kernel-level ETW tracing or system-owned service inspection.
        </p>
      </div>
    </div>
  );
};

export const ThreatNoticeBanner: React.FC = () => {
  const { threatScore, setActiveView } = useApp();

  if (threatScore > 50) return null;

  return (
    <div className="bg-rose-950/70 border border-rose-800/80 rounded-lg p-3 mb-4 flex items-center justify-between text-xs text-rose-200">
      <div className="flex items-center gap-2.5">
        <ShieldAlert className="w-4 h-4 text-rose-400 animate-pulse" />
        <div>
          <span className="font-bold uppercase tracking-wider text-rose-300">
            Elevated Threat Level ({threatScore}/100):
          </span>{' '}
          Active critical incidents detected requiring immediate analyst triage.
        </div>
      </div>
      <button
        onClick={() => setActiveView('incidents')}
        className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded font-medium transition"
      >
        Triage Incidents
      </button>
    </div>
  );
};
