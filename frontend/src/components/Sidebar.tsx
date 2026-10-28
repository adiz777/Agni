import React from 'react';
import { useApp, ViewType } from '../context/AppContext';
import { AgniLogo } from '../assets/AgniLogo';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Cpu,
  FileCheck2,
  Network,
  Sliders,
  Power,
  FileSpreadsheet,
  History,
  Settings,
  HelpCircle,
} from 'lucide-react';

interface NavItem {
  id: ViewType;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

export const Sidebar: React.FC = () => {
  const { activeView, setActiveView, isSampleMode } = useApp();

  const navItems: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'events', label: 'Live Events', icon: Activity },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert, badge: '3' },
    { id: 'processes', label: 'Process Explorer', icon: Cpu },
    { id: 'fim', label: 'File Integrity', icon: FileCheck2 },
    { id: 'network', label: 'Network Intel', icon: Network },
    { id: 'rules', label: 'Detection Rules', icon: Sliders, badge: '18' },
    { id: 'persistence', label: 'Persistence', icon: Power },
    { id: 'reports', label: 'Reports', icon: FileSpreadsheet },
    { id: 'audit', label: 'Audit Logs', icon: History },
    { id: 'settings', label: 'Settings', icon: Settings },
    { id: 'diagnostics', label: 'Diagnostics & About', icon: HelpCircle },
  ];

  return (
    <aside 
      aria-label="Main Navigation"
      className="w-64 bg-[#0f172a] border-r border-slate-800 flex flex-col justify-between flex-shrink-0 min-h-screen"
    >
      <div>
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80">
          <AgniLogo markSize={32} />
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Host Status */}
      <div className="p-4 border-t border-slate-800 bg-slate-900/40 text-xs">
        <div className="flex items-center justify-between mb-2">
          <span className="text-slate-400">Sensor Status</span>
          <span className="flex items-center gap-1.5 text-emerald-400 font-mono text-[11px]">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Healthy
          </span>
        </div>
        <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>Mode</span>
          <span className={isSampleMode ? 'text-purple-400' : 'text-cyan-400'}>
            {isSampleMode ? 'Sample (Demo)' : 'Live Host'}
          </span>
        </div>
      </div>
    </aside>
  );
};
