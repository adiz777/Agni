import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { api } from '../services/api';

export type ViewType = 
  | 'overview' 
  | 'events' 
  | 'incidents' 
  | 'processes' 
  | 'fim' 
  | 'network' 
  | 'rules' 
  | 'persistence' 
  | 'reports' 
  | 'audit' 
  | 'settings' 
  | 'diagnostics';

export interface ToastItem {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  message: string;
}

interface AppContextType {
  activeView: ViewType;
  setActiveView: (view: ViewType) => void;
  isSampleMode: boolean;
  toggleSampleMode: (enable?: boolean) => Promise<void>;
  platform: string;
  threatScore: number;
  setThreatScore: (score: number) => void;
  incidentSeverityFilter: string | null;
  setIncidentSeverityFilter: (sev: string | null) => void;
  toasts: ToastItem[];
  addToast: (message: string, type?: ToastItem['type']) => void;
  removeToast: (id: string) => void;
  refreshTrigger: number;
  triggerRefresh: () => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

const normalizeView = (raw: string): ViewType | null => {
  const clean = raw.replace(/^#\/?/, '').replace(/^\//, '').trim();
  const aliasMap: Record<string, ViewType> = {
    'live-events': 'events',
    'file-integrity': 'fim',
    'network-intel': 'network',
  };
  if (aliasMap[clean]) return aliasMap[clean];
  const validViews: ViewType[] = [
    'overview', 'events', 'incidents', 'processes', 'fim',
    'network', 'rules', 'persistence', 'reports', 'audit', 'settings', 'diagnostics'
  ];
  return validViews.includes(clean as ViewType) ? (clean as ViewType) : null;
};

export const AppProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [activeView, setActiveViewState] = useState<ViewType>(() => {
    return normalizeView(window.location.hash) || normalizeView(window.location.pathname) || 'overview';
  });

  const [isSampleMode, setIsSampleMode] = useState<boolean>(true);
  const [platform, setPlatform] = useState<string>('Windows');
  const [threatScore, setThreatScore] = useState<number>(55);
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  const triggerRefresh = () => setRefreshTrigger(prev => prev + 1);

  const addToast = (message: string, type: ToastItem['type'] = 'info') => {
    const id = `toast-${Date.now()}-${Math.random()}`;
    setToasts(prev => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const removeToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const setActiveView = (view: ViewType) => {
    setActiveViewState(view);
    window.location.hash = `#/${view}`;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    const handleHashChange = () => {
      const view = normalizeView(window.location.hash);
      if (view) {
        setActiveViewState(view);
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  // Fetch initial host & demo status
  useEffect(() => {
    api.getHealth()
      .then(res => {
        if (res.platform) setPlatform(res.platform);
        setIsSampleMode(res.mode === 'demo');
      })
      .catch(() => {});
  }, [refreshTrigger]);

  const toggleSampleMode = async (enable?: boolean) => {
    const nextState = enable !== undefined ? enable : !isSampleMode;
    try {
      await api.toggleDemoMode(nextState);
      setIsSampleMode(nextState);
      addToast(
        nextState 
          ? 'Switched to Sample/Demo Data Mode (Simulated APT scenario)' 
          : 'Switched to Live Host Telemetry Mode', 
        nextState ? 'warning' : 'success'
      );
      triggerRefresh();
    } catch {
      setIsSampleMode(nextState);
      addToast(`Sample Mode set to ${nextState ? 'Enabled' : 'Disabled'}`, 'info');
      triggerRefresh();
    }
  };

  return (
    <AppContext.Provider
      value={{
        activeView,
        setActiveView,
        isSampleMode,
        toggleSampleMode,
        platform,
        threatScore,
        setThreatScore,
        incidentSeverityFilter,
        setIncidentSeverityFilter,
        toasts,
        addToast,
        removeToast,
        refreshTrigger,
        triggerRefresh,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
