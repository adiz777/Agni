import React from 'react';
import { AppProvider, useApp } from './context/AppContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { SampleModeBanner, ThreatNoticeBanner } from './components/Banners';
import { ToastContainer } from './components/Toast';

import { OverviewView } from './views/OverviewView';
import { LiveEventsView } from './views/LiveEventsView';
import { IncidentsView } from './views/IncidentsView';
import { ProcessExplorerView } from './views/ProcessExplorerView';
import { FileIntegrityView } from './views/FileIntegrityView';
import { NetworkIntelView } from './views/NetworkIntelView';
import { DetectionRulesView } from './views/DetectionRulesView';
import { PersistenceView } from './views/PersistenceView';
import { ReportsView } from './views/ReportsView';
import { AuditLogsView } from './views/AuditLogsView';
import { SettingsView } from './views/SettingsView';
import { DiagnosticsView } from './views/DiagnosticsView';

const MainContent: React.FC = () => {
  const { activeView } = useApp();

  const renderView = () => {
    switch (activeView) {
      case 'overview':
        return <OverviewView />;
      case 'events':
        return <LiveEventsView />;
      case 'incidents':
        return <IncidentsView />;
      case 'processes':
        return <ProcessExplorerView />;
      case 'fim':
        return <FileIntegrityView />;
      case 'network':
        return <NetworkIntelView />;
      case 'rules':
        return <DetectionRulesView />;
      case 'persistence':
        return <PersistenceView />;
      case 'reports':
        return <ReportsView />;
      case 'audit':
        return <AuditLogsView />;
      case 'settings':
        return <SettingsView />;
      case 'diagnostics':
        return <DiagnosticsView />;
      default:
        return <OverviewView />;
    }
  };

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[#0a0f1d] min-h-screen">
      <Navbar />
      <main className="flex-1 p-6 overflow-y-auto">
        <ThreatNoticeBanner />
        {renderView()}
      </main>
      <ToastContainer />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AppProvider>
      <div className="flex flex-col min-h-screen bg-[#0a0f1d] text-slate-100 antialiased font-sans">
        <SampleModeBanner />
        <div className="flex flex-1 min-h-0">
          <Sidebar />
          <MainContent />
        </div>
      </div>
    </AppProvider>
  );
};

export default App;
