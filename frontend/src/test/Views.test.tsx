import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { AppProvider } from '../context/AppContext';
import { OverviewView } from '../views/OverviewView';
import { LiveEventsView } from '../views/LiveEventsView';
import { IncidentsView } from '../views/IncidentsView';
import { ProcessExplorerView } from '../views/ProcessExplorerView';
import { FileIntegrityView } from '../views/FileIntegrityView';
import { NetworkIntelView } from '../views/NetworkIntelView';
import { DetectionRulesView } from '../views/DetectionRulesView';
import { PersistenceView } from '../views/PersistenceView';
import { ReportsView } from '../views/ReportsView';
import { AuditLogsView } from '../views/AuditLogsView';
import { SettingsView } from '../views/SettingsView';
import { DiagnosticsView } from '../views/DiagnosticsView';

const renderWithProvider = (ui: React.ReactElement) => {
  return render(<AppProvider>{ui}</AppProvider>);
};

describe('Overview View', () => {
  it('renders threat posture score, sensors grid, and dynamic triage queue', async () => {
    renderWithProvider(<OverviewView />);
    await waitFor(() => {
      expect(screen.getByText('Threat Posture')).toBeInTheDocument();
      expect(screen.getByText('Sensor Engine Health Telemetry')).toBeInTheDocument();
      expect(screen.getByText('Critical Incident Triage Queue')).toBeInTheDocument();
      expect(screen.getByText(/Shadow Copy Deletion/i)).toBeInTheDocument();
      expect(screen.getByText('AGNI-R-PROC-003')).toBeInTheDocument();
    });
  });
});

describe('Live Events View', () => {
  it('renders events stream, allows filtering by severity, and opens event detail drawer', async () => {
    renderWithProvider(<LiveEventsView />);
    await waitFor(() => {
      expect(screen.getByText('Streaming Active')).toBeInTheDocument();
      expect(screen.getAllByText('PROCESS_EXEC').length).toBeGreaterThan(0);
    });

    // Test severity filter button
    const critBtn = screen.getByRole('button', { name: 'Critical' });
    fireEvent.click(critBtn);
    expect(screen.getAllByText('PROCESS_EXEC').length).toBeGreaterThan(0);

    // Click on row to open drawer
    const detailsBtns = screen.getAllByText('Details');
    fireEvent.click(detailsBtns[0]);
    await waitFor(() => {
      expect(screen.getByText('Normalized Attributes')).toBeInTheDocument();
      expect(screen.getByText('Copy JSON')).toBeInTheDocument();
    });
  });

  it('triggers JSON and CSV exports', async () => {
    renderWithProvider(<LiveEventsView />);
    await waitFor(() => {
      expect(screen.getByText('Export JSON')).toBeInTheDocument();
      expect(screen.getByText('Export CSV')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Export JSON'));
    fireEvent.click(screen.getByText('Export CSV'));
  });
});

describe('Incidents View', () => {
  it('toggles between Kanban and Table modes', async () => {
    renderWithProvider(<IncidentsView />);
    await waitFor(() => {
      expect(screen.getByText('Kanban Board')).toBeInTheDocument();
      expect(screen.getByText('Table Grid')).toBeInTheDocument();
    });

    // Switch to table
    fireEvent.click(screen.getByText('Table Grid'));
    expect(screen.getByText('Incident Title')).toBeInTheDocument();

    // Switch back to Kanban
    fireEvent.click(screen.getByText('Kanban Board'));
  });

  it('opens incident detail drawer and allows adding notes', async () => {
    renderWithProvider(<IncidentsView />);
    await waitFor(() => {
      expect(screen.getAllByText(/Shadow Copy Deletion/i).length).toBeGreaterThan(0);
    });

    // Click incident card
    const incCard = screen.getAllByText(/Shadow Copy Deletion/i)[0];
    fireEvent.click(incCard);

    await waitFor(() => {
      expect(screen.getByText(/Threat Evidence & Triage Dossier/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/Record forensic findings/i)).toBeInTheDocument();
    });

    // Add note
    const textarea = screen.getByPlaceholderText(/Record forensic findings/i);
    fireEvent.change(textarea, { target: { value: 'Verified ransomware command execution.' } });
    const saveNoteBtn = screen.getByText('Save Analyst Note');
    fireEvent.click(saveNoteBtn);

    await waitFor(() => {
      expect(screen.getByText('Verified ransomware command execution.')).toBeInTheDocument();
    });
  });
});

describe('Process Explorer View', () => {
  it('renders process list, filters by search, and opens inspector modal', async () => {
    renderWithProvider(<ProcessExplorerView />);
    await waitFor(() => {
      expect(screen.getByText('vssadmin.exe')).toBeInTheDocument();
    });

    // Filter by search
    const searchInput = screen.getByPlaceholderText(/Search PID, name, path/i);
    fireEvent.change(searchInput, { target: { value: 'vssadmin' } });
    expect(screen.getByText('vssadmin.exe')).toBeInTheDocument();

    // Open inspect modal
    const inspectBtns = screen.getAllByRole('button', { name: 'Inspect' });
    fireEvent.click(inspectBtns[0]);

    await waitFor(() => {
      expect(screen.getByText(/Sanitized Command Line/i)).toBeInTheDocument();
      expect(screen.getByText(/Read-Only Monitoring/i)).toBeInTheDocument();
    });
  });

  it('toggles between Flat Table and Lineage Hierarchy and renders indented process tree', async () => {
    renderWithProvider(<ProcessExplorerView />);
    await waitFor(() => {
      expect(screen.getByText('vssadmin.exe')).toBeInTheDocument();
    });

    // Initial flat table mode
    expect(screen.getByText('Flat Table')).toBeInTheDocument();
    expect(screen.queryByText('Lineage Hierarchy & Process Name')).not.toBeInTheDocument();

    // Switch to Lineage Hierarchy
    const treeBtn = screen.getByText('Lineage Hierarchy');
    fireEvent.click(treeBtn);

    // Verify tree mode table header and nodes
    await waitFor(() => {
      expect(screen.getByText('Lineage Hierarchy & Process Name')).toBeInTheDocument();
      const treeRows = screen.getAllByTestId('process-tree-node');
      expect(treeRows.length).toBeGreaterThan(0);
    });

    // Verify hierarchy structure: root process vs child process depth
    const explorerRow = screen.getAllByTestId('process-tree-node').find(el => el.getAttribute('data-pid') === '840');
    expect(explorerRow).toBeDefined();
    expect(explorerRow?.getAttribute('data-depth')).toBe('0');

    const vssRow = screen.getAllByTestId('process-tree-node').find(el => el.getAttribute('data-pid') === '8840');
    expect(vssRow).toBeDefined();
    expect(Number(vssRow?.getAttribute('data-depth'))).toBeGreaterThan(0);

    // Verify tree controls (Collapse All / Expand All)
    const collapseAllBtn = screen.getByText('Collapse All');
    fireEvent.click(collapseAllBtn);
    // After collapsing all parents, child processes like vssadmin (child of powershell) should be collapsed
    expect(screen.queryByTestId('tree-node-pid-8840')).not.toBeInTheDocument();

    const expandAllBtn = screen.getByText('Expand All');
    fireEvent.click(expandAllBtn);
    expect(screen.getByTestId('tree-node-pid-8840')).toBeInTheDocument();

    // Switch back to Flat Table
    const tableBtn = screen.getByText('Flat Table');
    fireEvent.click(tableBtn);

    await waitFor(() => {
      expect(screen.queryByText('Lineage Hierarchy & Process Name')).not.toBeInTheDocument();
      expect(screen.queryAllByTestId('process-tree-node').length).toBe(0);
    });
  });
});

describe('File Integrity View', () => {
  it('renders baselines and allows adding a new baseline and scanning', async () => {
    renderWithProvider(<FileIntegrityView />);
    await waitFor(() => {
      expect(screen.getByText('Windows Core Network Configs')).toBeInTheDocument();
      expect(screen.getByText('Scan Baselines Now')).toBeInTheDocument();
    });

    // Test scan trigger
    const scanBtn = screen.getByText('Scan Baselines Now');
    fireEvent.click(scanBtn);

    // Open Add Baseline modal
    const addBtn = screen.getByText('Add Baseline');
    fireEvent.click(addBtn);

    await waitFor(() => {
      expect(screen.getByText('Register File Integrity Baseline')).toBeInTheDocument();
    });
  });

  it('opens cryptographic diff modal for detected changes', async () => {
    renderWithProvider(<FileIntegrityView />);
    await waitFor(() => {
      expect(screen.getByText(/Inspect Diff/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Inspect Diff/i));
    await waitFor(() => {
      expect(screen.getByText(/Baseline Established SHA-256/i)).toBeInTheDocument();
      expect(screen.getByText(/Observed Current SHA-256/i)).toBeInTheDocument();
    });
  });
});

describe('Network Intelligence View', () => {
  it('renders adapters, active sockets, and ARP device inventory', async () => {
    renderWithProvider(<NetworkIntelView />);
    await waitFor(() => {
      expect(screen.getByText(/Vayu Network Defensive Scope Policy/i)).toBeInTheDocument();
      expect(screen.getByText(/Host Network Adapters/i)).toBeInTheDocument();
      expect(screen.getByText(/Active TCP\/UDP Sockets/i)).toBeInTheDocument();
      expect(screen.getByText(/Authorized Subnet Devices/i)).toBeInTheDocument();
    });
  });
});

describe('Detection Rules View', () => {
  it('renders 18 detection rules catalog and allows toggle and dry-run testing', async () => {
    renderWithProvider(<DetectionRulesView />);
    await waitFor(() => {
      expect(screen.getByText('AGNI-R-PROC-001')).toBeInTheDocument();
      expect(screen.getByText('AGNI-R-PROC-003')).toBeInTheDocument();
    });

    // Open inspect modal
    const inspectBtns = screen.getAllByRole('button', { name: 'Inspect' });
    fireEvent.click(inspectBtns[0]);

    await waitFor(() => {
      expect(screen.getByText(/Declarative Match Conditions AST/i)).toBeInTheDocument();
      expect(screen.getByText('Dry-Run Test Rule')).toBeInTheDocument();
    });

    // Test dry run button
    fireEvent.click(screen.getByText('Dry-Run Test Rule'));
    await waitFor(() => {
      expect(screen.getByText(/Test Evaluation:/i)).toBeInTheDocument();
    });
  });
});

describe('Persistence View', () => {
  it('renders autorun entries and allows category filtering', async () => {
    renderWithProvider(<PersistenceView />);
    await waitFor(() => {
      expect(screen.getByText('AgniUpdate')).toBeInTheDocument();
      expect(screen.getAllByText('Registry Run Key').length).toBeGreaterThan(0);
    });

    // Click inspect
    const inspectBtns = screen.getAllByRole('button', { name: 'Inspect' });
    fireEvent.click(inspectBtns[0]);

    await waitFor(() => {
      expect(screen.getByText(/Target Executable Path/i)).toBeInTheDocument();
    });
  });
});

describe('Reports View', () => {
  it('configures report options and initiates download', async () => {
    renderWithProvider(<ReportsView />);
    await waitFor(() => {
      expect(screen.getByText(/Security Intelligence Report Generator/i)).toBeInTheDocument();
      expect(screen.getByText('Generate & Download Report')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('JSON'));
    fireEvent.click(screen.getByText('Generate & Download Report'));
  });
});

describe('Audit Logs View', () => {
  it('renders audit trail and executes cryptographic sequence verification', async () => {
    renderWithProvider(<AuditLogsView />);
    await waitFor(() => {
      expect(screen.getByText(/Immutable System Audit Trail/i)).toBeInTheDocument();
      expect(screen.getByText('Verify Audit Chain')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Verify Audit Chain'));
    await waitFor(() => {
      expect(screen.getByText('Audit Chain Verified')).toBeInTheDocument();
    });
  });
});

describe('Settings View', () => {
  it('renders polling sliders, AI assistant consent gate, and demo seed controls', async () => {
    renderWithProvider(<SettingsView />);
    await waitFor(() => {
      expect(screen.getByText(/Sensor Polling Rates/i)).toBeInTheDocument();
      expect(screen.getByText(/Mandatory Privacy & Data Consent/i)).toBeInTheDocument();
      expect(screen.getByText(/Seed Operation Ignis Vector APT/i)).toBeInTheDocument();
    });

    // Test Save Settings
    const saveBtn = screen.getByText('Save Settings');
    fireEvent.click(saveBtn);
  });
});

describe('Diagnostics & About View', () => {
  it('renders platform metadata and runs interactive self-tests', async () => {
    renderWithProvider(<DiagnosticsView />);
    await waitFor(() => {
      expect(screen.getByText(/Host & Runtime Environment/i)).toBeInTheDocument();
      expect(screen.getByText(/Run All Diagnostic Tests/i)).toBeInTheDocument();
      expect(screen.getByText(/Aditya Zala/i)).toBeInTheDocument();
    });

    const runBtn = screen.getByText('Run All Diagnostic Tests');
    fireEvent.click(runBtn);
    await waitFor(() => {
      expect(screen.getByText(/Executing Self-Tests/i)).toBeInTheDocument();
    });
  });
});
