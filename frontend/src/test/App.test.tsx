import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';

describe('Agni SOC Dashboard App Shell', () => {
  it('renders root layout with Agni branding and SOC dark theme', async () => {
    render(<App />);
    expect(screen.getAllByText('AGNI').length).toBeGreaterThan(0);
    expect(screen.getAllByText('अग्नि').length).toBeGreaterThan(0);
  });

  it('renders all 12 navigation views in sidebar', async () => {
    render(<App />);
    const expectedViews = [
      'Overview',
      'Live Events',
      'Incidents',
      'Process Explorer',
      'File Integrity',
      'Network Intel',
      'Detection Rules',
      'Persistence',
      'Reports',
      'Audit Logs',
      'Settings',
      'Diagnostics & About',
    ];

    for (const view of expectedViews) {
      expect(screen.getByText(view)).toBeInTheDocument();
    }
  });

  it('switches views when navigation items are clicked', async () => {
    render(<App />);

    // Click Detection Rules
    const rulesBtn = screen.getByText('Detection Rules');
    fireEvent.click(rulesBtn);
    await waitFor(() => {
      expect(screen.getByText('Detection Rules Catalog')).toBeInTheDocument();
    });

    // Click Network Intel
    const netBtn = screen.getByText('Network Intel');
    fireEvent.click(netBtn);
    await waitFor(() => {
      expect(screen.getByText('Vayu Network Intelligence')).toBeInTheDocument();
    });

    // Click Overview
    const ovBtn = screen.getByText('Overview');
    fireEvent.click(ovBtn);
    await waitFor(() => {
      expect(screen.getByText('SOC Situational Overview')).toBeInTheDocument();
    });
  });

  it('renders Sample Mode warning banner when sample mode is active and allows toggling', async () => {
    render(<App />);
    expect(screen.getByText(/DEMO MODE ACTIVE/i)).toBeInTheDocument();

    const switchBtn = screen.getByText('Switch to Live Host Telemetry');
    fireEvent.click(switchBtn);

    await waitFor(() => {
      expect(screen.queryByText(/DEMO MODE ACTIVE/i)).not.toBeInTheDocument();
    });
  });
});
