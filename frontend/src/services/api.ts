import {
  ApiResponse,
  AuditLogRead,
  DetectionRuleRead,
  DiagnosticsReport,
  FIMBaselineRead,
  FIMChangeRead,
  FIMScanResult,
  HealthResponse,
  IncidentDetailRead,
  IncidentNoteRead,
  IncidentRead,
  IncidentStatus,
  InterfaceRead,
  NetworkDeviceRead,
  PaginatedResponse,
  PersistenceRead,
  ProcessRead,
  SensorHealthStatus,
  SocketRead,
  SystemSettingsRead,
  TelemetryEventRead,
  TelemetryOverviewRead,
} from '../types/api';
import {
  MOCK_AUDIT_LOGS,
  MOCK_BASELINES,
  MOCK_DEVICES,
  MOCK_DIAGNOSTICS,
  MOCK_EVENTS,
  MOCK_FIM_CHANGES,
  MOCK_HEALTH,
  MOCK_INCIDENTS,
  MOCK_INTERFACES,
  MOCK_OVERVIEW,
  MOCK_PERSISTENCE,
  MOCK_PROCESSES,
  MOCK_RULES,
  MOCK_SENSORS,
  MOCK_SETTINGS,
  MOCK_SOCKETS,
} from './mockData';

// API Base configuration targeting 127.0.0.1:8000/api/v1 with relative fallback
const getBaseUrl = (): string => {
  if (typeof window !== 'undefined' && window.location.hostname === '127.0.0.1' && window.location.port === '8000') {
    return '/api/v1';
  }
  return 'http://127.0.0.1:8000/api/v1';
};

const BASE_URL = getBaseUrl();

// Mutable state store for offline/demo/testing mode
let stateIncidents: IncidentDetailRead[] = [...MOCK_INCIDENTS];
let stateRules: DetectionRuleRead[] = [...MOCK_RULES];
let stateBaselines: FIMBaselineRead[] = [...MOCK_BASELINES];
let stateFimChanges: FIMChangeRead[] = [...MOCK_FIM_CHANGES];
let stateSettings: SystemSettingsRead = { ...MOCK_SETTINGS };
let stateAuditLogs: AuditLogRead[] = [...MOCK_AUDIT_LOGS];

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${BASE_URL}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const json: ApiResponse<T> = await res.json();
    return json.data;
  } catch (err) {
    // If backend is offline or unreachable, handle with interactive local store
    return handleOfflineFallback<T>(endpoint, options, err);
  }
}

function handleOfflineFallback<T>(endpoint: string, options: RequestInit, _err: unknown): T {
  const method = (options.method || 'GET').toUpperCase();
  const cleanEndpoint = endpoint.split('?')[0];

  // GET endpoints
  if (method === 'GET') {
    if (cleanEndpoint === '/health') return MOCK_HEALTH as unknown as T;
    if (cleanEndpoint === '/sensor/status') return MOCK_SENSORS as unknown as T;
    if (cleanEndpoint === '/diagnostics') return MOCK_DIAGNOSTICS as unknown as T;
    if (cleanEndpoint === '/telemetry/overview') return MOCK_OVERVIEW as unknown as T;
    if (cleanEndpoint === '/telemetry/events') {
      const resp: PaginatedResponse<TelemetryEventRead> = {
        items: MOCK_EVENTS,
        total: MOCK_EVENTS.length,
        limit: 50,
        offset: 0,
      };
      return resp as unknown as T;
    }
    if (cleanEndpoint === '/telemetry/processes') return MOCK_PROCESSES as unknown as T;
    if (cleanEndpoint === '/telemetry/network/connections') return MOCK_SOCKETS as unknown as T;
    if (cleanEndpoint === '/telemetry/network/interfaces') return MOCK_INTERFACES as unknown as T;
    if (cleanEndpoint === '/telemetry/network/devices') return MOCK_DEVICES as unknown as T;
    if (cleanEndpoint === '/telemetry/persistence') return MOCK_PERSISTENCE as unknown as T;
    if (cleanEndpoint === '/fim/status') {
      return {
        total_baselines: stateBaselines.length,
        total_files_monitored: stateBaselines.reduce((a, b) => a + b.total_files, 0),
        total_changes_detected: stateFimChanges.length,
        unacknowledged_changes: stateFimChanges.filter(c => !c.acknowledged).length,
        baselines: stateBaselines,
      } as unknown as T;
    }
    if (cleanEndpoint === '/fim/baselines') return stateBaselines as unknown as T;
    if (cleanEndpoint === '/fim/changes') return stateFimChanges as unknown as T;
    if (cleanEndpoint === '/rules') return stateRules as unknown as T;
    if (cleanEndpoint.startsWith('/rules/')) {
      const id = cleanEndpoint.replace('/rules/', '');
      const r = stateRules.find(x => x.id === id);
      return (r || stateRules[0]) as unknown as T;
    }
    if (cleanEndpoint === '/incidents' || cleanEndpoint === '/incidents/') {
      const resp: PaginatedResponse<IncidentRead> = {
        items: stateIncidents,
        total: stateIncidents.length,
        limit: 50,
        offset: 0,
      };
      return resp as unknown as T;
    }
    if (cleanEndpoint.startsWith('/incidents/')) {
      const id = cleanEndpoint.replace('/incidents/', '');
      const inc = stateIncidents.find(x => x.id === id);
      return (inc || stateIncidents[0]) as unknown as T;
    }
    if (cleanEndpoint === '/audit/logs') {
      const resp: PaginatedResponse<AuditLogRead> = {
        items: stateAuditLogs,
        total: stateAuditLogs.length,
        limit: 50,
        offset: 0,
      };
      return resp as unknown as T;
    }
    if (cleanEndpoint === '/settings') return stateSettings as unknown as T;
    if (cleanEndpoint === '/demo/status') {
      return {
        is_seeded: true,
        scenario_name: 'Operation Ignis Vector APT',
        events_count: MOCK_EVENTS.length,
        incidents_count: stateIncidents.length,
        alerts_count: 6,
        devices_count: MOCK_DEVICES.length,
        target_hostname: 'AGNI-SOC-NODE-01',
        last_seeded_at: new Date().toISOString(),
      } as unknown as T;
    }
  }

  // Mutations (PATCH, POST, PUT)
  if (method === 'PATCH') {
    if (cleanEndpoint.includes('/rules/') && cleanEndpoint.endsWith('/toggle')) {
      const ruleId = cleanEndpoint.split('/')[2];
      const body = options.body ? JSON.parse(options.body as string) : {};
      stateRules = stateRules.map(r => r.id === ruleId ? { ...r, enabled: body.enabled ?? !r.enabled } : r);
      const updated = stateRules.find(r => r.id === ruleId);
      logAuditAction('RULE_TOGGLED', `rule:${ruleId}`, { enabled: updated?.enabled });
      return updated as unknown as T;
    }
    if (cleanEndpoint.startsWith('/incidents/')) {
      const incId = cleanEndpoint.split('/')[2];
      const body = options.body ? JSON.parse(options.body as string) : {};
      stateIncidents = stateIncidents.map(inc => {
        if (inc.id === incId) {
          const updated: IncidentDetailRead = {
            ...inc,
            status: body.status || inc.status,
            assigned_analyst: body.assigned_analyst || inc.assigned_analyst,
          };
          if (body.analyst_note) {
            updated.notes = [
              ...updated.notes,
              {
                id: `note-${Date.now()}`,
                incident_id: incId,
                author: body.assigned_analyst || 'local_analyst',
                created_at: new Date().toISOString(),
                content: body.analyst_note,
              },
            ];
          }
          return updated;
        }
        return inc;
      });
      const updatedInc = stateIncidents.find(x => x.id === incId);
      logAuditAction('INCIDENT_STATUS_TRANSITION', `incident:${incId}`, body);
      return updatedInc as unknown as T;
    }
  }

  if (method === 'POST') {
    if (cleanEndpoint.includes('/incidents/') && cleanEndpoint.endsWith('/notes')) {
      const incId = cleanEndpoint.split('/')[2];
      const body = options.body ? JSON.parse(options.body as string) : {};
      const newNote = {
        id: `note-${Date.now()}`,
        incident_id: incId,
        author: body.author || 'local_analyst',
        created_at: new Date().toISOString(),
        content: body.content,
      };
      stateIncidents = stateIncidents.map(inc => {
        if (inc.id === incId) {
          return { ...inc, notes: [...inc.notes, newNote] };
        }
        return inc;
      });
      logAuditAction('NOTE_ADDED', `incident:${incId}`, { author: newNote.author });
      return newNote as unknown as T;
    }
    if (cleanEndpoint === '/fim/baseline' || cleanEndpoint === '/fim/baselines') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      const newBase: FIMBaselineRead = {
        id: `base-${Date.now()}`,
        name: body.name || 'Custom Baseline',
        target_path: body.target_path || 'C:\\Windows\\System32',
        recursive: body.recursive ?? false,
        created_at: new Date().toISOString(),
        last_scanned_at: new Date().toISOString(),
        total_files: 12,
        status: 'Clean',
      };
      stateBaselines = [newBase, ...stateBaselines];
      logAuditAction('FIM_BASELINE_CREATED', `baseline:${newBase.id}`, { path: newBase.target_path });
      return newBase as unknown as T;
    }
    if (cleanEndpoint === '/fim/scan') {
      const scanResults: FIMScanResult[] = stateBaselines.map(b => ({
        baseline_id: b.id,
        files_scanned: b.total_files,
        changes_detected: stateFimChanges.filter(c => c.baseline_id === b.id).length,
        scan_duration_ms: 18.5,
        changes: stateFimChanges.filter(c => c.baseline_id === b.id),
      }));
      logAuditAction('FIM_SCAN_EXECUTED', 'fim_service', { scanned_baselines: stateBaselines.length });
      return scanResults as unknown as T;
    }
    if (cleanEndpoint === '/demo/seed') {
      stateIncidents = [...MOCK_INCIDENTS];
      logAuditAction('DEMO_DATA_SEEDED', 'sample_generator', { scenario: 'Operation Ignis Vector' });
      return { is_seeded: true, events_count: 6, incidents_count: 3 } as unknown as T;
    }
    if (cleanEndpoint === '/demo/clear') {
      stateIncidents = [];
      stateFimChanges = [];
      logAuditAction('DEMO_DATA_CLEARED', 'sample_generator', {});
      return { message: 'All demo data removed successfully' } as unknown as T;
    }
    if (cleanEndpoint === '/demo/toggle') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      if (body.enabled) {
        stateIncidents = [...MOCK_INCIDENTS];
      } else {
        stateIncidents = [];
      }
      logAuditAction('DEMO_MODE_TOGGLED', 'demo_toggle', { enabled: body.enabled });
      return { is_seeded: body.enabled } as unknown as T;
    }
  }

  if (method === 'PUT') {
    if (cleanEndpoint === '/settings') {
      const body = options.body ? JSON.parse(options.body as string) : {};
      stateSettings = { ...stateSettings, ...body };
      logAuditAction('CONFIG_UPDATED', 'system_settings', body);
      return stateSettings as unknown as T;
    }
  }

  return {} as T;
}

function logAuditAction(action: string, target_resource: string, details?: Record<string, unknown>) {
  const newAudit: AuditLogRead = {
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    actor: 'web_console',
    action,
    target_resource,
    details,
  };
  stateAuditLogs = [newAudit, ...stateAuditLogs];
}

export const api = {
  // Health & Diagnostics
  getHealth: () => request<HealthResponse>('/health'),
  getSensorStatus: () => request<SensorHealthStatus[]>('/sensor/status'),
  getDiagnostics: () => request<DiagnosticsReport>('/diagnostics'),

  // Telemetry Overview & Events
  getOverview: () => request<TelemetryOverviewRead>('/telemetry/overview'),
  getEvents: (params?: { category?: string; severity?: string; include_sample?: boolean; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params?.category) q.append('category', params.category);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.include_sample !== undefined) q.append('include_sample', String(params.include_sample));
    if (params?.limit) q.append('limit', String(params.limit));
    if (params?.offset) q.append('offset', String(params.offset));
    const qs = q.toString();
    return request<PaginatedResponse<TelemetryEventRead>>(`/telemetry/events${qs ? `?${qs}` : ''}`);
  },

  // Processes & Network
  getProcesses: (limit = 200) => request<ProcessRead[]>(`/telemetry/processes?limit=${limit}`),
  getNetworkConnections: (limit = 500) => request<SocketRead[]>(`/telemetry/network/connections?limit=${limit}`),
  getNetworkInterfaces: () => request<InterfaceRead[]>('/telemetry/network/interfaces'),
  getNetworkDevices: (includeSample = true) => request<NetworkDeviceRead[]>(`/telemetry/network/devices?include_sample=${includeSample}`),
  getPersistence: () => request<PersistenceRead[]>('/telemetry/persistence'),

  // FIM
  getFimStatus: () => request<{ total_baselines: number; total_files_monitored: number; total_changes_detected: number; unacknowledged_changes: number; baselines: FIMBaselineRead[] }>('/fim/status'),
  getFimBaselines: () => request<FIMBaselineRead[]>('/fim/baselines'),
  createFimBaseline: (payload: { name: string; target_path: string; recursive?: boolean }) => request<FIMBaselineRead>('/fim/baseline', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  scanFimBaselines: (baselineId?: string) => request<FIMScanResult[]>('/fim/scan', {
    method: 'POST',
    body: JSON.stringify(baselineId ? { baseline_id: baselineId } : {}),
  }),
  getFimChanges: (limit = 50, acknowledged?: boolean) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (acknowledged !== undefined) q.append('acknowledged', String(acknowledged));
    return request<FIMChangeRead[]>(`/fim/changes?${q.toString()}`);
  },

  // Detection Rules
  getRules: (params?: { enabled?: boolean; severity?: string; category?: string }) => {
    const q = new URLSearchParams();
    if (params?.enabled !== undefined) q.append('enabled', String(params.enabled));
    if (params?.severity) q.append('severity', params.severity);
    if (params?.category) q.append('category', params.category);
    const qs = q.toString();
    return request<DetectionRuleRead[]>(`/rules${qs ? `?${qs}` : ''}`);
  },
  getRule: (id: string) => request<DetectionRuleRead>(`/rules/${id}`),
  toggleRule: (id: string, enabled: boolean) => request<DetectionRuleRead>(`/rules/${id}/toggle`, {
    method: 'PATCH',
    body: JSON.stringify({ enabled }),
  }),
  testRule: (ruleData: unknown, sampleEvent: unknown) => request<{ matched: boolean; evaluation_time_ms: number }>('/rules/test', {
    method: 'POST',
    body: JSON.stringify({ rule: ruleData, event: sampleEvent }),
  }),

  // Incidents
  getIncidents: (params?: { status?: string; severity?: string; include_sample?: boolean; limit?: number; offset?: number }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.severity) q.append('severity', params.severity);
    if (params?.include_sample !== undefined) q.append('include_sample', String(params.include_sample));
    if (params?.limit) q.append('limit', String(params.limit));
    if (params?.offset) q.append('offset', String(params.offset));
    const qs = q.toString();
    return request<PaginatedResponse<IncidentRead>>(`/incidents${qs ? `?${qs}` : ''}`);
  },
  getIncidentDetail: (id: string) => request<IncidentDetailRead>(`/incidents/${id}`),
  updateIncidentStatus: (id: string, status: IncidentStatus, note?: string, analyst?: string) => request<IncidentDetailRead>(`/incidents/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status,
      analyst_note: note,
      assigned_analyst: analyst,
    }),
  }),
  addIncidentNote: (incidentId: string, content: string, author?: string) => request<IncidentNoteRead>(`/incidents/${incidentId}/notes`, {
    method: 'POST',
    body: JSON.stringify({ content, author: author || 'local_analyst' }),
  }),

  // Reports
  exportReport: async (req: { format: 'json' | 'csv' | 'html'; severity?: string; status?: string; include_sample?: boolean }) => {
    const url = `${BASE_URL}/reports/generate`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (res.ok) {
        const blob = await res.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `agni-security-report-${Date.now()}.${req.format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        logAuditAction('REPORT_GENERATED', `report:${req.format}`, req);
        return { success: true };
      }
    } catch {
      // Fallback local report generation
    }

    // Local client-side report generator fallback
    let content = '';
    let mimeType = 'text/plain';
    const timestamp = new Date().toISOString();

    if (req.format === 'json') {
      mimeType = 'application/json';
      content = JSON.stringify({
        title: 'Agni Security Intelligence Report',
        generated_at: timestamp,
        parameters: req,
        incidents: stateIncidents,
        events: MOCK_EVENTS,
      }, null, 2);
    } else if (req.format === 'csv') {
      mimeType = 'text/csv';
      content = 'Incident ID,Title,Severity,Status,Alert Count,First Seen,Last Seen\n' +
        stateIncidents.map(i => `"${i.id}","${i.title}","${i.severity}","${i.status}",${i.alert_count},"${i.first_seen}","${i.last_seen}"`).join('\n');
    } else {
      mimeType = 'text/html';
      content = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Agni Security Report</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0a0f1d; color: #f8fafc; padding: 2rem; }
    h1 { color: #06b6d4; border-bottom: 2px solid #1e293b; padding-bottom: 0.5rem; }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
    th, td { border: 1px solid #1e293b; padding: 0.75rem; text-align: left; }
    th { background: #0f172a; color: #38bdf8; }
    tr:nth-child(even) { background: #141e33; }
    .critical { color: #f87171; font-weight: bold; }
    .high { color: #fb923c; font-weight: bold; }
  </style>
</head>
<body>
  <h1>Agni Threat Intelligence Executive Report</h1>
  <p>Generated: ${timestamp} | Mode: ${req.include_sample ? 'Sample & Live Telemetry' : 'Live Host Only'}</p>
  <h2>Correlated Incidents</h2>
  <table>
    <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Alerts</th></tr></thead>
    <tbody>
      ${stateIncidents.map(i => `<tr><td>${i.id}</td><td>${i.title}</td><td class="${i.severity.toLowerCase()}">${i.severity}</td><td>${i.status}</td><td>${i.alert_count}</td></tr>`).join('')}
    </tbody>
  </table>
</body>
</html>`;
    }

    const blob = new Blob([content], { type: mimeType });
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = `agni-security-report-${Date.now()}.${req.format}`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(downloadUrl);
    document.body.removeChild(a);
    logAuditAction('REPORT_GENERATED', `report:${req.format}`, req);
    return { success: true };
  },

  // Audit Logs
  getAuditLogs: (limit = 50, offset = 0) => request<PaginatedResponse<AuditLogRead>>(`/audit/logs?limit=${limit}&offset=${offset}`),

  // Settings
  getSettings: () => request<SystemSettingsRead>('/settings'),
  updateSettings: (payload: Partial<SystemSettingsRead>) => request<SystemSettingsRead>('/settings', {
    method: 'PUT',
    body: JSON.stringify(payload),
  }),

  // Demo Mode
  getDemoStatus: () => request<{ is_seeded: boolean }>('/demo/status'),
  seedDemoData: (hostname?: string) => request<{ is_seeded: boolean }>('/demo/seed', {
    method: 'POST',
    body: JSON.stringify({ hostname }),
  }),
  clearDemoData: () => request<{ message: string }>('/demo/clear', { method: 'POST' }),
  toggleDemoMode: (enabled: boolean) => request<{ is_seeded: boolean }>('/demo/toggle', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  }),
};
