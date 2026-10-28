export type Severity = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export type Category = 'process' | 'network' | 'fim' | 'file_integrity' | 'persistence' | 'system';

export type IncidentStatus = 'New' | 'Triaged' | 'In Progress' | 'Resolved' | 'False Positive';

export type IncidentPriority = 'P1_Critical' | 'P2_High' | 'P3_Medium' | 'P4_Low';

export interface ApiResponse<T> {
  status: string;
  data: T;
  timestamp: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface HealthResponse {
  status: string;
  version: string;
  platform: string;
  mode: string;
  uptime_seconds: number;
  timestamp: string;
}

export interface SensorHealthStatus {
  sensor_name: string;
  status: string;
  last_collection: string;
  items_collected: number;
  error_count: number;
  latency_ms: number;
  message?: string;
}

export interface DiagnosticsReport {
  hostname: string;
  os_name: string;
  os_version: string;
  architecture: string;
  python_version: string;
  database_status: string;
  database_wal_mode: boolean;
  active_threads: number;
  memory_usage_mb: number;
  cpu_percent: number;
  capabilities: Record<string, boolean>;
  sensors: SensorHealthStatus[];
}

export interface TelemetryOverviewRead {
  total_events_24h: number;
  active_incidents: number;
  monitored_processes: number;
  active_sockets: number;
  network_devices_count: number;
  fim_monitored_files: number;
  threat_posture_score: number;
  sensor_health: string;
  platform: string;
  is_demo_mode: boolean;
  recent_events: TelemetryEventRead[];
}

export interface TelemetryEventRead {
  id: string;
  timestamp: string;
  event_version: string;
  category: string;
  action: string;
  severity: Severity;
  source: string;
  hostname?: string;
  os_name?: string;
  actor_pid?: number;
  actor_name?: string;
  actor_path?: string;
  actor_cmdline?: string;
  actor_user?: string;
  target_type?: string;
  target_identifier?: string;
  target_details?: Record<string, unknown>;
  details?: Record<string, unknown>;
  is_sample: boolean;
}

export interface ProcessRead {
  pid: number;
  ppid: number;
  name: string;
  exe?: string;
  cmdline?: string;
  username?: string;
  status?: string;
  cpu_percent?: number;
  memory_rss?: number;
  memory_vms?: number;
  memory_percent?: number;
  create_time?: number;
  num_threads?: number;
  access_restricted?: boolean;
  details?: Record<string, unknown>;
}

export interface SocketRead {
  pid: number;
  process_name?: string;
  protocol: string;
  local_address: string;
  local_port: number;
  remote_address?: string;
  remote_port?: number;
  status?: string;
  family?: string;
  is_outbound?: boolean;
  access_restricted?: boolean;
}

export interface InterfaceRead {
  name: string;
  mac_address?: string;
  ipv4_addresses: string[];
  ipv6_addresses: string[];
  netmask?: string;
  broadcast?: string;
  is_up: boolean;
  speed_mbps?: number;
  mtu?: number;
}

export interface NetworkDeviceRead {
  id: string;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  vendor?: string;
  interface_name?: string;
  is_gateway?: boolean;
  first_seen: string;
  last_seen: string;
  active_connections_count: number;
  is_sample: boolean;
}

export interface PersistenceRead {
  entry_id: string;
  name: string;
  target_path?: string;
  location_type: string;
  location_detail?: string;
  arguments?: string;
  enabled: boolean;
  suspicious_indicators: string[];
}

export interface FIMBaselineRead {
  id: string;
  name: string;
  target_path: string;
  recursive: boolean;
  file_patterns?: string[];
  exclude_patterns?: string[];
  max_file_size_bytes?: number;
  created_at: string;
  last_scanned_at?: string;
  total_files: number;
  status: string;
}

export interface FIMChangeRead {
  id: string;
  baseline_id: string;
  file_path: string;
  change_type: string;
  previous_sha256?: string;
  current_sha256?: string;
  previous_size?: number;
  current_size?: number;
  detected_at: string;
  acknowledged: boolean;
}

export interface FIMScanResult {
  baseline_id: string;
  files_scanned: number;
  changes_detected: number;
  scan_duration_ms: number;
  changes: FIMChangeRead[];
}

export interface DetectionRuleRead {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  source: string;
  match_conditions: Record<string, unknown>;
  correlation_window: number;
  threshold: number;
  group_by?: string;
  explanation?: string;
  investigation_steps?: string[];
  mitre_attack?: string;
  version: string;
  enabled: boolean;
  is_custom: boolean;
}

export interface DetectionAlertRead {
  id: string;
  incident_id?: string;
  rule_id: string;
  event_id: string;
  timestamp: string;
  severity: Severity;
  title: string;
  explanation?: string;
  details?: Record<string, unknown>;
}

export interface IncidentNoteRead {
  id: string;
  incident_id: string;
  author: string;
  created_at: string;
  content: string;
}

export interface IncidentRead {
  id: string;
  title: string;
  severity: Severity;
  priority: IncidentPriority | string;
  status: IncidentStatus;
  rule_id: string;
  entity_key: string;
  first_seen: string;
  last_seen: string;
  alert_count: number;
  is_sample: boolean;
  assigned_analyst?: string;
}

export interface IncidentDetailRead extends IncidentRead {
  alerts: DetectionAlertRead[];
  notes: IncidentNoteRead[];
}

export interface AuditLogRead {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target_resource: string;
  details?: Record<string, unknown>;
}

export interface SettingItem {
  key: string;
  value: string;
  description?: string;
  updated_at: string;
}

export interface SystemSettingsRead {
  telemetry_interval_seconds: number;
  fim_poll_interval_seconds: number;
  network_poll_interval_seconds: number;
  correlation_window_seconds: number;
  event_retention_days: number;
  demo_mode_enabled: boolean;
  ai_provider: string;
  ai_endpoint?: string;
  ai_consent_granted: boolean;
  settings_items: SettingItem[];
}

export interface DemoStatusRead {
  is_seeded: boolean;
  scenario_name?: string;
  events_count: number;
  incidents_count: number;
  alerts_count: number;
  devices_count: number;
  target_hostname?: string;
  last_seeded_at?: string;
}
