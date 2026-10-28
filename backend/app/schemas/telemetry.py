"""
Telemetry Schemas
Process, Socket, FIM, Network, and Persistence Pydantic Models
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# -----------------------------------------------------------------------------
# Process Schemas
# -----------------------------------------------------------------------------
class ProcessRead(BaseModel):
    pid: int
    ppid: int | None = None
    name: str
    exe: str | None = None
    cmdline: list[str] = Field(default_factory=list)
    username: str | None = None
    status: str = "running"
    cpu_percent: float = 0.0
    memory_rss: int = 0
    memory_vms: int = 0
    memory_percent: float = 0.0
    create_time: datetime
    num_threads: int = 1
    access_restricted: bool = False
    details: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Network Sockets & Interfaces Schemas
# -----------------------------------------------------------------------------
class SocketRead(BaseModel):
    pid: int | None = None
    process_name: str | None = None
    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    status: str
    family: str = "IPv4"
    is_outbound: bool = False
    access_restricted: bool = False

    model_config = ConfigDict(from_attributes=True)


class InterfaceRead(BaseModel):
    name: str
    mac_address: str | None = None
    ipv4_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    netmask: str | None = None
    broadcast: str | None = None
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 1500

    model_config = ConfigDict(from_attributes=True)


class NetworkDeviceRead(BaseModel):
    id: str
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    interface_name: str | None = None
    is_gateway: bool = False
    first_seen: datetime
    last_seen: datetime
    active_connections_count: int = 0
    is_sample: bool = False

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Persistence Schemas
# -----------------------------------------------------------------------------
class PersistenceRead(BaseModel):
    entry_id: str
    name: str
    target_path: str
    location_type: str
    location_detail: str
    arguments: str | None = None
    enabled: bool = True
    suspicious_indicators: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# FIM Schemas
# -----------------------------------------------------------------------------
class FIMBaselineCreate(BaseModel):
    name: str
    target_path: str
    recursive: bool = True
    file_patterns: list[str] = Field(default_factory=lambda: ["*"])
    exclude_patterns: list[str] | None = None
    max_file_size_bytes: int = 104857600  # 100 MB


class FIMBaselineRead(BaseModel):
    id: str
    name: str
    target_path: str
    recursive: bool
    file_patterns: list[str]
    exclude_patterns: list[str] | None = None
    max_file_size_bytes: int
    created_at: datetime
    last_scanned_at: datetime | None = None
    total_files: int
    status: str

    model_config = ConfigDict(from_attributes=True)


class FIMEntryRead(BaseModel):
    id: str
    baseline_id: str
    file_path: str
    sha256_hash: str
    file_size_bytes: int
    mtime: datetime
    permissions: str | None = None
    owner: str | None = None
    last_verified_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FIMChangeRead(BaseModel):
    id: str
    baseline_id: str
    file_path: str
    change_type: str  # CREATED, MODIFIED, DELETED
    previous_sha256: str | None = None
    current_sha256: str | None = None
    previous_size: int | None = None
    current_size: int | None = None
    detected_at: datetime
    acknowledged: bool

    model_config = ConfigDict(from_attributes=True)


class FIMScanRequest(BaseModel):
    baseline_id: str | None = None


class FIMScanResult(BaseModel):
    baseline_id: str
    files_scanned: int
    changes_detected: int
    scan_duration_ms: float
    changes: list[FIMChangeRead]


# -----------------------------------------------------------------------------
# Telemetry Event Schemas
# -----------------------------------------------------------------------------
class TelemetryEventCreate(BaseModel):
    category: str
    action: str
    severity: str = "Informational"
    source: str
    hostname: str | None = None
    os_name: str | None = None
    actor_pid: int | None = None
    actor_name: str | None = None
    actor_path: str | None = None
    actor_cmdline: str | None = None
    actor_user: str | None = None
    target_type: str | None = None
    target_identifier: str | None = None
    target_details: dict[str, Any] | None = None
    details: dict[str, Any] | None = None
    is_sample: bool = False


class TelemetryEventRead(BaseModel):
    id: str
    timestamp: datetime
    event_version: str
    category: str
    action: str
    severity: str
    source: str
    hostname: str
    os_name: str
    actor_pid: int | None = None
    actor_name: str | None = None
    actor_path: str | None = None
    actor_cmdline: str | None = None
    actor_user: str | None = None
    target_type: str | None = None
    target_identifier: str | None = None
    target_details: dict[str, Any] | None = None
    details: dict[str, Any] | None = None
    is_sample: bool = False

    model_config = ConfigDict(from_attributes=True)


class TelemetryOverviewRead(BaseModel):
    total_events_24h: int
    active_incidents: int
    monitored_processes: int
    active_sockets: int
    network_devices_count: int
    fim_monitored_files: int
    threat_posture_score: int  # 0 to 100 (100 = best)
    sensor_health: str  # healthy, degraded, error
    platform: str
    is_demo_mode: bool
    recent_events: list[TelemetryEventRead]
