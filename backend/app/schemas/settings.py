"""
Settings, Audit, Demo, and Health Schemas
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# -----------------------------------------------------------------------------
# System Settings Schemas
# -----------------------------------------------------------------------------
class SettingItem(BaseModel):
    key: str
    value: str
    description: str | None = None
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SystemSettingsRead(BaseModel):
    telemetry_interval_seconds: int = 5
    fim_poll_interval_seconds: int = 60
    network_poll_interval_seconds: int = 15
    correlation_window_seconds: int = 300
    event_retention_days: int = 30
    demo_mode_enabled: bool = False
    ai_provider: str = "none"  # none, ollama, openai
    ai_endpoint: str | None = None
    ai_consent_granted: bool = False
    settings_items: list[SettingItem] = Field(default_factory=list)


class SystemSettingsUpdate(BaseModel):
    telemetry_interval_seconds: int | None = None
    fim_poll_interval_seconds: int | None = None
    network_poll_interval_seconds: int | None = None
    correlation_window_seconds: int | None = None
    event_retention_days: int | None = None
    demo_mode_enabled: bool | None = None
    ai_provider: str | None = None
    ai_endpoint: str | None = None
    ai_consent_granted: bool | None = None


# -----------------------------------------------------------------------------
# Audit Log Schemas
# -----------------------------------------------------------------------------
class AuditLogRead(BaseModel):
    id: str
    timestamp: datetime
    action: str
    actor: str
    target_resource: str
    details: dict[str, Any] | None = None
    status: str

    model_config = ConfigDict(from_attributes=True)


class AuditLogListResponse(BaseModel):
    items: list[AuditLogRead]
    total: int


# -----------------------------------------------------------------------------
# Demo Mode Schemas
# -----------------------------------------------------------------------------
class DemoStatusRead(BaseModel):
    has_sample_data: bool
    sample_events_count: int
    sample_incidents_count: int
    sample_alerts_count: int
    sample_devices_count: int


class DemoToggleRequest(BaseModel):
    enabled: bool


class DemoSeedRequest(BaseModel):
    hostname: str | None = "DharmaCipher"


# -----------------------------------------------------------------------------
# Health & Diagnostics Schemas
# -----------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    platform: str
    mode: str = "live"  # live or demo
    uptime_seconds: float
    timestamp: datetime


class SensorHealthStatus(BaseModel):
    sensor_name: str
    status: str  # healthy, degraded, unavailable
    last_collection: datetime
    items_collected: int
    error_count: int
    latency_ms: float
    message: str | None = None


class DiagnosticsReport(BaseModel):
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    python_version: str
    database_status: str
    database_wal_mode: bool
    active_threads: int
    memory_usage_mb: float
    cpu_percent: float
    capabilities: dict[str, bool]
    sensors: list[SensorHealthStatus]
