"""
Threat Detection, Rule, Alert, and Incident Schemas
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# -----------------------------------------------------------------------------
# Detection Rule Schemas
# -----------------------------------------------------------------------------
class DetectionRuleCreate(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    source: str
    match_conditions: dict[str, Any]
    correlation_window: int = 0
    threshold: int = 1
    group_by: str | None = None
    explanation: str
    investigation_steps: list[str] = Field(default_factory=list)
    mitre_attack: str | None = None
    version: str = "1.0.0"
    enabled: bool = True
    is_custom: bool = True


class DetectionRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    category: str | None = None
    match_conditions: dict[str, Any] | None = None
    correlation_window: int | None = None
    threshold: int | None = None
    group_by: str | None = None
    explanation: str | None = None
    investigation_steps: list[str] | None = None
    mitre_attack: str | None = None
    enabled: bool | None = None


class DetectionRuleRead(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    source: str
    match_conditions: dict[str, Any]
    correlation_window: int
    threshold: int
    group_by: str | None = None
    explanation: str
    investigation_steps: list[str]
    mitre_attack: str | None = None
    version: str
    enabled: bool
    is_custom: bool

    model_config = ConfigDict(from_attributes=True)


class RuleToggleRequest(BaseModel):
    enabled: bool


class RuleTestRequest(BaseModel):
    rule: dict[str, Any]
    event: dict[str, Any]


class RuleTestResult(BaseModel):
    matched: bool
    valid: bool
    error: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    extracted_fields: dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# Alert & Note Schemas
# -----------------------------------------------------------------------------
class DetectionAlertRead(BaseModel):
    id: str
    incident_id: str
    rule_id: str
    timestamp: datetime
    severity: str
    explanation: str
    triggering_event_id: str | None = None
    match_details: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


class IncidentNoteCreate(BaseModel):
    content: str
    author: str | None = "local_analyst"


class IncidentNoteRead(BaseModel):
    id: str
    incident_id: str
    author: str
    created_at: datetime
    content: str

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Incident Schemas
# -----------------------------------------------------------------------------
class IncidentRead(BaseModel):
    id: str
    title: str
    rule_id: str
    severity: str
    priority: str
    status: str
    entity_key: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    summary: str
    mitre_attack: str | None = None
    assigned_analyst: str | None = None
    is_sample: bool

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    alerts: list[DetectionAlertRead] = Field(default_factory=list)
    notes: list[IncidentNoteRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class IncidentStatusUpdate(BaseModel):
    status: str  # New, Triaged, In Progress, Resolved, False Positive
    analyst_note: str | None = None
    assigned_analyst: str | None = None


class ReportExportRequest(BaseModel):
    format: str = "json"  # json, csv, html
    start_time: datetime | None = None
    end_time: datetime | None = None
    severity: str | None = None
    status: str | None = None
    include_sample: bool = False
