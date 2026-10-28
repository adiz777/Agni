"""
Threat Detection & Incident Management SQLAlchemy Models
- DetectionRuleModel
- IncidentModel
- DetectionAlertModel
- IncidentNoteModel
"""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DetectionRuleModel(Base):
    """
    Declarative threat detection rule definition.
    """
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g., AGNI-R-PROC-001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # Informational, Low, Medium, High, Critical
    category: Mapped[str] = mapped_column(String(32), nullable=False)  # process, network, fim, persistence
    source: Mapped[str] = mapped_column(String(32), nullable=False)    # agni_core, vayu, fim

    # AST Match Conditions & Correlation
    match_conditions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    correlation_window: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # Seconds (0 = single event)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    group_by: Mapped[str | None] = mapped_column(String(64), nullable=True)           # e.g. actor.pid, target.identifier

    # SOC Analyst Guidance & Classification
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    investigation_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    mitre_attack: Mapped[str | None] = mapped_column(String(32), nullable=True)       # e.g. T1059.001
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0.0")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class IncidentModel(Base):
    """
    Incident container clustering correlated alerts.
    """
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), ForeignKey("detection_rules.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="P3_Medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="New", index=True)

    # Correlation & Entity Grouping
    entity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Narrative Context
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_attack: Mapped[str | None] = mapped_column(String(32), nullable=True)
    assigned_analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_sample: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    # Relationships
    alerts: Mapped[list["DetectionAlertModel"]] = relationship(
        "DetectionAlertModel", back_populates="incident", cascade="all, delete-orphan"
    )
    notes: Mapped[list["IncidentNoteModel"]] = relationship(
        "IncidentNoteModel", back_populates="incident", cascade="all, delete-orphan"
    )


class DetectionAlertModel(Base):
    """
    Individual detection alert instance produced by a rule match.
    """
    __tablename__ = "detection_alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    triggering_event_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("telemetry_events.id"), nullable=True
    )
    match_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    incident: Mapped["IncidentModel"] = relationship("IncidentModel", back_populates="alerts")


class IncidentNoteModel(Base):
    """
    Analyst investigation note associated with an incident.
    """
    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False, default="local_analyst")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)

    incident: Mapped["IncidentModel"] = relationship("IncidentModel", back_populates="notes")
