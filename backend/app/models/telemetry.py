"""
Telemetry & FIM SQLAlchemy Models
- TelemetryEventModel (Normalized Common Event Schema v1.0.0)
- FIMBaselineModel, FIMEntryModel, FIMChangeModel
- NetworkDeviceModel
"""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class TelemetryEventModel(Base):
    """
    Normalized, immutable telemetry record representing an observed host fact.
    """
    __tablename__ = "telemetry_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.now(UTC)
    )
    event_version: Mapped[str] = mapped_column(String(10), nullable=False, default="1.0.0")
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # process, network, fim, persistence, system
    action: Mapped[str] = mapped_column(String(32), nullable=False)                # spawned, terminated, connected, modified, etc.
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # Informational, Low, Medium, High, Critical
    source: Mapped[str] = mapped_column(String(32), nullable=False)                # agni_core, vayu, fim, persistence

    # Host Context
    hostname: Mapped[str] = mapped_column(String(128), nullable=False)
    os_name: Mapped[str] = mapped_column(String(32), nullable=False)

    # Actor (Subject executing action)
    actor_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_cmdline: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_user: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Target (Object acted upon)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)        # file, ip, reg_key, process
    target_identifier: Mapped[str | None] = mapped_column(Text, nullable=True)        # e.g., C:\Windows\Temp\payload.exe, 192.168.1.50
    target_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Contextual Metadata & Isolation
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    is_sample: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)


class FIMBaselineModel(Base):
    """
    Monitored directory or path definition for FIM baselines.
    """
    __tablename__ = "fim_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_path: Mapped[str] = mapped_column(Text, nullable=False)
    recursive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    file_patterns: Mapped[list[str]] = mapped_column(JSON, nullable=False)  # ["*"] or ["*.sys", "*.exe"]
    exclude_patterns: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)  # ["*.tmp", "*.log"]
    max_file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=104857600)  # 100MB
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Active")  # Active, Paused, Error

    entries: Mapped[list["FIMEntryModel"]] = relationship(
        "FIMEntryModel", back_populates="baseline", cascade="all, delete-orphan"
    )
    changes: Mapped[list["FIMChangeModel"]] = relationship(
        "FIMChangeModel", back_populates="baseline", cascade="all, delete-orphan"
    )


class FIMEntryModel(Base):
    """
    Stored hash baseline for an individual file.
    """
    __tablename__ = "fim_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    baseline_id: Mapped[str] = mapped_column(String(36), ForeignKey("fim_baselines.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mtime: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    permissions: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    baseline: Mapped["FIMBaselineModel"] = relationship("FIMBaselineModel", back_populates="entries")


class FIMChangeModel(Base):
    """
    Recorded file change (creation, modification, deletion) detected during scan.
    """
    __tablename__ = "fim_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    baseline_id: Mapped[str] = mapped_column(String(36), ForeignKey("fim_baselines.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    change_type: Mapped[str] = mapped_column(String(32), nullable=False)  # CREATED, MODIFIED, DELETED
    previous_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    baseline: Mapped["FIMBaselineModel"] = relationship("FIMBaselineModel", back_populates="changes")


class NetworkDeviceModel(Base):
    """
    Locally discovered network device from passive ARP cache.
    """
    __tablename__ = "network_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_gateway: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    active_connections_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_sample: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
