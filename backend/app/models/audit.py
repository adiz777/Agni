"""
Audit Log & System Settings SQLAlchemy Models
- AuditLogModel
- SystemSettingModel
"""
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLogModel(Base):
    """
    Immutable chronological record of administrative actions and config changes.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.now(UTC)
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)  # CONFIG_UPDATE, RULE_TOGGLE, etc.
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="local_analyst")
    target_resource: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="SUCCESS")


class SystemSettingModel(Base):
    """
    Persistent key-value configuration setting.
    """
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
