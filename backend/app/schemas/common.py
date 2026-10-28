"""
Common Enumerations and Response Wrappers
"""
from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class SeverityEnum(StrEnum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class CategoryEnum(StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    FIM = "fim"
    FILE_INTEGRITY = "file_integrity"
    PERSISTENCE = "persistence"
    SYSTEM = "system"


class IncidentStatusEnum(StrEnum):
    NEW = "New"
    TRIAGED = "Triaged"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class IncidentPriorityEnum(StrEnum):
    P1_CRITICAL = "P1_Critical"
    P2_HIGH = "P2_High"
    P3_MEDIUM = "P3_Medium"
    P4_LOW = "P4_Low"


class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class ApiResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = ConfigDict(from_attributes=True)
