"""
Unit Tests: Telemetry Event Normalization & Severity Classification
"""
import uuid
from datetime import UTC, datetime

from app.models.event import TelemetryEventModel
from app.schemas.common import CategoryEnum, SeverityEnum
from app.schemas.telemetry import TelemetryEventCreate, TelemetryEventRead


def test_event_normalization_schema():
    """Verify TelemetryEventCreate normalization into model and schema."""
    event_in = TelemetryEventCreate(
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="TestHost",
        os_name="Windows",
        actor_pid=1234,
        actor_name="cmd.exe",
        actor_cmdline="cmd.exe /c whoami",
        actor_user="SYSTEM",
        target_type="process",
        target_identifier="whoami.exe",
        details={"parent_pid": 1000},
        is_sample=False,
    )

    assert event_in.category == "process"
    assert event_in.severity == "High"
    assert event_in.actor_pid == 1234


def test_event_persistence_and_reading(test_db):
    """Test creating an event in SQLite and reading it back."""
    event_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    event_orm = TelemetryEventModel(
        id=event_id,
        timestamp=now,
        event_version="1.0.0",
        category="network",
        action="connected",
        severity="Medium",
        source="vayu",
        hostname="Endpoint01",
        os_name="Linux",
        actor_pid=5050,
        actor_name="curl",
        target_type="ip",
        target_identifier="93.184.216.34:443",
        details={"remote_port": 443},
        is_sample=True,
    )
    test_db.add(event_orm)
    test_db.commit()

    retrieved = test_db.query(TelemetryEventModel).filter(TelemetryEventModel.id == event_id).first()
    assert retrieved is not None
    assert retrieved.actor_name == "curl"
    assert retrieved.category == "network"
    assert retrieved.severity == "Medium"
    assert retrieved.is_sample is True

    # Validate against Pydantic schema
    read_schema = TelemetryEventRead.model_validate(retrieved)
    assert read_schema.id == event_id
    assert read_schema.actor_name == "curl"


def test_severity_levels():
    """Verify all 5 standard severity values are recognized."""
    allowed = {"Informational", "Low", "Medium", "High", "Critical"}
    for sev in SeverityEnum:
        assert sev.value in allowed


def test_category_levels():
    """Verify standard event categories."""
    allowed = {"process", "network", "fim", "file_integrity", "persistence", "system"}
    for cat in CategoryEnum:
        assert cat.value in allowed
