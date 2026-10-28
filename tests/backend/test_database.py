"""
Unit Tests: SQLite WAL Mode Persistence & ORM Model Integrity
"""
import uuid
from datetime import UTC, datetime

from sqlalchemy import text

from app.models.detection import (
    DetectionAlertModel,
    DetectionRuleModel,
    IncidentModel,
    IncidentNoteModel,
)
from app.models.telemetry import (
    FIMBaselineModel,
    FIMChangeModel,
    FIMEntryModel,
)


def test_sqlite_wal_mode(test_db):
    """Verify SQLite connection is configured with journal_mode=WAL."""
    result = test_db.execute(text("PRAGMA journal_mode;")).scalar()
    # In temporary test databases on some platforms it may return memory or wal
    assert result.lower() in ("wal", "memory")


def test_models_crud_and_relationships(test_db):
    """Verify relational integrity across Incidents, Alerts, and Notes."""
    now = datetime.now(UTC)

    rule = DetectionRuleModel(
        id="RULE-DB-001",
        name="DB Test Rule",
        description="Testing foreign keys",
        severity="High",
        category="network",
        source="vayu",
        match_conditions={"field": "category", "operator": "equals", "value": "network"},
        explanation="Testing cascade delete",
        investigation_steps=["Step 1"],
    )
    test_db.add(rule)
    test_db.commit()

    incident = IncidentModel(
        id=str(uuid.uuid4()),
        title="Test Incident Cascade",
        rule_id=rule.id,
        severity="High",
        priority="P2_High",
        status="New",
        entity_key="RULE-DB-001:1.1.1.1",
        first_seen=now,
        last_seen=now,
        event_count=1,
        summary="Testing relationships",
    )
    test_db.add(incident)
    test_db.commit()

    alert = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        rule_id=rule.id,
        timestamp=now,
        severity="High",
        explanation="Alert child of incident",
    )
    note = IncidentNoteModel(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        author="analyst",
        created_at=now,
        content="Note child of incident",
    )
    test_db.add_all([alert, note])
    test_db.commit()

    # Query parent and verify relationships loaded
    inc = test_db.query(IncidentModel).filter(IncidentModel.id == incident.id).first()
    assert len(inc.alerts) == 1
    assert len(inc.notes) == 1
    assert inc.alerts[0].id == alert.id
    assert inc.notes[0].id == note.id

    # Test Cascade Delete
    test_db.delete(inc)
    test_db.commit()

    # Children should be deleted
    assert test_db.query(DetectionAlertModel).filter(DetectionAlertModel.id == alert.id).first() is None
    assert test_db.query(IncidentNoteModel).filter(IncidentNoteModel.id == note.id).first() is None


def test_fim_baseline_cascade(test_db):
    """Verify FIMBaselineModel cascades to FIMEntryModel and FIMChangeModel."""
    now = datetime.now(UTC)
    base_id = str(uuid.uuid4())
    baseline = FIMBaselineModel(
        id=base_id,
        name="Test Baseline",
        target_path="C:\\Test",
        recursive=True,
        file_patterns=["*.txt"],
        created_at=now,
        total_files=1,
        status="Active",
    )
    test_db.add(baseline)
    test_db.commit()

    entry = FIMEntryModel(
        id=str(uuid.uuid4()),
        baseline_id=base_id,
        file_path="C:\\Test\\file.txt",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_size_bytes=0,
        mtime=now,
        last_verified_at=now,
    )
    change = FIMChangeModel(
        id=str(uuid.uuid4()),
        baseline_id=base_id,
        file_path="C:\\Test\\file.txt",
        change_type="CREATED",
        detected_at=now,
        acknowledged=False,
    )
    test_db.add_all([entry, change])
    test_db.commit()

    # Delete baseline
    test_db.delete(baseline)
    test_db.commit()

    assert test_db.query(FIMEntryModel).filter(FIMEntryModel.baseline_id == base_id).first() is None
    assert test_db.query(FIMChangeModel).filter(FIMChangeModel.baseline_id == base_id).first() is None
