"""
Unit Tests: Incident Correlator, Sliding Window Tracking & Lifecycle Transitions
"""
import uuid
from datetime import UTC, datetime

import pytest

from app.engine.correlator import IncidentCorrelator, SlidingWindowTracker
from app.models.event import TelemetryEventModel
from app.models.incident import DetectionAlertModel, IncidentModel
from app.models.rule import DetectionRuleModel


def test_sliding_window_tracker():
    """Verify threshold evaluation and time window pruning."""
    tracker = SlidingWindowTracker()
    now = datetime.now(UTC)

    # Window of 10s, threshold 3
    # 1st event -> None
    r1 = tracker.record_and_check_threshold("RULE-01", "entity-A", now, "e1", 10, 3)
    assert r1 is None

    # 2nd event -> None
    r2 = tracker.record_and_check_threshold("RULE-01", "entity-A", now, "e2", 10, 3)
    assert r2 is None

    # 3rd event -> Trigger!
    r3 = tracker.record_and_check_threshold("RULE-01", "entity-A", now, "e3", 10, 3)
    assert r3 == ["e1", "e2", "e3"]

    # In cooldown immediately after trigger -> None
    r4 = tracker.record_and_check_threshold("RULE-01", "entity-A", now, "e4", 10, 3)
    assert r4 is None


def test_incident_clustering_and_deduplication(test_db):
    """Verify multiple alerts for the same entity key group into one incident."""
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    rule = DetectionRuleModel(
        id="RULE-TEST-001",
        name="Test Incident Clustering",
        description="Test Rule",
        severity="High",
        category="process",
        source="agni_core",
        match_conditions={},
        correlation_window=0,
        threshold=1,
        group_by="actor.pid",
        explanation="Test explanation",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    now = datetime.now(UTC)

    # Event 1
    event1 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="Host1",
        os_name="Windows",
        actor_pid=8888,
        actor_name="cmd.exe",
    )
    test_db.add(event1)
    test_db.commit()

    alert1 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now,
        severity=rule.severity,
        explanation=rule.explanation,
        triggering_event_id=event1.id,
    )

    inc1 = correlator.correlate_alert(test_db, rule, alert1, event1)
    assert inc1.event_count == 1
    assert inc1.status == "New"

    # Event 2 with same PID -> should deduplicate into inc1
    event2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="Host1",
        os_name="Windows",
        actor_pid=8888,
        actor_name="cmd.exe",
    )
    test_db.add(event2)
    test_db.commit()

    alert2 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now,
        severity=rule.severity,
        explanation=rule.explanation,
        triggering_event_id=event2.id,
    )

    inc2 = correlator.correlate_alert(test_db, rule, alert2, event2)
    assert inc2.id == inc1.id
    assert inc2.event_count == 2


def test_incident_status_transition_lifecycle(test_db):
    """Verify incident state machine transitions and audit logging."""
    correlator = IncidentCorrelator()

    rule = DetectionRuleModel(
        id="RULE-LIFECYCLE-001",
        name="Lifecycle Rule",
        description="Test",
        severity="Medium",
        category="process",
        source="agni_core",
        match_conditions={},
        explanation="Test",
        investigation_steps=[],
    )
    test_db.add(rule)
    test_db.commit()

    now = datetime.now(UTC)
    incident = IncidentModel(
        id=str(uuid.uuid4()),
        title="Test Incident",
        rule_id=rule.id,
        severity="Medium",
        priority="P3_Medium",
        status="New",
        entity_key=f"{rule.id}:123",
        first_seen=now,
        last_seen=now,
        event_count=1,
        summary="Summary",
    )
    test_db.add(incident)
    test_db.commit()

    # Valid transition: New -> Triaged
    t1 = correlator.transition_incident_status(
        test_db, incident.id, "Triaged", actor="analyst_1", note_content="Initial triage started"
    )
    assert t1.status == "Triaged"
    assert len(t1.notes) == 1

    # Valid transition: Triaged -> In Progress
    t2 = correlator.transition_incident_status(test_db, incident.id, "In Progress", actor="analyst_1")
    assert t2.status == "In Progress"

    # Valid transition: In Progress -> Resolved
    t3 = correlator.transition_incident_status(test_db, incident.id, "Resolved", actor="analyst_1")
    assert t3.status == "Resolved"

    # Invalid transition: Resolved -> Triaged (should raise ValueError)
    with pytest.raises(ValueError):
        correlator.transition_incident_status(test_db, incident.id, "Triaged", actor="analyst_1")
