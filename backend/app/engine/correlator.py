"""
Agni (अग्नि) - Incident Correlator & Lifecycle Manager
File: backend/app/engine/correlator.py
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

from sqlalchemy.orm import Session

from app.engine.rules import extract_field
from app.models.audit import AuditLogModel
from app.models.event import TelemetryEventModel
from app.models.incident import DetectionAlertModel, IncidentModel, IncidentNoteModel
from app.models.rule import DetectionRuleModel

logger = logging.getLogger("agni.engine.correlator")


# Priority mapping from severity
SEVERITY_PRIORITY_MAP = {
    "Critical": "P1_Critical",
    "High": "P2_High",
    "Medium": "P3_Medium",
    "Low": "P4_Low",
    "Informational": "P4_Low",
}

# Incident State Machine Allowed Transitions
VALID_STATUS_TRANSITIONS: dict[str, list[str]] = {
    "New": ["Triaged", "In Progress", "Resolved", "False Positive"],
    "Triaged": ["In Progress", "Resolved", "False Positive"],
    "In Progress": ["Resolved", "False Positive", "Triaged"],
    "Resolved": ["New", "In Progress"],  # Reopening
    "False Positive": ["New", "Resolved"],
}


class SlidingWindowTracker:
    """Tracks sliding time windows for threshold rules in memory with thread safety."""

    def __init__(self):
        self._lock = Lock()
        self._windows: dict[tuple[str, str], deque[tuple[datetime, str]]] = {}
        self._cooldowns: dict[tuple[str, str], datetime] = {}

    def record_and_check_threshold(
        self,
        rule_id: str,
        group_val: str,
        event_time: datetime,
        event_id: str,
        window_seconds: int,
        threshold: int,
        cooldown_seconds: int = 60,
    ) -> list[str] | None:
        """
        Records an event and checks if threshold is reached within window_seconds.
        Returns list of event_ids if threshold met and not in cooldown; None otherwise.
        """
        key = (rule_id, str(group_val))
        cutoff = event_time - timedelta(seconds=window_seconds)

        with self._lock:
            last_alert = self._cooldowns.get(key)
            if last_alert and (event_time - last_alert).total_seconds() < cooldown_seconds:
                return None

            if key not in self._windows:
                self._windows[key] = deque()

            d = self._windows[key]
            d.append((event_time, event_id))

            while d and d[0][0] < cutoff:
                d.popleft()

            if len(d) >= threshold:
                matched_ids = [eid for _, eid in d]
                self._cooldowns[key] = event_time
                d.clear()
                return matched_ids

        return None


class IncidentCorrelator:
    """Manages alert deduplication, incident clustering, and lifecycle state management."""

    def __init__(self, dedup_window_seconds: int = 300):
        self.dedup_window_seconds = dedup_window_seconds
        self.window_tracker = SlidingWindowTracker()

    def resolve_entity_key(self, rule: DetectionRuleModel, event: TelemetryEventModel) -> str:
        """Computes the grouping entity key (e.g. f'{rule.id}:{actor_pid}')."""
        group_by_field = rule.group_by
        entity_val = None

        if group_by_field:
            entity_val = extract_field(event, group_by_field)

        if entity_val is None:
            entity_val = (
                getattr(event, "actor_pid", None)
                or getattr(event, "target_identifier", None)
                or getattr(event, "hostname", None)
                or "global"
            )

        return f"{rule.id}:{entity_val}"

    def correlate_alert(
        self,
        db: Session,
        rule: DetectionRuleModel,
        alert: DetectionAlertModel,
        event: TelemetryEventModel,
    ) -> IncidentModel:
        """
        Clusters a DetectionAlertModel into an existing open IncidentModel,
        or creates a new IncidentModel.
        """
        entity_key = self.resolve_entity_key(rule, event)
        now_utc = alert.timestamp or datetime.now(UTC)
        cutoff_time = now_utc - timedelta(seconds=self.dedup_window_seconds)

        existing_incident = (
            db.query(IncidentModel)
            .filter(
                IncidentModel.entity_key == entity_key,
                IncidentModel.status.in_(["New", "Triaged", "In Progress"]),
                IncidentModel.last_seen >= cutoff_time,
                IncidentModel.is_sample == event.is_sample,
            )
            .order_by(IncidentModel.last_seen.desc())
            .first()
        )

        if existing_incident:
            existing_incident.event_count += 1
            existing_incident.last_seen = now_utc
            alert.incident_id = existing_incident.id
            db.add(alert)
            db.commit()
            db.refresh(existing_incident)
            logger.debug(
                "Correlated alert %s into existing incident %s (count=%d)",
                alert.id, existing_incident.id, existing_incident.event_count
            )
            return existing_incident

        priority = SEVERITY_PRIORITY_MAP.get(rule.severity, "P3_Medium")
        incident_id = str(uuid4())

        new_incident = IncidentModel(
            id=incident_id,
            title=rule.name,
            rule_id=rule.id,
            severity=rule.severity,
            priority=priority,
            status="New",
            entity_key=entity_key,
            first_seen=now_utc,
            last_seen=now_utc,
            event_count=1,
            summary=rule.explanation,
            mitre_attack=rule.mitre_attack,
            assigned_analyst=None,
            is_sample=event.is_sample,
        )

        db.add(new_incident)
        alert.incident_id = incident_id
        db.add(alert)
        db.commit()
        db.refresh(new_incident)
        logger.info("Created new incident %s [%s] for rule %s", incident_id, rule.severity, rule.id)
        return new_incident

    def record_threshold_match(
        self,
        db: Session,
        rule: DetectionRuleModel,
        event: TelemetryEventModel,
    ) -> DetectionAlertModel | None:
        """
        Records an event match for a threshold rule. If the sliding window threshold
        is reached, generates a DetectionAlertModel and correlates it into an incident.
        """
        group_val = extract_field(event, rule.group_by or "host.hostname") or "global"
        now_utc = event.timestamp or datetime.now(UTC)

        matched_event_ids = self.window_tracker.record_and_check_threshold(
            rule_id=rule.id,
            group_val=str(group_val),
            event_time=now_utc,
            event_id=str(event.id),
            window_seconds=rule.correlation_window,
            threshold=rule.threshold,
        )

        if not matched_event_ids:
            return None

        alert = DetectionAlertModel(
            id=str(uuid4()),
            incident_id="",
            rule_id=rule.id,
            timestamp=now_utc,
            severity=rule.severity,
            explanation=f"{rule.explanation} (Threshold of {rule.threshold} events in {rule.correlation_window}s met)",
            triggering_event_id=event.id,
            match_details={
                "threshold_rule_id": rule.id,
                "threshold": rule.threshold,
                "correlation_window_sec": rule.correlation_window,
                "triggering_event_ids": matched_event_ids,
                "group_by": rule.group_by,
                "group_val": group_val,
            },
        )

        self.correlate_alert(db, rule, alert, event)
        return alert

    def transition_incident_status(
        self,
        db: Session,
        incident_id: str,
        new_status: str,
        actor: str = "analyst",
        note_content: str | None = None,
        assigned_analyst: str | None = None,
    ) -> IncidentModel:
        """
        Validates and executes an incident status transition.
        Records an entry in AuditLogModel and appends an IncidentNoteModel if provided.
        """
        incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID '{incident_id}' not found.")

        current_status = incident.status
        allowed = VALID_STATUS_TRANSITIONS.get(current_status, [])

        if new_status not in allowed and new_status != current_status:
            raise ValueError(
                f"Invalid status transition from '{current_status}' to '{new_status}'. Allowed: {allowed}"
            )

        incident.status = new_status
        if assigned_analyst is not None:
            incident.assigned_analyst = assigned_analyst

        now_utc = datetime.now(UTC)

        if note_content:
            note = IncidentNoteModel(
                id=str(uuid4()),
                incident_id=incident.id,
                author=actor,
                created_at=now_utc,
                content=note_content,
            )
            db.add(note)

        audit_entry = AuditLogModel(
            id=str(uuid4()),
            timestamp=now_utc,
            action="INCIDENT_STATUS_TRANSITION",
            actor=actor,
            target_resource=f"incident:{incident.id}",
            details={
                "incident_id": incident.id,
                "previous_status": current_status,
                "new_status": new_status,
                "has_note": bool(note_content),
                "assigned_analyst": incident.assigned_analyst,
            },
            status="SUCCESS",
        )
        db.add(audit_entry)

        db.commit()
        db.refresh(incident)
        logger.info("Transitioned incident %s from %s to %s by %s", incident_id, current_status, new_status, actor)
        return incident
