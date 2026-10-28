"""
Agni (अग्नि) - Detection Engine
File: backend/app/engine/detector.py
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.engine.rules import evaluate_condition, extract_field, validate_condition_ast
from app.models.event import TelemetryEventModel
from app.models.incident import DetectionAlertModel
from app.models.rule import DetectionRuleModel

logger = logging.getLogger("agni.engine.detector")


class Detector:
    """Core Varuna detection engine processing live telemetry against active detection rules."""

    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir or (Path(__file__).resolve().parent.parent.parent / "rules")

    def load_rules_from_disk(self) -> list[dict[str, Any]]:
        """Reads and validates all rule JSON files from backend/rules/."""
        loaded_rules: list[dict[str, Any]] = []
        if not self.rules_dir.exists():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return loaded_rules

        for rule_file in self.rules_dir.glob("*.json"):
            try:
                with open(rule_file, encoding="utf-8") as f:
                    rule_data = json.load(f)

                is_valid, err = validate_condition_ast(rule_data.get("match_conditions", {}))
                if not is_valid:
                    logger.error("Rule %s invalid condition AST: %s", rule_file.name, err)
                    continue

                loaded_rules.append(rule_data)
            except Exception as e:
                logger.error("Failed loading rule file %s: %s", rule_file.name, e)

        logger.info("Loaded %d valid detection rules from %s", len(loaded_rules), self.rules_dir)
        return loaded_rules

    def sync_rules_to_db(self, db: Session) -> int:
        """
        Synchronizes disk rules into the database detection_rules table.
        Adds new rules and updates existing stock rules without overwriting custom flags.
        """
        disk_rules = self.load_rules_from_disk()
        synced_count = 0

        for r_dict in disk_rules:
            rule_id = r_dict["id"]
            existing = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_id).first()

            if existing:
                if not existing.is_custom:
                    existing.name = r_dict["name"]
                    existing.description = r_dict["description"]
                    existing.severity = r_dict["severity"]
                    existing.category = r_dict["category"]
                    existing.source = r_dict["source"]
                    existing.match_conditions = r_dict["match_conditions"]
                    existing.correlation_window = r_dict.get("correlation_window", 0)
                    existing.threshold = r_dict.get("threshold", 1)
                    existing.group_by = r_dict.get("group_by")
                    existing.explanation = r_dict["explanation"]
                    existing.investigation_steps = r_dict.get("investigation_steps", [])
                    existing.mitre_attack = r_dict.get("mitre_attack")
                    existing.version = r_dict.get("version", "1.0.0")
            else:
                new_rule = DetectionRuleModel(
                    id=rule_id,
                    name=r_dict["name"],
                    description=r_dict["description"],
                    severity=r_dict["severity"],
                    category=r_dict["category"],
                    source=r_dict["source"],
                    match_conditions=r_dict["match_conditions"],
                    correlation_window=r_dict.get("correlation_window", 0),
                    threshold=r_dict.get("threshold", 1),
                    group_by=r_dict.get("group_by"),
                    explanation=r_dict["explanation"],
                    investigation_steps=r_dict.get("investigation_steps", []),
                    mitre_attack=r_dict.get("mitre_attack"),
                    version=r_dict.get("version", "1.0.0"),
                    enabled=r_dict.get("enabled", True),
                    is_custom=False,
                )
                db.add(new_rule)
            synced_count += 1

        db.commit()
        logger.info("Synchronized %d detection rules into database.", synced_count)
        return synced_count

    def get_active_rules(self, db: Session) -> list[DetectionRuleModel]:
        """Returns all currently enabled detection rules."""
        return db.query(DetectionRuleModel).filter(DetectionRuleModel.enabled.is_(True)).all()

    def process_event(
        self,
        db: Session,
        event: TelemetryEventModel,
        correlator: Any | None = None,
    ) -> list[DetectionAlertModel]:
        """
        Processes a single TelemetryEventModel against all active rules.
        Emits and correlates DetectionAlertModel instances for any matched conditions.
        """
        active_rules = self.get_active_rules(db)
        alerts: list[DetectionAlertModel] = []
        now_utc = datetime.now(UTC)

        for rule in active_rules:
            try:
                # Category/source filter check if both specified and rule not "any"
                if rule.category and event.category:
                    # Map file_integrity and fim
                    r_cat = "file_integrity" if rule.category == "fim" else rule.category
                    e_cat = "file_integrity" if event.category == "fim" else event.category
                    if r_cat != e_cat and rule.category != "any":
                        if rule.source != "any" and rule.source != event.source:
                            continue

                # Evaluate AST condition tree
                if not evaluate_condition(rule.match_conditions, event):
                    continue

                # Rule matched
                if rule.correlation_window > 0 and rule.threshold > 1:
                    if correlator:
                        threshold_alert = correlator.record_threshold_match(db, rule, event)
                        if threshold_alert:
                            alerts.append(threshold_alert)
                else:
                    alert = DetectionAlertModel(
                        id=str(uuid4()),
                        incident_id="",
                        rule_id=rule.id,
                        timestamp=event.timestamp or now_utc,
                        severity=rule.severity,
                        explanation=rule.explanation,
                        triggering_event_id=event.id,
                        match_details={
                            "matched_rule_id": rule.id,
                            "matched_rule_name": rule.name,
                            "mitre_attack": rule.mitre_attack,
                            "event_category": event.category,
                            "event_action": event.action,
                            "actor_name": getattr(event, "actor_name", None),
                            "actor_cmdline": getattr(event, "actor_cmdline", None),
                            "target_identifier": getattr(event, "target_identifier", None),
                        },
                    )

                    if correlator:
                        correlator.correlate_alert(db, rule, alert, event)
                    alerts.append(alert)

            except Exception as e:
                logger.error("Error evaluating rule %s against event %s: %s", rule.id, event.id, e, exc_info=True)
                continue

        return alerts

    def test_rule(self, rule_data: dict[str, Any], sample_event: dict[str, Any]) -> dict[str, Any]:
        """
        Dry-run helper for testing a rule against a sample event payload.
        Returns match status, extracted fields, and evaluation details without persisting.
        """
        conditions = rule_data.get("match_conditions", {})
        is_valid, err = validate_condition_ast(conditions)
        if not is_valid:
            return {"matched": False, "valid": False, "error": err}

        matched = evaluate_condition(conditions, sample_event)
        inspected_fields = self._collect_condition_fields(conditions)
        extracted = {f: extract_field(sample_event, f) for f in inspected_fields}

        return {
            "matched": matched,
            "valid": True,
            "rule_id": rule_data.get("id"),
            "severity": rule_data.get("severity"),
            "extracted_fields": extracted,
        }

    def _collect_condition_fields(self, condition: dict[str, Any]) -> list[str]:
        """Helper to collect all referenced field paths in an AST condition."""
        fields: list[str] = []
        if "field" in condition:
            fields.append(condition["field"])
        for key in ("and", "or"):
            if key in condition and isinstance(condition[key], list):
                for sub in condition[key]:
                    fields.extend(self._collect_condition_fields(sub))
        if "not" in condition and isinstance(condition["not"], dict):
            fields.extend(self._collect_condition_fields(condition["not"]))
        return list(dict.fromkeys(fields))
