"""
Detection Rules Management Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_detector
from app.core.security import record_audit_log
from app.engine.detector import Detector
from app.engine.rules import validate_condition_ast
from app.models.rule import DetectionRuleModel
from app.schemas.common import ApiResponse
from app.schemas.detection import (
    DetectionRuleCreate,
    DetectionRuleRead,
    DetectionRuleUpdate,
    RuleTestRequest,
    RuleTestResult,
    RuleToggleRequest,
)

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=ApiResponse[list[DetectionRuleRead]])
@router.get("/", response_model=ApiResponse[list[DetectionRuleRead]])
def list_rules(
    enabled: bool | None = Query(None, description="Filter by enabled state"),
    severity: str | None = Query(None, description="Filter by severity"),
    category: str | None = Query(None, description="Filter by category"),
    db: Session = Depends(get_db),
) -> ApiResponse[list[DetectionRuleRead]]:
    """List detection rules library."""
    query = db.query(DetectionRuleModel)
    if enabled is not None:
        query = query.filter(DetectionRuleModel.enabled == enabled)
    if severity:
        query = query.filter(DetectionRuleModel.severity.ilike(severity))
    if category:
        query = query.filter(DetectionRuleModel.category.ilike(category))

    rules = query.order_by(DetectionRuleModel.id).all()
    return ApiResponse(data=[DetectionRuleRead.model_validate(r) for r in rules])


@router.get("/{rule_id}", response_model=ApiResponse[DetectionRuleRead])
def get_rule(rule_id: str, db: Session = Depends(get_db)) -> ApiResponse[DetectionRuleRead]:
    """Retrieve full rule definition by ID."""
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )
    return ApiResponse(data=DetectionRuleRead.model_validate(rule))


@router.post("", response_model=ApiResponse[DetectionRuleRead])
@router.post("/", response_model=ApiResponse[DetectionRuleRead])
def create_custom_rule(
    rule_in: DetectionRuleCreate,
    db: Session = Depends(get_db),
) -> ApiResponse[DetectionRuleRead]:
    """Register a new custom detection rule."""
    existing = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_in.id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule ID '{rule_in.id}' already exists",
        )

    # Validate condition AST syntax
    is_valid, err = validate_condition_ast(rule_in.match_conditions)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid match conditions AST: {err}",
        )

    rule = DetectionRuleModel(
        id=rule_in.id,
        name=rule_in.name,
        description=rule_in.description,
        severity=rule_in.severity,
        category=rule_in.category,
        source=rule_in.source,
        match_conditions=rule_in.match_conditions,
        correlation_window=rule_in.correlation_window,
        threshold=rule_in.threshold,
        group_by=rule_in.group_by,
        explanation=rule_in.explanation,
        investigation_steps=rule_in.investigation_steps,
        mitre_attack=rule_in.mitre_attack,
        version=rule_in.version,
        enabled=rule_in.enabled,
        is_custom=True,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    record_audit_log(
        db,
        action="RULE_CREATED",
        target_resource=f"rule:{rule.id}",
        details={"name": rule.name, "severity": rule.severity},
    )

    return ApiResponse(data=DetectionRuleRead.model_validate(rule))


@router.patch("/{rule_id}", response_model=ApiResponse[DetectionRuleRead])
def update_rule(
    rule_id: str,
    rule_update: DetectionRuleUpdate,
    db: Session = Depends(get_db),
) -> ApiResponse[DetectionRuleRead]:
    """Update rule parameters."""
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")

    update_data = rule_update.model_dump(exclude_unset=True)

    if "match_conditions" in update_data:
        is_valid, err = validate_condition_ast(update_data["match_conditions"])
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid match conditions AST: {err}",
            )

    for field, val in update_data.items():
        setattr(rule, field, val)

    db.commit()
    db.refresh(rule)

    record_audit_log(
        db,
        action="RULE_UPDATED",
        target_resource=f"rule:{rule.id}",
        details=update_data,
    )

    return ApiResponse(data=DetectionRuleRead.model_validate(rule))


@router.patch("/{rule_id}/toggle", response_model=ApiResponse[DetectionRuleRead])
def toggle_rule(
    rule_id: str,
    toggle_in: RuleToggleRequest,
    db: Session = Depends(get_db),
) -> ApiResponse[DetectionRuleRead]:
    """Toggle enabled/disabled state of a rule."""
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found")

    old_state = rule.enabled
    rule.enabled = toggle_in.enabled
    db.commit()
    db.refresh(rule)

    record_audit_log(
        db,
        action="RULE_TOGGLED",
        target_resource=f"rule:{rule.id}",
        details={"previous_state": old_state, "new_state": rule.enabled},
    )

    return ApiResponse(data=DetectionRuleRead.model_validate(rule))


@router.post("/test", response_model=ApiResponse[RuleTestResult])
def test_rule(
    test_req: RuleTestRequest,
    detector: Detector = Depends(get_detector),
) -> ApiResponse[RuleTestResult]:
    """Dry-run test evaluation of a candidate rule against a test event."""
    res = detector.test_rule(rule_data=test_req.rule, sample_event=test_req.event)
    return ApiResponse(data=RuleTestResult(**res))
