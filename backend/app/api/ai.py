"""
Safe AI Investigation Assistant Endpoints (R3)
Provides read-only, non-remediative threat analysis with explicit consent and redaction.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_ai_service, get_db
from app.core.security import record_audit_log
from app.models.audit import SystemSettingModel
from app.models.detection import IncidentModel
from app.models.telemetry import TelemetryEventModel
from app.schemas.ai import (
    AIConfigUpdate,
    AIInvestigationResponse,
    AIModelListResponse,
    AIStatusRead,
    IncidentInvestigationRequest,
    RedactionPreviewRequest,
    RedactionPreviewResponse,
)
from app.schemas.common import ApiResponse
from app.services.ai_assistant import AIAssistantService

router = APIRouter(prefix="/ai", tags=["AI Assistant"])


@router.get("/status", response_model=ApiResponse[AIStatusRead])
@router.get("", response_model=ApiResponse[AIStatusRead])
def get_ai_status(
    db: Session = Depends(get_db),
    ai_service: AIAssistantService = Depends(get_ai_service),
) -> ApiResponse[AIStatusRead]:
    """Retrieve current AI investigation assistant status and configuration."""
    status_data = ai_service.get_status(db)
    return ApiResponse(data=status_data)


@router.post("/config", response_model=ApiResponse[AIStatusRead])
def update_ai_config(
    config_in: AIConfigUpdate,
    db: Session = Depends(get_db),
    ai_service: AIAssistantService = Depends(get_ai_service),
) -> ApiResponse[AIStatusRead]:
    """Update AI assistant configuration parameters."""
    now = datetime.now(UTC)
    updates = config_in.model_dump(exclude_unset=True)

    key_mappings = {
        "enabled": "ai_enabled",
        "provider": "ai_provider",
        "base_url": "ai_endpoint",
        "model": "ai_model",
        "api_key": "ai_api_key",
        "consent_granted": "ai_consent_granted",
        "timeout_seconds": "ai_timeout_seconds",
    }

    for param, val in updates.items():
        db_key = key_mappings.get(param, param)
        val_str = str(val).lower() if isinstance(val, bool) else str(val)
        existing = db.query(SystemSettingModel).filter(SystemSettingModel.key == db_key).first()
        if existing:
            existing.value = val_str
            existing.updated_at = now
        else:
            db.add(
                SystemSettingModel(
                    key=db_key,
                    value=val_str,
                    description=f"AI setting for {param}",
                    updated_at=now,
                )
            )

    db.commit()

    # Record state modification in immutable audit trail
    safe_audit_details = {k: ("[REDACTED]" if k == "api_key" else v) for k, v in updates.items()}
    record_audit_log(
        db,
        action="CONFIG_UPDATED",
        target_resource="ai_configuration",
        details=safe_audit_details,
    )

    updated_status = ai_service.get_status(db)
    return ApiResponse(data=updated_status)


@router.post("/preview-redaction", response_model=ApiResponse[RedactionPreviewResponse])
def preview_redaction(
    req: RedactionPreviewRequest,
    db: Session = Depends(get_db),
    ai_service: AIAssistantService = Depends(get_ai_service),
) -> ApiResponse[RedactionPreviewResponse]:
    """Generate pre-flight preview of redacted telemetry prior to sending to LLM."""
    cfg = ai_service.get_config(db)
    is_external = ai_service.is_external_endpoint(cfg.base_url, cfg.provider)

    if req.incident_id:
        incident = db.query(IncidentModel).filter(IncidentModel.id == req.incident_id).first()
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident with ID '{req.incident_id}' not found.",
            )

        events: list[TelemetryEventModel] = []
        if req.include_correlated_events and incident.alerts:
            event_ids = [a.triggering_event_id for a in incident.alerts if a.triggering_event_id]
            if event_ids:
                events = db.query(TelemetryEventModel).filter(TelemetryEventModel.id.in_(event_ids)).all()

        raw_text = ai_service.build_investigation_prompt(incident, events)
    elif req.sample_text:
        raw_text = req.sample_text
    else:
        raw_text = "Sample telemetry verification test."

    redacted_text, counts = ai_service.redactor.redact_text(raw_text)

    preview_resp = RedactionPreviewResponse(
        incident_id=req.incident_id,
        original_text_summary=raw_text[:1000],
        redacted_text_summary=redacted_text[:1000],
        redacted_items_count=counts,
        target_endpoint=cfg.base_url,
        is_external=is_external,
    )
    return ApiResponse(data=preview_resp)


@router.post("/investigate", response_model=ApiResponse[AIInvestigationResponse])
@router.post("/investigate-incident", response_model=ApiResponse[AIInvestigationResponse])
async def investigate_incident(
    req: IncidentInvestigationRequest,
    db: Session = Depends(get_db),
    ai_service: AIAssistantService = Depends(get_ai_service),
) -> ApiResponse[AIInvestigationResponse]:
    """
    Run safe, read-only AI investigation on an incident.
    Enforces disabled-by-default check, explicit consent gate, and PII redaction.
    """
    cfg = ai_service.get_config(db)
    is_external = ai_service.is_external_endpoint(cfg.base_url, cfg.provider)

    # 1. Gate 1: Check disabled-by-default status
    if not cfg.enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI Assistant is disabled. Enable it in Settings to perform automated investigation.",
        )

    # 2. Gate 2: Explicit User Consent Gate for external endpoints
    if is_external and not (req.consent_given or cfg.consent_granted):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Explicit user consent is required before dispatching telemetry to external AI endpoints.",
        )

    # 3. Locate target incident
    incident = db.query(IncidentModel).filter(IncidentModel.id == req.incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{req.incident_id}' not found.",
        )

    # 4. Fetch correlated evidence events
    events: list[TelemetryEventModel] = []
    if req.include_correlated_events and incident.alerts:
        event_ids = [a.triggering_event_id for a in incident.alerts if a.triggering_event_id]
        if event_ids:
            events = (
                db.query(TelemetryEventModel)
                .filter(TelemetryEventModel.id.in_(event_ids))
                .limit(req.max_events)
                .all()
            )

    # 5. Execute safe investigation
    result = await ai_service.investigate_incident(
        incident=incident,
        correlated_events=events,
        db=db,
        user_notes=req.user_notes,
        consent_given=req.consent_given,
    )

    # 6. Record in immutable audit trail
    record_audit_log(
        db,
        action="AI_INVESTIGATION",
        target_resource=f"incident:{incident.id}",
        details={
            "provider": result.provider_used,
            "model": result.model_used,
            "success": result.success,
            "error": result.error,
            "redacted_total": result.redaction_summary.get("total", 0),
        },
    )

    return ApiResponse(data=result)


@router.get("/models", response_model=ApiResponse[AIModelListResponse])
async def list_ai_models(
    db: Session = Depends(get_db),
    ai_service: AIAssistantService = Depends(get_ai_service),
) -> ApiResponse[AIModelListResponse]:
    """List available LLM models from the configured endpoint."""
    model_list = await ai_service.list_available_models(db)
    return ApiResponse(data=model_list)
