"""
Incident Management & Analyst Triage Endpoints
"""
from datetime import UTC

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_correlator, get_db
from app.engine.correlator import IncidentCorrelator
from app.models.incident import IncidentModel, IncidentNoteModel
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.detection import (
    IncidentDetailRead,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentRead,
    IncidentStatusUpdate,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=ApiResponse[PaginatedResponse[IncidentRead]])
@router.get("/", response_model=ApiResponse[PaginatedResponse[IncidentRead]])
def list_incidents(
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    include_sample: bool = Query(True, description="Include sample mode incidents"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> ApiResponse[PaginatedResponse[IncidentRead]]:
    """List grouped and correlated incidents."""
    query = db.query(IncidentModel)

    if not include_sample:
        query = query.filter(IncidentModel.is_sample.is_(False))
    if status_filter:
        query = query.filter(IncidentModel.status.ilike(status_filter))
    if severity:
        query = query.filter(IncidentModel.severity.ilike(severity))

    total = query.count()
    incidents_orm = query.order_by(IncidentModel.last_seen.desc()).offset(offset).limit(limit).all()
    items = [IncidentRead.model_validate(inc) for inc in incidents_orm]

    return ApiResponse(
        data=PaginatedResponse(items=items, total=total, limit=limit, offset=offset)
    )


@router.get("/{incident_id}", response_model=ApiResponse[IncidentDetailRead])
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
) -> ApiResponse[IncidentDetailRead]:
    """Retrieve full incident dossier including alerts and notes."""
    incident = (
        db.query(IncidentModel)
        .options(joinedload(IncidentModel.alerts), joinedload(IncidentModel.notes))
        .filter(IncidentModel.id == incident_id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return ApiResponse(data=IncidentDetailRead.model_validate(incident))


@router.patch("/{incident_id}", response_model=ApiResponse[IncidentDetailRead])
def update_incident_status(
    incident_id: str,
    update_in: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    correlator: IncidentCorrelator = Depends(get_correlator),
) -> ApiResponse[IncidentDetailRead]:
    """Transition incident investigation lifecycle state."""
    try:
        updated = correlator.transition_incident_status(
            db=db,
            incident_id=incident_id,
            new_status=update_in.status,
            actor="local_analyst",
            note_content=update_in.analyst_note,
            assigned_analyst=update_in.assigned_analyst,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    # Refresh with eager load
    incident = (
        db.query(IncidentModel)
        .options(joinedload(IncidentModel.alerts), joinedload(IncidentModel.notes))
        .filter(IncidentModel.id == updated.id)
        .first()
    )
    return ApiResponse(data=IncidentDetailRead.model_validate(incident))


@router.post("/{incident_id}/notes", response_model=ApiResponse[IncidentNoteRead])
def add_incident_note(
    incident_id: str,
    note_in: IncidentNoteCreate,
    db: Session = Depends(get_db),
) -> ApiResponse[IncidentNoteRead]:
    """Append an analyst investigation note to an incident."""
    import uuid
    from datetime import datetime

    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    note = IncidentNoteModel(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        author=note_in.author or "local_analyst",
        created_at=datetime.now(UTC),
        content=note_in.content,
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    return ApiResponse(data=IncidentNoteRead.model_validate(note))
