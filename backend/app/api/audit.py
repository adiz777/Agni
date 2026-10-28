"""
System Audit Log Endpoints
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.audit import AuditLogModel
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.settings import AuditLogRead

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/logs", response_model=ApiResponse[PaginatedResponse[AuditLogRead]])
def list_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> ApiResponse[PaginatedResponse[AuditLogRead]]:
    """Retrieve immutable chronological audit trail."""
    query = db.query(AuditLogModel)
    total = query.count()
    items_orm = query.order_by(AuditLogModel.timestamp.desc()).offset(offset).limit(limit).all()
    items = [AuditLogRead.model_validate(log) for log in items_orm]

    return ApiResponse(
        data=PaginatedResponse(items=items, total=total, limit=limit, offset=offset)
    )
