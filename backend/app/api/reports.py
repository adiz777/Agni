"""
Security Reports Export Endpoints (JSON, CSV, HTML)
"""
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.security import record_audit_log
from app.schemas.detection import ReportExportRequest
from app.services.exporter import ReportExporter

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/export")
@router.post("/generate")
def export_report(
    req: ReportExportRequest,
    db: Session = Depends(get_db),
):
    """
    Generate and stream an incident report in JSON, CSV, or standalone HTML format.
    """
    try:
        content_type, filename, raw_bytes = ReportExporter.export(
            db=db,
            export_format=req.format,
            start_time=req.start_time,
            end_time=req.end_time,
            severity=req.severity,
            status=req.status,
            include_sample=req.include_sample,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    record_audit_log(
        db,
        action="REPORT_GENERATED",
        target_resource=f"report:{req.format}",
        details={"format": req.format, "filename": filename, "include_sample": req.include_sample},
    )

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Length": str(len(raw_bytes)),
    }

    return Response(
        content=raw_bytes,
        media_type=content_type,
        headers=headers,
    )
