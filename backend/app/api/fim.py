"""
File Integrity Monitoring (FIM) Endpoints
"""
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_correlator, get_db, get_detector, get_fim_service
from app.core.security import record_audit_log, validate_safe_path
from app.engine.correlator import IncidentCorrelator
from app.engine.detector import Detector
from app.models.event import TelemetryEventModel
from app.models.fim import FIMBaselineModel, FIMChangeModel, FIMEntryModel
from app.schemas.common import ApiResponse
from app.schemas.telemetry import (
    FIMBaselineCreate,
    FIMBaselineRead,
    FIMChangeRead,
    FIMScanRequest,
    FIMScanResult,
)
from app.services.fim import FIMPathSecurityError, FIMService

router = APIRouter(prefix="/fim", tags=["File Integrity Monitoring"])


@router.get("/status", response_model=ApiResponse[dict])
def get_fim_status(db: Session = Depends(get_db)) -> ApiResponse[dict]:
    """Summary of FIM baselines, monitored files, and recent changes."""
    baselines = db.query(FIMBaselineModel).all()
    total_entries = db.query(FIMEntryModel).count()
    total_changes = db.query(FIMChangeModel).count()
    unack_changes = db.query(FIMChangeModel).filter(FIMChangeModel.acknowledged.is_(False)).count()

    return ApiResponse(
        data={
            "total_baselines": len(baselines),
            "total_files_monitored": total_entries,
            "total_changes_detected": total_changes,
            "unacknowledged_changes": unack_changes,
            "baselines": [FIMBaselineRead.model_validate(b) for b in baselines],
        }
    )


@router.get("/baselines", response_model=ApiResponse[list[FIMBaselineRead]])
def list_baselines(db: Session = Depends(get_db)) -> ApiResponse[list[FIMBaselineRead]]:
    """List all registered FIM baseline configurations."""
    baselines = db.query(FIMBaselineModel).order_by(FIMBaselineModel.created_at.desc()).all()
    return ApiResponse(data=[FIMBaselineRead.model_validate(b) for b in baselines])


@router.post("/baseline", response_model=ApiResponse[FIMBaselineRead])
@router.post("/baselines", response_model=ApiResponse[FIMBaselineRead])
def create_baseline(
    baseline_in: FIMBaselineCreate,
    db: Session = Depends(get_db),
    fim_service: FIMService = Depends(get_fim_service),
) -> ApiResponse[FIMBaselineRead]:
    """Register a new path baseline and hash all matching files."""
    try:
        resolved_path = validate_safe_path(baseline_in.target_path, must_exist=True)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid baseline path: {e}",
        ) from e

    baseline_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    # Initial snapshot
    try:
        records = fim_service.scan_path(
            target_path=str(resolved_path),
            recursive=baseline_in.recursive,
            file_patterns=baseline_in.file_patterns,
            exclude_patterns=baseline_in.exclude_patterns,
            max_file_size_bytes=baseline_in.max_file_size_bytes,
        )
    except FIMPathSecurityError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    baseline = FIMBaselineModel(
        id=baseline_id,
        name=baseline_in.name,
        target_path=str(resolved_path),
        recursive=baseline_in.recursive,
        file_patterns=baseline_in.file_patterns,
        exclude_patterns=baseline_in.exclude_patterns,
        max_file_size_bytes=baseline_in.max_file_size_bytes,
        created_at=now,
        last_scanned_at=now,
        total_files=len(records),
        status="Active",
    )
    db.add(baseline)

    for rec in records:
        entry = FIMEntryModel(
            id=str(uuid.uuid4()),
            baseline_id=baseline_id,
            file_path=rec.file_path,
            sha256_hash=rec.sha256_hash,
            file_size_bytes=rec.file_size_bytes,
            mtime=rec.mtime,
            permissions=rec.permissions,
            owner=rec.owner,
            last_verified_at=now,
        )
        db.add(entry)

    db.commit()
    db.refresh(baseline)

    record_audit_log(
        db,
        action="FIM_BASELINE_CREATED",
        target_resource=f"fim_baseline:{baseline_id}",
        details={"name": baseline.name, "path": baseline.target_path, "files": len(records)},
    )

    return ApiResponse(data=FIMBaselineRead.model_validate(baseline))


@router.post("/scan", response_model=ApiResponse[list[FIMScanResult]])
def run_fim_scan(
    scan_req: FIMScanRequest | None = None,
    db: Session = Depends(get_db),
    fim_service: FIMService = Depends(get_fim_service),
    detector: Detector = Depends(get_detector),
    correlator: IncidentCorrelator = Depends(get_correlator),
) -> ApiResponse[list[FIMScanResult]]:
    """
    Execute live FIM integrity scan against baselines, detect differences,
    record changes and generate telemetry events into the detection engine.
    """
    baseline_id = scan_req.baseline_id if scan_req else None
    query = db.query(FIMBaselineModel)
    if baseline_id:
        query = query.filter(FIMBaselineModel.id == baseline_id)

    baselines = query.all()
    if not baselines:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No matching FIM baseline found to scan.",
        )

    results: list[FIMScanResult] = []
    now = datetime.now(UTC)

    for b in baselines:
        t0 = datetime.now()
        # Retrieve existing entries
        existing_entries = db.query(FIMEntryModel).filter(FIMEntryModel.baseline_id == b.id).all()
        baseline_map = {
            e.file_path: {
                "sha256_hash": e.sha256_hash,
                "file_size_bytes": e.file_size_bytes,
                "mtime": e.mtime,
            }
            for e in existing_entries
        }

        # Current files scan
        current_records = fim_service.scan_path(
            target_path=b.target_path,
            recursive=b.recursive,
            file_patterns=b.file_patterns,
            exclude_patterns=b.exclude_patterns,
            max_file_size_bytes=b.max_file_size_bytes,
        )

        changes, events = fim_service.diff_baseline(baseline_map, current_records)
        duration_ms = (datetime.now() - t0).total_seconds() * 1000

        # Persist changes
        change_reads: list[FIMChangeRead] = []
        for ch in changes:
            ch_model = FIMChangeModel(
                id=str(uuid.uuid4()),
                baseline_id=b.id,
                file_path=ch["file_path"],
                change_type=ch["change_type"],
                previous_sha256=ch["previous_sha256"],
                current_sha256=ch["current_sha256"],
                previous_size=ch["previous_size"],
                current_size=ch["current_size"],
                detected_at=now,
                acknowledged=False,
            )
            db.add(ch_model)
            db.commit()
            db.refresh(ch_model)
            change_reads.append(FIMChangeRead.model_validate(ch_model))

        # Send telemetry events to detection pipeline
        for ev in events:
            ev_model = TelemetryEventModel(
                id=ev["event_id"],
                timestamp=now,
                event_version="1.0.0",
                category=ev["category"],
                action=ev["action"],
                severity=ev["severity"],
                source=ev["source"],
                hostname=ev["host"]["hostname"],
                os_name=ev["host"]["os"],
                actor_pid=None,
                actor_name="system",
                target_type=ev["target"]["type"],
                target_identifier=ev["target"]["identifier"],
                target_details=ev["target"]["details"],
                details=ev["details"],
                is_sample=False,
            )
            db.add(ev_model)
            db.commit()
            db.refresh(ev_model)
            detector.process_event(db, ev_model, correlator=correlator)

        # Update baseline status
        b.last_scanned_at = now
        b.total_files = len(current_records)
        db.commit()

        results.append(
            FIMScanResult(
                baseline_id=b.id,
                files_scanned=len(current_records),
                changes_detected=len(changes),
                scan_duration_ms=round(duration_ms, 2),
                changes=change_reads,
            )
        )

    return ApiResponse(data=results)


@router.get("/changes", response_model=ApiResponse[list[FIMChangeRead]])
def list_fim_changes(
    limit: int = Query(50, ge=1, le=500),
    acknowledged: bool | None = Query(None),
    db: Session = Depends(get_db),
) -> ApiResponse[list[FIMChangeRead]]:
    """List historical file integrity changes."""
    query = db.query(FIMChangeModel)
    if acknowledged is not None:
        query = query.filter(FIMChangeModel.acknowledged == acknowledged)

    changes = query.order_by(FIMChangeModel.detected_at.desc()).limit(limit).all()
    return ApiResponse(data=[FIMChangeRead.model_validate(c) for c in changes])
