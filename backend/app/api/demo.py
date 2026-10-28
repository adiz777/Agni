"""
Demo / Sample Telemetry Mode Endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_sample_generator
from app.core.security import record_audit_log
from app.engine.sample_generator import SampleDataGenerator
from app.schemas.common import ApiResponse
from app.schemas.settings import DemoSeedRequest, DemoStatusRead, DemoToggleRequest

router = APIRouter(prefix="/demo", tags=["Demo Mode"])


@router.get("/status", response_model=ApiResponse[DemoStatusRead])
def get_demo_status(
    db: Session = Depends(get_db),
    generator: SampleDataGenerator = Depends(get_sample_generator),
) -> ApiResponse[DemoStatusRead]:
    """Check whether demo data is currently seeded in the database."""
    status_dict = generator.get_sample_status(db)
    return ApiResponse(data=DemoStatusRead(**status_dict))


@router.post("/seed", response_model=ApiResponse[DemoStatusRead])
def seed_demo_data(
    req: DemoSeedRequest = DemoSeedRequest(),
    db: Session = Depends(get_db),
    generator: SampleDataGenerator = Depends(get_sample_generator),
) -> ApiResponse[DemoStatusRead]:
    """Inject the Operation Ignis Vector APT multi-stage scenario."""
    status_dict = generator.seed_scenario(db, target_hostname=req.hostname or "DharmaCipher")

    record_audit_log(
        db,
        action="DEMO_DATA_SEEDED",
        target_resource="sample_generator",
        details=status_dict,
    )

    return ApiResponse(data=DemoStatusRead(**status_dict))


@router.post("/clear", response_model=ApiResponse[dict])
def clear_demo_data(
    db: Session = Depends(get_db),
    generator: SampleDataGenerator = Depends(get_sample_generator),
) -> ApiResponse[dict]:
    """Purge all synthetic sample entities from the database."""
    res = generator.clear_sample_data(db)

    record_audit_log(
        db,
        action="DEMO_DATA_CLEARED",
        target_resource="sample_generator",
        details=res,
    )

    return ApiResponse(data={"message": "All demo data removed successfully", "details": res})


@router.post("/toggle", response_model=ApiResponse[DemoStatusRead])
def toggle_demo_mode(
    req: DemoToggleRequest,
    db: Session = Depends(get_db),
    generator: SampleDataGenerator = Depends(get_sample_generator),
) -> ApiResponse[DemoStatusRead]:
    """Toggle demo mode: seed sample data if true, clear if false."""
    if req.enabled:
        status_dict = generator.seed_scenario(db)
    else:
        generator.clear_sample_data(db)
        status_dict = generator.get_sample_status(db)

    record_audit_log(
        db,
        action="DEMO_MODE_TOGGLED",
        target_resource="demo_toggle",
        details={"enabled": req.enabled},
    )

    return ApiResponse(data=DemoStatusRead(**status_dict))
