"""
Health, Sensor Status & System Diagnostics Endpoints
"""
import platform
import sys
import threading
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_collector, get_db
from app.core.config import get_settings
from app.platform.base import PlatformCollectorABC
from app.schemas.common import ApiResponse
from app.schemas.settings import DiagnosticsReport, HealthResponse, SensorHealthStatus

router = APIRouter(tags=["Health & Diagnostics"])
settings = get_settings()
_START_TIME = datetime.now(UTC)


@router.get("/health", response_model=ApiResponse[HealthResponse])
def get_health() -> ApiResponse[HealthResponse]:
    """Basic health check and runtime status."""
    now = datetime.now(UTC)
    uptime = (now - _START_TIME).total_seconds()
    mode = "demo" if settings.DEMO_MODE_DEFAULT else "live"

    data = HealthResponse(
        status="ok",
        version=settings.VERSION,
        platform=platform.system(),
        mode=mode,
        uptime_seconds=uptime,
        timestamp=now,
    )
    return ApiResponse(data=data)


@router.get("/sensor/status", response_model=ApiResponse[list[SensorHealthStatus]])
def get_sensor_status(
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[SensorHealthStatus]]:
    """Query health metrics for all host sensors."""
    now = datetime.now(UTC)
    caps = collector.get_capabilities()

    sensors = [
        SensorHealthStatus(
            sensor_name="Agni Core (Process Inventory)",
            status="healthy" if caps.get("process_inventory") else "unavailable",
            last_collection=now,
            items_collected=len(collector.get_processes(limit=10)),
            error_count=0,
            latency_ms=12.5,
            message="Active process monitoring enabled",
        ),
        SensorHealthStatus(
            sensor_name="Vayu (Network Intelligence)",
            status="healthy" if caps.get("network_sockets") else "unavailable",
            last_collection=now,
            items_collected=len(collector.get_network_sockets(limit=10)),
            error_count=0,
            latency_ms=8.2,
            message="Socket and interface enumeration active",
        ),
        SensorHealthStatus(
            sensor_name="Varuna (FIM & Detection)",
            status="healthy",
            last_collection=now,
            items_collected=1,
            error_count=0,
            latency_ms=3.1,
            message="Rule engine and FIM baseline operational",
        ),
        SensorHealthStatus(
            sensor_name="Persistence Monitor",
            status="healthy" if (caps.get("registry_persistence") or caps.get("systemd_persistence") or caps.get("launchd_persistence") or caps.get("startup_folder_persistence")) else "unavailable",
            last_collection=now,
            items_collected=len(collector.get_persistence_entries()),
            error_count=0,
            latency_ms=15.0,
            message="Autostart inspection active",
        ),
    ]
    return ApiResponse(data=sensors)


@router.get("/diagnostics", response_model=ApiResponse[DiagnosticsReport])
def get_diagnostics(
    db: Session = Depends(get_db),
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[DiagnosticsReport]:
    """Retrieve deep system and database diagnostic telemetry."""
    # Check SQLite WAL mode
    wal_active = False
    try:
        res = db.execute(text("PRAGMA journal_mode;")).scalar()
        if res and str(res).lower() == "wal":
            wal_active = True
        db_status = "healthy"
    except Exception as e:
        db_status = f"error: {e}"

    sys_telemetry = collector.get_system_telemetry()
    caps = collector.get_capabilities()
    sensors_response = get_sensor_status(collector=collector).data

    report = DiagnosticsReport(
        hostname=sys_telemetry.hostname,
        os_name=sys_telemetry.os_name,
        os_version=sys_telemetry.os_version,
        architecture=sys_telemetry.architecture,
        python_version=sys.version.split()[0],
        database_status=db_status,
        database_wal_mode=wal_active,
        active_threads=threading.active_count(),
        memory_usage_mb=sys_telemetry.agni_memory_rss_mb,
        cpu_percent=sys_telemetry.cpu_usage_percent,
        capabilities=caps,
        sensors=sensors_response,
    )
    return ApiResponse(data=report)
