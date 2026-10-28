"""
Host Telemetry, Events, Processes, Network & Persistence Endpoints
"""
import platform
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_collector, get_correlator, get_db, get_detector, get_sample_generator
from app.engine.correlator import IncidentCorrelator
from app.engine.detector import Detector
from app.engine.sample_generator import SampleDataGenerator
from app.models.event import TelemetryEventModel
from app.models.incident import IncidentModel
from app.models.network import NetworkDeviceModel
from app.models.telemetry import FIMEntryModel
from app.platform.base import PlatformCollectorABC
from app.schemas.common import ApiResponse, PaginatedResponse
from app.schemas.telemetry import (
    InterfaceRead,
    NetworkDeviceRead,
    PersistenceRead,
    ProcessRead,
    SocketRead,
    TelemetryEventCreate,
    TelemetryEventRead,
    TelemetryOverviewRead,
)

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get("/overview", response_model=ApiResponse[TelemetryOverviewRead])
def get_telemetry_overview(
    db: Session = Depends(get_db),
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[TelemetryOverviewRead]:
    """Retrieve high-level SOC dashboard KPI overview metrics."""
    now = datetime.now(UTC)
    day_ago = now - timedelta(days=1)

    total_events_24h = (
        db.query(TelemetryEventModel)
        .filter(TelemetryEventModel.timestamp >= day_ago)
        .count()
    )

    active_incidents = (
        db.query(IncidentModel)
        .filter(IncidentModel.status.in_(["New", "Triaged", "In Progress"]))
        .count()
    )

    recent_events_orm = (
        db.query(TelemetryEventModel)
        .order_by(TelemetryEventModel.timestamp.desc())
        .limit(10)
        .all()
    )

    # Count other components
    procs = collector.get_processes(limit=500)
    socks = collector.get_network_sockets(limit=1000)
    dev_count = db.query(NetworkDeviceModel).count()
    fim_count = db.query(FIMEntryModel).count()

    # Calculate threat posture score (100 - active incidents * 15, bounded [0, 100])
    threat_score = max(0, min(100, 100 - (active_incidents * 15)))

    overview = TelemetryOverviewRead(
        total_events_24h=total_events_24h,
        active_incidents=active_incidents,
        monitored_processes=len(procs),
        active_sockets=len(socks),
        network_devices_count=dev_count,
        fim_monitored_files=fim_count,
        threat_posture_score=threat_score,
        sensor_health="healthy" if len(procs) > 0 else "degraded",
        platform=platform.system(),
        is_demo_mode=False,
        recent_events=[TelemetryEventRead.model_validate(e) for e in recent_events_orm],
    )
    return ApiResponse(data=overview)


@router.get("/events", response_model=ApiResponse[PaginatedResponse[TelemetryEventRead]])
def get_events(
    db: Session = Depends(get_db),
    category: str | None = Query(None, description="Filter by event category"),
    severity: str | None = Query(None, description="Filter by event severity"),
    include_sample: bool = Query(True, description="Include synthetic demo events"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> ApiResponse[PaginatedResponse[TelemetryEventRead]]:
    """Paginated live and sample telemetry events."""
    query = db.query(TelemetryEventModel)

    if not include_sample:
        query = query.filter(TelemetryEventModel.is_sample.is_(False))
    if category:
        query = query.filter(TelemetryEventModel.category.ilike(category))
    if severity:
        query = query.filter(TelemetryEventModel.severity.ilike(severity))

    total = query.count()
    items_orm = query.order_by(TelemetryEventModel.timestamp.desc()).offset(offset).limit(limit).all()
    items = [TelemetryEventRead.model_validate(item) for item in items_orm]

    return ApiResponse(
        data=PaginatedResponse(items=items, total=total, limit=limit, offset=offset)
    )


@router.post("/events", response_model=ApiResponse[TelemetryEventRead])
def ingest_event(
    event_in: TelemetryEventCreate,
    db: Session = Depends(get_db),
    detector: Detector = Depends(get_detector),
    correlator: IncidentCorrelator = Depends(get_correlator),
) -> ApiResponse[TelemetryEventRead]:
    """Ingest a single telemetry event and evaluate it against detection rules."""
    now = datetime.now(UTC)
    event_orm = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_version="1.0.0",
        category=event_in.category,
        action=event_in.action,
        severity=event_in.severity,
        source=event_in.source,
        hostname=event_in.hostname or platform.node(),
        os_name=event_in.os_name or platform.system(),
        actor_pid=event_in.actor_pid,
        actor_name=event_in.actor_name,
        actor_path=event_in.actor_path,
        actor_cmdline=event_in.actor_cmdline,
        actor_user=event_in.actor_user,
        target_type=event_in.target_type,
        target_identifier=event_in.target_identifier,
        target_details=event_in.target_details,
        details=event_in.details,
        is_sample=event_in.is_sample,
    )
    db.add(event_orm)
    db.commit()
    db.refresh(event_orm)

    # Evaluate event against rules and correlate
    detector.process_event(db, event_orm, correlator=correlator)

    return ApiResponse(data=TelemetryEventRead.model_validate(event_orm))


@router.post("/sample-events/generate", response_model=ApiResponse[dict])
def generate_sample_events(
    scenario: str = Query("apt_intrusion", description="Scenario name to generate"),
    db: Session = Depends(get_db),
    generator: SampleDataGenerator = Depends(get_sample_generator),
) -> ApiResponse[dict]:
    """Generate sample telemetry events simulating an attack scenario."""
    status_dict = generator.seed_scenario(db)
    return ApiResponse(
        data={"scenario": scenario, "message": "Sample scenario generated successfully", "details": status_dict}
    )


@router.get("/processes", response_model=ApiResponse[list[ProcessRead]])
def get_processes(
    limit: int = Query(200, ge=1, le=1000),
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[ProcessRead]]:
    """Active process inventory with resource metrics."""
    procs = collector.get_processes(limit=limit)
    res = [
        ProcessRead(
            pid=p.pid,
            ppid=p.ppid,
            name=p.name,
            exe=p.exe,
            cmdline=p.cmdline,
            username=p.username,
            status=p.status,
            cpu_percent=p.cpu_percent,
            memory_rss=p.memory_rss,
            memory_vms=p.memory_vms,
            memory_percent=p.memory_percent,
            create_time=p.create_time,
            num_threads=p.num_threads,
            access_restricted=p.access_restricted,
            details=p.details,
        )
        for p in procs
    ]
    return ApiResponse(data=res)


@router.get("/network/connections", response_model=ApiResponse[list[SocketRead]])
def get_network_connections(
    limit: int = Query(500, ge=1, le=2000),
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[SocketRead]]:
    """Active socket connections with process ownership."""
    sockets = collector.get_network_sockets(limit=limit)
    res = [
        SocketRead(
            pid=s.pid,
            process_name=s.process_name,
            protocol=s.protocol,
            local_address=s.local_address,
            local_port=s.local_port,
            remote_address=s.remote_address,
            remote_port=s.remote_port,
            status=s.status,
            family=s.family,
            is_outbound=s.is_outbound,
            access_restricted=s.access_restricted,
        )
        for s in sockets
    ]
    return ApiResponse(data=res)


@router.get("/network/interfaces", response_model=ApiResponse[list[InterfaceRead]])
def get_network_interfaces(
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[InterfaceRead]]:
    """Network adapters and interface properties."""
    ifaces = collector.get_network_interfaces()
    res = [
        InterfaceRead(
            name=i.name,
            mac_address=i.mac_address,
            ipv4_addresses=i.ipv4_addresses,
            ipv6_addresses=i.ipv6_addresses,
            netmask=i.netmask,
            broadcast=i.broadcast,
            is_up=i.is_up,
            speed_mbps=i.speed_mbps,
            mtu=i.mtu,
        )
        for i in ifaces
    ]
    return ApiResponse(data=res)


@router.get("/network/devices", response_model=ApiResponse[list[NetworkDeviceRead]])
def get_network_devices(
    db: Session = Depends(get_db),
    include_sample: bool = Query(True),
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[NetworkDeviceRead]]:
    """Passive device inventory discovered from kernel ARP table."""
    # Synchronize current live ARP cache into DB
    live_devices = collector.get_arp_cache()
    now = datetime.now(UTC)

    for d in live_devices:
        existing = db.query(NetworkDeviceModel).filter(NetworkDeviceModel.ip_address == d.ip_address).first()
        if existing:
            existing.last_seen = now
            existing.mac_address = d.mac_address or existing.mac_address
            existing.interface_name = d.interface_name or existing.interface_name
            existing.vendor = d.vendor or existing.vendor
        else:
            new_dev = NetworkDeviceModel(
                id=str(uuid.uuid4()),
                ip_address=d.ip_address,
                mac_address=d.mac_address,
                hostname=None,
                vendor=d.vendor,
                interface_name=d.interface_name,
                is_gateway=d.is_gateway,
                first_seen=now,
                last_seen=now,
                active_connections_count=0,
                is_sample=False,
            )
            db.add(new_dev)
    db.commit()

    query = db.query(NetworkDeviceModel)
    if not include_sample:
        query = query.filter(NetworkDeviceModel.is_sample.is_(False))

    devices = query.order_by(NetworkDeviceModel.last_seen.desc()).all()
    return ApiResponse(data=[NetworkDeviceRead.model_validate(dev) for dev in devices])


@router.get("/persistence", response_model=ApiResponse[list[PersistenceRead]])
def get_persistence(
    collector: PlatformCollectorABC = Depends(get_collector),
) -> ApiResponse[list[PersistenceRead]]:
    """Read-only inspection of host startup and persistence mechanisms."""
    entries = collector.get_persistence_entries()
    res = [
        PersistenceRead(
            entry_id=e.entry_id,
            name=e.name,
            target_path=e.target_path,
            location_type=e.location_type,
            location_detail=e.location_detail,
            arguments=e.arguments,
            enabled=e.enabled,
            suspicious_indicators=e.suspicious_indicators,
        )
        for e in entries
    ]
    return ApiResponse(data=res)
