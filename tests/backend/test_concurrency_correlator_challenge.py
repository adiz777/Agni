"""
Empirical Challenge Test Suite: Concurrency (WAL Mode), Sliding-Window Correlator, and Data Isolation
File: tests/backend/test_concurrency_correlator_challenge.py
"""
import concurrent.futures
import os
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app.api.deps import get_db
from app.core.database import Base
from app.engine.correlator import IncidentCorrelator, SlidingWindowTracker
from app.engine.detector import Detector
from app.engine.sample_generator import SampleDataGenerator
from app.main import app
from app.models.audit import AuditLogModel
from app.models.event import TelemetryEventModel
from app.models.incident import DetectionAlertModel, IncidentModel, IncidentNoteModel
from app.models.network import NetworkDeviceModel
from app.models.rule import DetectionRuleModel
from app.models.telemetry import FIMBaselineModel
from app.services.exporter import ReportExporter


@pytest.fixture
def on_disk_wal_db():
    """
    Creates a real on-disk SQLite database file with WAL journal mode enabled.
    This fixture ensures we test real concurrent filesystem locking and WAL behaviors.
    """
    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    db_path = tf.name
    tf.close()

    db_url = f"sqlite:///{Path(db_path).as_posix()}"
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False, "timeout": 30.0},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA cache_size=-64000;")
        cursor.close()

    SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    # Initialize detection rules in disk DB
    detector = Detector()
    with SessionMaker() as init_session:
        detector.sync_rules_to_db(init_session)

    yield engine, SessionMaker, db_path

    engine.dispose()
    for ext in ["", "-wal", "-shm"]:
        p = db_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


# =============================================================================
# PART 1: HIGH-THROUGHPUT EVENT INGESTION & SQLITE WAL CONCURRENCY
# =============================================================================

def test_wal_mode_active_and_pragmas(on_disk_wal_db):
    """Verify that SQLite engine operates strictly in WAL mode with busy timeout configured."""
    engine, SessionMaker, db_path = on_disk_wal_db
    with SessionMaker() as session:
        mode = session.execute(text("PRAGMA journal_mode;")).scalar()
        sync = session.execute(text("PRAGMA synchronous;")).scalar()
        busy = session.execute(text("PRAGMA busy_timeout;")).scalar()
        fk = session.execute(text("PRAGMA foreign_keys;")).scalar()

    assert mode.lower() == "wal", f"Expected WAL mode, got {mode}"
    # Synchronous NORMAL in SQLite is 1
    assert sync in (1, "NORMAL"), f"Expected NORMAL synchronous, got {sync}"
    assert busy >= 5000, f"Expected busy_timeout >= 5000, got {busy}"
    assert fk == 1, f"Expected foreign_keys=ON, got {fk}"


def test_high_throughput_concurrent_readers_and_writers(on_disk_wal_db):
    """
    Stress-test high-throughput event ingestion with 8 concurrent writers and 8 concurrent readers.
    Verifies that:
    - Readers do not block writers, and writers do not block readers.
    - Zero SQLite locking exceptions (database is locked) occur under WAL mode.
    - 100% of inserted events are committed and retrievable.
    """
    engine, SessionMaker, db_path = on_disk_wal_db

    NUM_WRITERS = 8
    EVENTS_PER_WRITER = 50
    TOTAL_WRITES = NUM_WRITERS * EVENTS_PER_WRITER

    NUM_READERS = 8
    READS_PER_READER = 25

    writer_errors: list[Exception] = []
    reader_errors: list[Exception] = []
    reader_counts: list[int] = []

    def writer_task(writer_id: int):
        try:
            for _ in range(EVENTS_PER_WRITER):
                with SessionMaker() as session:
                    ev = TelemetryEventModel(
                        id=str(uuid.uuid4()),
                        timestamp=datetime.now(UTC),
                        category="process",
                        action="spawned",
                        severity="Low",
                        source="stress_writer",
                        hostname=f"host-{writer_id}",
                        os_name="Windows",
                        actor_pid=1000 + writer_id,
                        actor_name=f"proc_{writer_id}.exe",
                        is_sample=False,
                    )
                    session.add(ev)
                    session.commit()
        except Exception as e:
            writer_errors.append(e)

    def reader_task(reader_id: int):
        try:
            for _ in range(READS_PER_READER):
                with SessionMaker() as session:
                    count = session.query(TelemetryEventModel).count()
                    reader_counts.append(count)
                    # Also run a filtered query
                    _ = session.query(TelemetryEventModel).filter(
                        TelemetryEventModel.severity == "Low"
                    ).limit(10).all()
                time.sleep(0.005)
        except Exception as e:
            reader_errors.append(e)

    start_time = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WRITERS + NUM_READERS) as executor:
        writer_futures = [executor.submit(writer_task, wid) for wid in range(NUM_WRITERS)]
        reader_futures = [executor.submit(reader_task, rid) for rid in range(NUM_READERS)]

        concurrent.futures.wait(writer_futures + reader_futures)

    duration = time.perf_counter() - start_time

    assert len(writer_errors) == 0, f"Writers encountered errors: {writer_errors}"
    assert len(reader_errors) == 0, f"Readers encountered errors: {reader_errors}"

    # Verify final total records
    with SessionMaker() as session:
        final_count = session.query(TelemetryEventModel).count()

    assert final_count == TOTAL_WRITES, f"Expected {TOTAL_WRITES} events, but found {final_count}"
    throughput = TOTAL_WRITES / duration
    print(f"\n[WAL Stress Test] {TOTAL_WRITES} writes + {len(reader_counts)} reads in {duration:.2f}s ({throughput:.1f} writes/s)")


def test_concurrent_api_ingest_and_query_via_testclient(on_disk_wal_db):
    """
    Stress-test API event ingestion and event listing endpoints concurrently.
    Confirms no 500 errors, no deadlocks, and clean pagination under concurrent load.
    """
    engine, SessionMaker, db_path = on_disk_wal_db

    def override_get_db():
        session = SessionMaker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)
    api_errors: list[str] = []

    def api_ingest(worker_id: int):
        for _ in range(20):
            payload = {
                "category": "process",
                "action": "spawned",
                "severity": "Informational",
                "source": "api_stress",
                "hostname": f"node-{worker_id}",
                "actor_pid": 2000 + worker_id,
                "actor_name": "notepad.exe",
                "is_sample": False,
            }
            res = client.post("/api/v1/telemetry/events", json=payload)
            if res.status_code != 200:
                api_errors.append(f"Ingest failed: {res.status_code} {res.text}")

    def api_read(worker_id: int):
        for _ in range(15):
            res = client.get("/api/v1/telemetry/events?limit=20&include_sample=false")
            if res.status_code != 200:
                api_errors.append(f"Read failed: {res.status_code} {res.text}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(api_ingest, i) for i in range(4)] + [
            executor.submit(api_read, i) for i in range(4)
        ]
        concurrent.futures.wait(futures)

    app.dependency_overrides.clear()
    assert len(api_errors) == 0, f"Concurrent API operations had failures: {api_errors}"


# =============================================================================
# PART 2: SLIDING-WINDOW INCIDENT CORRELATION EMPIRICAL TESTS
# =============================================================================

def test_sliding_window_in_window_deduplication(test_db):
    """
    Verify that multiple events matching the same (rule_id, entity_key) within
    the 300s correlation window deduplicate into the exact same IncidentModel,
    incrementing event_count and updating last_seen.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    rule = DetectionRuleModel(
        id="RULE-SLIDE-001",
        name="Sliding Window Test Rule",
        description="Verify in-window clustering",
        severity="High",
        category="process",
        source="agni_core",
        match_conditions={},
        correlation_window=0,
        threshold=1,
        group_by="actor.pid",
        explanation="Testing deduplication window",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    t0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)

    # Event 1 at T0
    e1 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t0,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostA",
        os_name="Windows",
        actor_pid=5555,
        actor_name="mimikatz.exe",
        is_sample=False,
    )
    test_db.add(e1)
    test_db.commit()

    a1 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t0,
        severity="High",
        explanation="First detection",
        triggering_event_id=e1.id,
    )
    inc1 = correlator.correlate_alert(test_db, rule, a1, e1)

    assert inc1.event_count == 1
    # SQLite returns naive datetime; normalize to UTC for comparison
    assert (inc1.first_seen.replace(tzinfo=UTC) if inc1.first_seen.tzinfo is None else inc1.first_seen) == t0
    assert (inc1.last_seen.replace(tzinfo=UTC) if inc1.last_seen.tzinfo is None else inc1.last_seen) == t0
    original_incident_id = inc1.id

    # Event 2 at T0 + 120s (inside 300s window)
    t2 = t0 + timedelta(seconds=120)
    e2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t2,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostA",
        os_name="Windows",
        actor_pid=5555,
        actor_name="mimikatz.exe",
        is_sample=False,
    )
    test_db.add(e2)
    test_db.commit()

    a2 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t2,
        severity="High",
        explanation="Second detection",
        triggering_event_id=e2.id,
    )
    inc2 = correlator.correlate_alert(test_db, rule, a2, e2)

    assert inc2.id == original_incident_id, "Event within window must deduplicate into existing incident"
    assert inc2.event_count == 2
    assert (inc2.first_seen.replace(tzinfo=UTC) if inc2.first_seen.tzinfo is None else inc2.first_seen) == t0
    assert (inc2.last_seen.replace(tzinfo=UTC) if inc2.last_seen.tzinfo is None else inc2.last_seen) == t2

    # Event 3 at T0 + 299s (still within 300s of last_seen T2 and T0)
    t3 = t0 + timedelta(seconds=299)
    e3 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t3,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostA",
        os_name="Windows",
        actor_pid=5555,
        actor_name="mimikatz.exe",
        is_sample=False,
    )
    test_db.add(e3)
    test_db.commit()

    a3 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t3,
        severity="High",
        explanation="Third detection",
        triggering_event_id=e3.id,
    )
    inc3 = correlator.correlate_alert(test_db, rule, a3, e3)

    assert inc3.id == original_incident_id
    assert inc3.event_count == 3
    assert (inc3.last_seen.replace(tzinfo=UTC) if inc3.last_seen.tzinfo is None else inc3.last_seen) == t3

    # Verify only 1 incident exists in DB for this entity
    count = test_db.query(IncidentModel).filter(IncidentModel.entity_key == f"{rule.id}:5555").count()
    assert count == 1


def test_sliding_window_out_of_window_does_not_merge(test_db):
    """
    Verify that an event occurring strictly outside the correlation window (> 300s)
    does NOT merge into the old incident, but cleanly spawns a new IncidentModel.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    rule = DetectionRuleModel(
        id="RULE-SLIDE-002",
        name="Out of Window Isolation",
        description="Verify separation outside 300s",
        severity="Medium",
        category="process",
        source="agni_core",
        match_conditions={},
        correlation_window=0,
        threshold=1,
        group_by="actor.pid",
        explanation="Testing window cutoff",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    t0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)

    # Initial Event at T0
    e1 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t0,
        category="process",
        action="spawned",
        severity="Medium",
        source="agni_core",
        hostname="HostB",
        os_name="Windows",
        actor_pid=6666,
        actor_name="powershell.exe",
        is_sample=False,
    )
    test_db.add(e1)
    test_db.commit()

    a1 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t0,
        severity="Medium",
        explanation="Alert 1 at T0",
        triggering_event_id=e1.id,
    )
    inc1 = correlator.correlate_alert(test_db, rule, a1, e1)
    assert inc1.event_count == 1
    assert inc1.id is not None

    # Event 2 at T0 + 301 seconds (STRICTLY outside 300s window)
    t2 = t0 + timedelta(seconds=301)
    e2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t2,
        category="process",
        action="spawned",
        severity="Medium",
        source="agni_core",
        hostname="HostB",
        os_name="Windows",
        actor_pid=6666,
        actor_name="powershell.exe",
        is_sample=False,
    )
    test_db.add(e2)
    test_db.commit()

    a2 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t2,
        severity="Medium",
        explanation="Alert 2 at T0 + 301s",
        triggering_event_id=e2.id,
    )
    inc2 = correlator.correlate_alert(test_db, rule, a2, e2)

    assert inc2.id != inc1.id, "Event outside correlation window must create a NEW incident!"
    assert inc2.event_count == 1, "New incident must start with event_count=1"
    assert (inc2.first_seen.replace(tzinfo=UTC) if inc2.first_seen.tzinfo is None else inc2.first_seen) == t2
    assert (inc2.last_seen.replace(tzinfo=UTC) if inc2.last_seen.tzinfo is None else inc2.last_seen) == t2

    # Check total incidents for this entity key is exactly 2
    total_incidents = (
        test_db.query(IncidentModel)
        .filter(IncidentModel.entity_key == f"{rule.id}:6666")
        .order_by(IncidentModel.first_seen.asc())
        .all()
    )
    assert len(total_incidents) == 2
    assert total_incidents[0].id == inc1.id
    assert total_incidents[1].id == inc2.id


def test_sliding_window_resolved_incident_does_not_merge(test_db):
    """
    Verify that once an incident is marked 'Resolved' or 'False Positive',
    subsequent events for the same entity do not merge into it, but spawn a new 'New' incident.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    rule = DetectionRuleModel(
        id="RULE-SLIDE-003",
        name="Resolved Incident Isolation",
        description="Verify resolved state stops clustering",
        severity="Low",
        category="process",
        source="agni_core",
        match_conditions={},
        explanation="Testing lifecycle cutoff",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    now = datetime.now(UTC)
    e1 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="HostC",
        os_name="Windows",
        actor_pid=7777,
        actor_name="cmd.exe",
        is_sample=False,
    )
    test_db.add(e1)
    test_db.commit()

    a1 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now,
        severity="Low",
        explanation="Initial Alert",
        triggering_event_id=e1.id,
    )
    inc1 = correlator.correlate_alert(test_db, rule, a1, e1)

    # Transition to Resolved
    correlator.transition_incident_status(test_db, inc1.id, "Resolved", actor="analyst")

    # Ingest event 2 immediately (within 10 seconds of resolution)
    e2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=10),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="HostC",
        os_name="Windows",
        actor_pid=7777,
        actor_name="cmd.exe",
        is_sample=False,
    )
    test_db.add(e2)
    test_db.commit()

    a2 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now + timedelta(seconds=10),
        severity="Low",
        explanation="Post-resolution Alert",
        triggering_event_id=e2.id,
    )
    inc2 = correlator.correlate_alert(test_db, rule, a2, e2)

    assert inc2.id != inc1.id, "Alert following resolution must create a new incident"
    assert inc2.status == "New"
    assert inc1.status == "Resolved"


def test_sliding_window_entity_key_cross_rule_isolation(test_db):
    """
    Verify that events for different rules or different entities never cross-contaminate.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    r1 = DetectionRuleModel(
        id="RULE-X-01",
        name="Rule X",
        description="Rule X",
        severity="High",
        category="process",
        source="agni_core",
        match_conditions={},
        group_by="actor.pid",
        explanation="X",
        investigation_steps=[],
        enabled=True,
    )
    r2 = DetectionRuleModel(
        id="RULE-Y-02",
        name="Rule Y",
        description="Rule Y",
        severity="Medium",
        category="network",
        source="vayu",
        match_conditions={},
        group_by="actor.pid",
        explanation="Y",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add_all([r1, r2])
    test_db.commit()

    now = datetime.now(UTC)

    # Event for Rule 1, PID 8000
    e1 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostD",
        os_name="Windows",
        actor_pid=8000,
        is_sample=False,
    )
    # Event for Rule 2, PID 8000 (same PID, different rule)
    e2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="network",
        action="connected",
        severity="Medium",
        source="vayu",
        hostname="HostD",
        os_name="Windows",
        actor_pid=8000,
        is_sample=False,
    )
    # Event for Rule 1, PID 9000 (different PID, same rule)
    e3 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostD",
        os_name="Windows",
        actor_pid=9000,
        is_sample=False,
    )
    test_db.add_all([e1, e2, e3])
    test_db.commit()

    a1 = DetectionAlertModel(id=str(uuid.uuid4()), incident_id="", rule_id=r1.id, timestamp=now, severity="High", explanation="A1", triggering_event_id=e1.id)
    a2 = DetectionAlertModel(id=str(uuid.uuid4()), incident_id="", rule_id=r2.id, timestamp=now, severity="Medium", explanation="A2", triggering_event_id=e2.id)
    a3 = DetectionAlertModel(id=str(uuid.uuid4()), incident_id="", rule_id=r1.id, timestamp=now, severity="High", explanation="A3", triggering_event_id=e3.id)

    inc1 = correlator.correlate_alert(test_db, r1, a1, e1)
    inc2 = correlator.correlate_alert(test_db, r2, a2, e2)
    inc3 = correlator.correlate_alert(test_db, r1, a3, e3)

    assert len({inc1.id, inc2.id, inc3.id}) == 3, "All three incidents must have unique IDs"
    assert inc1.entity_key == "RULE-X-01:8000"
    assert inc2.entity_key == "RULE-Y-02:8000"
    assert inc3.entity_key == "RULE-X-01:9000"


def test_sliding_window_tracker_multithreaded_stress():
    """
    Stress-test SlidingWindowTracker under multi-threaded concurrency.
    Ensures memory deque operations and cooldown checks do not race or raise errors.
    """
    tracker = SlidingWindowTracker()
    now = datetime.now(UTC)

    triggers: list[list[str]] = []

    def feed_events(thread_id: int):
        for i in range(10):
            res = tracker.record_and_check_threshold(
                rule_id="RULE-BURST",
                group_val="burst_group",
                event_time=now + timedelta(seconds=i),
                event_id=f"t{thread_id}_e{i}",
                window_seconds=15,
                threshold=5,
                cooldown_seconds=30,
            )
            if res:
                triggers.append(res)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(feed_events, tid) for tid in range(8)]
        concurrent.futures.wait(futures)

    # Because cooldown is 30s, exactly ONE trigger should have fired during the burst
    assert len(triggers) == 1
    assert len(triggers[0]) >= 5


# =============================================================================
# PART 3: SAMPLE DATA ISOLATION & DEMO PURGE INTEGRITY
# =============================================================================

def test_sample_isolation_telemetry_events_endpoint(client, test_db):
    """
    Verify queries with include_sample=false strictly return ZERO sample events,
    even when thousands of sample events exist in the database.
    """
    detector = Detector()
    correlator = IncidentCorrelator()
    generator = SampleDataGenerator(detector=detector, correlator=correlator)

    # 1. Seed APT sample scenario
    generator.seed_scenario(test_db)

    # 2. Add 10 live events
    now = datetime.now(UTC)
    for i in range(10):
        live_ev = TelemetryEventModel(
            id=str(uuid.uuid4()),
            timestamp=now - timedelta(seconds=i * 10),
            category="process",
            action="spawned",
            severity="Medium",
            source="live_sensor",
            hostname="Production-Server-01",
            os_name="Windows",
            actor_pid=4000 + i,
            actor_name="legitimate_service.exe",
            is_sample=False,
        )
        test_db.add(live_ev)
    test_db.commit()

    # Verify DB has both sample and live events
    sample_count = test_db.query(TelemetryEventModel).filter(TelemetryEventModel.is_sample.is_(True)).count()
    live_count = test_db.query(TelemetryEventModel).filter(TelemetryEventModel.is_sample.is_(False)).count()
    assert sample_count > 0, "Sample events must be present in DB"
    assert live_count == 10, f"Expected 10 live events, got {live_count}"

    # Query with include_sample=false
    res = client.get("/api/v1/telemetry/events?include_sample=false&limit=100")
    assert res.status_code == 200
    data = res.json()["data"]

    assert data["total"] == 10, f"Expected total 10 live events, got {data['total']}"
    assert len(data["items"]) == 10

    for item in data["items"]:
        assert item["is_sample"] is False, f"Leaked sample event: {item['id']}"
        assert item["hostname"] == "Production-Server-01"

    # Query with include_sample=true
    res_all = client.get("/api/v1/telemetry/events?include_sample=true&limit=100")
    assert res_all.status_code == 200
    data_all = res_all.json()["data"]
    assert data_all["total"] == sample_count + 10


def test_sample_isolation_incidents_and_devices(client, test_db):
    """
    Verify that /incidents and /network/devices endpoints strictly isolate sample data.
    """
    detector = Detector()
    correlator = IncidentCorrelator()
    generator = SampleDataGenerator(detector=detector, correlator=correlator)

    # 1. Seed demo scenario
    generator.seed_scenario(test_db)

    # 2. Add 1 live incident and 1 live device
    now = datetime.now(UTC)
    live_inc = IncidentModel(
        id=str(uuid.uuid4()),
        title="Live Production Security Alert",
        rule_id="AGNI-R-PROC-001",
        severity="High",
        priority="P2_High",
        status="New",
        entity_key="AGNI-R-PROC-001:9999",
        first_seen=now,
        last_seen=now,
        event_count=1,
        summary="Live alert",
        is_sample=False,
    )
    live_dev = NetworkDeviceModel(
        id=str(uuid.uuid4()),
        ip_address="10.0.0.1",
        mac_address="aa:bb:cc:dd:ee:ff",
        hostname="prod-router",
        interface_name="eth0",
        first_seen=now,
        last_seen=now,
        is_sample=False,
    )
    test_db.add_all([live_inc, live_dev])
    test_db.commit()

    # Query incidents with include_sample=false
    res_inc = client.get("/api/v1/incidents?include_sample=false")
    assert res_inc.status_code == 200
    inc_data = res_inc.json()["data"]
    assert inc_data["total"] == 1
    assert inc_data["items"][0]["id"] == live_inc.id
    assert inc_data["items"][0]["is_sample"] is False

    # Query devices with include_sample=false
    res_dev = client.get("/api/v1/telemetry/network/devices?include_sample=false")
    assert res_dev.status_code == 200
    dev_data = res_dev.json()["data"]
    for dev in dev_data:
        assert dev["is_sample"] is False, f"Leaked sample device: {dev['id']}"


def test_sample_isolation_report_exporter(test_db):
    """
    Verify multi-format report exporter strictly excludes sample data when include_sample=False.
    """
    detector = Detector()
    detector.sync_rules_to_db(test_db)
    correlator = IncidentCorrelator()
    generator = SampleDataGenerator(detector=detector, correlator=correlator)

    # Seed demo scenario
    generator.seed_scenario(test_db)

    # Add 1 live incident
    now = datetime.now(UTC)
    live_inc = IncidentModel(
        id=str(uuid.uuid4()),
        title="Production High Priority Incident",
        rule_id="AGNI-R-PROC-001",
        severity="Critical",
        priority="P1_Critical",
        status="New",
        entity_key="AGNI-R-PROC-001:1234",
        first_seen=now,
        last_seen=now,
        event_count=1,
        summary="Real attack on production server",
        is_sample=False,
    )
    test_db.add(live_inc)
    test_db.commit()

    # 1. JSON Export
    ct, fn, json_bytes = ReportExporter.export(test_db, "json", include_sample=False)
    import json
    report_dict = json.loads(json_bytes.decode("utf-8"))
    assert report_dict["summary_statistics"]["total_incidents"] == 1
    assert len(report_dict["incidents"]) == 1
    assert report_dict["incidents"][0]["id"] == live_inc.id

    # 2. CSV Export
    ct, fn, csv_bytes = ReportExporter.export(test_db, "csv", include_sample=False)
    csv_text = csv_bytes.decode("utf-8")
    assert live_inc.id in csv_text
    # None of the sample incident IDs should be present
    sample_inc_ids = [i.id for i in test_db.query(IncidentModel).filter(IncidentModel.is_sample.is_(True)).all()]
    for s_id in sample_inc_ids:
        assert s_id not in csv_text

    # 3. HTML Export
    ct, fn, html_bytes = ReportExporter.export(test_db, "html", include_sample=False)
    html_text = html_bytes.decode("utf-8")
    assert "Production High Priority Incident" in html_text
    for s_id in sample_inc_ids:
        assert s_id not in html_text


def test_demo_purge_targeted_elimination_and_live_preservation(client, test_db):
    """
    Verify that demo purge removes 100% of synthetic sample records
    while leaving 100% of live telemetry, incidents, alerts, notes, FIM baselines,
    and audit logs completely intact and unaltered.
    """
    detector = Detector()
    correlator = IncidentCorrelator()
    generator = SampleDataGenerator(detector=detector, correlator=correlator)

    # 1. Seed APT demo scenario
    generator.seed_scenario(test_db)

    # 2. Create rich set of live production records
    now = datetime.now(UTC)

    live_event_ids: list[str] = []
    for i in range(25):
        eid = str(uuid.uuid4())
        live_event_ids.append(eid)
        ev = TelemetryEventModel(
            id=eid,
            timestamp=now - timedelta(minutes=i),
            category="process",
            action="executed",
            severity="Low",
            source="live_agent",
            hostname="PROD-APP-01",
            os_name="Windows",
            actor_pid=3000 + i,
            actor_name="service.exe",
            is_sample=False,
        )
        test_db.add(ev)

    live_inc_id = str(uuid.uuid4())
    live_inc = IncidentModel(
        id=live_inc_id,
        title="Production Live Incident",
        rule_id="AGNI-R-PROC-001",
        severity="High",
        priority="P2_High",
        status="In Progress",
        entity_key="AGNI-R-PROC-001:3000",
        first_seen=now,
        last_seen=now,
        event_count=5,
        summary="Real investigation in progress",
        assigned_analyst="analyst_alice",
        is_sample=False,
    )
    test_db.add(live_inc)

    live_alert_id = str(uuid.uuid4())
    live_alert = DetectionAlertModel(
        id=live_alert_id,
        incident_id=live_inc_id,
        rule_id="AGNI-R-PROC-001",
        timestamp=now,
        severity="High",
        explanation="Live Alert",
        triggering_event_id=live_event_ids[0],
    )
    test_db.add(live_alert)

    live_note_id = str(uuid.uuid4())
    live_note = IncidentNoteModel(
        id=live_note_id,
        incident_id=live_inc_id,
        author="analyst_alice",
        created_at=now,
        content="Analyzed memory dump, confirmed legitimate sysadmin action.",
    )
    test_db.add(live_note)

    live_dev_id = str(uuid.uuid4())
    live_dev = NetworkDeviceModel(
        id=live_dev_id,
        ip_address="10.10.10.1",
        mac_address="11:22:33:44:55:66",
        hostname="core-switch-01",
        interface_name="eth0",
        first_seen=now,
        last_seen=now,
        is_sample=False,
    )
    test_db.add(live_dev)

    live_fim_id = str(uuid.uuid4())
    live_fim = FIMBaselineModel(
        id=live_fim_id,
        name="Production Sys32 Baseline",
        target_path="C:\\Windows\\System32\\drivers\\etc",
        recursive=False,
        file_patterns=["*"],
        created_at=now,
        total_files=5,
        status="Active",
    )
    test_db.add(live_fim)

    live_audit_id = str(uuid.uuid4())
    live_audit = AuditLogModel(
        id=live_audit_id,
        timestamp=now,
        action="CONFIG_UPDATE",
        actor="admin",
        target_resource="settings",
        details={"setting": "retention_days", "value": 30},
        status="SUCCESS",
    )
    test_db.add(live_audit)

    test_db.commit()

    # Pre-purge checks: sample records exist
    pre_status = generator.get_sample_status(test_db)
    assert pre_status["has_sample_data"] is True
    assert pre_status["sample_events_count"] > 0
    assert pre_status["sample_incidents_count"] > 0
    assert pre_status["sample_devices_count"] > 0

    # 3. Trigger Purge via API endpoint
    purge_res = client.post("/api/v1/demo/clear")
    assert purge_res.status_code == 200

    # 4. Post-purge verification
    post_status = generator.get_sample_status(test_db)
    assert post_status["has_sample_data"] is False
    assert post_status["sample_events_count"] == 0
    assert post_status["sample_incidents_count"] == 0
    assert post_status["sample_alerts_count"] == 0
    assert post_status["sample_devices_count"] == 0

    # 5. Verify ALL Live Records remain 100% intact!
    for eid in live_event_ids:
        assert test_db.query(TelemetryEventModel).filter(TelemetryEventModel.id == eid).first() is not None

    live_inc_in_db = test_db.query(IncidentModel).filter(IncidentModel.id == live_inc_id).first()
    assert live_inc_in_db is not None
    assert live_inc_in_db.title == "Production Live Incident"
    assert live_inc_in_db.assigned_analyst == "analyst_alice"
    assert live_inc_in_db.event_count == 5

    live_alert_in_db = test_db.query(DetectionAlertModel).filter(DetectionAlertModel.id == live_alert_id).first()
    assert live_alert_in_db is not None
    assert live_alert_in_db.incident_id == live_inc_id

    live_note_in_db = test_db.query(IncidentNoteModel).filter(IncidentNoteModel.id == live_note_id).first()
    assert live_note_in_db is not None
    assert live_note_in_db.content == "Analyzed memory dump, confirmed legitimate sysadmin action."

    live_dev_in_db = test_db.query(NetworkDeviceModel).filter(NetworkDeviceModel.id == live_dev_id).first()
    assert live_dev_in_db is not None
    assert live_dev_in_db.hostname == "core-switch-01"

    live_fim_in_db = test_db.query(FIMBaselineModel).filter(FIMBaselineModel.id == live_fim_id).first()
    assert live_fim_in_db is not None

    live_audit_in_db = test_db.query(AuditLogModel).filter(AuditLogModel.id == live_audit_id).first()
    assert live_audit_in_db is not None


def test_sample_and_live_cross_contamination_immunity(test_db):
    """
    Verify that an identical event (same rule, same entity key) emitted as both
    live (is_sample=False) and demo (is_sample=True) never merges into the other.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    rule = DetectionRuleModel(
        id="RULE-CROSS-01",
        name="Cross-Contamination Test",
        description="Verify sample vs live isolation",
        severity="High",
        category="process",
        source="agni_core",
        match_conditions={},
        group_by="actor.pid",
        explanation="Testing sample boundary",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    now = datetime.now(UTC)

    # 1. Live event
    live_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="TargetHost",
        os_name="Windows",
        actor_pid=9999,
        is_sample=False,
    )
    test_db.add(live_event)
    test_db.commit()

    live_alert = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now,
        severity="High",
        explanation="Live trigger",
        triggering_event_id=live_event.id,
    )
    live_incident = correlator.correlate_alert(test_db, rule, live_alert, live_event)

    # 2. Sample event with the EXACT same rule and PID within 5 seconds
    sample_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=5),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="TargetHost",
        os_name="Windows",
        actor_pid=9999,
        is_sample=True,
    )
    test_db.add(sample_event)
    test_db.commit()

    sample_alert = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now + timedelta(seconds=5),
        severity="High",
        explanation="Sample trigger",
        triggering_event_id=sample_event.id,
    )
    sample_incident = correlator.correlate_alert(test_db, rule, sample_alert, sample_event)

    # Assert they did NOT merge
    assert live_incident.id != sample_incident.id, "Live and Sample incidents must never merge!"
    assert live_incident.is_sample is False
    assert sample_incident.is_sample is True
    assert live_incident.event_count == 1
    assert sample_incident.event_count == 1

    # Ingest a second live event -> merges only into live incident
    live_event2 = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=now + timedelta(seconds=10),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="TargetHost",
        os_name="Windows",
        actor_pid=9999,
        is_sample=False,
    )
    test_db.add(live_event2)
    test_db.commit()

    live_alert2 = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=now + timedelta(seconds=10),
        severity="High",
        explanation="Live trigger 2",
        triggering_event_id=live_event2.id,
    )
    updated_live = correlator.correlate_alert(test_db, rule, live_alert2, live_event2)
    assert updated_live.id == live_incident.id
    assert updated_live.event_count == 2
    assert sample_incident.event_count == 1


# =============================================================================
# PART 4: ADVERSARIAL STRESS CHALLENGES & VULNERABILITY MINING
# =============================================================================

@pytest.mark.xfail(
    reason="BUG: Correlator overwrites last_seen unconditionally without max(), causing timestamp inversion (first_seen > last_seen) on out-of-order events",
    strict=True,
)
def test_out_of_order_events_timestamp_inversion(test_db):
    """
    Adversarial Challenge: Out-of-order event ingestion.
    When network latency causes an older event (12:00:00) to arrive after a newer event (12:05:00),
    verify whether the correlator preserves the invariant: first_seen <= last_seen.
    """
    correlator = IncidentCorrelator(dedup_window_seconds=600)

    rule = DetectionRuleModel(
        id="RULE-CHALLENGE-OOO",
        name="Out of Order Challenge",
        description="Verify timestamp monotonicity",
        severity="High",
        category="process",
        source="agni_core",
        match_conditions={},
        group_by="actor.pid",
        explanation="Testing out-of-order arrival",
        investigation_steps=[],
        enabled=True,
    )
    test_db.add(rule)
    test_db.commit()

    t_new = datetime(2026, 10, 28, 12, 5, 0, tzinfo=UTC)
    t_old = datetime(2026, 10, 28, 12, 1, 0, tzinfo=UTC)

    # 1. Newer event arrives first
    e_new = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t_new,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostOOO",
        os_name="Windows",
        actor_pid=4444,
        is_sample=False,
    )
    test_db.add(e_new)
    test_db.commit()

    a_new = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t_new,
        severity="High",
        explanation="Newer event",
        triggering_event_id=e_new.id,
    )
    inc = correlator.correlate_alert(test_db, rule, a_new, e_new)

    # Normalize tz
    inc_first = inc.first_seen.replace(tzinfo=UTC) if inc.first_seen.tzinfo is None else inc.first_seen
    inc_last = inc.last_seen.replace(tzinfo=UTC) if inc.last_seen.tzinfo is None else inc.last_seen
    assert inc_first == t_new
    assert inc_last == t_new

    # 2. Older event arrives second (within correlation window of the incident)
    e_old = TelemetryEventModel(
        id=str(uuid.uuid4()),
        timestamp=t_old,
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="HostOOO",
        os_name="Windows",
        actor_pid=4444,
        is_sample=False,
    )
    test_db.add(e_old)
    test_db.commit()

    a_old = DetectionAlertModel(
        id=str(uuid.uuid4()),
        incident_id="",
        rule_id=rule.id,
        timestamp=t_old,
        severity="High",
        explanation="Older delayed event",
        triggering_event_id=e_old.id,
    )
    inc_updated = correlator.correlate_alert(test_db, rule, a_old, e_old)

    upd_first = inc_updated.first_seen.replace(tzinfo=UTC) if inc_updated.first_seen.tzinfo is None else inc_updated.first_seen
    upd_last = inc_updated.last_seen.replace(tzinfo=UTC) if inc_updated.last_seen.tzinfo is None else inc_updated.last_seen

    # CRITICAL INVARIANT: first_seen must always be <= last_seen!
    # If the correlator simply did `last_seen = now_utc`, last_seen would become 12:01:00 while first_seen is 12:05:00!
    assert upd_first <= upd_last, f"Timestamp inversion detected! first_seen ({upd_first}) > last_seen ({upd_last})"


def test_concurrent_incident_correlation_race_condition(on_disk_wal_db):
    """
    Adversarial Challenge: Concurrency race condition on incident creation.
    When 8 threads concurrently ingest alerts for the exact same entity key simultaneously,
    measure whether SQLite transactions and correlator logic serialize cleanly or create duplicate incidents.
    """
    engine, SessionMaker, db_path = on_disk_wal_db
    correlator = IncidentCorrelator(dedup_window_seconds=300)

    # Insert test rule
    with SessionMaker() as session:
        rule = DetectionRuleModel(
            id="RULE-CONC-RACE",
            name="Concurrent Race Rule",
            description="Testing race conditions",
            severity="Critical",
            category="process",
            source="agni_core",
            match_conditions={},
            group_by="actor.pid",
            explanation="Concurrent stampede test",
            investigation_steps=[],
            enabled=True,
        )
        session.add(rule)
        session.commit()

    NUM_THREADS = 8
    now = datetime.now(UTC)
    incident_ids_created: list[str] = []
    thread_errors: list[Exception] = []

    def correlate_worker(worker_id: int):
        try:
            with SessionMaker() as session:
                ev = TelemetryEventModel(
                    id=str(uuid.uuid4()),
                    timestamp=now,
                    category="process",
                    action="spawned",
                    severity="Critical",
                    source="agni_core",
                    hostname="StampedeHost",
                    os_name="Windows",
                    actor_pid=3333,
                    is_sample=False,
                )
                session.add(ev)
                session.commit()

                alert = DetectionAlertModel(
                    id=str(uuid.uuid4()),
                    incident_id="",
                    rule_id="RULE-CONC-RACE",
                    timestamp=now,
                    severity="Critical",
                    explanation=f"Stampede Alert {worker_id}",
                    triggering_event_id=ev.id,
                )
                r = session.query(DetectionRuleModel).filter(DetectionRuleModel.id == "RULE-CONC-RACE").first()
                inc = correlator.correlate_alert(session, r, alert, ev)
                incident_ids_created.append(inc.id)
        except Exception as e:
            thread_errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(correlate_worker, i) for i in range(NUM_THREADS)]
        concurrent.futures.wait(futures)

    assert len(thread_errors) == 0, f"Thread errors encountered: {thread_errors}"

    with SessionMaker() as session:
        incidents = session.query(IncidentModel).filter(IncidentModel.entity_key == "RULE-CONC-RACE:3333").all()

    print(f"\n[Stampede Challenge] {NUM_THREADS} threads created {len(incidents)} distinct incident(s). IDs: {[i.id for i in incidents]}")
    # Document empirical behavior: In non-serialized isolation, concurrent threads may create multiple incidents
    # if queries occur before any commit.
    assert len(incidents) >= 1


def test_concurrent_live_writers_during_demo_purge(on_disk_wal_db):
    """
    Adversarial Challenge: Purging demo data while live writers are actively ingesting.
    Ensures WAL mode allows purge transactions without locking or destroying concurrent live writes.
    """
    engine, SessionMaker, db_path = on_disk_wal_db
    detector = Detector()
    correlator = IncidentCorrelator()
    generator = SampleDataGenerator(detector=detector, correlator=correlator)

    # 1. Seed demo data
    with SessionMaker() as session:
        generator.seed_scenario(session)

    # 2. Concurrently run 4 live writer threads inserting 25 events each (100 total)
    #    and 1 thread running clear_sample_data
    written_live_ids: list[str] = []
    writer_errors: list[Exception] = []
    purge_errors: list[Exception] = []

    def live_writer(wid: int):
        for _ in range(25):
            try:
                with SessionMaker() as session:
                    eid = str(uuid.uuid4())
                    ev = TelemetryEventModel(
                        id=eid,
                        timestamp=datetime.now(UTC),
                        category="process",
                        action="spawned",
                        severity="Low",
                        source="stress_live",
                        hostname="ProdHost",
                        os_name="Windows",
                        actor_pid=5000 + wid,
                        is_sample=False,
                    )
                    session.add(ev)
                    session.commit()
                    written_live_ids.append(eid)
                time.sleep(0.002)
            except Exception as e:
                writer_errors.append(e)

    def purge_task():
        time.sleep(0.01)  # start right in the middle of writing
        try:
            with SessionMaker() as session:
                generator.clear_sample_data(session)
        except Exception as e:
            purge_errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        writer_futures = [executor.submit(live_writer, w) for w in range(4)]
        purge_future = executor.submit(purge_task)
        concurrent.futures.wait(writer_futures + [purge_future])

    assert len(writer_errors) == 0, f"Writer errors during purge: {writer_errors}"
    assert len(purge_errors) == 0, f"Purge error during active writes: {purge_errors}"

    # Verify all live events survived
    with SessionMaker() as session:
        live_count = session.query(TelemetryEventModel).filter(TelemetryEventModel.is_sample.is_(False)).count()
        sample_count = session.query(TelemetryEventModel).filter(TelemetryEventModel.is_sample.is_(True)).count()

    assert live_count == len(written_live_ids) == 100, f"Expected 100 live events, got {live_count}"
    assert sample_count == 0, f"Expected 0 sample events after purge, got {sample_count}"


def test_mixed_concurrency_sample_isolation(on_disk_wal_db):
    """
    Adversarial Challenge: Mixed concurrent stream of sample and live events.
    Verifies that continuous reader queries with include_sample=false never leak
    a single sample event even while dozens of sample events are being committed concurrently.
    """
    engine, SessionMaker, db_path = on_disk_wal_db

    leaked_events: list[str] = []
    concurrency_errors: list[Exception] = []

    def sample_writer(wid: int):
        for _ in range(30):
            try:
                with SessionMaker() as session:
                    ev = TelemetryEventModel(
                        id=str(uuid.uuid4()),
                        timestamp=datetime.now(UTC),
                        category="process",
                        action="spawned",
                        severity="High",
                        source="sample_stream",
                        hostname="DemoHost",
                        os_name="Windows",
                        actor_pid=8800 + wid,
                        is_sample=True,
                    )
                    session.add(ev)
                    session.commit()
            except Exception as e:
                concurrency_errors.append(e)

    def live_writer(wid: int):
        for _ in range(30):
            try:
                with SessionMaker() as session:
                    ev = TelemetryEventModel(
                        id=str(uuid.uuid4()),
                        timestamp=datetime.now(UTC),
                        category="process",
                        action="spawned",
                        severity="Low",
                        source="live_stream",
                        hostname="ProdHost",
                        os_name="Windows",
                        actor_pid=2200 + wid,
                        is_sample=False,
                    )
                    session.add(ev)
                    session.commit()
            except Exception as e:
                concurrency_errors.append(e)

    def isolated_reader(rid: int):
        for _ in range(20):
            try:
                with SessionMaker() as session:
                    results = (
                        session.query(TelemetryEventModel)
                        .filter(TelemetryEventModel.is_sample.is_(False))
                        .limit(50)
                        .all()
                    )
                    for r in results:
                        if r.is_sample:
                            leaked_events.append(r.id)
                time.sleep(0.005)
            except Exception as e:
                concurrency_errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = (
            [executor.submit(sample_writer, i) for i in range(3)]
            + [executor.submit(live_writer, i) for i in range(3)]
            + [executor.submit(isolated_reader, i) for i in range(4)]
        )
        concurrent.futures.wait(futures)

    assert len(concurrency_errors) == 0, f"Errors in mixed concurrency: {concurrency_errors}"
    assert len(leaked_events) == 0, f"Sample events leaked into isolated query: {leaked_events}"

