"""
API Integration Tests: End-to-End Verification across all 28 Endpoints
"""
import tempfile
from pathlib import Path


def test_root_and_v1_health(client):
    """Verify root health probe and v1 health endpoints."""
    # Root /health
    r_root = client.get("/health")
    assert r_root.status_code == 200
    assert r_root.json()["status"] == "ok"

    # API v1 /api/v1/health
    r_v1 = client.get("/api/v1/health")
    assert r_v1.status_code == 200
    data = r_v1.json()["data"]
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


def test_sensor_status_and_diagnostics(client):
    """Verify sensor status and deep diagnostics endpoints."""
    r_sensor = client.get("/api/v1/sensor/status")
    assert r_sensor.status_code == 200
    sensors = r_sensor.json()["data"]
    assert len(sensors) >= 4

    r_diag = client.get("/api/v1/diagnostics")
    assert r_diag.status_code == 200
    diag = r_diag.json()["data"]
    assert diag["database_status"] == "healthy"
    assert "process_inventory" in diag["capabilities"]


def test_telemetry_endpoints(client):
    """Verify telemetry overview, processes, sockets, interfaces, and persistence."""
    # Overview
    r_over = client.get("/api/v1/telemetry/overview")
    assert r_over.status_code == 200
    assert "threat_posture_score" in r_over.json()["data"]

    # Processes
    r_proc = client.get("/api/v1/telemetry/processes?limit=10")
    assert r_proc.status_code == 200
    assert isinstance(r_proc.json()["data"], list)

    # Connections
    r_conn = client.get("/api/v1/telemetry/network/connections?limit=10")
    assert r_conn.status_code == 200

    # Interfaces
    r_iface = client.get("/api/v1/telemetry/network/interfaces")
    assert r_iface.status_code == 200

    # Persistence
    r_pers = client.get("/api/v1/telemetry/persistence")
    assert r_pers.status_code == 200


def test_events_ingestion_and_query(client):
    """Verify ingesting a live event via API and retrieving it via paginated filter."""
    event_payload = {
        "category": "process",
        "action": "spawned",
        "severity": "High",
        "source": "agni_core",
        "actor_name": "cmd.exe",
        "actor_cmdline": "cmd.exe /c whoami",
        "actor_pid": 9999,
        "is_sample": False,
    }

    # Ingest event
    r_post = client.post("/api/v1/telemetry/events", json=event_payload)
    assert r_post.status_code == 200
    ingested = r_post.json()["data"]
    assert ingested["actor_name"] == "cmd.exe"

    # Query events
    r_get = client.get("/api/v1/telemetry/events?category=process&limit=10")
    assert r_get.status_code == 200
    paginated = r_get.json()["data"]
    assert paginated["total"] >= 1
    assert any(e["actor_name"] == "cmd.exe" for e in paginated["items"])


def test_fim_endpoints_lifecycle(client):
    """Verify FIM baseline creation, scanning, and changes query."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        test_file = p / "critical_config.ini"
        test_file.write_text("[section]\nkey=value\n")

        # Create baseline
        baseline_payload = {
            "name": "Test Baseline",
            "target_path": str(p),
            "recursive": False,
            "file_patterns": ["*.ini"],
        }
        r_create = client.post("/api/v1/fim/baseline", json=baseline_payload)
        assert r_create.status_code == 200
        b_data = r_create.json()["data"]
        baseline_id = b_data["id"]
        assert b_data["total_files"] == 1

        # Check status
        r_status = client.get("/api/v1/fim/status")
        assert r_status.status_code == 200
        assert r_status.json()["data"]["total_files_monitored"] >= 1

        # Modify file and trigger scan
        test_file.write_text("[section]\nkey=MODIFIED\n")
        r_scan = client.post("/api/v1/fim/scan", json={"baseline_id": baseline_id})
        assert r_scan.status_code == 200
        scan_results = r_scan.json()["data"]
        assert len(scan_results) == 1
        assert scan_results[0]["changes_detected"] == 1

        # Check changes list
        r_changes = client.get("/api/v1/fim/changes")
        assert r_changes.status_code == 200
        changes = r_changes.json()["data"]
        assert any(c["change_type"] == "MODIFIED" for c in changes)


def test_rules_endpoints(client):
    """Verify rule catalog listing, detail, toggle, and dry-run testing."""
    # List rules
    r_list = client.get("/api/v1/rules")
    assert r_list.status_code == 200
    rules = r_list.json()["data"]
    assert len(rules) >= 18

    # Get single rule
    r_one = client.get("/api/v1/rules/AGNI-R-PROC-001")
    assert r_one.status_code == 200
    assert r_one.json()["data"]["name"] == "Encoded PowerShell Command Execution"

    # Toggle rule
    r_toggle = client.patch("/api/v1/rules/AGNI-R-PROC-001/toggle", json={"enabled": False})
    assert r_toggle.status_code == 200
    assert r_toggle.json()["data"]["enabled"] is False

    # Dry-run test rule
    test_req = {
        "rule": {
            "id": "TEMP-01",
            "match_conditions": {"field": "actor.name", "operator": "equals", "value": "test.exe"},
        },
        "event": {"actor": {"name": "test.exe"}},
    }
    r_test = client.post("/api/v1/rules/test", json=test_req)
    assert r_test.status_code == 200
    assert r_test.json()["data"]["matched"] is True


def test_demo_and_incidents_lifecycle(client):
    """Verify demo data seeding, incident lifecycle update, and clearing."""
    # Seed demo scenario
    r_seed = client.post("/api/v1/demo/seed", json={"hostname": "DharmaCipher"})
    assert r_seed.status_code == 200
    seed_status = r_seed.json()["data"]
    assert seed_status["has_sample_data"] is True
    assert seed_status["sample_events_count"] > 0
    assert seed_status["sample_incidents_count"] > 0

    # Query incidents
    r_inc = client.get("/api/v1/incidents?include_sample=true")
    assert r_inc.status_code == 200
    incidents = r_inc.json()["data"]["items"]
    assert len(incidents) > 0

    incident_id = incidents[0]["id"]

    # Transition incident status
    r_patch = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "Triaged", "analyst_note": "Analyst verified malicious intent."},
    )
    assert r_patch.status_code == 200
    updated_inc = r_patch.json()["data"]
    assert updated_inc["status"] == "Triaged"
    assert len(updated_inc["notes"]) >= 1

    # Clear demo data
    r_clear = client.post("/api/v1/demo/clear")
    assert r_clear.status_code == 200

    r_status_after = client.get("/api/v1/demo/status")
    assert r_status_after.json()["data"]["has_sample_data"] is False


def test_reports_export_formats(client):
    """Verify generating JSON, CSV, and HTML reports."""
    # First seed demo data so report has content
    client.post("/api/v1/demo/seed")

    # JSON export
    r_json = client.post("/api/v1/reports/export", json={"format": "json", "include_sample": True})
    assert r_json.status_code == 200
    assert "application/json" in r_json.headers["content-type"]
    assert b"Agni" in r_json.content

    # CSV export
    r_csv = client.post("/api/v1/reports/export", json={"format": "csv", "include_sample": True})
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    assert b"Incident ID" in r_csv.content

    # HTML export
    r_html = client.post("/api/v1/reports/export", json={"format": "html", "include_sample": True})
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers["content-type"]
    assert b"<!DOCTYPE html>" in r_html.content
    assert b"<svg" in r_html.content  # Agni SVG Logo embedded


def test_settings_and_audit_endpoints(client):
    """Verify settings read/update and audit log query."""
    # Settings read
    r_set = client.get("/api/v1/settings")
    assert r_set.status_code == 200
    current_settings = r_set.json()["data"]
    assert "telemetry_interval_seconds" in current_settings

    # Settings update
    r_up = client.put("/api/v1/settings", json={"telemetry_interval_seconds": 10})
    assert r_up.status_code == 200
    assert r_up.json()["data"]["telemetry_interval_seconds"] == 10

    # Audit log read
    r_audit = client.get("/api/v1/audit/logs")
    assert r_audit.status_code == 200
    assert r_audit.json()["data"]["total"] > 0
