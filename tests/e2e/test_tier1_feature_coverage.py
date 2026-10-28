"""Tier 1: Feature Coverage (Representative Happy-Path Tests).

Covers:
- Sensor health, diagnostics, and overview
- Process inventory and process inspection
- SHA-256 FIM baseline and change detection
- Network interfaces and active connections
- Passive device inventory (ARP discovery)
- Startup & persistence visibility
- Detection rule catalog, test dry-run, and toggle
- Incident creation, grouping, and lifecycle transitions
- Multi-format report export (JSON, CSV, HTML)
- Sample / Demo mode seeding, isolation, and purge
- Settings management and immutable audit logging
"""

from __future__ import annotations

import json
import os

from tests.e2e.harness.base import AgniE2ETestCase
from tests.e2e.harness.fixtures import make_process_event


class TestTier1FeatureCoverage(AgniE2ETestCase):
    """Happy path verification for all 12 core Agni platform capabilities."""

    def test_01_health_and_diagnostics_endpoints(self) -> None:
        """Health, sensor status, and system diagnostics respond with valid metadata."""
        # 1. Health
        health_resp = self.client.get_health()
        self.assertTrue(health_resp.is_success, f"Health endpoint failed: {health_resp.text}")
        health_data = health_resp.data
        self.assertEqual(health_data.get("status"), "ok")
        self.assertIn("version", health_data)
        self.assertIn("platform", health_data)

        # 2. Sensor Status
        sensor_resp = self.client.get_sensor_status()
        self.assertTrue(sensor_resp.is_success, f"Sensor status failed: {sensor_resp.text}")
        sensor_data = sensor_resp.data
        self.assertEqual(sensor_data.get("status"), "healthy")
        self.assertIn("latency_ms", sensor_data)
        self.assertIn("cpu_percent", sensor_data)
        self.assertIn("memory_rss_mb", sensor_data)

        # 3. Diagnostics
        diag_resp = self.client.get_diagnostics()
        self.assertTrue(diag_resp.is_success, f"Diagnostics failed: {diag_resp.text}")
        diag_data = diag_resp.data
        self.assertIn("hostname", diag_data)
        self.assertIn("os", diag_data)
        self.assertEqual(diag_data.get("database_status"), "connected")

    def test_02_telemetry_overview(self) -> None:
        """Overview endpoint returns threat posture score and key metric counters."""
        overview_resp = self.client.get_overview()
        self.assertTrue(overview_resp.is_success, f"Overview failed: {overview_resp.text}")
        data = overview_resp.data
        self.assertIn("threat_score", data)
        self.assertIn("active_incidents_count", data)
        self.assertIn("events_24h_count", data)

    def test_03_process_inventory(self) -> None:
        """Process explorer lists running processes with execution metadata."""
        proc_resp = self.client.get_processes(limit=10)
        self.assertTrue(proc_resp.is_success, f"Processes list failed: {proc_resp.text}")
        procs = proc_resp.data
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0, "Process list should not be empty")

        p = procs[0]
        self.assertIn("pid", p)
        self.assertIn("name", p)
        self.assertIn("cpu_percent", p)
        self.assertIn("memory_rss_mb", p)

        # Query specific PID
        detail_resp = self.client.get_process(p["pid"])
        self.assertTrue(detail_resp.is_success, f"Process detail failed for PID {p['pid']}")
        self.assertEqual(detail_resp.data.get("pid"), p["pid"])

    def test_04_fim_baseline_and_change_detection(self) -> None:
        """FIM baseline creation, file hashing, and change detection (CREATED, MODIFIED, DELETED)."""
        temp_dir = self.create_temp_directory()
        f1_path = os.path.join(temp_dir, "app.conf")
        f2_path = os.path.join(temp_dir, "main.py")

        with open(f1_path, "w", encoding="utf-8") as f:
            f.write("DEBUG=False\nPORT=8080\n")
        with open(f2_path, "w", encoding="utf-8") as f:
            f.write("print('Hello Agni')\n")

        # 1. Create Baseline
        b_resp = self.client.create_fim_baseline(name="AppConfig", target_path=temp_dir, recursive=True)
        self.assertTrue(b_resp.is_success, f"FIM baseline create failed: {b_resp.text}")
        baseline_id = b_resp.data.get("id")
        self.assertIsNotNone(baseline_id)
        self.assertEqual(b_resp.data.get("total_files"), 2)

        # 2. Modify f1, Delete f2, Create f3
        with open(f1_path, "a", encoding="utf-8") as f:
            f.write("SECRET_KEY=evil_injected\n")
        os.remove(f2_path)
        f3_path = os.path.join(temp_dir, "evil_backdoor.py")
        with open(f3_path, "w", encoding="utf-8") as f:
            f.write("import socket; ...\n")

        # 3. Trigger FIM Scan
        scan_resp = self.client.scan_fim(baseline_id=baseline_id)
        self.assertTrue(scan_resp.is_success, f"FIM scan failed: {scan_resp.text}")
        changes_detected = scan_resp.data.get("changes_detected_count")
        self.assertEqual(changes_detected, 3, f"Expected 3 changes, got: {scan_resp.data}")

        # 4. Verify Changes List
        ch_resp = self.client.get_fim_changes(baseline_id=baseline_id)
        self.assertTrue(ch_resp.is_success, f"Get FIM changes failed: {ch_resp.text}")
        change_types = {c["change_type"] for c in ch_resp.data}
        self.assertIn("CREATED", change_types)
        self.assertIn("MODIFIED", change_types)
        self.assertIn("DELETED", change_types)

        # 5. Clean up Baseline
        del_resp = self.client.delete_fim_baseline(baseline_id)
        self.assertTrue(del_resp.is_success, f"Delete baseline failed: {del_resp.text}")

    def test_05_network_interfaces_and_connections(self) -> None:
        """Network interface enumeration and active socket inspection."""
        if_resp = self.client.get_network_interfaces()
        self.assertTrue(if_resp.is_success, f"Network interfaces failed: {if_resp.text}")
        interfaces = if_resp.data
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)
        self.assertIn("ip_address", interfaces[0])
        self.assertIn("status", interfaces[0])

        conn_resp = self.client.get_network_connections()
        self.assertTrue(conn_resp.is_success, f"Network connections failed: {conn_resp.text}")
        sockets = conn_resp.data
        self.assertIsInstance(sockets, list)
        if sockets:
            s = sockets[0]
            self.assertIn("protocol", s)
            self.assertIn("local_port", s)
            self.assertIn("status", s)

    def test_06_passive_network_devices(self) -> None:
        """Network device inventory returns discovered ARP neighbor entries."""
        dev_resp = self.client.get_network_devices()
        self.assertTrue(dev_resp.is_success, f"Network devices failed: {dev_resp.text}")
        devices = dev_resp.data
        self.assertIsInstance(devices, list)
        if devices:
            d = devices[0]
            self.assertIn("ip_address", d)
            self.assertIn("mac_address", d)
            self.assertIn("first_seen", d)
            self.assertIn("last_seen", d)

    def test_07_startup_persistence_visibility(self) -> None:
        """Persistence inspection enumerates startup entries without modifying system state."""
        pers_resp = self.client.get_persistence_entries()
        self.assertTrue(pers_resp.is_success, f"Persistence query failed: {pers_resp.text}")
        entries = pers_resp.data
        self.assertIsInstance(entries, list)
        if entries:
            e = entries[0]
            self.assertIn("name", e)
            self.assertIn("category", e)
            self.assertIn("command", e)

        scan_resp = self.client.scan_persistence()
        self.assertTrue(scan_resp.is_success, f"Persistence scan failed: {scan_resp.text}")

    def test_08_detection_rules_catalog_and_test(self) -> None:
        """Detection rule catalog inspection, test dry-run, and toggle controls."""
        rules_resp = self.client.get_rules()
        self.assertTrue(rules_resp.is_success, f"Rules catalog failed: {rules_resp.text}")
        rules = rules_resp.data
        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 18, f"Expected 18 default rules, found {len(rules)}")

        rule_id = "AGNI-R-PROC-001"
        single_rule_resp = self.client.get_rule(rule_id)
        self.assertTrue(single_rule_resp.is_success, f"Get rule {rule_id} failed")
        rule = single_rule_resp.data
        self.assertEqual(rule.get("id"), rule_id)
        self.assertEqual(rule.get("severity"), "High")
        self.assertIn("match_conditions", rule)

        # Test dry-run rule against a matching event
        test_ev = make_process_event("powershell.exe", "powershell.exe -NoP -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
        test_resp = self.client.test_rule(rule, test_ev)
        self.assertTrue(test_resp.is_success, f"Rule dry-run failed: {test_resp.text}")
        self.assertTrue(test_resp.data.get("matched"), "Rule should match encoded powershell event")

        # Toggle rule state
        toggle_resp = self.client.toggle_rule(rule_id, enabled=False)
        self.assertTrue(toggle_resp.is_success, f"Toggle rule failed: {toggle_resp.text}")
        self.assertFalse(toggle_resp.data.get("enabled"), "Rule should now be disabled")

        # Restore rule state
        self.client.toggle_rule(rule_id, enabled=True)

    def test_09_incident_creation_and_lifecycle(self) -> None:
        """Rule triggering automatically creates an incident with full lifecycle state management."""
        event_payload = make_process_event(
            name="powershell.exe",
            cmdline="powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            pid=3344,
        )
        ingest_resp = self.client.ingest_event(event_payload)
        self.assertTrue(ingest_resp.is_success, f"Event ingestion failed: {ingest_resp.text}")
        self.assertGreater(ingest_resp.data.get("triggered_incidents_count"), 0)

        # Verify Incident was created
        inc_resp = self.client.get_incidents()
        self.assertTrue(inc_resp.is_success, f"Get incidents failed: {inc_resp.text}")
        incidents = inc_resp.data
        self.assertGreater(len(incidents), 0)

        target_inc = next((i for i in incidents if i["rule_id"] == "AGNI-R-PROC-001"), None)
        self.assertIsNotNone(target_inc, "Incident for AGNI-R-PROC-001 should exist")
        inc_id = target_inc["id"]
        self.assertEqual(target_inc["severity"], "High")
        self.assertEqual(target_inc["priority"], "P2_High")
        self.assertEqual(target_inc["status"], "New")

        # Lifecycle transition: New -> Triaged
        trans_resp = self.client.update_incident_status(inc_id, status="Triaged", note="Confirmed suspicious script")
        self.assertTrue(trans_resp.is_success, f"Status update failed: {trans_resp.text}")
        self.assertEqual(trans_resp.data.get("status"), "Triaged")

        # Append analyst note
        note_resp = self.client.add_incident_note(inc_id, content="Extracted C2 beacon string from decoded payload")
        self.assertTrue(note_resp.is_success, f"Add note failed: {note_resp.text}")
        self.assertIn("id", note_resp.data)

        # Inspect Incident Detail
        detail_resp = self.client.get_incident(inc_id)
        self.assertTrue(detail_resp.is_success)
        self.assertEqual(len(detail_resp.data.get("notes", [])), 2)  # status change note + analyst note

    def test_10_multiformat_report_export(self) -> None:
        """Report generation produces valid JSON, CSV, and HTML formats."""
        # 1. JSON Export
        json_resp = self.client.export_report(export_format="json", date_range="24h")
        self.assertTrue(json_resp.is_success, f"JSON export failed: {json_resp.text}")
        self.assertIn("application/json", json_resp.headers.get("Content-Type", ""))
        parsed_json = json.loads(json_resp.text)
        self.assertIn("incidents", parsed_json)

        # 2. CSV Export
        csv_resp = self.client.export_report(export_format="csv", date_range="24h")
        self.assertTrue(csv_resp.is_success, f"CSV export failed: {csv_resp.text}")
        self.assertIn("text/csv", csv_resp.headers.get("Content-Type", ""))
        lines = csv_resp.text.strip().splitlines()
        self.assertGreater(len(lines), 0)
        self.assertIn("Incident ID", lines[0])
        self.assertIn("Severity", lines[0])

        # 3. HTML Export
        html_resp = self.client.export_report(export_format="html", date_range="24h")
        self.assertTrue(html_resp.is_success, f"HTML export failed: {html_resp.text}")
        self.assertIn("text/html", html_resp.headers.get("Content-Type", ""))
        self.assertIn("<!DOCTYPE html>", html_resp.text)
        self.assertIn("Agni", html_resp.text)

    def test_11_sample_demo_mode_lifecycle(self) -> None:
        """Demo mode seeds synthetic multi-stage attack and isolates it from live queries."""
        # 1. Seed Demo Data
        seed_resp = self.client.seed_demo_data()
        self.assertTrue(seed_resp.is_success, f"Seed demo failed: {seed_resp.text}")
        self.assertGreater(seed_resp.data.get("events_count"), 0)

        # 2. Verify Demo Status
        status_resp = self.client.get_demo_status()
        self.assertTrue(status_resp.is_success)
        self.assertTrue(status_resp.data.get("has_sample_data"))

        # 3. Query Live Events (include_sample=false) vs All (include_sample=true)
        live_resp = self.client.get_events(include_sample=False)
        self.assertTrue(live_resp.is_success)
        for ev in live_resp.data:
            self.assertFalse(ev.get("is_sample", False), "Live query should NOT contain sample events")

        all_resp = self.client.get_events(include_sample=True)
        self.assertTrue(all_resp.is_success)
        sample_count = sum(1 for e in all_resp.data if e.get("is_sample", False))
        self.assertGreater(sample_count, 0, "All events query should contain sample events")

        # 4. Clear Demo Data
        clear_resp = self.client.clear_demo_data()
        self.assertTrue(clear_resp.is_success, f"Clear demo failed: {clear_resp.text}")

        # 5. Verify Clean Status
        clean_status = self.client.get_demo_status()
        self.assertFalse(clean_status.data.get("has_sample_data"))

    def test_12_settings_and_audit_logging(self) -> None:
        """Settings mutations are validated and recorded in immutable audit logs."""
        # 1. Get Settings
        curr_settings = self.client.get_settings()
        self.assertTrue(curr_settings.is_success)
        orig_poll = curr_settings.data.get("polling_interval_sec")

        # 2. Update Settings
        new_poll = 15
        upd_resp = self.client.update_settings({"polling_interval_sec": new_poll})
        self.assertTrue(upd_resp.is_success, f"Update settings failed: {upd_resp.text}")
        self.assertEqual(upd_resp.data.get("polling_interval_sec"), new_poll)

        # 3. Verify in Audit Logs
        audit_resp = self.client.get_audit_logs(limit=10)
        self.assertTrue(audit_resp.is_success, f"Audit logs failed: {audit_resp.text}")
        logs = audit_resp.data
        self.assertGreater(len(logs), 0)

        settings_audit = next((entry for entry in logs if entry.get("action") == "SETTINGS_UPDATE"), None)
        self.assertIsNotNone(settings_audit, "Audit trail must record SETTINGS_UPDATE action")
        self.assertEqual(settings_audit.get("actor"), "local_analyst")
        self.assertEqual(settings_audit.get("status"), "SUCCESS")

        # Restore settings
        self.client.update_settings({"polling_interval_sec": orig_poll})
