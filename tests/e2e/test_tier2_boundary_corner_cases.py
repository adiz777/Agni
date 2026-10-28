"""Tier 2: Boundary & Corner Cases (Adversarial, Resource Stress, & Edge Conditions).

Covers:
- Empty directory FIM baselines and zero-file change scans
- Nonexistent target paths for baseline registration
- Path traversal attack vectors (../../etc/passwd, null bytes, double slashes)
- Invalid severity levels in telemetry events and detection rules
- Malformed detection rule payloads (missing keys, invalid regex, illegal AST operators)
- FIM file size limits exceeding max_file_size_bytes threshold
- Rapid socket bursts and high-frequency event ingestion
"""

from __future__ import annotations

import os

from tests.e2e.harness.base import AgniE2ETestCase
from tests.e2e.harness.fixtures import (
    ADVERSARIAL_PATH_TRAVERSAL_VECTORS,
    INVALID_SEVERITY_LEVELS,
    MALFORMED_RULES,
    make_network_event,
    make_process_event,
)


class TestTier2BoundaryCornerCases(AgniE2ETestCase):
    """Boundary, input validation, and adversarial edge case verification."""

    def test_01_empty_directory_fim_baseline(self) -> None:
        """Creating and scanning a FIM baseline on an empty directory succeeds with zero files."""
        empty_dir = self.create_temp_directory()

        b_resp = self.client.create_fim_baseline(name="EmptyBaseline", target_path=empty_dir)
        self.assertTrue(b_resp.is_success, f"Failed to create empty baseline: {b_resp.text}")
        self.assertEqual(b_resp.data.get("total_files"), 0)

        # Scanning empty baseline returns zero changes detected
        scan_resp = self.client.scan_fim(baseline_id=b_resp.data.get("id"))
        self.assertTrue(scan_resp.is_success)
        self.assertEqual(scan_resp.data.get("changes_detected_count"), 0)

    def test_02_nonexistent_path_rejection(self) -> None:
        """Registering a nonexistent directory for FIM baseline returns HTTP 400."""
        nonexistent = os.path.join(self.create_temp_directory(), "does_not_exist_xyz123")
        b_resp = self.client.create_fim_baseline(name="BadPath", target_path=nonexistent)
        self.assertEqual(b_resp.status_code, 400, "Should reject nonexistent path with 400 Bad Request")
        self.assertIn("not exist", b_resp.text.lower())

    def test_03_path_traversal_attempts_prevented(self) -> None:
        """Path traversal patterns in FIM baseline registration are strictly rejected."""
        for traversal_vector in ADVERSARIAL_PATH_TRAVERSAL_VECTORS:
            with self.subTest(vector=traversal_vector):
                resp = self.client.create_fim_baseline(name="TraversalTest", target_path=traversal_vector)
                self.assertIn(
                    resp.status_code,
                    (400, 422),
                    f"Path traversal vector '{traversal_vector}' must be rejected with 400/422, got {resp.status_code}",
                )

    def test_04_invalid_severity_levels_rejected(self) -> None:
        """Ingesting events with invalid or unsupported severity levels returns HTTP 422."""
        for invalid_sev in INVALID_SEVERITY_LEVELS:
            with self.subTest(severity=invalid_sev):
                event = make_process_event("test.exe", "test.exe")
                event["severity"] = invalid_sev
                resp = self.client.ingest_event(event)
                self.assertEqual(
                    resp.status_code,
                    422,
                    f"Invalid severity '{invalid_sev}' should be rejected with HTTP 422, got {resp.status_code}",
                )

    def test_05_malformed_detection_rule_validation(self) -> None:
        """Registering malformed detection rules (missing keys, bad regex, illegal operators) returns HTTP 422."""
        for malformed in MALFORMED_RULES:
            with self.subTest(rule_id=malformed.get("id", "missing_id")):
                resp = self.client.create_rule(malformed)
                self.assertEqual(
                    resp.status_code,
                    422,
                    f"Malformed rule should be rejected with HTTP 422, got {resp.status_code}: {resp.text}",
                )

    def test_06_fim_large_file_size_boundary(self) -> None:
        """Files exceeding max_file_size_bytes are flagged rather than causing memory exhaustion."""
        temp_dir = self.create_temp_directory()
        large_file = os.path.join(temp_dir, "large_sample.iso")
        # Write 2MB file but configure baseline max_file_size_bytes=1048576 (1MB)
        with open(large_file, "wb") as f:
            f.write(b"X" * (2 * 1024 * 1024))

        b_resp = self.client.create_fim_baseline(
            name="SizeLimitBaseline",
            target_path=temp_dir,
            max_file_size_bytes=1048576,  # 1MB
        )
        self.assertTrue(b_resp.is_success, f"Failed baseline creation: {b_resp.text}")
        self.assertEqual(b_resp.data.get("total_files"), 1)

    def test_07_rapid_socket_burst_anomaly_handling(self) -> None:
        """Ingesting a rapid burst of socket connection events does not crash the correlation engine."""
        burst_pid = 9999
        for port in range(1000, 1025):  # 25 unique socket events in rapid succession
            ev = make_network_event(remote_ip="192.168.1.50", remote_port=port, pid=burst_pid, process_name="scanner.exe")
            resp = self.client.ingest_event(ev)
            self.assertTrue(resp.is_success, f"Event ingest failed during burst: {resp.text}")

        # Check that events were recorded and engine remained responsive
        events_resp = self.client.get_events(category="network")
        self.assertTrue(events_resp.is_success)
        network_events = [e for e in events_resp.data if e.get("actor", {}).get("pid") == burst_pid]
        self.assertEqual(len(network_events), 25)
