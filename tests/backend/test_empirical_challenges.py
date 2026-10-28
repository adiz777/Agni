"""
Empirical Challenge Test Suite for Agni Milestone 1
Target: Varuna Detection Engine (AST Condition Evaluator, Correlator) & File Integrity Monitor (FIM)

Verifies:
1. Complex AST Rules (nested boolean and/or/not trees, regex edge cases, case sensitivity, missing keys).
2. FIM Edge Cases (zero-byte files, binary streams, path traversal attempts, modification without size change).
3. Epistemic Integrity (telemetry event immutability vs suspected incident interpretations).
4. Concurrency & High Load evaluation.
"""
from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.engine.correlator import IncidentCorrelator, SlidingWindowTracker
from app.engine.detector import Detector
from app.engine.rules import (
    evaluate_condition,
    extract_field,
    validate_condition_ast,
)
from app.models.event import TelemetryEventModel
from app.models.incident import IncidentModel
from app.models.rule import DetectionRuleModel
from app.services.fim import (
    FIMPathSecurityError,
    FIMService,
    compute_streaming_sha256,
    sanitize_watch_path,
)

# =============================================================================
# 1. Complex AST Rule Evaluation & Boundary Handling
# =============================================================================

class TestASTComplexRulesAndBoundaries:
    """Empirical challenge suite for AST rule evaluation."""

    def test_deeply_nested_boolean_tree(self):
        """Stress-test 5-level deep nested boolean AST with mixed and/or/not branches."""
        ast_rule = {
            "and": [
                {
                    "or": [
                        {"field": "actor.name", "operator": "equals", "value": "powershell.exe"},
                        {"field": "actor.name", "operator": "equals", "value": "pwsh.exe"},
                    ]
                },
                {
                    "not": {
                        "or": [
                            {"field": "actor.user", "operator": "equals", "value": "system"},
                            {"field": "details.is_whitelisted", "operator": "equals", "value": True},
                        ]
                    }
                },
                {
                    "or": [
                        {
                            "and": [
                                {"field": "details.remote_port", "operator": "gte", "value": 1024},
                                {"field": "details.remote_port", "operator": "lte", "value": 65535},
                            ]
                        },
                        {"field": "details.remote_port", "operator": "in", "value": [80, 443, 8080]},
                    ]
                },
                {
                    "field": "actor.cmdline",
                    "operator": "regex",
                    "value": r"(?i)-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]+",
                },
            ]
        }

        # Validate syntax passes AST validator
        is_valid, err = validate_condition_ast(ast_rule)
        assert is_valid, f"Rule AST must be valid: {err}"

        # Scenario A: Matching event with case variation, port in range, non-whitelisted user
        event_match = {
            "actor": {
                "name": "PowerShell.EXE",
                "user": "DOMAIN\\analyst",
                "cmdline": "powershell.exe -EncodedCommand SQBFAFgAIAA...",
            },
            "details": {
                "remote_port": 4444,
                "is_whitelisted": False,
            },
        }
        assert evaluate_condition(ast_rule, event_match) is True

        # Scenario B: Counter-example - user is "system" (trips the NOT clause)
        event_system_user = copy.deepcopy(event_match)
        event_system_user["actor"]["user"] = "SYSTEM"
        assert evaluate_condition(ast_rule, event_system_user) is False

        # Scenario C: Counter-example - whitelisted flag True (trips the NOT clause)
        event_whitelisted = copy.deepcopy(event_match)
        event_whitelisted["details"]["is_whitelisted"] = True
        assert evaluate_condition(ast_rule, event_whitelisted) is False

        # Scenario D: Counter-example - port outside valid ranges (e.g. port 22)
        event_bad_port = copy.deepcopy(event_match)
        event_bad_port["details"]["remote_port"] = 22
        assert evaluate_condition(ast_rule, event_bad_port) is False

        # Scenario E: Alternative port in [80, 443, 8080] should pass even if < 1024
        event_port_80 = copy.deepcopy(event_match)
        event_port_80["details"]["remote_port"] = 80
        assert evaluate_condition(ast_rule, event_port_80) is True

    def test_ast_missing_and_malformed_telemetry_keys(self):
        """Verify graceful degradation when encountering null, missing, or malformed telemetry structures."""
        # Condition targeting deep dot-notation keys
        cond = {
            "and": [
                {"field": "actor.nested.missing.deep.key", "operator": "equals", "value": "test"},
                {"field": "details.nonexistent", "operator": "gt", "value": 10},
            ]
        }

        # 1. Empty dict
        assert evaluate_condition(cond, {}) is False

        # 2. Event is None
        assert evaluate_condition(cond, None) is False

        # 3. Intermediary keys are None
        event_null_nested = {"actor": None, "details": None}
        assert evaluate_condition(cond, event_null_nested) is False

        # 4. Intermediary keys are wrong types (scalar instead of dict)
        event_scalar_type = {"actor": 12345, "details": "not-a-dict"}
        assert evaluate_condition(cond, event_scalar_type) is False

        # 5. Intermediary keys are lists instead of dicts
        event_list_type = {"actor": [1, 2, 3], "details": []}
        assert evaluate_condition(cond, event_list_type) is False

        # 6. Extract field on None / empty
        assert extract_field({}, "") is None
        assert extract_field(None, "actor.name") is None
        assert extract_field({}, "actor.name") is None
        assert extract_field({"actor": {"name": None}}, "actor.name") is None

    def test_ast_regex_edge_cases_and_case_sensitivity(self):
        """Stress-test regex matching, invalid regex handling, and case sensitivity distinction."""
        # 1. Invalid regex patterns must not raise unhandled exceptions
        invalid_regexes = [
            r"[unclosed_bracket",
            r"(?P<incomplete",
            r"*starts_with_quantifier",
            "trailing_escape\\",  # Single trailing backslash in raw regex string
            r"((((nested_unclosed",
        ]
        for pat in invalid_regexes:
            cond = {"field": "actor.cmdline", "operator": "regex", "value": pat}
            # Validator must detect invalid regex
            ok, err = validate_condition_ast(cond)
            assert ok is False
            assert "Invalid regex pattern" in str(err)
            # Evaluator must return False safely without unhandled exception
            assert evaluate_condition(cond, {"actor": {"cmdline": "test command"}}) is False

        # 2. Case sensitivity: 'regex' vs 'iregex'
        exact_regex_cond = {"field": "target.identifier", "operator": "regex", "value": r"^C:\\Windows\\System32\\.*\.exe$"}
        iregex_cond = {"field": "target.identifier", "operator": "iregex", "value": r"^c:\\windows\\system32\\.*\.exe$"}

        # Mixed-case event
        target_path = r"C:\Windows\System32\svchost.exe"
        lower_path = r"c:\windows\system32\svchost.exe"

        assert evaluate_condition(exact_regex_cond, {"target": {"identifier": target_path}}) is True
        # Exact regex requires matching case of 'C:\Windows\System32'
        assert evaluate_condition(exact_regex_cond, {"target": {"identifier": lower_path}}) is False
        # iregex matches regardless of case
        assert evaluate_condition(iregex_cond, {"target": {"identifier": target_path}}) is True
        assert evaluate_condition(iregex_cond, {"target": {"identifier": lower_path}}) is True

        # 3. Regex on non-string values
        cond_on_int = {"field": "details.port", "operator": "regex", "value": r"^\d{4}$"}
        assert evaluate_condition(cond_on_int, {"details": {"port": 8080}}) is True
        assert evaluate_condition(cond_on_int, {"details": {"port": 80}}) is False
        assert evaluate_condition(cond_on_int, {"details": {"port": None}}) is False

    def test_ast_numeric_and_null_operators(self):
        """Test numeric comparisons with type mismatches, float precision, and null checks."""
        # Numeric operators
        gt_cond = {"field": "details.cpu_percent", "operator": "gt", "value": 85.5}
        lte_cond = {"field": "details.count", "operator": "lte", "value": 0}

        # Valid numbers
        assert evaluate_condition(gt_cond, {"details": {"cpu_percent": 90.0}}) is True
        assert evaluate_condition(gt_cond, {"details": {"cpu_percent": 85.5}}) is False
        assert evaluate_condition(lte_cond, {"details": {"count": 0}}) is True
        assert evaluate_condition(lte_cond, {"details": {"count": -5}}) is True
        assert evaluate_condition(lte_cond, {"details": {"count": 1}}) is False

        # Numeric comparison with string numbers (should convert and compare)
        assert evaluate_condition(gt_cond, {"details": {"cpu_percent": "92.3"}}) is True

        # Numeric comparison with unparseable strings or None
        assert evaluate_condition(gt_cond, {"details": {"cpu_percent": "invalid_number"}}) is False
        assert evaluate_condition(gt_cond, {"details": {"cpu_percent": None}}) is False

        # Null / Not-Null / Exists operators
        is_null_cond = {"field": "actor.pid", "operator": "is_null", "value": None}
        not_null_cond = {"field": "actor.pid", "operator": "not_null", "value": None}
        exists_cond = {"field": "actor.pid", "operator": "exists", "value": None}

        assert evaluate_condition(is_null_cond, {"actor": {"pid": None}}) is True
        assert evaluate_condition(is_null_cond, {"actor": {"name": "test"}}) is True
        assert evaluate_condition(is_null_cond, {"actor": {"pid": 1234}}) is False

        assert evaluate_condition(not_null_cond, {"actor": {"pid": 1234}}) is True
        assert evaluate_condition(not_null_cond, {"actor": {"pid": None}}) is False

        assert evaluate_condition(exists_cond, {"actor": {"pid": 1234}}) is True
        assert evaluate_condition(exists_cond, {"actor": {"pid": None}}) is False


# =============================================================================
# 2. File Integrity Monitoring (FIM) Edge Cases
# =============================================================================

class TestFIMEdgeCasesAndBoundaries:
    """Empirical challenge suite for FIM service."""

    def test_fim_zero_byte_file_lifecycle(self):
        """Verify baseline creation, hashing, and diffing for zero-byte empty files."""
        fim = FIMService()
        EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            empty_file = root / "empty.cfg"
            empty_file.touch()

            # 1. Verify compute_streaming_sha256 on empty file returns standard empty hash
            sha, err = compute_streaming_sha256(empty_file)
            assert err is None
            assert sha == EMPTY_SHA256

            # 2. Scan path and establish baseline
            records = fim.scan_path(td)
            assert len(records) == 1
            assert records[0].file_size_bytes == 0
            assert records[0].sha256_hash == EMPTY_SHA256

            baseline = {
                records[0].file_path: {
                    "sha256_hash": records[0].sha256_hash,
                    "file_size_bytes": records[0].file_size_bytes,
                    "mtime": records[0].mtime,
                }
            }

            # 3. Transition: Modify empty file to contain 16 bytes
            empty_file.write_bytes(b"A" * 16)
            current_records = fim.scan_path(td)
            assert len(current_records) == 1
            assert current_records[0].file_size_bytes == 16
            assert current_records[0].sha256_hash != EMPTY_SHA256

            changes, events = fim.diff_baseline(baseline, current_records)
            assert len(changes) == 1
            assert changes[0]["change_type"] == "MODIFIED"
            assert changes[0]["previous_size"] == 0
            assert changes[0]["current_size"] == 16
            assert changes[0]["previous_sha256"] == EMPTY_SHA256

            # 4. Transition: Truncate file back to 0 bytes
            new_baseline = {
                current_records[0].file_path: {
                    "sha256_hash": current_records[0].sha256_hash,
                    "file_size_bytes": current_records[0].file_size_bytes,
                    "mtime": current_records[0].mtime,
                }
            }
            empty_file.write_bytes(b"")
            truncated_records = fim.scan_path(td)
            assert truncated_records[0].file_size_bytes == 0
            assert truncated_records[0].sha256_hash == EMPTY_SHA256

            changes2, events2 = fim.diff_baseline(new_baseline, truncated_records)
            assert len(changes2) == 1
            assert changes2[0]["change_type"] == "MODIFIED"
            assert changes2[0]["previous_size"] == 16
            assert changes2[0]["current_size"] == 0
            assert changes2[0]["current_sha256"] == EMPTY_SHA256

    def test_fim_binary_files_and_chunk_boundaries(self):
        """Stress-test streaming SHA-256 against exact 64KB chunk boundaries and binary data."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # Test payload sizes: 64KB-1, exact 64KB, 64KB+1, and 256KB binary with null bytes
            sizes = [
                64 * 1024 - 1,   # 65,535 bytes
                64 * 1024,       # 65,536 bytes (exact buffer boundary)
                64 * 1024 + 1,   # 65,537 bytes
                256 * 1024 + 42, # ~256KB
            ]

            for idx, size in enumerate(sizes):
                # Generate binary pattern with null bytes and non-ASCII characters
                binary_content = bytes((i % 256) for i in range(size))
                file_path = root / f"boundary_{idx}.bin"
                file_path.write_bytes(binary_content)

                expected_hash = hashlib.sha256(binary_content).hexdigest()
                computed_hash, err = compute_streaming_sha256(file_path)

                assert err is None, f"Hash calculation failed for size {size}: {err}"
                assert computed_hash == expected_hash, f"Hash mismatch for binary size {size} across chunk boundary"

    def test_fim_modification_without_size_change(self):
        """
        Attacker scenario: Modifying content without changing file size.
        E.g. flipping bytes in a payload or configuration file.
        Must report MODIFIED based on SHA-256 mismatch even when sizes are identical.
        """
        fim = FIMService()

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg_file = root / "service.conf"
            # Initial content: 64 bytes
            initial_content = b"PORT=8080\nHOST=127.0.0.1\nDEBUG=0\nSECRET_KEY=ABCDEF1234567890\nPADDING=123"
            cfg_file.write_bytes(initial_content)
            initial_size = len(initial_content)

            # Establish initial baseline
            records_init = fim.scan_path(td)
            assert len(records_init) == 1
            baseline = {
                records_init[0].file_path: {
                    "sha256_hash": records_init[0].sha256_hash,
                    "file_size_bytes": records_init[0].file_size_bytes,
                    "mtime": records_init[0].mtime,
                }
            }

            # Attacker replaces content with DIFFERENT content of EXACT SAME size
            # Swap DEBUG=0 to DEBUG=1 and adjust padding by 0 bytes
            modified_content = b"PORT=8080\nHOST=127.0.0.1\nDEBUG=1\nSECRET_KEY=ABCDEF1234567890\nPADDING=123"
            assert len(modified_content) == initial_size
            cfg_file.write_bytes(modified_content)

            # Scan and diff
            records_curr = fim.scan_path(td)
            assert len(records_curr) == 1
            assert records_curr[0].file_size_bytes == initial_size

            changes, events = fim.diff_baseline(baseline, records_curr)

            assert len(changes) == 1
            assert changes[0]["change_type"] == "MODIFIED", "Must detect MODIFIED even when file size is identical"
            assert changes[0]["previous_size"] == initial_size
            assert changes[0]["current_size"] == initial_size
            assert changes[0]["previous_sha256"] != changes[0]["current_sha256"]
            assert events[0]["action"] == "modified"

    def test_fim_path_traversal_and_malicious_paths(self):
        """Verify strict rejection of path traversal sequences, null bytes, and non-existent paths."""
        # 1. Null byte injection
        with pytest.raises(FIMPathSecurityError, match="Null byte detected"):
            sanitize_watch_path("C:\\safe_dir\x00\\..\\windows")

        # 2. Empty or whitespace-only paths
        with pytest.raises(FIMPathSecurityError, match="Watch path cannot be empty"):
            sanitize_watch_path("")

        with pytest.raises(FIMPathSecurityError, match="Watch path cannot be empty"):
            sanitize_watch_path("    ")

        # 3. Nonexistent directory
        with pytest.raises(FIMPathSecurityError, match="Target watch path does not exist"):
            sanitize_watch_path("C:\\nonexistent_dir_987654321_impossible")

        # 4. Traversal resolving to nonexistent targets
        with pytest.raises(FIMPathSecurityError, match="Target watch path does not exist"):
            sanitize_watch_path("..\\..\\..\\..\\..\\..\\definitely_missing_123456")


# =============================================================================
# 3. Epistemic Integrity: Detection Alerts vs Factual Ground Truth
# =============================================================================

class TestEpistemicIntegrity:
    """
    Epistemic Integrity Requirement:
    Observed factual telemetry events must NEVER be mutated or overwritten by detection engine
    or incident correlator evaluations. Suspicion must remain strictly in alerts and incidents.
    """

    def test_detection_engine_never_mutates_factual_telemetry(self, test_db):
        """
        Verify that processing an event through Detector and IncidentCorrelator
        does not alter any field on the TelemetryEventModel.
        """
        detector = Detector()
        detector.sync_rules_to_db(test_db)
        correlator = IncidentCorrelator()

        # Create a genuine factual telemetry event with severity="Low"
        raw_details = {
            "remote_ip": "192.168.1.100",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "bytes_sent": 1024,
        }
        event = TelemetryEventModel(
            id=str(uuid.uuid4()),
            category="network",
            action="connected",
            severity="Low",  # Factual collector severity is Low
            source="vayu",
            hostname="WS-PROD-01",
            os_name="Windows",
            actor_pid=9999,
            actor_name="cmd.exe",
            target_identifier="192.168.1.100:4444",
            target_type="socket",
            details=copy.deepcopy(raw_details),
            is_sample=False,
            timestamp=datetime.now(UTC),
        )
        test_db.add(event)
        test_db.commit()
        test_db.refresh(event)

        # Snapshot ground truth event attributes before detection processing
        initial_event_id = event.id
        initial_severity = event.severity
        initial_action = event.action
        initial_category = event.category
        initial_source = event.source
        initial_hostname = event.hostname
        initial_os_name = event.os_name
        initial_actor_pid = event.actor_pid
        initial_actor_name = event.actor_name
        initial_target_identifier = event.target_identifier
        initial_details = copy.deepcopy(event.details)
        initial_is_sample = event.is_sample
        initial_timestamp = event.timestamp

        # Process event against rules (Rule AGNI-R-NET-001 has severity="High")
        alerts = detector.process_event(test_db, event, correlator=correlator)

        # Confirm rule AGNI-R-NET-001 was triggered
        assert len(alerts) >= 1
        matched_alert = next((a for a in alerts if a.rule_id == "AGNI-R-NET-001"), None)
        assert matched_alert is not None
        assert matched_alert.severity == "High"  # Rule severity is High

        # Re-fetch the ground truth event from the database to check persisted state
        persisted_event = test_db.query(TelemetryEventModel).filter(TelemetryEventModel.id == initial_event_id).one()

        # Epistemic Assertion 1: Ground truth severity remains 'Low' and was NOT elevated
        assert persisted_event.severity == initial_severity == "Low"
        assert persisted_event.severity != matched_alert.severity

        # Epistemic Assertion 2: All other ground truth fields are strictly identical
        assert persisted_event.id == initial_event_id
        assert persisted_event.action == initial_action
        assert persisted_event.category == initial_category
        assert persisted_event.source == initial_source
        assert persisted_event.hostname == initial_hostname
        assert persisted_event.os_name == initial_os_name
        assert persisted_event.actor_pid == initial_actor_pid
        assert persisted_event.actor_name == initial_actor_name
        assert persisted_event.target_identifier == initial_target_identifier
        assert persisted_event.details == initial_details
        assert persisted_event.is_sample == initial_is_sample
        assert persisted_event.timestamp == initial_timestamp

        # Epistemic Assertion 3: The alert and incident correctly separate belief from observation
        incident = test_db.query(IncidentModel).filter(IncidentModel.id == matched_alert.incident_id).first()
        assert incident is not None
        assert incident.severity == "High"
        assert incident.title == "Outbound Connection to Known Reverse Shell / C2 Port"
        assert incident.event_count == 1

    def test_correlator_threshold_does_not_mutate_events(self, test_db):
        """Verify that sliding-window threshold evaluation leaves all events unmodified."""
        # Create a custom threshold rule in test_db
        threshold_rule = DetectionRuleModel(
            id="CHALLENGE-THRESH-001",
            name="Rapid Port Scan Threshold Challenge",
            description="Detects rapid outbound connections",
            severity="Critical",
            category="network",
            source="vayu",
            match_conditions={"field": "details.protocol", "operator": "equals", "value": "TCP"},
            correlation_window=60,
            threshold=3,
            group_by="actor.pid",
            explanation="Multiple outbound connections from single PID",
            investigation_steps=["Inspect socket connections", "Verify PID"],
            version="1.0.0",
            enabled=True,
            is_custom=True,
        )
        test_db.add(threshold_rule)
        test_db.commit()

        detector = Detector()
        correlator = IncidentCorrelator()

        created_events = []
        for i in range(3):
            ev = TelemetryEventModel(
                id=str(uuid.uuid4()),
                category="network",
                action="connected",
                severity="Informational",
                source="vayu",
                hostname="WS-01",
                os_name="Windows",
                actor_pid=5555,
                actor_name="scanner.exe",
                target_identifier=f"10.0.0.{i+1}:80",
                details={"protocol": "TCP", "attempt": i},
                is_sample=False,
                timestamp=datetime.now(UTC),
            )
            test_db.add(ev)
            test_db.commit()
            created_events.append(ev)

            # Process event
            alerts = detector.process_event(test_db, ev, correlator=correlator)
            if i < 2:
                # Threshold not yet reached (threshold=3)
                assert len(alerts) == 0
            else:
                # 3rd event should trigger the threshold alert
                assert len(alerts) == 1
                assert alerts[0].rule_id == "CHALLENGE-THRESH-001"
                assert alerts[0].severity == "Critical"

        # Verify all 3 underlying events retain their original Informational severity and details
        for i, ev in enumerate(created_events):
            db_ev = test_db.query(TelemetryEventModel).filter(TelemetryEventModel.id == ev.id).one()
            assert db_ev.severity == "Informational"
            assert db_ev.details["attempt"] == i


# =============================================================================
# 4. Concurrency & Stress Harness
# =============================================================================

class TestConcurrencyAndStressHarness:
    """Stress test sliding-window tracker and rule evaluation under concurrent load."""

    def test_concurrent_sliding_window_tracker(self):
        """Stress-test thread-safety of SlidingWindowTracker under concurrent execution."""
        tracker = SlidingWindowTracker()
        rule_id = "STRESS-RULE-001"
        group_val = "192.168.1.50"
        window_sec = 10
        threshold = 5

        results: list[list[str] | None] = []

        def worker(worker_id: int):
            worker_results = []
            for j in range(10):
                event_time = datetime.now(UTC)
                eid = f"event-{worker_id}-{j}"
                res = tracker.record_and_check_threshold(
                    rule_id=rule_id,
                    group_val=group_val,
                    event_time=event_time,
                    event_id=eid,
                    window_seconds=window_sec,
                    threshold=threshold,
                    cooldown_seconds=0,  # 0 cooldown to test raw thread-safe threshold counts
                )
                worker_results.append(res)
            return worker_results

        # Execute 8 concurrent workers pushing 80 events simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, w) for w in range(8)]
            for f in concurrent.futures.as_completed(futures):
                results.extend(f.result())

        # Collect all threshold hits
        threshold_hits = [r for r in results if r is not None]
        # At least one threshold trigger must have occurred without race exceptions
        assert len(threshold_hits) > 0
        for hit in threshold_hits:
            assert len(hit) >= threshold


# =============================================================================
# 5. Operator Exhaustiveness & Empirical Findings
# =============================================================================

class TestASTOperatorExhaustiveness:
    """Challenge coverage for all OPERATOR_MAP operators and ORM vs dict disparities."""

    def test_ast_orm_vs_dict_nested_details_disparity(self):
        """
        Empirically verify the subtle behavior disparity between raw dicts and ORM objects:
        When an event is a raw dict, extract_field traverses 'details.nested.foo'.
        When an event is an ORM TelemetryEventModel, extract_field executes
        details_dict.get('nested.foo') which returns None unless key contains literal dot.
        """
        # Dictionary representation
        dict_event = {"details": {"connection": {"remote_port": 4444}}}
        assert extract_field(dict_event, "details.connection.remote_port") == 4444

        # ORM representation
        orm_event = TelemetryEventModel(
            id=str(uuid.uuid4()),
            category="network",
            action="connected",
            severity="Low",
            source="vayu",
            details={"connection": {"remote_port": 4444}},
        )
        # ORM model returns None for multi-dot nested lookup under details
        assert extract_field(orm_event, "details.connection.remote_port") is None

        # But single-dot lookup on ORM works as expected
        orm_event_flat = TelemetryEventModel(
            id=str(uuid.uuid4()),
            category="network",
            action="connected",
            severity="Low",
            source="vayu",
            details={"remote_port": 4444},
        )
        assert extract_field(orm_event_flat, "details.remote_port") == 4444

    def test_all_operator_map_permutations(self):
        """Exhaustively verify all registered operators in OPERATOR_MAP."""
        sample_event = {
            "actor": {
                "name": "powershell.exe",
                "cmdline": "powershell -ExecutionPolicy Bypass",
                "pid": 1234,
                "user": "alice",
            },
            "details": {
                "tags": ["prod", "web", "high-risk"],
                "score": 75.5,
                "count": 10,
                "null_field": None,
            },
        }

        # equals / eq / exact_equals / not_equals / neq
        assert evaluate_condition({"field": "actor.name", "operator": "equals", "value": "POWERSHELL.EXE"}, sample_event)
        assert evaluate_condition({"field": "actor.name", "operator": "eq", "value": "POWERSHELL.EXE"}, sample_event)
        assert evaluate_condition({"field": "actor.name", "operator": "exact_equals", "value": "powershell.exe"}, sample_event)
        assert not evaluate_condition({"field": "actor.name", "operator": "exact_equals", "value": "POWERSHELL.EXE"}, sample_event)
        assert evaluate_condition({"field": "actor.name", "operator": "not_equals", "value": "cmd.exe"}, sample_event)
        assert evaluate_condition({"field": "actor.name", "operator": "neq", "value": "cmd.exe"}, sample_event)

        # contains / icontains / not_contains
        assert evaluate_condition({"field": "actor.cmdline", "operator": "contains", "value": "executionpolicy"}, sample_event)
        assert evaluate_condition({"field": "actor.cmdline", "operator": "icontains", "value": "EXECUTIONPOLICY"}, sample_event)
        assert evaluate_condition({"field": "actor.cmdline", "operator": "not_contains", "value": "-enc"}, sample_event)
        assert evaluate_condition({"field": "details.tags", "operator": "contains", "value": "web"}, sample_event)

        # startswith / endswith
        assert evaluate_condition({"field": "actor.name", "operator": "startswith", "value": "power"}, sample_event)
        assert evaluate_condition({"field": "actor.name", "operator": "endswith", "value": ".exe"}, sample_event)

        # in / in_list / not_in
        assert evaluate_condition({"field": "actor.user", "operator": "in", "value": ["bob", "ALICE", "charlie"]}, sample_event)
        assert evaluate_condition({"field": "actor.user", "operator": "in_list", "value": ["bob", "ALICE"]}, sample_event)
        assert evaluate_condition({"field": "actor.user", "operator": "not_in", "value": ["root", "admin"]}, sample_event)

        # regex / matches / iregex
        assert evaluate_condition({"field": "actor.cmdline", "operator": "regex", "value": r"-ExecutionPolicy\s+\w+"}, sample_event)
        assert evaluate_condition({"field": "actor.cmdline", "operator": "matches", "value": r"-ExecutionPolicy\s+\w+"}, sample_event)
        assert not evaluate_condition({"field": "actor.cmdline", "operator": "regex", "value": r"-executionpolicy"}, sample_event)
        assert evaluate_condition({"field": "actor.cmdline", "operator": "iregex", "value": r"-executionpolicy"}, sample_event)

        # gt / gte / lt / lte
        assert evaluate_condition({"field": "details.score", "operator": "gt", "value": 70}, sample_event)
        assert evaluate_condition({"field": "details.score", "operator": "gte", "value": 75.5}, sample_event)
        assert evaluate_condition({"field": "details.count", "operator": "lt", "value": 15}, sample_event)
        assert evaluate_condition({"field": "details.count", "operator": "lte", "value": 10}, sample_event)

        # is_null / not_null / exists
        assert evaluate_condition({"field": "details.null_field", "operator": "is_null", "value": None}, sample_event)
        assert evaluate_condition({"field": "actor.pid", "operator": "not_null", "value": None}, sample_event)
        assert evaluate_condition({"field": "actor.cmdline", "operator": "exists", "value": None}, sample_event)
        assert not evaluate_condition({"field": "details.missing", "operator": "exists", "value": None}, sample_event)

    def test_empty_ast_branches_fail_safely(self):
        """Verify that empty boolean branches (empty and/or) fail gracefully."""
        # Empty AND list
        assert evaluate_condition({"and": []}, {"actor": {"name": "test"}}) is False
        # Empty OR list
        assert evaluate_condition({"or": []}, {"actor": {"name": "test"}}) is False
        # Empty dict
        assert evaluate_condition({}, {"actor": {"name": "test"}}) is False


# =============================================================================
# 6. FIM API & Path Traversal HTTP Integration
# =============================================================================

class TestFIMAPIAndMetadataBoundaries:
    """Verifies FIM API route edge cases and security protections."""

    def test_fim_api_null_byte_rejection(self, client):
        """POST /api/v1/fim/baseline with null byte must return 400 Bad Request."""
        res = client.post("/api/v1/fim/baseline", json={
            "name": "Malicious Null Byte Baseline",
            "target_path": "C:\\Windows\x00\\traversal",
        })
        assert res.status_code == 400
        assert "Null byte" in res.json().get("detail", "")

    def test_fim_api_nonexistent_path_rejection(self, client):
        """POST /api/v1/fim/baseline with nonexistent path must return 404 Not Found."""
        res = client.post("/api/v1/fim/baseline", json={
            "name": "Missing Directory Baseline",
            "target_path": "C:\\nonexistent_dir_00000000_123456",
        })
        assert res.status_code == 404
        assert "does not exist" in res.json().get("detail", "")

