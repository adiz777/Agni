# Agni (अग्नि) Test Suite Ready

The automated opaque-box End-to-End (E2E) testing framework for Agni (अग्नि) is fully implemented, verified, and ready for continuous testing across all project milestones.

---

## 1. Quick Start: How to Run the Tests

The test suite runs with **zero external dependencies** using Python's standard library, and is completely compatible with `pytest` and `unittest`.

### Primary CLI Runner (Colored Summaries & Tier Selectors)
```bash
# Execute all tiers (Tiers 1-4)
python tests/e2e/runner.py

# Execute specific tier
python tests/e2e/runner.py --tier 1    # Tier 1: Feature Coverage
python tests/e2e/runner.py --tier 2    # Tier 2: Boundary & Corner Cases
python tests/e2e/runner.py --tier 3    # Tier 3: Cross-Feature Combinations
python tests/e2e/runner.py --tier 4    # Tier 4: Real-World Workload Scenarios

# Run against a live backend (default: http://127.0.0.1:8000/api/v1)
python tests/e2e/runner.py --url http://127.0.0.1:8000/api/v1
```

### Standard Python Unittest Runner
```bash
# Discover and run full test suite
python -m unittest discover tests/e2e -v

# Run individual test files
python -m unittest tests/e2e/test_tier1_feature_coverage.py -v
python -m unittest tests/e2e/test_tier2_boundary_corner_cases.py -v
python -m unittest tests/e2e/test_tier3_cross_feature_combinations.py -v
python -m unittest tests/e2e/test_tier4_real_world_scenarios.py -v
```

### Pytest (CI / Virtual Environment)
```bash
python -m pytest tests/e2e/ -v
```

---

## 2. Test Verification Summary

```
===========================================================================
E2E TEST EXECUTION SUMMARY
===========================================================================
 [PASS] Tier 1: Feature Coverage                      | 12 passed,  0 failed |  1.86s
 [PASS] Tier 2: Boundary & Corner Cases               |  7 passed,  0 failed |  1.92s
 [PASS] Tier 3: Cross-Feature Combinations            |  5 passed,  0 failed |  1.79s
 [PASS] Tier 4: Real-World Workload Scenarios         |  1 passed,  0 failed |  1.70s
---------------------------------------------------------------------------
Total: 25 passed, 0 failed, 0 errors across 4 tiers in 7.31s — ALL TESTS PASSED
```

---

## 3. Test Coverage Matrix

### Tier 1: Feature Coverage (`tests/e2e/test_tier1_feature_coverage.py`)
- `test_01_health_and_diagnostics_endpoints`: Validates `/health`, `/sensor/status`, `/diagnostics` metadata.
- `test_02_telemetry_overview`: Validates threat posture score, active incidents count, 24h event counters.
- `test_03_process_inventory`: Validates `/processes` and `/processes/{pid}` CPU/RAM/cmdline inspection.
- `test_04_fim_baseline_and_change_detection`: Validates baseline creation, SHA-256 hashing, CREATED/MODIFIED/DELETED detection, and baseline deletion.
- `test_05_network_interfaces_and_connections`: Validates interface inventory (IP/MAC/status) and active TCP/UDP sockets with PID mapping.
- `test_06_passive_network_devices`: Validates ARP cache discovery with first-seen/last-seen timestamps.
- `test_07_startup_persistence_visibility`: Validates read-only inspection of autorun locations across OSes.
- `test_08_detection_rules_catalog_and_test`: Validates the 18 default rules catalog, dry-run rule matching, and toggle enable/disable controls.
- `test_09_incident_creation_and_lifecycle`: Validates incident generation from triggered rules, priority mapping, triage transitions (`New` -> `Triaged`), and analyst notes.
- `test_10_multiformat_report_export`: Validates report streaming in JSON, RFC 4180 CSV, and standalone dark-themed HTML formats.
- `test_11_sample_demo_mode_lifecycle`: Validates seeding simulated APT attacks, verifying data isolation from live queries (`include_sample=false`), and purging demo data.
- `test_12_settings_and_audit_logging`: Validates runtime configuration updates and synchronous audit trail creation.

### Tier 2: Boundary & Corner Cases (`tests/e2e/test_tier2_boundary_corner_cases.py`)
- `test_01_empty_directory_fim_baseline`: Validates handling of empty directories without crashing.
- `test_02_nonexistent_path_rejection`: Rejects nonexistent baseline paths with HTTP 400.
- `test_03_path_traversal_attempts_prevented`: Verifies rejection of directory traversal attacks (`../../etc/passwd`, null bytes, `%2e%2e%2f`).
- `test_04_invalid_severity_levels_rejected`: Rejects invalid severities (`UltraCritical`, `Panic`) with HTTP 422.
- `test_05_malformed_detection_rule_validation`: Rejects malformed rules (missing fields, illegal AST operators, unclosed regex) with HTTP 422.
- `test_06_fim_large_file_size_boundary`: Flags files exceeding `max_file_size_bytes` without memory exhaustion.
- `test_07_rapid_socket_burst_anomaly_handling`: Verifies correlation engine stability under high-velocity connection bursts.

### Tier 3: Cross-Feature Combinations (`tests/e2e/test_tier3_cross_feature_combinations.py`)
- `test_01_process_spawn_and_suspicious_socket_correlation`: Correlates LOLBin process execution (`certutil.exe`) with outbound socket connection on port 4444.
- `test_02_fim_modification_and_persistence_correlation`: Correlates hosts file modification with Registry Run key creation.
- `test_03_demo_mode_data_isolation_from_live_telemetry`: Ensures live events remain separate from demo events and are preserved upon demo purge.
- `test_04_incident_triage_audit_log_correlation`: Verifies that every incident status change automatically writes an audit log entry.
- `test_05_rule_disabling_suppresses_incident_creation`: Verifies that disabled rules immediately cease generating alerts for matching events.

### Tier 4: Real-World Workload Scenarios (`tests/e2e/test_tier4_real_world_scenarios.py`)
- `test_operation_ignis_vector_multi_stage_intrusion_lifecycle`:
  Full end-to-end execution of a 6-stage simulated APT intrusion:
  1. Initial Execution (Encoded PowerShell LOLBin) -> Triggers `AGNI-R-PROC-001`
  2. Staging / Download (Certutil LOLBin) -> Triggers `AGNI-R-PROC-002`
  3. Defense Evasion (Hosts File Tamper) -> Triggers `AGNI-R-FIM-001`
  4. Persistence (Registry Run Key) -> Triggers `AGNI-R-PERS-001`
  5. Command & Control (Port 4444 Beaconing) -> Triggers `AGNI-R-NET-001` with deduplication
  6. Ransomware Staging (Vssadmin Shadow Deletion) -> Triggers `AGNI-R-PROC-003` (P1 Critical)
  7. SOC Incident Triage & Lifecycle: Status updated to `In Progress`, forensic notes appended
  8. Forensic Report Export: Complete intrusion timeline exported to JSON, CSV, and standalone HTML.

---

## 4. Key Files Created

- `tests/e2e/__init__.py`: Package initialization.
- `tests/e2e/runner.py`: Dedicated CLI test runner with tier selection and colored reporting.
- `tests/e2e/harness/__init__.py`: Harness package.
- `tests/e2e/harness/client.py`: High-level `AgniAPIClient` exercising all 28 REST endpoints.
- `tests/e2e/harness/server.py`: In-process reference mock server implementing the full API specification.
- `tests/e2e/harness/base.py`: Shared `AgniE2ETestCase` handling live connection and reference server lifecycle.
- `tests/e2e/harness/fixtures.py`: 18 defensive rules, event generators, and adversarial test vectors.
- `tests/e2e/test_tier1_feature_coverage.py`: Tier 1 test suite (12 tests).
- `tests/e2e/test_tier2_boundary_corner_cases.py`: Tier 2 test suite (7 tests).
- `tests/e2e/test_tier3_cross_feature_combinations.py`: Tier 3 test suite (5 tests).
- `tests/e2e/test_tier4_real_world_scenarios.py`: Tier 4 test suite (1 comprehensive scenario).
- `TEST_INFRA.md`: Architectural documentation and coverage matrix.
- `TEST_READY.md`: Execution manual and readiness certification.
