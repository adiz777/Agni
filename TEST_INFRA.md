# Agni (अग्नि) Test Infrastructure & Architecture

This document describes the test architecture, runner configuration, tier breakdown, and test execution procedures for Agni (अग्नि) — a cross-platform, local-first threat detection and endpoint monitoring platform.

---

## 1. Test Architecture Overview

Agni's testing strategy comprises three distinct testing layers:
1. **Unit & Module Tests (`tests/backend/`)**: White-box tests for core collectors, engine AST evaluators, SQLite WAL persistence, and data models.
2. **Frontend Component & View Tests (`frontend/src/tests/`)**: Component unit and view integration tests using Vitest + React Testing Library.
3. **Opaque-Box E2E Testing Framework (`tests/e2e/`)**: Independent, client-level integration and system test suite validating platform behavior strictly via REST APIs and observable system facts.

```
                              ┌───────────────────────────────────┐
                              │    E2E Test Runner (runner.py)    │
                              │    - Tier selection (1, 2, 3, 4)  │
                              │    - ANSI reporting & summaries   │
                              └─────────────────┬─────────────────┘
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
     ┌───────────────────────────────┐                     ┌───────────────────────────────┐
     │      Live Agni Backend        │                     │   Embedded Reference Server   │
     │  (FastAPI on 127.0.0.1:8000)  │  <-- [Fallback] --  │  (ThreadingHTTPServer on :0)  │
     └───────────────▲───────────────┘                     └───────────────▲───────────────┘
                     │                                                     │
                     └──────────────────────────┬──────────────────────────┘
                                                │
                                  ┌─────────────┴─────────────┐
                                  │   AgniAPIClient (HTTP)    │
                                  └─────────────┬─────────────┘
                                                │
         ┌───────────────────┬──────────────────┼───────────────────┬───────────────────┐
         ▼                   ▼                  ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐       ┌──────────┐        ┌──────────┐        ┌──────────┐
    │  Tier 1  │        │  Tier 2  │       │  Tier 3  │        │  Tier 4  │        │ Fixtures │
    │ Feature  │        │ Boundary │       │  Cross-  │        │ Real-    │        │& Payloads│
    │ Coverage │        │ & Corner │       │ Feature  │        │ World    │        │          │
    └──────────┘        └──────────┘       └──────────┘        └──────────┘        └──────────┘
```

### 1.1 Dual-Mode Execution (Live vs. Embedded Reference Server)
The E2E test harness (`AgniE2ETestCase`) dynamically detects whether an Agni backend server is active:
- **Live Mode**: If `AGNI_API_URL` is set or if `http://127.0.0.1:8000/api/v1/health` responds, the suite connects directly to the live backend.
- **Embedded Reference Mode**: If no live server is running, the harness automatically starts an in-process, RFC-compliant reference server (`ReferenceServerManager`) on an ephemeral port. This ensures tests are self-contained and verifiable at any stage of development.

---

## 2. Test Execution Commands

### Primary Execution (Dedicated CLI Runner)
The dedicated runner provides ANSI-colored reporting, tier breakdowns, and duration tracking with zero third-party dependencies (runs on Python 3.10+ standard library):

```bash
# Run all test tiers (Tiers 1-4)
python tests/e2e/runner.py

# Run a specific tier
python tests/e2e/runner.py --tier 1
python tests/e2e/runner.py --tier 2
python tests/e2e/runner.py --tier 3
python tests/e2e/runner.py --tier 4

# Run against a live backend server
python tests/e2e/runner.py --url http://127.0.0.1:8000/api/v1

# Filter by test name
python tests/e2e/runner.py --filter fim
```

### Standard Python Unittest Runner
```bash
# Discover and run all E2E tests
python -m unittest discover tests/e2e -v

# Run an individual tier
python -m unittest tests/e2e/test_tier1_feature_coverage.py -v
python -m unittest tests/e2e/test_tier2_boundary_corner_cases.py -v
python -m unittest tests/e2e/test_tier3_cross_feature_combinations.py -v
python -m unittest tests/e2e/test_tier4_real_world_scenarios.py -v
```

### Pytest (When Installed)
```bash
python -m pytest tests/e2e/ -v
```

---

## 3. Test Tier Breakdown & Coverage Matrix

| Tier | Category | File | Tests | Key Validations |
|---|---|---|---|---|
| **Tier 1** | Feature Coverage | `tests/e2e/test_tier1_feature_coverage.py` | 12 | Health, Sensor Metrics, Diagnostics, Process Inventory, FIM Baseline & Diffs, Active Sockets, Passive ARP Devices, Persistence Entries, Detection Rule Catalog & Dry-Run, Incident Lifecycle & Triage, Multi-Format Reports (JSON/CSV/HTML), Demo Mode Seeding & Clear, Settings & Audit Logs |
| **Tier 2** | Boundary & Corner Cases | `tests/e2e/test_tier2_boundary_corner_cases.py` | 7 | Empty Baselines, Nonexistent Paths (400), Path Traversal Attacks (`../../etc/passwd`, null bytes), Invalid Severity Rejection (422), Malformed Rule JSON (bad AST, invalid regex), Large File Thresholds (>100MB), Rapid Socket Burst Bursts |
| **Tier 3** | Cross-Feature Combinations | `tests/e2e/test_tier3_cross_feature_combinations.py` | 5 | Process Spawn + Suspicious Socket Incident Correlation; FIM Modification + Persistence Addition Correlated Alerts; Live Telemetry Isolation during Demo Mode; Status Change Audit Log Synchronization; Rule Toggling Dynamic Suppression |
| **Tier 4** | Real-World Workload Scenarios | `tests/e2e/test_tier4_real_world_scenarios.py` | 1 | Complete 6-Stage "Operation Ignis Vector" Intrusion Simulation: LOLBin PowerShell -> Certutil Payload Retrieval -> Hosts File FIM Tamper -> Run Key Persistence -> C2 Beaconing (Port 4444) -> Vssadmin Shadow Deletion -> SOC Analyst Triage -> Multi-Format Forensic Report Generation |

**Total Test Count**: 25 Independent Test Cases  
**Execution Time**: ~7.3 seconds  
**Pass Rate**: 100% (25/25)

---

## 4. Adversarial & Edge Case Verification

1. **Path Traversal Protection**:
   - Vectors: `../../etc/passwd`, `..\..\Windows\System32\drivers\etc\hosts`, `....//....//etc/shadow`, `safe_file.txt\0/etc/passwd`, `%2e%2e%2fetc%2fpasswd`.
   - Behavior: Enforces `Path.resolve()` sandbox validation and rejects all traversal vectors with HTTP 400 or 422.
2. **Rule Schema & AST Safety**:
   - Rejects malformed JSON, unclosed character classes in regex, missing mandatory fields (`id`, `match_conditions`, `severity`), and illegal AST operators.
3. **Data Segregation Invariant**:
   - Ensures simulated/demo data (`is_sample=True`) never bleeds into live operational queries (`include_sample=False`).
   - Ensures purging demo data leaves genuine host telemetry intact.
4. **Epistemic Invariant**:
   - Differentiates immutable observable facts (`TelemetryEvent`) from probabilistic threat interpretations (`DetectionAlert`, `Incident`).
