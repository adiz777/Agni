# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-28

### Added
- **Core Platform Architecture**:
  - FastAPI backend with strict local loopback binding defense (`127.0.0.1:8000`).
  - SQLite database in Write-Ahead Logging (WAL) mode for low-latency concurrent event ingestion.
  - Epistemic sensor collectors for Windows, Linux, and macOS with graceful privilege degradation.
- **Varuna Threat Correlation & Detection Engine**:
  - Declarative YAML/JSON AST rule syntax with boolean logic operators (`AND`, `OR`, `NOT`, `ANY`, `REGEX`).
  - 18 default production rules mapped to MITRE ATT&CK techniques (T1490, T1059, T1071, T1053, T1547, T1036, etc.).
  - Sliding time-window correlation engine for multi-stage adversary incident synthesis.
- **Passive Sensor Pipeline**:
  - Process Explorer with real-time CPU, RSS/VMS memory, user context, and restricted-access handling.
  - Vayu Network Intelligence: adapter enumeration, socket-to-process correlation, and passive kernel ARP cache discovery.
  - File Integrity Monitoring (FIM): chunked SHA-256 baseline hashing and discrepancy alerting.
  - Host Startup & Persistence Inspector (Registry Run keys, Startup folders, systemd services, cron, launchd).
- **Incident Investigation & SOC Dashboard**:
  - React 18 + TypeScript + Vite + Tailwind CSS dark cyber SOC interface.
  - Real-time Situational Overview with calculated Threat Posture dial, active incident counts, and component health monitors.
  - Live Telemetry Stream with instant severity and category filtering and CSV/JSON export.
  - Incident Investigation workspace featuring Kanban board and Table views, timeline inspection, and analyst notes.
  - Cryptographically hash-chained audit log with sequence verification.
  - Operation Ignis Vector APT multi-stage scenario simulation generator.
- **Testing & Verification Suite**:
  - Pytest unit and integration test suite covering rules, database, FIM, networking, and platform collectors.
  - Multi-tier opaque-box E2E runner validating feature coverage, boundary conditions, cross-feature combinations, and real-world attack scenarios.
  - Frontend Vitest component and view tests with 100% pass rate.
  - Automated headless Chrome 1920x1080 screenshot capture pipeline.
- **Documentation & CI/CD**:
  - Complete portfolio documentation suite, architecture deep dive, STRIDE threat model, and platform support matrix.
  - GitHub Actions CI workflow executing backend pytest, ruff linting, frontend vitest, tsc typechecking, and build validation.
