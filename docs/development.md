# Development & Verification Guide

This guide details the engineering workflows, test suites, and linting procedures used to build, maintain, and verify Agni.

---

## 1. Project Layout Overview

```
Agni/
├── backend/                  # FastAPI backend & Varuna engine
│   ├── app/
│   │   ├── api/              # REST API endpoints & route dependencies
│   │   ├── core/             # Configuration, database & security guards
│   │   ├── engine/           # Varuna rule evaluator, correlator & demo generator
│   │   ├── models/           # SQLAlchemy ORM models (events, incidents, FIM)
│   │   ├── platform/         # Cross-platform sensor collectors (Win, Linux, Mac)
│   │   ├── schemas/          # Pydantic v2 schemas for request/response validation
│   │   └── services/         # FIM service, exporter & AI advisory engine
│   ├── rules/                # Default YAML/JSON Varuna detection rules
│   ├── pyproject.toml        # Ruff, pytest, and build configuration
│   └── requirements.txt      # Python dependencies
├── frontend/                 # React 18 + Vite + Tailwind CSS dashboard
│   ├── src/
│   │   ├── assets/           # Agni SVG brand emblems & icons
│   │   ├── components/       # UI elements (Kanban, Navbar, Sidebar, Modals, Banners)
│   │   ├── context/          # AppContext global state & hash navigation
│   │   ├── services/         # Axios API client & mock data
│   │   └── views/            # 12 SOC view views (Overview, Events, Incidents, etc.)
│   ├── package.json          # Node dependencies & scripts
│   └── vite.config.ts        # Vite dev/preview server & Vitest configuration
├── docs/                     # Full portfolio documentation suite
│   ├── assets/               # Full HD 1080p UI screenshots & vector assets
│   ├── architecture.md       # Architecture deep dive & Mermaid diagrams
│   ├── platform-support.md   # OS sensor matrix & privilege degradation
│   ├── threat-model.md       # STRIDE threat model & boundary mitigations
│   └── development.md        # This guide
├── scripts/                  # Automated verification & execution scripts
│   ├── capture_screenshots.py# Headless Chrome 1080p screenshot pipeline
│   ├── windows/              # PowerShell install & run scripts
│   └── unix/                 # Bash install & run scripts
└── tests/                    # Comprehensive testing suites
    ├── backend/              # Unit & integration tests for backend & engine
    └── e2e/                  # Multi-tier opaque-box E2E test runner
```

---

## 2. Running Test Suites

Agni maintains a strict policy: **all code changes must pass 100% of tests before merge**.

### Backend Unit & Integration Tests (Pytest)
```bash
python -m pytest tests/backend/ -v
```
Covers:
- `test_rules.py`: Varuna AST rule parsing, condition matching, and invalid rule rejection.
- `test_correlator.py`: Multi-stage incident synthesis and sliding window deduplication.
- `test_database.py`: SQLite WAL mode, migrations, and atomic transactions.
- `test_fim.py`: File integrity hashing, baseline creation, and discrepancy detection.
- `test_platform.py`: Cross-platform sensor collectors and privilege degradation.

### Multi-Tier Opaque-Box E2E Runner
```bash
python tests/e2e/runner.py
```
Executes four rigorous tiers of independent validation:
- **Tier 1: Feature Coverage** - Comprehensive endpoint and schema validation.
- **Tier 2: Boundary & Corner Cases** - Edge conditions, empty payloads, maximum buffer limits.
- **Tier 3: Cross-Feature Combinations** - Telemetry ingestion followed by rule triggering and incident verification.
- **Tier 4: Real-World Scenarios** - Full multi-stage APT intrusion lifecycle.

### Frontend Component Tests (Vitest)
```bash
cd frontend
npm run test
```
Runs 20 automated tests validating UI components, Kanban transitions, table filtering, and cryptographic audit log verification.

---

## 3. Code Style, Formatting & Linting

### Python (Ruff)
Ruff enforces PEP 8 compliance, import sorting, and code safety:
```bash
python -m ruff check backend/ tests/ --config backend/pyproject.toml
```
To automatically apply safe fixes:
```bash
python -m ruff check --fix backend/ tests/ --config backend/pyproject.toml
```

### TypeScript / Frontend
```bash
cd frontend
# Typecheck
npx tsc --noEmit

# Production build check
npm run build
```

---

## 4. Capturing Automated Screenshots

Agni includes an automated script that spins up the backend and frontend, seeds the Operation Ignis Vector APT scenario, and captures 1920x1080 screenshots with headless Chrome:

```bash
python scripts/capture_screenshots.py
```

Generated assets are placed directly in `docs/assets/`.
