<div align="center">

<img src="docs/assets/agni-logo.svg" alt="Agni Endpoint Defense & SOC Logo" width="460" />

### Sovereign, Local-First Threat Detection & Endpoint Security Operations

[![CI](https://github.com/adiz777/Agni/actions/workflows/ci.yml/badge.svg)](https://github.com/adiz777/Agni/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen.svg?style=flat-square)](tests/)
[![Coverage](https://img.shields.io/badge/Coverage-98%25-success.svg?style=flat-square)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20macOS-informational.svg?style=flat-square)](docs/platform-support.md)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB.svg?style=flat-square&logo=python&logoColor=white)](backend/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?style=flat-square&logo=react&logoColor=black)](frontend/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%20Aligned-red.svg?style=flat-square)](backend/rules/)

[Overview](#-overview) • [Screenshots](#-screenshot-gallery) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Detection Rules](#-declarative-varuna-rule-engine) • [Platform Matrix](#-platform-support-matrix) • [Security](#-security--privacy-guarantees) • [Author](#-author--credits)

</div>

---

## 🛡️ Overview

**Agni (अग्नि)** is a high-performance, **local-first defensive endpoint threat detection and security operations (SOC) platform**. Named after the primordial Sanskrit concept of the vigilant flame and sacred guardian, Agni transforms raw host operating system telemetry into actionable cyber threat intelligence—without ever exposing confidential internal telemetry to third-party cloud infrastructure.

Traditional endpoint agents often compromise system stability with invasive kernel drivers, exfiltrate raw user data to proprietary clouds, and cause alert fatigue with uncoordinated notifications. Agni solves this through:

- **100% Sovereign Local Telemetry**: All host observation, process auditing, network connection mapping, and file integrity baselines are processed and stored strictly on local loopback (`127.0.0.1`).
- **Epistemic Sensor Layer**: Non-destructive, read-only collection across Windows, Linux, and macOS with deterministic privilege degradation.
- **Varuna AST Correlation Engine**: Multi-stage attack detection via declarative YAML/JSON rules mapped to MITRE ATT&CK, synthesized across a temporal sliding window.
- **Tamper-Evident Cryptographic Audit Trail**: Immutable SHA-256 hash-chained audit logs ensuring zero repudiation.
- **Modern Cyber SOC Dashboard**: Fast, responsive React 18 / TypeScript single-page application with real-time Kanban triage, threat posture calculations, and offline AI analyst assistance.

---

## 📸 Screenshot Gallery

<div align="center">

### Situational Overview & Real-Time Threat Posture
*Real-time Threat Posture score, sensor component health, active incidents, and top triage queue.*
<img src="docs/assets/overview.png" alt="Agni SOC Overview Dashboard" width="95%" />

<br/><br/>

### Live Host Telemetry Event Stream
*Continuous streaming telemetry table with category filters, severity tags, and instant search.*
<img src="docs/assets/live-events.png" alt="Agni Live Telemetry Stream" width="95%" />

<br/><br/>

### Multi-Stage Incident Investigation & Kanban Triage
*Correlated multi-stage adversary incidents arranged into interactive Kanban workflow columns.*
<img src="docs/assets/incidents.png" alt="Agni Incident Investigation Kanban" width="95%" />

<br/><br/>

### Vayu Network Intelligence & Socket Mapping
*Network interface adapters, process-to-socket ownership, and passive ARP device discovery.*
<img src="docs/assets/network-intel.png" alt="Agni Vayu Network Intelligence" width="95%" />

<br/><br/>

### File Integrity Monitoring (FIM SHA-256)
*Cryptographic chunked SHA-256 baselines across sensitive system paths and persistence locations.*
<img src="docs/assets/file-integrity.png" alt="Agni File Integrity Monitoring" width="95%" />

</div>

---

## 🏛 Architecture

Agni's pipeline cleanly decouples OS telemetry observation from rule evaluation, persistence, and presentation:

```mermaid
flowchart TD
    subgraph Host["Host Operating System"]
        Proc[Process Tree & Subsystems]
        Net[Sockets, Adapters & ARP Cache]
        FS[Monitored Filesystem Paths]
        Pers[Startup Keys & System Daemons]
    end

    subgraph Sensor["Agni Epistemic Sensor Layer"]
        Collector[Cross-Platform Sensor Collector\n(Windows / Linux / macOS)]
        Scrubber[Telemetry Scrubber\n(Token, Password & PII Redaction)]
    end

    subgraph Engine["Varuna Detection & Core Engine"]
        Rules[(18+ MITRE ATT&CK\nDeclarative YAML Rules)]
        ASTEval[Varuna AST Rule Evaluator]
        Correlator[Temporal Sliding Window\nIncident Correlator]
        Audit[SHA-256 Hash-Chained\nCryptographic Audit Trail]
    end

    subgraph Storage["Local Storage"]
        DB[(SQLite WAL Database\n127.0.0.1:8000)]
    end

    subgraph Gateway["Loopback API Gateway"]
        FastAPI[FastAPI Security Router\nStrict Loopback Enforcement]
    end

    subgraph UI["Cyber SOC Dashboard"]
        ReactApp[React 18 + Vite + Tailwind\nSOC Workspace & AI Assistant]
    end

    Proc & Net & FS & Pers --> Collector
    Collector --> Scrubber
    Scrubber --> DB
    Scrubber --> ASTEval
    Rules --> ASTEval
    ASTEval --> Correlator
    Correlator --> DB
    Correlator --> Audit
    Audit --> DB

    DB --> FastAPI
    FastAPI <-->|HTTP / WebSocket / 127.0.0.1| ReactApp
```

For comprehensive details on components, data flow, and class contracts, see [`docs/architecture.md`](docs/architecture.md).

---

## ⚡ Quick Start

### Prerequisites
- **Python 3.11+**
- **Node.js 18+** & `npm`

### 1. Clone Repository
```bash
git clone https://github.com/adiz777/Agni.git
cd Agni
```

### 2. Start the Backend (API & Varuna Detection Engine)

#### Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
```

#### Linux / macOS (Bash):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
```

*The backend initializes SQLite with Write-Ahead Logging (WAL) and synchronizes 18 default defensive rules.*

### 3. Start the Frontend SOC Dashboard

```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` in your browser.

---

## 📜 Declarative Varuna Rule Engine

Detection rules in Agni are expressed as human-readable, schema-validated YAML or JSON files. Rules support boolean logic (`and`, `or`, `not`), regular expressions, substring matching, and threshold aggregations.

Example: **Detecting Shadow Copy Deletion (Ransomware Preparation)**
```yaml
id: AGNI-R-PROC-003
title: Shadow Copy Deletion Attempt via Vssadmin
severity: CRITICAL
status: active
mitre_attack:
  tactic: Defense Evasion / Impact
  technique: T1490
conditions:
  and:
    - field: category
      operator: equals
      value: PROCESS
    - field: action
      operator: equals
      value: spawned
    - or:
        - field: actor_name
          operator: equals
          value: vssadmin.exe
        - field: actor_cmdline
          operator: regex
          value: (?i)vssadmin(\.exe)?\s+delete\s+shadows
remediation:
  summary: Adversary attempting to inhibit system recovery prior to encryption.
  recommended_actions:
    - Isolate endpoint from network immediately.
    - Check for ransomware precursor binaries in %TEMP%.
```

---

## 📊 Platform Support Matrix

Agni runs across all three major desktop and server operating systems:

| Capability | Windows (10/11, Server) | Linux (Kernel 5.4+) | macOS (Sonoma, Sequoia) |
| :--- | :---: | :---: | :---: |
| **Process Tree & Resource Metrics** | ✅ Full | ✅ Full | ✅ Full |
| **Command-Line Scrubbing** | ✅ Full | ✅ Full | ✅ Full |
| **Active Sockets & PID Ownership** | ✅ Full | ✅ Full | ✅ Full |
| **Passive ARP Table Discovery** | ✅ Full | ✅ Full | ✅ Full |
| **File Integrity (Chunked SHA-256)**| ✅ Full | ✅ Full | ✅ Full |
| **Autostart & Persistence Audit** | ✅ Registry & Startup | ✅ systemd & cron | ✅ launchd & LaunchAgents |
| **Privilege Degradation Mode** | ✅ User-level safe | ✅ User-level safe | ✅ User-level safe |

Read the full matrix in [`docs/platform-support.md`](docs/platform-support.md).

---

## 🔒 Security & Privacy Guarantees

1. **Loopback Only (`127.0.0.1`)**: Agni rejects binding to external interfaces out of the box. Host telemetry never leaves the endpoint.
2. **Zero Invasiveness / Non-Destructive**: Collects data through safe operating system query APIs. No kernel hooking, driver patching, or unconfirmed process terminations.
3. **Telemetry Scrubbing**: Passwords, API tokens, Authorization headers, and sensitive environment variables are sanitized prior to persistence.
4. **Cryptographic Immutability**: All analyst operations and configuration updates are chained using SHA-256. Any tampering breaks the chain.

Read the detailed STRIDE threat analysis in [`docs/threat-model.md`](docs/threat-model.md).

---

## 🧪 Testing & Verification

Agni is backed by an extensive multi-tier verification suite:

```bash
# Backend pytest suite (unit, integration & rules)
python -m pytest tests/backend/ -v

# Independent opaque-box E2E runner (4 tiers)
python tests/e2e/runner.py

# Code style & PEP 8 linting
python -m ruff check backend/ tests/ --config backend/pyproject.toml

# Frontend component tests (Vitest)
cd frontend && npm run test

# TypeScript type validation
npx tsc --noEmit
```

---

## 👨‍💻 Author & Credits

**Agni (अग्नि)** is designed and developed by **Aditya Zala**.

- **Portfolio**: [https://adizala.me](https://adizala.me)
- **GitHub**: [@adiz777](https://github.com/adiz777)
- **Email**: [adizala7303@gmail.com](mailto:adizala7303@gmail.com)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - Copyright © 2026 Aditya Zala.
