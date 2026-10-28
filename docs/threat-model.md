# Agni (अग्नि) Threat Model & Security Posture Analysis

This document outlines the security architecture, trust boundaries, and **STRIDE Threat Modeling** evaluation for Agni.

---

## 1. System Overview & Trust Boundaries

Agni sits directly on monitored endpoints. The trust boundary separates:
1. **Untrusted Host Environment**: Potentially compromised user processes, adversary binaries, network attackers, and malicious input data.
2. **Agni Runtime Boundary**: The local Python engine, SQLite database, and React web dashboard.
3. **Analyst Boundary**: The authorized operator interacting with the local browser.

```
+-----------------------------------------------------------------------+
| UNTRUSTED ENVIRONMENT                                                 |
|  - Malware / Malicious Binaries (vssadmin, certutil, reverse shells)   |
|  - Hostile Sockets & Spoofed ARP Frames                               |
|  - Untrusted Command-Line Arguments & Environment Variables           |
+-----------------------------------------------------------------------+
                                  |
                   [ Sensor Collection Barrier ]
                   - Read-only OS telemetry inspection
                   - Regex credential scrubbing & PII truncation
                                  v
+-----------------------------------------------------------------------+
| AGNI ENGINE & SECURE STORAGE                                          |
|  - Strict Loopback Binding (127.0.0.1:8000 only)                      |
|  - SQLite WAL (local file permissions, strict parameter binding)      |
|  - Tamper-Evident SHA-256 Audit Trail (Hash Chain)                    |
|  - Varuna AST Declarative Detection Rules                             |
+-----------------------------------------------------------------------+
                                  |
                   [ Loopback REST API & CORS Gateway ]
                   - Origin checked against localhost / 127.0.0.1
                                  v
+-----------------------------------------------------------------------+
| REACT SOC DASHBOARD (127.0.0.1:5173)                                  |
|  - Strict Content-Security / React Auto-Escaping (XSS Prevention)     |
|  - Human-in-the-Loop Analyst Operations                               |
+-----------------------------------------------------------------------+
```

---

## 2. STRIDE Threat Analysis & Mitigations

| Threat Category | Potential Attack Vector | Agni Defensive Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Attacker injects fake telemetry events into API to deceive analysts or cause alert flooding. | - Strict loopback binding (`127.0.0.1`) prevents remote telemetry injection.<br>- Demo and sample events are explicitly flagged (`is_sample=True`) and partitioned from live data.<br>- Synthetic events are visually demarcated with amber banner indicators. |
| **Tampering** | Adversary attempts to erase evidence by modifying detection rules or dropping audit log records. | - Audit trail is cryptographically chained using cumulative SHA-256 hashes.<br>- Any dropped or altered log row invalidates sequence hash verification.<br>- SQLite database is stored locally in protected user data directories with restricted ACLs. |
| **Repudiation** | Operator or malware claims an action was never executed or logged. | - Every analyst triage operation, note creation, and rule modification logs timestamp, actor user, and SHA-256 integrity hash. |
| **Information Disclosure** | Memory scraping, command-line inspection, or API extraction leaking user passwords, tokens, or private paths. | - Built-in Telemetry Sanitizer scrubs API tokens, JWTs, `-p <password>`, and credentials before storage.<br>- Zero telemetry is ever transmitted outside localhost loopback.<br>- Database contains no external telemetry transmission endpoints. |
| **Denial of Service** | Process fork bombs, socket flooding, or massive log spam exhausting CPU, memory, or disk. | - Sensor poll cycles enforce strict limits (`MAX_SOCKETS_PER_CYCLE = 2000`).<br>- FIM file hashing streams in 64KB chunks up to `MAX_FIM_FILE_SIZE_BYTES = 100MB`.<br>- Sliding window deduplication collapses repetitive alert bursts.<br>- Retention policies automatically prune records after 30 days. |
| **Elevation of Privilege** | Attacker exploits Agni to run root or SYSTEM commands via command injection. | - Agni executes **zero** autonomous shell execution on detected incidents.<br>- Detection engine uses safe AST pattern matching rather than `eval()` or `exec()`.<br>- Non-destructive architecture: Agni observes and alerts, leaving enforcement to deliberate analyst action. |

---

## 3. Attack Tree & Specific Risk Mitigations

### Attack Tree 1: Malicious Process Hijacking Telemetry Stream
- **Goal**: Inject false events to mask adversary presence.
- **Prerequisites**: Compromised local user account.
- **Mitigation**:
  - Agni collects data directly from kernel tables (`/proc`, `psutil`, Win32 API), not through interception proxies or userland hooks.
  - Varuna rules evaluate raw parent-child process relationships and executable paths.

### Attack Tree 2: Stored Cross-Site Scripting (XSS) via Process Names
- **Goal**: Attacker launches process named `<script>alert(1)</script>` or creates file with malicious HTML payload to execute code in the SOC dashboard.
- **Mitigation**:
  - React 18 JSX default text auto-escaping renders all strings as pure text.
  - Zero use of `dangerouslySetInnerHTML` for untrusted event payloads.
  - Strict Content-Security Headers on FastAPI API responses.

### Attack Tree 3: External Network Ingress & Unauthorized API Access
- **Goal**: Remote attacker on the LAN attempts to query Agni's endpoints or retrieve host telemetry.
- **Mitigation**:
  - FastAPI lifespan enforces loopback verification during boot:
    ```python
    if not verify_loopback_host(settings.HOST, settings.ALLOW_EXTERNAL_BIND):
        raise RuntimeError("Binding to host is prohibited without explicit authorization.")
    ```
  - External network interfaces (`0.0.0.0`, `192.168.x.x`) are rejected outright.
