# Security Policy

Agni (अग्नि) is built from the ground up as a **local-first, privacy-preserving defensive endpoint detection and SOC monitoring platform**. Because Agni operates directly alongside operating system kernels and processes, security integrity and non-destructiveness are first-order engineering constraints.

---

## Supported Versions

| Version | Supported          | Security Maintenance Status |
| ------- | ------------------ | --------------------------- |
| 1.0.x   | :white_check_mark: | Current Active Release      |
| < 1.0   | :x:                | Unsupported Development     |

---

## Security Model & Architectural Boundaries

Agni enforces strict security boundaries designed to prevent the monitoring platform itself from introducing attack surface:

1. **Strict Local Loopback Binding (Defense in Depth)**:
   - By default, Agni binds exclusively to `127.0.0.1` (`localhost`).
   - Binding to `0.0.0.0` or external network interfaces is rejected during startup unless explicitly overridden via `AGNI_ALLOW_EXTERNAL_BIND=true`.
   - The React frontend dashboard communicates only over loopback via localhost or unix sockets.

2. **Zero-Exfiltration & Local-First Processing**:
   - All host telemetry, process snapshots, file hashes, and network tables remain on the local machine.
   - Database operations use local SQLite with Write-Ahead Logging (WAL) and synchronous transactions.
   - Telemetry scrubbing removes PII, environment variables, credentials, and user tokens prior to storage.

3. **Non-Destructive Observation**:
   - Sensor collectors run in read-only observation mode.
   - Agni does **not** inject code, patch kernel binaries, or execute autonomous kill commands without explicit human analyst interaction.
   - Privilege degradation: if run as an unprivileged user, Agni degrades gracefully to monitoring current-user processes rather than failing or requesting privilege elevation unsafely.

4. **Tamper-Evident Cryptographic Audit Trail**:
   - Every analyst disposition, rule update, and configuration change is appended to a cryptographic hash-chained audit log (SHA-256 with sequence verification).
   - Tampering with prior audit log entries breaks the cryptochain and triggers immediate dashboard warnings.

---

## Reporting a Security Vulnerability

If you discover a security vulnerability, security bypass, or unintended exposure in Agni, please do **not** open a public issue. Follow our responsible disclosure process:

1. **Email Vulnerability Details**:
   - Send an encrypted or direct email to **Aditya Zala**: `adizala7303@gmail.com`
   - Include `[SECURITY REPORT] Agni Vulnerability` in the subject line.
2. **Include in Your Report**:
   - Detailed description of the vulnerability and attack vector.
   - Step-by-step reproduction instructions or a minimal proof-of-concept.
   - Operating system and version where the issue was observed.
   - Threat impact assessment (e.g., local privilege escalation, memory exhaustion, CORS escape).
3. **Disclosure Timeline**:
   - **Initial Acknowledgement**: Within 24-48 hours.
   - **Triage & Status Update**: Within 72 hours.
   - **Remediation & Patch Release**: Typically within 14 business days, coordinated with you before public disclosure.

---

## Safe Harbor Policy

Security researchers conducting vulnerability research on Agni within the bounds of this policy:
- Will not be subjected to legal action or copyright/reverse-engineering claims.
- Will be credited in release notes and security advisories (unless anonymity is requested).
- Are requested to test only against local standalone installations and never against unauthorized third-party systems.
