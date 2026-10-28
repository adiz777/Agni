# Platform Support & Sensor Capability Matrix

Agni (अग्नि) is architected for cross-platform host observability across **Windows**, **Linux**, and **macOS**. Because system security primitives vary significantly across operating systems, Agni implements platform-tailored sensor collectors with standardized schema normalization and deterministic privilege degradation.

---

## Operating System Capability Matrix

| Feature / Subsystem | Windows 10/11 / Server | Linux (Kernel 5.4+) | macOS (Sonoma / Sequoia) |
| :--- | :---: | :---: | :---: |
| **Process Tree Enumeration** | :white_check_mark: Full (`psutil` + Win32) | :white_check_mark: Full (`psutil` + `/proc`) | :white_check_mark: Full (`psutil` + `sysctl`) |
| **Process Command-line Extraction** | :white_check_mark: (Scrubbed) | :white_check_mark: (Scrubbed) | :white_check_mark: (Scrubbed) |
| **CPU & Memory Metrics (RSS/VMS)** | :white_check_mark: Real-time | :white_check_mark: Real-time | :white_check_mark: Real-time |
| **Active Sockets (TCP/UDP)** | :white_check_mark: Full mapping | :white_check_mark: Full mapping | :white_check_mark: Full mapping |
| **Socket-to-PID Association** | :white_check_mark: Complete | :white_check_mark: Complete | :white_check_mark: Complete |
| **Network Interfaces & Speed** | :white_check_mark: Full adapters | :white_check_mark: Full adapters | :white_check_mark: Full adapters |
| **Passive ARP Table Discovery** | :white_check_mark: Win32 ARP table | :white_check_mark: `/proc/net/arp` / `ip neigh` | :white_check_mark: `arp -an` parser |
| **File Integrity Monitoring (FIM)** | :white_check_mark: Chunked SHA-256 | :white_check_mark: Chunked SHA-256 | :white_check_mark: Chunked SHA-256 |
| **Persistence: Run Keys / Startup** | :white_check_mark: HKCU/HKLM Registry & Startup | :white_check_mark: XDG Autostart | :white_check_mark: `~/Library/LaunchAgents` |
| **Persistence: System Services** | :white_check_mark: Win32 Services | :white_check_mark: systemd units | :white_check_mark: `/Library/LaunchDaemons` |
| **Persistence: Scheduled Tasks** | :white_check_mark: Task Scheduler (`schtasks`) | :white_check_mark: `/etc/crontab`, `/etc/cron.*` | :white_check_mark: `launchd` plist jobs |
| **Varuna Detection Rule Evaluation** | :white_check_mark: 100% Shared AST | :white_check_mark: 100% Shared AST | :white_check_mark: 100% Shared AST |
| **Sliding Window Incident Correlation** | :white_check_mark: 100% Shared AST | :white_check_mark: 100% Shared AST | :white_check_mark: 100% Shared AST |

---

## Privilege Degradation Modes

Agni never requires root or Administrator privileges to execute. When run with varying user permissions, the sensor collector adjusts dynamically:

### Mode A: Standard User (Unprivileged)
- **Monitored Scope**:
  - Full visibility into all child processes, sockets, and memory owned by the current user session.
  - Read access to user autostart items, shell configuration files (`.bashrc`, `.zshrc`, PowerShell profiles), and monitored user directories.
- **Degradation Handling**:
  - Elevated processes belonging to other users or system accounts (`SYSTEM`, `root`, `_spotlight`) have restricted details.
  - Sockets owned by system daemons are marked with `access_restricted=true` and display PID `0` or `None`.
  - The engine health indicator logs status as `sensor: healthy (restricted user mode)` and continues full detection on all accessible telemetry.

### Mode B: Elevated / Administrative (`sudo` or "Run as Administrator")
- **Monitored Scope**:
  - Complete host-wide visibility across all processes, background daemons, system services, and raw network sockets.
  - Inspection of system-level persistence (`HKLM`, `/etc/systemd/system`, `/Library/LaunchDaemons`).
  - FIM baseline verification across protected system directories (`/etc/`, `C:\Windows\System32\drivers\etc\`).

---

## Defensive Boundary Guarantees

1. **Strictly Non-Destructive**:
   Agni strictly operates as a passive observer. No kernel drivers, system file modifications, or process terminates are performed without explicit manual operator confirmation.
2. **Deterministic Memory Footprint**:
   Chunked streaming reads (64KB chunks) for file hashing guarantee that large files do not cause Out-Of-Memory (OOM) conditions.
3. **Loopback Only**:
   The web server and API reject external connections across all operating systems.
