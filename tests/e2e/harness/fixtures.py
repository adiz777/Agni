"""Test fixtures, sample telemetry events, detection rules, and intrusion scenarios for Agni E2E testing."""

from __future__ import annotations

import datetime
import uuid
from typing import Any


def generate_event_id() -> str:
    """Generate a valid UUID4 event identifier."""
    return str(uuid.uuid4())


def now_iso() -> str:
    """Return current UTC ISO 8601 timestamp."""
    return datetime.datetime.now(datetime.UTC).isoformat()


# The 18 Curated Defensive Detection Rules (from Agni specification)
DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "AGNI-R-PROC-001",
        "name": "Encoded PowerShell Command Execution",
        "description": "Detects execution of PowerShell with Base64 encoded command arguments (-enc, -encodedcommand).",
        "severity": "High",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "and": [
                {"field": "actor.name", "operator": "in", "value": ["powershell.exe", "pwsh.exe", "pwsh"]},
                {"field": "actor.cmdline", "operator": "regex", "value": "(?i)-(?:e|enc|encodedcommand)\\s+[A-Za-z0-9+/=]{10,}"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Adversaries leverage PowerShell's -EncodedCommand parameter to execute obfuscated scripts.",
        "investigation_steps": [
            "Decode the Base64 command string found in actor.cmdline.",
            "Check parent process to determine what launched PowerShell.",
            "Inspect network connections from this PID for C2 traffic.",
        ],
        "mitre_attack": "T1059.001",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-002",
        "name": "Certutil Suspicious Remote Download / Decode",
        "description": "Detects certutil.exe invoked with -urlcache, -split, or -decode flags.",
        "severity": "High",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "and": [
                {"field": "actor.name", "operator": "equals", "value": "certutil.exe"},
                {"field": "actor.cmdline", "operator": "regex", "value": "(?i)-(?:urlcache|split|decode)"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Certutil is a LOLBin frequently abused to download remote payloads.",
        "investigation_steps": [
            "Extract target URL from cmdline.",
            "Check FIM events for files created in destination directory.",
        ],
        "mitre_attack": "T1105",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-003",
        "name": "Shadow Copy Deletion Attempt via Vssadmin",
        "description": "Detects execution of vssadmin.exe attempting to delete volume shadow copies.",
        "severity": "Critical",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "and": [
                {"field": "actor.name", "operator": "equals", "value": "vssadmin.exe"},
                {"field": "actor.cmdline", "operator": "regex", "value": "(?i)delete\\s+shadows"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Ransomware operators routinely execute vssadmin delete shadows to prevent recovery.",
        "investigation_steps": [
            "Inspect all active processes under parent PID.",
            "Review file modification rates for ransomware encryption.",
        ],
        "mitre_attack": "T1490",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-004",
        "name": "Suspicious Binary Execution from Temporary Directory",
        "description": "Detects executable launch originating from AppData\\Local\\Temp or Unix /tmp directories.",
        "severity": "Medium",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "or": [
                {"field": "actor.path", "operator": "regex", "value": r"(?i)\\AppData\\Local\\Temp\\[^\\]+\.exe"},
                {"field": "actor.path", "operator": "regex", "value": r"^/tmp/[^/]+$"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Droppers frequently stage secondary executables inside temporary directories.",
        "investigation_steps": [
            "Compute SHA-256 of binary in temp folder.",
            "Identify dropping process by inspecting parent PID.",
        ],
        "mitre_attack": "T1036.005",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-005",
        "name": "Reconnaissance Command Burst",
        "description": "Detects multiple endpoint discovery commands executed within a short time window.",
        "severity": "Medium",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "field": "actor.name",
            "operator": "in",
            "value": ["whoami.exe", "whoami", "hostname.exe", "hostname", "net.exe", "id", "ipconfig.exe", "ifconfig"],
        },
        "correlation_window": 30,
        "threshold": 3,
        "group_by": "host.hostname",
        "explanation": "Adversaries perform situational discovery immediately after initial access.",
        "investigation_steps": ["Correlate parent process.", "Review user authentication logs."],
        "mitre_attack": "T1082",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-006",
        "name": "Double Extension Executable Execution",
        "description": "Detects execution of a binary disguised with deceptive double extensions.",
        "severity": "High",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "field": "actor.name",
            "operator": "regex",
            "value": r"(?i)\.(?:pdf|docx?|xlsx?|jpg|png|txt)\.exe$",
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Spearphishing tactic using document extension masquerading.",
        "investigation_steps": ["Capture executable for static analysis.", "Check origin location."],
        "mitre_attack": "T1036.007",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-007",
        "name": "Rundll32 Executing Remote or Script Protocol",
        "description": "Detects rundll32.exe executing javascript, vbscript, or remote URL protocols.",
        "severity": "High",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "and": [
                {"field": "actor.name", "operator": "equals", "value": "rundll32.exe"},
                {"field": "actor.cmdline", "operator": "regex", "value": "(?i)(?:javascript|vbscript|mshtml|http)"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Rundll32 with inline script engines is a defense evasion technique.",
        "investigation_steps": ["Inspect command line for script content."],
        "mitre_attack": "T1218.011",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PROC-008",
        "name": "Pipe to Shell Execution (Curl / Wget to Bash)",
        "description": "Detects curl or wget piped directly into a shell interpreter.",
        "severity": "Medium",
        "category": "process",
        "source": "agni_core",
        "match_conditions": {
            "and": [
                {"field": "actor.name", "operator": "in", "value": ["bash", "sh", "zsh"]},
                {"field": "actor.cmdline", "operator": "regex", "value": r"(?i)(?:curl|wget).*(?:bash|sh)"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Direct pipe to shell executes unverified remote code.",
        "investigation_steps": ["Inspect remote URL."],
        "mitre_attack": "T1059.004",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-FIM-001",
        "name": "System Hosts File Modification",
        "description": "Detects alteration of the operating system hosts resolution file.",
        "severity": "High",
        "category": "file_integrity",
        "source": "fim",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "file_integrity"},
                {"field": "action", "operator": "in", "value": ["modified", "created"]},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)(?:etc[/\\]hosts|drivers[/\\]etc[/\\]hosts)"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Adversaries modify hosts to hijack domains or block security updates.",
        "investigation_steps": ["Review diff in hosts file."],
        "mitre_attack": "T1565.001",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-FIM-002",
        "name": "Critical System Binary Integrity Violation",
        "description": "Detects modification of core system executables.",
        "severity": "Critical",
        "category": "file_integrity",
        "source": "fim",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "file_integrity"},
                {"field": "action", "operator": "equals", "value": "modified"},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)(?:/bin/|/usr/bin/|system32/)[^/\\]+\.(?:exe|dll|so)$"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Binary replacement indicates advanced persistence or Trojanization.",
        "investigation_steps": ["Compare SHA-256 with vendor-known good hashes."],
        "mitre_attack": "T1574.001",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-FIM-003",
        "name": "SSH Authorized Keys File Alteration",
        "description": "Detects addition or modification of SSH authorized_keys file.",
        "severity": "High",
        "category": "file_integrity",
        "source": "fim",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "file_integrity"},
                {"field": "action", "operator": "in", "value": ["modified", "created"]},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)\.ssh/authorized_keys$"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Backdooring authorized_keys provides persistent passwordless access.",
        "investigation_steps": ["Inspect authorized_keys identity/comment."],
        "mitre_attack": "T1098.004",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-FIM-004",
        "name": "Critical Configuration File Deletion",
        "description": "Detects deletion of monitored configuration files.",
        "severity": "Medium",
        "category": "file_integrity",
        "source": "fim",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "file_integrity"},
                {"field": "action", "operator": "equals", "value": "deleted"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Removal of baseline config files may signal anti-forensics.",
        "investigation_steps": ["Verify administrative intent."],
        "mitre_attack": "T1070.004",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-NET-001",
        "name": "Outbound Connection to Known Reverse Shell / C2 Port",
        "description": "Detects active TCP connection to known reverse shell ports (4444, 5555, 1337, 6667, 9001).",
        "severity": "High",
        "category": "network",
        "source": "vayu",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "network"},
                {"field": "action", "operator": "equals", "value": "connected"},
                {"field": "details.remote_port", "operator": "in", "value": [4444, 5555, 1337, 6667, 9001, 31337]},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "Default frameworks use ports like 4444 for C2 listeners.",
        "investigation_steps": ["Identify owning PID.", "Check destination IP."],
        "mitre_attack": "T1571",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-NET-002",
        "name": "LOLBin Outbound Network Connection",
        "description": "Detects network connection established by administrative utilities (certutil, cmd, rundll32).",
        "severity": "Medium",
        "category": "network",
        "source": "vayu",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "network"},
                {"field": "actor.name", "operator": "in", "value": ["certutil.exe", "cmd.exe", "rundll32.exe", "vssadmin.exe"]},
                {"field": "details.status", "operator": "in", "value": ["ESTABLISHED", "SYN_SENT"]},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "actor.pid",
        "explanation": "LOLBins connecting externally indicate payload download or C2 check-in.",
        "investigation_steps": ["Review full command line."],
        "mitre_attack": "T1105",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-NET-003",
        "name": "Rapid Outbound Socket Burst (Potential Port Scan / Exfil)",
        "description": "Detects a process opening multiple unique outbound sockets rapidly.",
        "severity": "Medium",
        "category": "network",
        "source": "vayu",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "network"},
                {"field": "action", "operator": "equals", "value": "connected"},
            ]
        },
        "correlation_window": 15,
        "threshold": 20,
        "group_by": "actor.pid",
        "explanation": "High velocity outbound socket creation indicates scanning or exfiltration.",
        "investigation_steps": ["Identify PID and target destinations."],
        "mitre_attack": "T1046",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PERS-001",
        "name": "Windows Registry Run Key Persistence Added",
        "description": "Detects addition of startup program under CurrentVersion\\Run registry keys.",
        "severity": "High",
        "category": "persistence",
        "source": "persistence_monitor",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "persistence"},
                {"field": "action", "operator": "equals", "value": "created"},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)CurrentVersion\\Run"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Registry Run keys automatically execute registered binaries on login.",
        "investigation_steps": ["Inspect path and command in registry value."],
        "mitre_attack": "T1547.001",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PERS-002",
        "name": "Startup Folder Shortcut / Executable Dropped",
        "description": "Detects new executable or shortcut created in Startup folders.",
        "severity": "High",
        "category": "persistence",
        "source": "persistence_monitor",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "persistence"},
                {"field": "action", "operator": "equals", "value": "created"},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)Programs[/\\]Startup"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Dropping shortcuts in Startup folder guarantees launch on user logon.",
        "investigation_steps": ["Inspect shortcut target path."],
        "mitre_attack": "T1547.001",
        "version": "1.0.0",
        "enabled": True,
    },
    {
        "id": "AGNI-R-PERS-003",
        "name": "New Systemd Service or LaunchAgent Created",
        "description": "Detects creation of a new unit in /etc/systemd/system or LaunchAgent in ~/Library/LaunchAgents.",
        "severity": "High",
        "category": "persistence",
        "source": "persistence_monitor",
        "match_conditions": {
            "and": [
                {"field": "category", "operator": "equals", "value": "persistence"},
                {"field": "action", "operator": "equals", "value": "created"},
                {"field": "target.identifier", "operator": "regex", "value": r"(?i)(?:systemd/system|LaunchAgents)/[^/]+\.(?:service|plist)$"},
            ]
        },
        "correlation_window": 0,
        "threshold": 1,
        "group_by": "target.identifier",
        "explanation": "Adversaries install services or LaunchAgents to survive reboots.",
        "investigation_steps": ["Read ExecStart or ProgramArguments."],
        "mitre_attack": "T1543.002",
        "version": "1.0.0",
        "enabled": True,
    },
]


# Standard Telemetry Event Factories
def make_process_event(
    name: str,
    cmdline: str,
    pid: int = 1234,
    ppid: int = 400,
    path: str = "C:\\Windows\\System32\\cmd.exe",
    is_sample: bool = False,
) -> dict[str, Any]:
    return {
        "event_id": generate_event_id(),
        "timestamp": now_iso(),
        "event_version": "1.0.0",
        "category": "process",
        "action": "spawned",
        "severity": "Medium",
        "source": "agni_core",
        "host": {"hostname": "TestHost", "os": "Windows", "os_version": "10.0.19045"},
        "actor": {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "path": path,
            "cmdline": cmdline,
            "user": "TestHost\\TestUser",
        },
        "target": {"type": "process", "identifier": name, "details": {}},
        "details": {"parent_name": "explorer.exe"},
        "is_sample": is_sample,
    }


def make_network_event(
    remote_ip: str,
    remote_port: int,
    pid: int = 1234,
    process_name: str = "test.exe",
    status: str = "ESTABLISHED",
    is_sample: bool = False,
) -> dict[str, Any]:
    return {
        "event_id": generate_event_id(),
        "timestamp": now_iso(),
        "event_version": "1.0.0",
        "category": "network",
        "action": "connected",
        "severity": "Low",
        "source": "vayu",
        "host": {"hostname": "TestHost", "os": "Windows"},
        "actor": {"pid": pid, "name": process_name},
        "target": {"type": "ip", "identifier": remote_ip},
        "details": {
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": 50123,
            "protocol": "TCP",
            "status": status,
        },
        "is_sample": is_sample,
    }


def make_fim_event(
    file_path: str,
    action: str = "modified",
    previous_sha256: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    current_sha256: str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    is_sample: bool = False,
) -> dict[str, Any]:
    return {
        "event_id": generate_event_id(),
        "timestamp": now_iso(),
        "event_version": "1.0.0",
        "category": "file_integrity",
        "action": action,
        "severity": "High",
        "source": "fim",
        "host": {"hostname": "TestHost", "os": "Windows"},
        "actor": {"pid": 2048, "name": "editor.exe"},
        "target": {"type": "file", "identifier": file_path},
        "details": {
            "file_path": file_path,
            "previous_sha256": previous_sha256,
            "current_sha256": current_sha256,
            "file_size": 1024,
        },
        "is_sample": is_sample,
    }


def make_persistence_event(
    target_identifier: str,
    action: str = "created",
    command: str = "C:\\Temp\\update.exe",
    is_sample: bool = False,
) -> dict[str, Any]:
    return {
        "event_id": generate_event_id(),
        "timestamp": now_iso(),
        "event_version": "1.0.0",
        "category": "persistence",
        "action": action,
        "severity": "High",
        "source": "persistence_monitor",
        "host": {"hostname": "TestHost", "os": "Windows"},
        "actor": {"pid": 3050, "name": "reg.exe"},
        "target": {"type": "registry", "identifier": target_identifier},
        "details": {"command": command, "user_scope": "User"},
        "is_sample": is_sample,
    }


# Adversarial Test Vectors
ADVERSARIAL_PATH_TRAVERSAL_VECTORS = [
    "../../etc/passwd",
    r"..\..\Windows\System32\drivers\etc\hosts",
    "....//....//etc/shadow",
    r"C:\Windows\System32\..\..\..\boot.ini",
    "/var/log/../../etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "safe_file.txt\0/etc/passwd",
]

INVALID_SEVERITY_LEVELS = [
    "UltraCritical",
    "Panic",
    "SevereEmergency",
    "Minor",
    "UNKNOWN_123",
    "",
]

MALFORMED_RULES = [
    # Missing required 'id'
    {"name": "Bad Rule", "severity": "High", "match_conditions": {}},
    # Invalid severity
    {"id": "BAD-01", "name": "Bad Sev", "severity": "Fatal", "match_conditions": {}},
    # Malformed regex in condition
    {
        "id": "BAD-02",
        "name": "Bad Regex",
        "severity": "High",
        "match_conditions": {"field": "actor.name", "operator": "regex", "value": "([a-z++"},
    },
    # Unknown operator
    {
        "id": "BAD-03",
        "name": "Bad Op",
        "severity": "Medium",
        "match_conditions": {"field": "actor.name", "operator": "magic_contains", "value": "cmd"},
    },
]
