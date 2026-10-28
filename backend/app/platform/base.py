"""
Agni Platform Collection Abstraction Layer
Base classes, data models, and common telemetry utilities.
"""

import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Data Models / Transfer Objects
# ---------------------------------------------------------------------------

@dataclass
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str
    exe: str | None
    cmdline: list[str]
    username: str | None
    status: str
    cpu_percent: float
    memory_rss: int
    memory_vms: int
    memory_percent: float
    create_time: datetime
    num_threads: int
    access_restricted: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "username": self.username,
            "status": self.status,
            "cpu_percent": round(self.cpu_percent, 2),
            "memory_rss": self.memory_rss,
            "memory_vms": self.memory_vms,
            "memory_percent": round(self.memory_percent, 2),
            "create_time": self.create_time.isoformat(),
            "num_threads": self.num_threads,
            "access_restricted": self.access_restricted,
            "details": self.details,
        }


@dataclass
class SocketInfo:
    pid: int | None
    process_name: str | None
    protocol: str  # TCP or UDP
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    status: str  # ESTABLISHED, LISTEN, TIME_WAIT, CLOSE_WAIT, etc.
    family: str = "IPv4"  # IPv4 or IPv6
    is_outbound: bool = False
    access_restricted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name or "SYSTEM",
            "protocol": self.protocol,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "status": self.status,
            "family": self.family,
            "is_outbound": self.is_outbound,
            "access_restricted": self.access_restricted,
        }


@dataclass
class InterfaceInfo:
    name: str
    mac_address: str | None
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    netmask: str | None = None
    broadcast: str | None = None
    is_up: bool = False
    speed_mbps: int = 0
    mtu: int = 1500

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mac_address": self.mac_address,
            "ipv4_addresses": self.ipv4_addresses,
            "ipv6_addresses": self.ipv6_addresses,
            "netmask": self.netmask,
            "broadcast": self.broadcast,
            "is_up": self.is_up,
            "speed_mbps": self.speed_mbps,
            "mtu": self.mtu,
        }


@dataclass
class NetworkDeviceInfo:
    ip_address: str
    mac_address: str
    interface_name: str | None
    entry_type: str  # dynamic or static
    vendor: str | None = None
    is_gateway: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "interface_name": self.interface_name,
            "entry_type": self.entry_type,
            "vendor": self.vendor,
            "is_gateway": self.is_gateway,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class PersistenceEntry:
    entry_id: str
    name: str
    target_path: str
    location_type: str  # registry_run, startup_folder, systemd_service, launch_agent, cron
    location_detail: str  # e.g., HKLM\... or /etc/systemd/system/...
    arguments: str | None = None
    enabled: bool = True
    suspicious_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "name": self.name,
            "target_path": self.target_path,
            "location_type": self.location_type,
            "location_detail": self.location_detail,
            "arguments": self.arguments,
            "enabled": self.enabled,
            "suspicious_indicators": self.suspicious_indicators,
        }


@dataclass
class SystemTelemetry:
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    cpu_usage_percent: float
    memory_total_bytes: int
    memory_used_bytes: int
    memory_percent: float
    disk_total_bytes: int
    disk_used_bytes: int
    disk_percent: float
    boot_time: datetime
    uptime_seconds: float
    python_version: str
    agni_process_pid: int
    agni_memory_rss_mb: float
    agni_cpu_percent: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "cpu_usage_percent": round(self.cpu_usage_percent, 2),
            "memory_total_bytes": self.memory_total_bytes,
            "memory_used_bytes": self.memory_used_bytes,
            "memory_percent": round(self.memory_percent, 2),
            "disk_total_bytes": self.disk_total_bytes,
            "disk_used_bytes": self.disk_used_bytes,
            "disk_percent": round(self.disk_percent, 2),
            "boot_time": self.boot_time.isoformat(),
            "uptime_seconds": round(self.uptime_seconds, 1),
            "python_version": self.python_version,
            "agni_process_pid": self.agni_process_pid,
            "agni_memory_rss_mb": round(self.agni_memory_rss_mb, 2),
            "agni_cpu_percent": round(self.agni_cpu_percent, 2),
        }


# ---------------------------------------------------------------------------
# Common Utility Functions
# ---------------------------------------------------------------------------

COMMON_OUI_VENDORS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1a:11": "Google",
    "00:1c:b3": "Apple",
    "3c:07:54": "Apple",
    "f0:18:98": "Apple",
    "00:1b:21": "Intel",
    "f4:4d:30": "Intel",
    "00:25:90": "Supermicro",
    "00:1e:67": "Intel Corporate",
    "70:85:c2": "ASRock",
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC address string to lower-case colon-separated format."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(clean) == 12:
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return mac.replace("-", ":").lower()


def is_multicast_or_broadcast(ip: str, mac: str) -> bool:
    """Check if an IP or MAC address is a broadcast or multicast address."""
    norm_mac = normalize_mac(mac)
    if norm_mac == "ff:ff:ff:ff:ff:ff":
        return True
    if norm_mac.startswith("01:00:5e") or norm_mac.startswith("33:33"):
        return True

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_multicast:
            return True
        if str(ip).endswith(".255") or str(ip) == "255.255.255.255":
            return True
    except ValueError:
        pass

    return False


def resolve_oui_vendor(mac: str) -> str | None:
    """Resolve hardware vendor from the first 3 octets of MAC address."""
    norm = normalize_mac(mac)
    prefix = norm[:8]
    return COMMON_OUI_VENDORS.get(prefix)


def is_private_ip(ip: str) -> bool:
    """Check if an IP address belongs to RFC1918 or link-local range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def sanitize_cmdline(cmdline_raw: Any) -> list[str]:
    """Sanitize process command line strings against null bytes and control chars."""
    if not cmdline_raw:
        return []
    if isinstance(cmdline_raw, str):
        cmdline_raw = [cmdline_raw]

    clean_args: list[str] = []
    for arg in cmdline_raw:
        if arg is None:
            continue
        cleaned = str(arg).replace("\x00", "").strip()
        clean_args.append(cleaned)
    return clean_args


def inspect_suspicious_persistence(path: str, args: str | None = None) -> list[str]:
    """
    Evaluate common malicious persistence heuristics.
    Flags execution from temporary folders, LOLBin abuse, and script flags.
    """
    indicators: list[str] = []
    full_target = f"{path} {args or ''}".lower()

    # 1. Staging from world-writable/temporary folders
    if any(tmp in full_target for tmp in [r"\appdata\local\temp", "/tmp/", "/var/tmp/", r"\temp\\"]):
        indicators.append("STAGING_FROM_TEMP_DIRECTORY")

    # 2. LOLBin invocation with execution/download parameters
    if "powershell" in full_target or "pwsh" in full_target:
        if any(flag in full_target for flag in ["-enc", "-encodedcommand", "-w hidden", "-noni", "downloadstring", "iex"]):
            indicators.append("OBFUSCATED_POWERSHELL_PAYLOAD")

    if "cmd.exe" in full_target and "/c" in full_target:
        indicators.append("SHELL_EXECUTION_WRAPPER")

    if any(lolbin in full_target for lolbin in ["mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"]):
        indicators.append("LOLBIN_AUTOSTART_INVOCATION")

    # 3. Suspicious double extensions
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|bat|cmd|vbs|ps1)", full_target):
        indicators.append("DOUBLE_EXTENSION_DECEPTION")

    return indicators


# ---------------------------------------------------------------------------
# Abstract Base Class: PlatformCollectorABC
# ---------------------------------------------------------------------------

class PlatformCollectorABC(ABC):
    """
    Abstract interface for platform-specific telemetry collectors.
    Concrete implementations exist for Windows, Linux, and macOS.
    """

    @abstractmethod
    def get_processes(self, limit: int = 500) -> list[ProcessInfo]:
        """Enumerate active processes on the host."""
        pass

    @abstractmethod
    def get_network_sockets(self, limit: int = 1000) -> list[SocketInfo]:
        """Enumerate active TCP and UDP sockets with owning PID resolution."""
        pass

    @abstractmethod
    def get_network_interfaces(self) -> list[InterfaceInfo]:
        """Enumerate local physical and virtual network adapters."""
        pass

    @abstractmethod
    def get_arp_cache(self) -> list[NetworkDeviceInfo]:
        """Parse local OS ARP cache table to identify observed neighbor devices."""
        pass

    @abstractmethod
    def get_persistence_entries(self) -> list[PersistenceEntry]:
        """Inspect OS autostart and persistence mechanisms."""
        pass

    @abstractmethod
    def get_system_telemetry(self) -> SystemTelemetry:
        """Collect host vitals, memory/CPU usage, uptime, and Agni process metrics."""
        pass

    @abstractmethod
    def get_capabilities(self) -> dict[str, bool]:
        """Return boolean dictionary of supported capabilities on this platform."""
        pass

    def diff_process_lifecycle(
        self, previous_snapshot: dict[int, float], current_processes: list[ProcessInfo]
    ) -> tuple[list[dict[str, Any]], dict[int, float]]:
        """
        Compute process lifecycle creation and termination events.
        Compares (pid, create_time) pairs to cleanly handle rapid PID reuse.

        Returns:
            Tuple of (lifecycle_events, updated_snapshot_dict)
        """
        current_map: dict[int, ProcessInfo] = {p.pid: p for p in current_processes}
        current_snapshot: dict[int, float] = {
            p.pid: p.create_time.timestamp() for p in current_processes
        }

        events: list[dict[str, Any]] = []

        # Detect Spawned Processes
        for pid, ctime in current_snapshot.items():
            if pid not in previous_snapshot or abs(previous_snapshot[pid] - ctime) > 1.0:
                proc = current_map[pid]
                events.append({
                    "action": "spawned",
                    "pid": proc.pid,
                    "ppid": proc.ppid,
                    "name": proc.name,
                    "path": proc.exe,
                    "cmdline": proc.cmdline,
                    "username": proc.username,
                    "timestamp": datetime.now(UTC).isoformat(),
                })

        # Detect Terminated Processes
        for prev_pid, prev_ctime in previous_snapshot.items():
            if prev_pid not in current_snapshot or abs(current_snapshot[prev_pid] - prev_ctime) > 1.0:
                events.append({
                    "action": "terminated",
                    "pid": prev_pid,
                    "timestamp": datetime.now(UTC).isoformat(),
                })

        return events, current_snapshot
