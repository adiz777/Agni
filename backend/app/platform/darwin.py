"""
Agni macOS (Darwin) Platform Collector
Implementation using psutil, plistlib, LaunchAgents, and launchd inspection.
"""

import os
import platform
import plistlib
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from app.platform.base import (
    InterfaceInfo,
    NetworkDeviceInfo,
    PersistenceEntry,
    PlatformCollectorABC,
    ProcessInfo,
    SocketInfo,
    SystemTelemetry,
    inspect_suspicious_persistence,
    is_multicast_or_broadcast,
    normalize_mac,
    resolve_oui_vendor,
    sanitize_cmdline,
)

try:
    import psutil
except ImportError:
    psutil = None


class MacOSPlatformCollector(PlatformCollectorABC):
    """macOS telemetry collector implementing PlatformCollectorABC."""

    def __init__(self) -> None:
        self.os_name = "macOS"
        self._agni_pid = os.getpid()

    def get_capabilities(self) -> dict[str, bool]:
        return {
            "process_inventory": psutil is not None,
            "network_sockets": psutil is not None,
            "network_interfaces": psutil is not None,
            "arp_cache": True,
            "registry_persistence": False,
            "startup_folder_persistence": False,
            "systemd_persistence": False,
            "launchd_persistence": True,
        }

    def get_processes(self, limit: int = 500) -> list[ProcessInfo]:
        if psutil is None:
            return []

        results: list[ProcessInfo] = []
        for proc in psutil.process_iter(
            attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time", "num_threads"]
        ):
            try:
                info = proc.info
                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem_info = proc.memory_info()
                    mem_pct = proc.memory_percent()
                    rss = mem_info.rss
                    vms = mem_info.vms
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu = 0.0
                    rss = 0
                    vms = 0
                    mem_pct = 0.0

                ctime = datetime.fromtimestamp(info.get("create_time", 0.0), tz=UTC)
                clean_cmd = sanitize_cmdline(info.get("cmdline"))

                results.append(
                    ProcessInfo(
                        pid=info["pid"],
                        ppid=info.get("ppid"),
                        name=info.get("name") or "unknown",
                        exe=info.get("exe"),
                        cmdline=clean_cmd,
                        username=info.get("username"),
                        status=info.get("status") or "running",
                        cpu_percent=cpu,
                        memory_rss=rss,
                        memory_vms=vms,
                        memory_percent=mem_pct,
                        create_time=ctime,
                        num_threads=info.get("num_threads") or 1,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

            if len(results) >= limit:
                break

        return results

    def get_network_sockets(self, limit: int = 1000) -> list[SocketInfo]:
        if psutil is None:
            return []

        pid_map: dict[int, str] = {}
        try:
            for p in psutil.process_iter(attrs=["pid", "name"]):
                try:
                    pid_map[p.info["pid"]] = p.info["name"]
                except Exception:
                    pass
        except Exception:
            pass

        results: list[SocketInfo] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return []

        for conn in conns:
            try:
                proto = "TCP" if conn.type == 1 else "UDP"
                laddr = conn.laddr.ip if conn.laddr else ""
                lport = conn.laddr.port if conn.laddr else 0
                raddr = conn.raddr.ip if conn.raddr else None
                rport = conn.raddr.port if conn.raddr else None
                status = conn.status if conn.status else "NONE"
                family = "IPv6" if ":" in laddr else "IPv4"
                pname = pid_map.get(conn.pid, "SYSTEM" if conn.pid == 0 else "UNKNOWN")

                results.append(
                    SocketInfo(
                        pid=conn.pid,
                        process_name=pname,
                        protocol=proto,
                        local_address=laddr,
                        local_port=lport,
                        remote_address=raddr,
                        remote_port=rport,
                        status=status,
                        family=family,
                        is_outbound=bool(raddr and status == "ESTABLISHED"),
                    )
                )
            except Exception:
                continue
            if len(results) >= limit:
                break
        return results

    def get_network_interfaces(self) -> list[InterfaceInfo]:
        if psutil is None:
            return []

        results: list[InterfaceInfo] = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception:
            return []

        for iface_name, addr_list in addrs.items():
            ipv4_list: list[str] = []
            ipv6_list: list[str] = []
            mac: str | None = None
            netmask: str | None = None
            broadcast: str | None = None

            for snic in addr_list:
                family_name = getattr(snic.family, "name", "")
                if family_name in ("AF_LINK", "AF_PACKET") or snic.family == 18:
                    mac = normalize_mac(snic.address)
                elif family_name == "AF_INET" or snic.family == 2:
                    ipv4_list.append(snic.address)
                    if snic.netmask:
                        netmask = snic.netmask
                    if snic.broadcast:
                        broadcast = snic.broadcast
                elif family_name == "AF_INET6" or snic.family == 30:
                    ipv6_list.append(snic.address.split("%")[0])

            stat = stats.get(iface_name)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else 0
            mtu = stat.mtu if stat else 1500

            results.append(
                InterfaceInfo(
                    name=iface_name,
                    mac_address=mac,
                    ipv4_addresses=ipv4_list,
                    ipv6_addresses=ipv6_list,
                    netmask=netmask,
                    broadcast=broadcast,
                    is_up=is_up,
                    speed_mbps=speed,
                    mtu=mtu,
                )
            )
        return results

    def get_arp_cache(self) -> list[NetworkDeviceInfo]:
        """Parse macOS `arp -an` non-shell output."""
        entries: list[NetworkDeviceInfo] = []
        now = datetime.now(UTC)
        try:
            proc = subprocess.run(["arp", "-an"], capture_output=True, text=True, shell=False, timeout=5.0)
            if proc.returncode != 0 or not proc.stdout:
                return []
        except Exception:
            return []

        for line in proc.stdout.splitlines():
            m = re.match(r"\?\s+\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\w+)", line)
            if not m:
                continue

            ip, raw_mac, iface = m.groups()
            norm_mac = normalize_mac(raw_mac)
            if is_multicast_or_broadcast(ip, norm_mac):
                continue

            vendor = resolve_oui_vendor(norm_mac)
            entries.append(
                NetworkDeviceInfo(
                    ip_address=ip,
                    mac_address=norm_mac,
                    interface_name=iface,
                    entry_type="dynamic",
                    vendor=vendor,
                    is_gateway=False,
                    first_seen=now,
                    last_seen=now,
                )
            )

        return entries

    def get_persistence_entries(self) -> list[PersistenceEntry]:
        """Inspect macOS LaunchAgents and LaunchDaemons plist files."""
        entries: list[PersistenceEntry] = []
        launch_dirs = [
            os.path.expanduser("~/Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]

        for l_dir in launch_dirs:
            p = Path(l_dir)
            if not p.exists() or not p.is_dir():
                continue

            try:
                for plist_file in p.glob("*.plist"):
                    try:
                        with open(plist_file, "rb") as f:
                            data = plistlib.load(f)

                        label = data.get("Label", plist_file.name)
                        prog = data.get("Program")
                        args = data.get("ProgramArguments")
                        target_str = prog or (args[0] if args else str(plist_file))
                        args_str = " ".join(args[1:]) if args and len(args) > 1 else None

                        indicators = inspect_suspicious_persistence(target_str, args_str)
                        entries.append(
                            PersistenceEntry(
                                entry_id=f"launchd_{label}",
                                name=label,
                                target_path=target_str,
                                location_type="launch_agent",
                                location_detail=str(plist_file),
                                arguments=args_str,
                                enabled=data.get("RunAtLoad", True),
                                suspicious_indicators=indicators,
                            )
                        )
                    except Exception:
                        continue
            except Exception:
                continue

        return entries

    def get_system_telemetry(self) -> SystemTelemetry:
        now = datetime.now(UTC)
        hostname = platform.node()
        os_ver = platform.mac_ver()[0] or platform.release()
        arch = platform.machine()
        py_ver = sys.version.split()[0]

        cpu_pct = 0.0
        mem_total = 0
        mem_used = 0
        mem_pct = 0.0
        disk_total = 0
        disk_used = 0
        disk_pct = 0.0
        boot_dt = now
        uptime_sec = 0.0
        agni_rss = 0.0
        agni_cpu = 0.0

        if psutil is not None:
            try:
                cpu_pct = psutil.cpu_percent(interval=None)
                vm = psutil.virtual_memory()
                mem_total = vm.total
                mem_used = vm.used
                mem_pct = vm.percent

                disk = psutil.disk_usage("/")
                disk_total = disk.total
                disk_used = disk.used
                disk_pct = disk.percent

                boot_dt = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
                uptime_sec = (now - boot_dt).total_seconds()

                self_proc = psutil.Process(self._agni_pid)
                agni_rss = self_proc.memory_info().rss / (1024 * 1024)
                agni_cpu = self_proc.cpu_percent(interval=None)
            except Exception:
                pass

        return SystemTelemetry(
            hostname=hostname,
            os_name="macOS",
            os_version=os_ver,
            architecture=arch,
            cpu_usage_percent=cpu_pct,
            memory_total_bytes=mem_total,
            memory_used_bytes=mem_used,
            memory_percent=mem_pct,
            disk_total_bytes=disk_total,
            disk_used_bytes=disk_used,
            disk_percent=disk_pct,
            boot_time=boot_dt,
            uptime_seconds=uptime_sec,
            python_version=py_ver,
            agni_process_pid=self._agni_pid,
            agni_memory_rss_mb=agni_rss,
            agni_cpu_percent=agni_cpu,
        )
