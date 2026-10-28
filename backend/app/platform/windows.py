"""
Agni Windows Platform Collector
Implementation using psutil, winreg, and native Windows command parsing.
"""

import os
import platform
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

try:
    import winreg
except ImportError:
    winreg = None


class WindowsPlatformCollector(PlatformCollectorABC):
    """Windows telemetry collector implementing PlatformCollectorABC."""

    def __init__(self) -> None:
        self.os_name = "Windows"
        self._agni_pid = os.getpid()

    def get_capabilities(self) -> dict[str, bool]:
        return {
            "process_inventory": psutil is not None,
            "network_sockets": psutil is not None,
            "network_interfaces": psutil is not None,
            "arp_cache": True,
            "registry_persistence": winreg is not None,
            "startup_folder_persistence": True,
            "systemd_persistence": False,
            "launchd_persistence": False,
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
                pid = info["pid"]

                try:
                    cpu = proc.cpu_percent(interval=None)
                    mem_info = proc.memory_info()
                    mem_percent = proc.memory_percent()
                    rss = mem_info.rss
                    vms = mem_info.vms
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    cpu = 0.0
                    rss = 0
                    vms = 0
                    mem_percent = 0.0

                ctime = datetime.fromtimestamp(info.get("create_time", 0.0), tz=UTC)
                clean_cmd = sanitize_cmdline(info.get("cmdline"))

                results.append(
                    ProcessInfo(
                        pid=pid,
                        ppid=info.get("ppid"),
                        name=info.get("name") or "unknown",
                        exe=info.get("exe"),
                        cmdline=clean_cmd,
                        username=info.get("username"),
                        status=info.get("status") or "running",
                        cpu_percent=cpu,
                        memory_rss=rss,
                        memory_vms=vms,
                        memory_percent=mem_percent,
                        create_time=ctime,
                        num_threads=info.get("num_threads") or 1,
                        access_restricted=False,
                    )
                )
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                try:
                    pid = proc.pid
                    name = proc.name()
                except Exception:
                    pid = -1
                    name = "system"
                results.append(
                    ProcessInfo(
                        pid=pid,
                        ppid=None,
                        name=name,
                        exe=None,
                        cmdline=[],
                        username=None,
                        status="running",
                        cpu_percent=0.0,
                        memory_rss=0,
                        memory_vms=0,
                        memory_percent=0.0,
                        create_time=datetime.now(UTC),
                        num_threads=1,
                        access_restricted=True,
                    )
                )
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
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        results: list[SocketInfo] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return []
        except Exception:
            return []

        for conn in connections:
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
                        access_restricted=False,
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
                family_val = getattr(snic, "family", None)
                if family_val == -1 or (hasattr(snic.family, "name") and snic.family.name == "AF_LINK"):
                    mac = normalize_mac(snic.address)
                elif hasattr(snic.family, "name") and snic.family.name == "AF_INET":
                    ipv4_list.append(snic.address)
                    if snic.netmask:
                        netmask = snic.netmask
                    if snic.broadcast:
                        broadcast = snic.broadcast
                elif hasattr(snic.family, "name") and snic.family.name == "AF_INET6":
                    ipv6_clean = snic.address.split("%")[0]
                    ipv6_list.append(ipv6_clean)

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
        """
        Query Windows native ARP cache table using non-shell subprocess.
        Parses `arp -a` output, normalizes MAC addresses, and filters broadcast/multicast.
        """
        entries: list[NetworkDeviceInfo] = []
        try:
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5.0,
            )
            if proc.returncode != 0 or not proc.stdout:
                return []
        except Exception:
            return []

        current_interface: str | None = None
        now = datetime.now(UTC)

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("Interface:"):
                parts = line.split()
                if len(parts) >= 2:
                    current_interface = parts[1]
                continue

            m = re.match(r"^([\d\.]+)\s+([0-9a-fA-F-]+)\s+(\w+)", line)
            if not m:
                continue

            ip, raw_mac, entry_type = m.groups()
            norm_mac = normalize_mac(raw_mac)

            if is_multicast_or_broadcast(ip, norm_mac):
                continue

            vendor = resolve_oui_vendor(norm_mac)
            is_gw = (
                current_interface is not None
                and ip == f"{current_interface.rsplit('.', 1)[0]}.1"
            )

            entries.append(
                NetworkDeviceInfo(
                    ip_address=ip,
                    mac_address=norm_mac,
                    interface_name=current_interface,
                    entry_type=entry_type.lower(),
                    vendor=vendor,
                    is_gateway=is_gw,
                    first_seen=now,
                    last_seen=now,
                )
            )

        return entries

    def get_persistence_entries(self) -> list[PersistenceEntry]:
        """Inspect Windows registry Run/RunOnce keys and User/Common Startup directories."""
        entries: list[PersistenceEntry] = []

        # 1. Registry Run & RunOnce keys
        if winreg is not None:
            registry_targets = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
            ]

            for hkey_root, subkey, label in registry_targets:
                try:
                    with winreg.OpenKey(hkey_root, subkey, 0, winreg.KEY_READ) as key:
                        num_values = winreg.QueryInfoKey(key)[1]
                        for idx in range(num_values):
                            try:
                                name, val, val_type = winreg.EnumValue(key, idx)
                                val_str = str(val)
                                target_file = val_str.split()[0].strip('"') if val_str else ""
                                args = val_str[len(target_file):].strip() if len(val_str) > len(target_file) else None
                                indicators = inspect_suspicious_persistence(target_file, args)

                                entries.append(
                                    PersistenceEntry(
                                        entry_id=f"winreg_{label}_{name}",
                                        name=name,
                                        target_path=target_file,
                                        location_type="registry_run",
                                        location_detail=f"{label}\\{name}",
                                        arguments=args,
                                        enabled=True,
                                        suspicious_indicators=indicators,
                                    )
                                )
                            except Exception:
                                continue
                except (FileNotFoundError, PermissionError):
                    continue
                except Exception:
                    continue

        # 2. Windows Startup Folders
        startup_paths = []
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup_paths.append(
                (Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup", "user_startup")
            )
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            startup_paths.append(
                (Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup", "common_startup")
            )

        for folder, label in startup_paths:
            if not folder.exists():
                continue
            try:
                for item in folder.iterdir():
                    if item.is_file():
                        indicators = inspect_suspicious_persistence(str(item))
                        entries.append(
                            PersistenceEntry(
                                entry_id=f"startup_{label}_{item.name}",
                                name=item.name,
                                target_path=str(item),
                                location_type="startup_folder",
                                location_detail=str(folder),
                                arguments=None,
                                enabled=True,
                                suspicious_indicators=indicators,
                            )
                        )
            except Exception:
                continue

        return entries

    def get_system_telemetry(self) -> SystemTelemetry:
        """Collect host vitals, memory/CPU usage, uptime, and Agni process metrics."""
        hostname = platform.node()
        os_version = platform.version()
        arch = platform.machine()

        cpu_usage = 0.0
        mem_total = 0
        mem_used = 0
        mem_pct = 0.0
        disk_total = 0
        disk_used = 0
        disk_pct = 0.0
        boot_time_dt = datetime.now(UTC)
        uptime = 0.0

        if psutil is not None:
            try:
                cpu_usage = psutil.cpu_percent(interval=None)
                vm = psutil.virtual_memory()
                mem_total = vm.total
                mem_used = vm.used
                mem_pct = vm.percent

                disk = psutil.disk_usage(os.path.abspath(os.sep))
                disk_total = disk.total
                disk_used = disk.used
                disk_pct = disk.percent

                btime = psutil.boot_time()
                boot_time_dt = datetime.fromtimestamp(btime, tz=UTC)
                uptime = (datetime.now(UTC) - boot_time_dt).total_seconds()
            except Exception:
                pass

        agni_rss = 0.0
        agni_cpu = 0.0
        if psutil is not None:
            try:
                curr_p = psutil.Process(self._agni_pid)
                agni_rss = curr_p.memory_info().rss / (1024 * 1024)
                agni_cpu = curr_p.cpu_percent(interval=None)
            except Exception:
                pass

        return SystemTelemetry(
            hostname=hostname,
            os_name="Windows",
            os_version=os_version,
            architecture=arch,
            cpu_usage_percent=cpu_usage,
            memory_total_bytes=mem_total,
            memory_used_bytes=mem_used,
            memory_percent=mem_pct,
            disk_total_bytes=disk_total,
            disk_used_bytes=disk_used,
            disk_percent=disk_pct,
            boot_time=boot_time_dt,
            uptime_seconds=uptime,
            python_version=sys.version.split()[0],
            agni_process_pid=self._agni_pid,
            agni_memory_rss_mb=agni_rss,
            agni_cpu_percent=agni_cpu,
        )
