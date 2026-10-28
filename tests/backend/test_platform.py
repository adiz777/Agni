"""
Unit Tests: Platform Collector Abstraction & Graceful Degradation
"""
from datetime import UTC, datetime

from app.platform import get_platform_collector
from app.platform.base import (
    ProcessInfo,
    inspect_suspicious_persistence,
    is_multicast_or_broadcast,
    normalize_mac,
    resolve_oui_vendor,
)


def test_mac_normalization():
    """Verify MAC address normalization across different formats."""
    # Dash separated
    assert normalize_mac("00-0C-29-12-34-56") == "00:0c:29:12:34:56"
    # Colon separated mixed case
    assert normalize_mac("00:0c:29:AB:CD:EF") == "00:0c:29:ab:cd:ef"
    # Raw 12 hex characters
    assert normalize_mac("000c29123456") == "00:0c:29:12:34:56"


def test_multicast_and_broadcast_filtering():
    """Verify broadcast and multicast IPs/MACs are identified."""
    assert is_multicast_or_broadcast("255.255.255.255", "ff:ff:ff:ff:ff:ff") is True
    assert is_multicast_or_broadcast("224.0.0.1", "01:00:5e:00:00:01") is True
    assert is_multicast_or_broadcast("192.168.1.50", "00:0c:29:12:34:56") is False


def test_oui_vendor_lookup():
    """Verify OUI hardware vendor resolution."""
    assert resolve_oui_vendor("00:0c:29:aa:bb:cc") == "VMware"
    assert resolve_oui_vendor("52:54:00:11:22:33") == "QEMU/KVM"
    assert resolve_oui_vendor("b8:27:eb:00:11:22") == "Raspberry Pi"
    assert resolve_oui_vendor("aa:bb:cc:dd:ee:ff") is None


def test_suspicious_persistence_heuristics():
    """Verify suspicious persistence detection flags."""
    indicators = inspect_suspicious_persistence(
        r"C:\Users\User\AppData\Local\Temp\evil.exe",
        "-enc SQBFAFgA",
    )
    assert "STAGING_FROM_TEMP_DIRECTORY" in indicators

    ps_indicators = inspect_suspicious_persistence(
        "powershell.exe",
        "-w hidden -enc SQBFAFgA",
    )
    assert "OBFUSCATED_POWERSHELL_PAYLOAD" in ps_indicators

    clean_indicators = inspect_suspicious_persistence(
        r"C:\Program Files\App\app.exe",
        "--service",
    )
    assert len(clean_indicators) == 0


def test_process_lifecycle_diffing():
    """Verify diff_process_lifecycle accurately identifies spawned and terminated processes."""
    collector = get_platform_collector()
    t0 = datetime.now(UTC)

    # Initial snapshot with PID 100, 200
    prev_snapshot = {
        100: t0.timestamp(),
        200: t0.timestamp(),
    }

    # Current processes: PID 200 (kept), PID 300 (spawned), PID 100 (terminated)
    current_procs = [
        ProcessInfo(
            pid=200,
            ppid=1,
            name="systemd",
            exe="/sbin/init",
            cmdline=["/sbin/init"],
            username="root",
            status="running",
            cpu_percent=0.0,
            memory_rss=1000,
            memory_vms=2000,
            memory_percent=0.1,
            create_time=t0,
            num_threads=1,
        ),
        ProcessInfo(
            pid=300,
            ppid=200,
            name="new_worker",
            exe="/usr/bin/worker",
            cmdline=["worker"],
            username="app",
            status="running",
            cpu_percent=1.0,
            memory_rss=5000,
            memory_vms=10000,
            memory_percent=0.5,
            create_time=datetime.now(UTC),
            num_threads=2,
        ),
    ]

    events, updated_snapshot = collector.diff_process_lifecycle(prev_snapshot, current_procs)

    actions = {e["action"] for e in events}
    assert "spawned" in actions
    assert "terminated" in actions

    spawned = next(e for e in events if e["action"] == "spawned")
    assert spawned["pid"] == 300

    terminated = next(e for e in events if e["action"] == "terminated")
    assert terminated["pid"] == 100


def test_collector_live_execution():
    """Verify current host collector returns non-empty telemetry safely."""
    collector = get_platform_collector()
    assert collector is not None

    procs = collector.get_processes(limit=10)
    assert isinstance(procs, list)
    assert len(procs) > 0

    caps = collector.get_capabilities()
    assert isinstance(caps, dict)
    assert caps.get("process_inventory") is True

    telemetry = collector.get_system_telemetry()
    assert telemetry.hostname != ""
    assert telemetry.python_version != ""
