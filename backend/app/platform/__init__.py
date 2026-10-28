"""
Agni Platform Collector Auto-Detection Factory
Detects host platform (Windows, Linux, macOS) and exports appropriate collector.
"""

import sys

from app.platform.base import (
    InterfaceInfo,
    NetworkDeviceInfo,
    PersistenceEntry,
    PlatformCollectorABC,
    ProcessInfo,
    SocketInfo,
    SystemTelemetry,
)

_COLLECTOR_INSTANCE: PlatformCollectorABC | None = None


def get_platform_collector() -> PlatformCollectorABC:
    """
    Return the singleton PlatformCollectorABC implementation for the current OS.
    Automatically detects 'win32', 'linux', or 'darwin'.
    """
    global _COLLECTOR_INSTANCE
    if _COLLECTOR_INSTANCE is not None:
        return _COLLECTOR_INSTANCE

    os_plat = sys.platform.lower()

    if os_plat.startswith("win"):
        from app.platform.windows import WindowsPlatformCollector
        _COLLECTOR_INSTANCE = WindowsPlatformCollector()
    elif os_plat.startswith("linux"):
        from app.platform.linux import LinuxPlatformCollector
        _COLLECTOR_INSTANCE = LinuxPlatformCollector()
    elif os_plat.startswith("darwin"):
        from app.platform.darwin import MacOSPlatformCollector
        _COLLECTOR_INSTANCE = MacOSPlatformCollector()
    else:
        # Fallback to Generic Linux/Unix collector with graceful degradation
        from app.platform.linux import LinuxPlatformCollector
        _COLLECTOR_INSTANCE = LinuxPlatformCollector()

    return _COLLECTOR_INSTANCE


def reset_platform_collector() -> None:
    """Reset cached collector instance (useful during testing/mocking)."""
    global _COLLECTOR_INSTANCE
    _COLLECTOR_INSTANCE = None


__all__ = [
    "get_platform_collector",
    "reset_platform_collector",
    "PlatformCollectorABC",
    "ProcessInfo",
    "SocketInfo",
    "InterfaceInfo",
    "NetworkDeviceInfo",
    "PersistenceEntry",
    "SystemTelemetry",
]
