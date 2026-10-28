#!/usr/bin/env bash
# ==============================================================================
# Clean uninstallation and teardown script for Agni on Unix (Linux / macOS)
# Stops running services, unregisters systemd/launchd, cleans up runtime files.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PID_FILE="$PROJECT_ROOT/agni.pid"
DATA_DIR="$PROJECT_ROOT/data"
PURGE_DATA=false

for arg in "$@"; do
    case "$arg" in
        --purge-data)
            PURGE_DATA=true
            ;;
    esac
done

echo "============================================================"
echo "         Agni Platform Uninstallation & Teardown            "
echo "============================================================"

# 1. Stop running process tree with Anti-PID-Reuse verification
if [ -f "$PID_FILE" ]; then
    TARGET_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$TARGET_PID" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
        PROC_NAME="$(ps -p "$TARGET_PID" -o comm= 2>/dev/null || true)"
        PROC_ARGS="$(ps -p "$TARGET_PID" -o args= 2>/dev/null || true)"
        COMBINED="${PROC_NAME} ${PROC_ARGS}"
        case "$COMBINED" in
            *[Pp]ython*|*[Uu]vicorn*|*[Aa]gni*)
                echo "[*] Terminating Agni process tree (PID: $TARGET_PID)..."
                if command -v pgrep >/dev/null 2>&1; then
                    CHILD_PIDS="$(pgrep -P "$TARGET_PID" 2>/dev/null || true)"
                    for CPID in $CHILD_PIDS; do
                        kill -15 "$CPID" 2>/dev/null || true
                    done
                fi
                kill -15 "$TARGET_PID" 2>/dev/null || true
                sleep 1
                if kill -0 "$TARGET_PID" 2>/dev/null; then
                    kill -9 "$TARGET_PID" 2>/dev/null || true
                fi
                ;;
            *)
                echo "[!] Process $TARGET_PID does not match Agni or Python (Anti-PID-Reuse check). Skipping kill."
                ;;
        esac
    fi
    rm -f "$PID_FILE"
fi

# 2. Linux systemd user service cleanup
if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user is-active --quiet agni.service 2>/dev/null; then
        echo "[*] Stopping systemd user service 'agni.service'..."
        systemctl --user stop agni.service || true
    fi
    if systemctl --user is-enabled --quiet agni.service 2>/dev/null; then
        echo "[*] Disabling systemd user service 'agni.service'..."
        systemctl --user disable agni.service || true
    fi
    SYSTEMD_UNIT="$HOME/.config/systemd/user/agni.service"
    if [ -f "$SYSTEMD_UNIT" ]; then
        rm -f "$SYSTEMD_UNIT"
        systemctl --user daemon-reload || true
        echo "[+] Removed systemd user unit."
    fi
fi

# 3. macOS LaunchAgent cleanup
LAUNCH_AGENT="$HOME/Library/LaunchAgents/com.agni.monitor.plist"
if [ -f "$LAUNCH_AGENT" ]; then
    echo "[*] Unloading macOS LaunchAgent..."
    launchctl unload "$LAUNCH_AGENT" 2>/dev/null || true
    rm -f "$LAUNCH_AGENT"
    echo "[+] Removed macOS LaunchAgent plist."
fi

# 4. Clean runtime PID file
rm -f "$PID_FILE"

# 5. Database data directory
if [ "$PURGE_DATA" = true ]; then
    if [ -d "$DATA_DIR" ]; then
        echo "[!] Purging database directory: $DATA_DIR"
        rm -rf "$DATA_DIR"
        echo "[+] Data purged."
    fi
else
    echo "[+] Preserved telemetry database directory: $DATA_DIR"
    echo "    (Pass --purge-data flag if you wish to remove telemetry records)"
fi

echo ""
echo "[+] Agni uninstallation completed cleanly."
