#!/usr/bin/env bash
# ==============================================================================
# Graceful stop script for Agni on Unix (Linux / macOS)
# Reads agni.pid, verifies process identity, and terminates the process tree.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PID_FILE="$PROJECT_ROOT/agni.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "[i] No agni.pid found. Agni does not appear to be running."
    exit 0
fi

TARGET_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [ -z "$TARGET_PID" ]; then
    echo "[!] agni.pid was empty. Removing."
    rm -f "$PID_FILE"
    exit 0
fi

if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "[i] Process $TARGET_PID is no longer active. Cleaning stale PID file."
    rm -f "$PID_FILE"
    exit 0
fi

# 1. Process Identity Verification (Anti-PID-Reuse)
PROC_NAME="$(ps -p "$TARGET_PID" -o comm= 2>/dev/null || true)"
PROC_ARGS="$(ps -p "$TARGET_PID" -o args= 2>/dev/null || true)"
COMBINED="${PROC_NAME} ${PROC_ARGS}"

case "$COMBINED" in
    *[Pp]ython*|*[Uu]vicorn*|*[Aa]gni*)
        # Valid Agni/Python process
        ;;
    *)
        echo "[!] Process $TARGET_PID does not match Agni or Python (Anti-PID-Reuse check failed)."
        echo "    Process details: $COMBINED"
        echo "    Skipping process termination to avoid killing unrelated workloads."
        rm -f "$PID_FILE"
        exit 1
        ;;
esac

echo "[*] Sending graceful stop signal (SIGTERM) to Agni PID $TARGET_PID..."

# 2. Terminate Child Processes (Process Tree)
if command -v pgrep >/dev/null 2>&1; then
    CHILD_PIDS="$(pgrep -P "$TARGET_PID" 2>/dev/null || true)"
    if [ -n "$CHILD_PIDS" ]; then
        for CPID in $CHILD_PIDS; do
            kill -15 "$CPID" 2>/dev/null || true
        done
    fi
fi

kill -15 "$TARGET_PID" 2>/dev/null || true

# Wait up to 5 seconds for clean exit
TIMEOUT=5
while [ $TIMEOUT -gt 0 ]; do
    if ! kill -0 "$TARGET_PID" 2>/dev/null; then
        echo "[+] Agni (PID: $TARGET_PID) terminated cleanly."
        rm -f "$PID_FILE"
        exit 0
    fi
    sleep 1
    TIMEOUT=$((TIMEOUT - 1))
done

if kill -0 "$TARGET_PID" 2>/dev/null; then
    echo "[!] Process $TARGET_PID did not exit cleanly. Issuing SIGKILL..."
    if command -v pgrep >/dev/null 2>&1; then
        CHILD_PIDS="$(pgrep -P "$TARGET_PID" 2>/dev/null || true)"
        if [ -n "$CHILD_PIDS" ]; then
            for CPID in $CHILD_PIDS; do
                kill -9 "$CPID" 2>/dev/null || true
            done
        fi
    fi
    kill -9 "$TARGET_PID" 2>/dev/null || true
fi

rm -f "$PID_FILE"
echo "[+] Shutdown complete."
