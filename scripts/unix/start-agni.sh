#!/usr/bin/env bash
# ==============================================================================
# Agni Threat Detection Engine - Unix Startup Runner
# Binds strictly to 127.0.0.1:8000 and records PID in agni.pid
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PID_FILE="$PROJECT_ROOT/agni.pid"
BACKEND_DIR="$PROJECT_ROOT/backend"

echo "============================================================"
echo "   Agni - Local Threat Detection & Monitoring Engine   "
echo "============================================================"
echo "Project Root : $PROJECT_ROOT"
echo "Network Bind : 127.0.0.1:8000 (Loopback only)"

# 1. Locate Python 3.11+
PYTHON_BIN="python3"
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_ROOT/.venv/bin/python"
    echo "[+] Using virtual environment Python: $PYTHON_BIN"
elif command -v python3 >/dev/null 2>&1; then
    echo "[+] Using system python3: $(python3 --version)"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
    echo "[+] Using system python: $(python --version)"
else
    echo "[-] Error: Python 3.11+ is required but not installed." >&2
    exit 1
fi

# 2. Check for active running instance (Anti-PID-Reuse verification)
if [ -f "$PID_FILE" ]; then
    EXISTING_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$EXISTING_PID" ] && kill -0 "$EXISTING_PID" 2>/dev/null; then
        PROC_NAME="$(ps -p "$EXISTING_PID" -o comm= 2>/dev/null || true)"
        PROC_ARGS="$(ps -p "$EXISTING_PID" -o args= 2>/dev/null || true)"
        COMBINED="${PROC_NAME} ${PROC_ARGS}"
        case "$COMBINED" in
            *[Pp]ython*|*[Uu]vicorn*|*[Aa]gni*)
                echo "[!] Agni is already running with PID $EXISTING_PID."
                echo "    Run ./scripts/unix/stop-agni.sh first."
                exit 1
                ;;
            *)
                echo "[i] Stale PID file found (PID $EXISTING_PID is not Agni). Removing."
                rm -f "$PID_FILE"
                ;;
        esac
    else
        rm -f "$PID_FILE"
    fi
fi

# 3. Clean exit cleanup handler
SERVER_PID=""
cleanup() {
    echo ""
    echo "[*] Stopping Agni..."
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -15 "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    echo "[+] Cleanup complete."
}
trap cleanup INT TERM EXIT

# 4. Launch backend server and track PID
export PYTHONPATH="$BACKEND_DIR:$PROJECT_ROOT"
cd "$BACKEND_DIR"

"$PYTHON_BIN" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
echo "[+] Starting Agni server on 127.0.0.1:8000 (PID: $SERVER_PID)..."
echo "[*] Press Ctrl+C to stop."

wait "$SERVER_PID"
