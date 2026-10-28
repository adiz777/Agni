#!/usr/bin/env bash
# ==============================================================================
# Health probe script for Agni on Unix (Linux / macOS)
# Queries http://127.0.0.1:8000/api/v1/health and exits 0 on healthy, 1 on down.
# ==============================================================================
set -euo pipefail

ENDPOINT="${1:-http://127.0.0.1:8000/api/v1/health}"

echo "[*] Probing Agni health at $ENDPOINT..."

if ! command -v curl >/dev/null 2>&1; then
    echo "[-] Error: curl is required to probe health." >&2
    exit 1
fi

RESPONSE="$(curl -s -m 5 "$ENDPOINT" || true)"

if [ -z "$RESPONSE" ]; then
    echo "============================================================"
    echo "              Agni Health Status: UNREACHABLE               "
    echo "============================================================"
    echo "[-] Could not establish connection to $ENDPOINT."
    echo "[!] Ensure Agni is running via ./scripts/unix/start-agni.sh"
    exit 1
fi

if echo "$RESPONSE" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    echo "============================================================"
    echo "               Agni Health Status: HEALTHY                  "
    echo "============================================================"
    if command -v python3 >/dev/null 2>&1; then
        echo "$RESPONSE" | python3 -m json.tool || echo "$RESPONSE"
    elif command -v jq >/dev/null 2>&1; then
        echo "$RESPONSE" | jq . || echo "$RESPONSE"
    else
        echo "$RESPONSE"
    fi
    exit 0
else
    echo "============================================================"
    echo "              Agni Health Status: UNHEALTHY                 "
    echo "============================================================"
    echo "$RESPONSE"
    exit 1
fi
