"""Opaque-box HTTP client for Agni REST API testing.

Treats Agni as an external service communicating strictly over HTTP/JSON.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class APIResponse:
    """Standardized response container for Agni API requests."""

    status_code: int
    headers: dict[str, str]
    raw_body: bytes

    @property
    def text(self) -> str:
        """Decode response body as UTF-8 string."""
        return self.raw_body.decode("utf-8", errors="replace")

    @property
    def json_data(self) -> dict[str, Any] | list[Any] | None:
        """Parse response body as JSON, returning None on parse failure."""
        try:
            return json.loads(self.text)
        except Exception:
            return None

    @property
    def data(self) -> Any:
        """Extract 'data' payload from standard Agni API envelope or return root JSON."""
        parsed = self.json_data
        if isinstance(parsed, dict) and "data" in parsed:
            return parsed["data"]
        return parsed

    @property
    def is_success(self) -> bool:
        """Check if HTTP status indicates success (2xx)."""
        return 200 <= self.status_code < 300

    @property
    def error_detail(self) -> str | None:
        """Extract error detail message from error payload."""
        parsed = self.json_data
        if isinstance(parsed, dict):
            return parsed.get("detail") or parsed.get("message")
        return None


class AgniAPIClient:
    """High-level client for executing opaque-box E2E tests against Agni."""

    def __init__(self, base_url: str | None = None, timeout: float = 10.0) -> None:
        if base_url is None:
            base_url = os.environ.get("AGNI_API_URL", "http://127.0.0.1:8000/api/v1")
        # Ensure trailing slash is stripped
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> APIResponse:
        """Execute HTTP request against Agni REST API."""
        if not path.startswith("/"):
            path = "/" + path
        url = self.base_url + path

        if params:
            # Filter None values and format boolean/strings
            filtered_params = {
                k: (str(v).lower() if isinstance(v, bool) else str(v))
                for k, v in params.items()
                if v is not None
            }
            if filtered_params:
                url += "?" + urllib.parse.urlencode(filtered_params)

        req_headers = {
            "Accept": "application/json",
            "User-Agent": "Agni-E2E-Harness/1.0.0",
        }
        if headers:
            req_headers.update(headers)

        body_bytes: bytes | None = None
        if json_data is not None:
            req_headers["Content-Type"] = "application/json"
            body_bytes = json.dumps(json_data).encode("utf-8")

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_headers = dict(resp.getheaders())
                return APIResponse(
                    status_code=resp.status,
                    headers=resp_headers,
                    raw_body=resp.read(),
                )
        except urllib.error.HTTPError as err:
            err_headers = dict(err.headers.items()) if err.headers else {}
            return APIResponse(
                status_code=err.code,
                headers=err_headers,
                raw_body=err.read(),
            )
        except urllib.error.URLError as err:
            raise ConnectionError(f"Failed to connect to Agni API at {url}: {err.reason}") from err

    # Convenience HTTP methods
    def get(self, path: str, params: dict[str, Any] | None = None) -> APIResponse:
        return self.request("GET", path, params=params)

    def post(self, path: str, json_data: Any | None = None, params: dict[str, Any] | None = None) -> APIResponse:
        return self.request("POST", path, params=params, json_data=json_data)

    def put(self, path: str, json_data: Any | None = None, params: dict[str, Any] | None = None) -> APIResponse:
        return self.request("PUT", path, params=params, json_data=json_data)

    def patch(self, path: str, json_data: Any | None = None, params: dict[str, Any] | None = None) -> APIResponse:
        return self.request("PATCH", path, params=params, json_data=json_data)

    def delete(self, path: str, params: dict[str, Any] | None = None) -> APIResponse:
        return self.request("DELETE", path, params=params)

    # 1. Health & Diagnostics
    def get_health(self) -> APIResponse:
        return self.get("/health")

    def get_sensor_status(self) -> APIResponse:
        return self.get("/sensor/status")

    def get_diagnostics(self) -> APIResponse:
        return self.get("/diagnostics")

    def get_overview(self) -> APIResponse:
        return self.get("/telemetry/overview")

    # 2. Endpoint Monitoring (Processes & FIM & Persistence)
    def get_processes(
        self,
        limit: int = 100,
        offset: int = 0,
        search: str | None = None,
        sort_by: str | None = None,
    ) -> APIResponse:
        return self.get("/processes", params={"limit": limit, "offset": offset, "search": search, "sort_by": sort_by})

    def get_process(self, pid: int) -> APIResponse:
        return self.get(f"/processes/{pid}")

    def get_fim_baselines(self) -> APIResponse:
        return self.get("/fim/baselines")

    def create_fim_baseline(
        self,
        name: str,
        target_path: str,
        recursive: bool = True,
        file_patterns: list[str] | None = None,
        max_file_size_bytes: int | None = None,
    ) -> APIResponse:
        payload = {
            "name": name,
            "target_path": target_path,
            "recursive": recursive,
            "file_patterns": file_patterns or ["*"],
            "max_file_size_bytes": max_file_size_bytes or 104857600,
        }
        return self.post("/fim/baselines", json_data=payload)

    def delete_fim_baseline(self, baseline_id: str) -> APIResponse:
        return self.delete(f"/fim/baselines/{baseline_id}")

    def scan_fim(self, baseline_id: str | None = None) -> APIResponse:
        return self.post("/fim/scan", json_data={"baseline_id": baseline_id} if baseline_id else {})

    def get_fim_changes(self, baseline_id: str | None = None, limit: int = 50) -> APIResponse:
        return self.get("/fim/changes", params={"baseline_id": baseline_id, "limit": limit})

    def get_persistence_entries(self) -> APIResponse:
        return self.get("/persistence/entries")

    def scan_persistence(self) -> APIResponse:
        return self.post("/persistence/scan")

    # 3. Network Intelligence (Vayu)
    def get_network_interfaces(self) -> APIResponse:
        return self.get("/network/interfaces")

    def get_network_connections(
        self,
        limit: int = 100,
        status: str | None = None,
        protocol: str | None = None,
    ) -> APIResponse:
        return self.get("/network/connections", params={"limit": limit, "status": status, "protocol": protocol})

    def get_network_devices(self, include_sample: bool = False) -> APIResponse:
        return self.get("/network/devices", params={"include_sample": include_sample})

    def get_network_config(self) -> APIResponse:
        return self.get("/network/config")

    def update_network_config(self, allowed_cidrs: list[str], passive_discovery_enabled: bool = True) -> APIResponse:
        return self.put(
            "/network/config",
            json_data={"allowed_cidrs": allowed_cidrs, "passive_discovery_enabled": passive_discovery_enabled},
        )

    # 4. Events & Detection Engine (Varuna)
    def get_events(
        self,
        category: str | None = None,
        severity: str | None = None,
        include_sample: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> APIResponse:
        return self.get(
            "/events",
            params={
                "category": category,
                "severity": severity,
                "include_sample": include_sample,
                "limit": limit,
                "offset": offset,
            },
        )

    def ingest_event(self, event_payload: dict[str, Any]) -> APIResponse:
        return self.post("/events", json_data=event_payload)

    def get_rules(self, category: str | None = None, enabled: bool | None = None) -> APIResponse:
        return self.get("/rules", params={"category": category, "enabled": enabled})

    def get_rule(self, rule_id: str) -> APIResponse:
        return self.get(f"/rules/{rule_id}")

    def create_rule(self, rule_payload: dict[str, Any]) -> APIResponse:
        return self.post("/rules", json_data=rule_payload)

    def toggle_rule(self, rule_id: str, enabled: bool) -> APIResponse:
        return self.patch(f"/rules/{rule_id}/toggle", json_data={"enabled": enabled})

    def test_rule(self, rule_payload: dict[str, Any], sample_event: dict[str, Any]) -> APIResponse:
        return self.post("/rules/test", json_data={"rule": rule_payload, "sample_event": sample_event})

    # 5. Incidents
    def get_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        include_sample: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> APIResponse:
        return self.get(
            "/incidents",
            params={
                "status": status,
                "severity": severity,
                "priority": priority,
                "include_sample": include_sample,
                "limit": limit,
                "offset": offset,
            },
        )

    def get_incident(self, incident_id: str) -> APIResponse:
        return self.get(f"/incidents/{incident_id}")

    def update_incident_status(self, incident_id: str, status: str, note: str | None = None) -> APIResponse:
        return self.patch(f"/incidents/{incident_id}/status", json_data={"status": status, "note": note})

    def add_incident_note(self, incident_id: str, content: str) -> APIResponse:
        return self.post(f"/incidents/{incident_id}/notes", json_data={"content": content})

    # 6. Reports
    def export_report(
        self,
        export_format: str = "json",
        date_range: str = "24h",
        include_sample: bool = False,
    ) -> APIResponse:
        return self.post(
            "/reports/export",
            json_data={"format": export_format, "date_range": date_range, "include_sample": include_sample},
        )

    # 7. Demo Data
    def seed_demo_data(self) -> APIResponse:
        return self.post("/demo/seed")

    def get_demo_status(self) -> APIResponse:
        return self.get("/demo/status")

    def clear_demo_data(self) -> APIResponse:
        return self.post("/demo/clear")

    # 8. Settings & Audit
    def get_settings(self) -> APIResponse:
        return self.get("/settings")

    def update_settings(self, settings_payload: dict[str, Any]) -> APIResponse:
        return self.put("/settings", json_data=settings_payload)

    def get_audit_logs(self, limit: int = 100, action: str | None = None) -> APIResponse:
        return self.get("/audit/logs", params={"limit": limit, "action": action})
