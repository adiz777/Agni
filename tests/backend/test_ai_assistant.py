"""
Comprehensive Test Suite for Safe AI Investigation Assistant & Telemetry Redaction (R3)
Verifies:
- TelemetryRedactor scrubbing (IPv4, IPv6, username, home directory, credential scrubbing, SIDs)
- Explicit consent gate: request without consent is rejected with HTTP 403 / descriptive error
- Provider fallback & timeout: simulated offline Ollama endpoint returns structured advisory message without crashing or raising 500
- Read-only advisory framing: system prompt enforces non-remediative advisory text
- Full REST API endpoints under /api/v1/ai
"""
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.engine.detector import Detector
from app.models.audit import SystemSettingModel
from app.models.detection import DetectionAlertModel, DetectionRuleModel, IncidentModel
from app.models.telemetry import TelemetryEventModel
from app.schemas.ai import AIConfig, AIInvestigationResponse
from app.services.ai_assistant import (
    ADVISORY_SYSTEM_PROMPT,
    AIAssistantService,
    TelemetryRedactor,
)


# ==============================================================================
# 1. TelemetryRedactor Unit Tests
# ==============================================================================
class TestTelemetryRedactor:
    """Test suite verifying accurate PII, IP, credential, and path scrubbing."""

    def test_redactor_ipv4_scrubbing(self):
        redactor = TelemetryRedactor()
        raw = "Connection from 192.168.1.100:4444 to 10.0.0.5:80. Loopback at 127.0.0.1."
        redacted, counts = redactor.redact_text(raw)

        assert "192.168.1.100" not in redacted
        assert "10.0.0.5" not in redacted
        assert "127.0.0.1" not in redacted
        assert "[IP_CLIENT_1]:4444" in redacted or "[IP_1]" in redacted or "[IP_CLIENT" in redacted
        assert "[IP_LOOPBACK]" in redacted
        assert counts["ipv4"] == 3

    def test_redactor_ipv6_scrubbing(self):
        redactor = TelemetryRedactor()
        raw = "Suspicious traffic on IPv6 ::1 and fe80::1 and 2001:db8::1 from host."
        redacted, counts = redactor.redact_text(raw)

        assert "::1" not in redacted
        assert "fe80::1" not in redacted
        assert "[IP_IPV6]" in redacted
        assert counts["ipv6"] >= 2

    def test_redactor_user_home_paths(self):
        redactor = TelemetryRedactor()
        win_path = r"Process spawned: C:\Users\malicious_user\AppData\Local\Temp\evil.exe"
        unix_path = "Reading /home/victim_user/.ssh/id_rsa credentials"
        mac_path = "Executed /Users/analyst/Downloads/script.sh"

        r_win, c_win = redactor.redact_text(win_path)
        r_unix, c_unix = redactor.redact_text(unix_path)
        r_mac, c_mac = redactor.redact_text(mac_path)

        assert r"C:\Users\malicious_user" not in r_win
        assert "[USER_HOME]" in r_win
        assert "/home/victim_user" not in r_unix
        assert "[USER_HOME]" in r_unix
        assert "/Users/analyst" not in r_mac
        assert "[USER_HOME]" in r_mac
        assert c_win["user_paths"] == 1
        assert c_unix["user_paths"] == 1
        assert c_mac["user_paths"] == 1

    def test_redactor_credentials_and_secrets(self):
        redactor = TelemetryRedactor()
        text = (
            "powershell.exe -NoProfile -p SecretP@ssw0rd! "
            "--password=SuperSecretPass! --token=ghp_abcdef1234567890abcdef1234567890 "
            "--api-key=sk-1234567890abcdef1234567890 "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
        )
        redacted, counts = redactor.redact_text(text)

        assert "SecretP@ssw0rd!" not in redacted
        assert "SuperSecretPass!" not in redacted
        assert "ghp_abcdef" not in redacted
        assert "sk-1234567890" not in redacted
        assert "eyJhbGci" not in redacted
        assert "[REDACTED_CREDENTIAL]" in redacted or "[REDACTED_API_KEY]" in redacted
        assert counts["credentials"] >= 4

    def test_redactor_windows_sid_and_unc_path(self):
        redactor = TelemetryRedactor()
        text = r"Actor SID S-1-5-21-3623811015-3361044348-30300820-1013 accessed \\fileserver\finance\q4.xlsx"
        redacted, counts = redactor.redact_text(text)

        assert "S-1-5-21-3623811015" not in redacted
        assert "[REDACTED_SID]" in redacted
        assert r"\\fileserver\finance" not in redacted
        assert "[REDACTED_UNC]" in redacted
        assert counts["sids"] == 1
        assert counts["unc_paths"] == 1

    def test_redactor_recursive_data_structure(self):
        redactor = TelemetryRedactor()
        data = {
            "incident": "INC-001",
            "remote_ip": "198.51.100.24",
            "details": {
                "cmdline": r"cmd.exe /c type C:\Users\john\secret.txt --token=secret_token_123",
                "nested_ips": ["203.0.113.1", "127.0.0.1"],
            },
        }
        sanitized, counts = redactor.redact_data(data)

        assert "198.51.100.24" not in sanitized["remote_ip"]
        assert r"C:\Users\john" not in sanitized["details"]["cmdline"]
        assert "secret_token_123" not in sanitized["details"]["cmdline"]
        assert "203.0.113.1" not in sanitized["details"]["nested_ips"][0]
        assert counts["total"] >= 4


# ==============================================================================
# 2. Advisory System Prompt & Framing Tests
# ==============================================================================
class TestAdvisoryFraming:
    """Verify strictly read-only, non-remediative system prompt constraints."""

    def test_advisory_system_prompt_constraints(self):
        prompt = ADVISORY_SYSTEM_PROMPT

        # Must state read-only advisory role
        assert "passive, read-only security operations assistant" in prompt
        assert "STRICT CONSTRAINTS" in prompt
        assert "strictly an ADVISORY tool" in prompt

        # Negative constraints against code execution
        assert "NEVER output executable shell scripts" in prompt
        assert "NEVER recommend terminating processes, deleting files, killing network connections, or altering firewall rules automatically" in prompt

        # Required 4 markdown sections
        assert "### Threat Summary & Hypothesis" in prompt
        assert "### MITRE ATT&CK Mapping" in prompt
        assert "### Potential Benign Explanations (False Positive Assessment)" in prompt
        assert "### Recommended Manual Analyst Verification Steps" in prompt


# ==============================================================================
# 3. Explicit Consent Gate Tests
# ==============================================================================
class TestConsentGate:
    """Verify that requests without consent or while disabled are rejected."""

    def _seed_incident(self, db):
        rule = DetectionRuleModel(
            id="AGNI-R-PROC-TEST",
            name="Test Rule",
            description="Test rule description",
            severity="High",
            category="process",
            source="agni_core",
            match_conditions={},
            explanation="Explanation",
            investigation_steps=["Step 1"],
            version="1.0.0",
            enabled=True,
        )
        db.merge(rule)
        incident = IncidentModel(
            id="inc-test-consent-01",
            title="Suspicious Process Spawn",
            rule_id="AGNI-R-PROC-TEST",
            severity="High",
            entity_key="actor:1234",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=1,
            summary="Process spawned with encoded payload",
            is_sample=False,
        )
        db.merge(incident)
        db.commit()
        return incident

    def test_request_when_ai_disabled_rejected_with_403(self, client, test_db):
        """When AI is disabled by default, requests are rejected with HTTP 403."""
        self._seed_incident(test_db)

        # Ensure disabled in settings table
        test_db.query(SystemSettingModel).filter(SystemSettingModel.key.in_(["ai_enabled", "ai_provider"])).delete()
        test_db.add(SystemSettingModel(key="ai_enabled", value="false", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_provider", value="none", updated_at=datetime.now(UTC)))
        test_db.commit()

        resp = client.post(
            "/api/v1/ai/investigate",
            json={
                "incident_id": "inc-test-consent-01",
                "consent_given": False,
            },
        )
        assert resp.status_code == 403
        data = resp.json()
        assert "AI Assistant is disabled" in data["detail"]

    def test_external_provider_without_consent_rejected_with_403(self, client, test_db):
        """When using external/hosted endpoint, consent_given=False returns HTTP 403."""
        self._seed_incident(test_db)

        # Enable AI but configure external OpenAI provider with no default consent
        test_db.query(SystemSettingModel).filter(
            SystemSettingModel.key.in_(["ai_enabled", "ai_provider", "ai_consent_granted", "ai_endpoint"])
        ).delete()
        test_db.add(SystemSettingModel(key="ai_enabled", value="true", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_provider", value="openai", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_endpoint", value="https://api.openai.com/v1", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_consent_granted", value="false", updated_at=datetime.now(UTC)))
        test_db.commit()

        resp = client.post(
            "/api/v1/ai/investigate",
            json={
                "incident_id": "inc-test-consent-01",
                "consent_given": False,
            },
        )
        assert resp.status_code == 403
        data = resp.json()
        assert "Explicit user consent is required" in data["detail"]

    def test_external_provider_with_consent_proceeds(self, client, test_db):
        """When consent is provided, request passes consent gate."""
        self._seed_incident(test_db)

        test_db.query(SystemSettingModel).filter(
            SystemSettingModel.key.in_(["ai_enabled", "ai_provider", "ai_consent_granted", "ai_endpoint"])
        ).delete()
        test_db.add(SystemSettingModel(key="ai_enabled", value="true", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_provider", value="openai", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_endpoint", value="https://api.openai.com/v1", updated_at=datetime.now(UTC)))
        test_db.add(SystemSettingModel(key="ai_consent_granted", value="false", updated_at=datetime.now(UTC)))
        test_db.commit()

        # Mock LLM network call to verify consent passed through
        with patch.object(
            AIAssistantService,
            "_query_openai",
            new_callable=AsyncMock,
            return_value="### Threat Summary & Hypothesis\nTest analysis.",
        ):
            resp = client.post(
                "/api/v1/ai/investigate",
                json={
                    "incident_id": "inc-test-consent-01",
                    "consent_given": True,
                },
            )
            assert resp.status_code == 200
            assert resp.json()["data"]["success"] is True


# ==============================================================================
# 4. Fallback & Timeout Resilience Tests
# ==============================================================================
class TestProviderFallbackAndTimeout:
    """Verify simulated offline Ollama or hung connection returns advisory without 500."""

    @pytest.mark.asyncio
    async def test_simulated_offline_ollama_returns_advisory_without_500(self, test_db):
        """Simulated connection refused to Ollama returns graceful structured response."""
        Detector().sync_rules_to_db(test_db)
        service = AIAssistantService()

        # Configure Ollama provider
        cfg = AIConfig(
            enabled=True,
            provider="ollama",
            base_url="http://127.0.0.1:11434",
            model="llama3.2",
            timeout_seconds=2.0,
        )

        incident = IncidentModel(
            id="inc-offline-01",
            title="Credential Dumping Alert",
            rule_id="AGNI-R-PROC-002",
            severity="Critical",
            entity_key="actor:2048",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=2,
            summary="Attempted LSASS memory dump",
            is_sample=False,
        )
        test_db.add(incident)
        test_db.commit()

        # Force ConnectError as if Ollama daemon is stopped
        with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
            with patch.object(service, "get_config", return_value=cfg):
                res: AIInvestigationResponse = await service.investigate_incident(
                    incident=incident,
                    correlated_events=[],
                    db=test_db,
                    consent_given=True,
                )

                assert res.success is False
                assert "AI endpoint unreachable" in (res.error or "")
                assert "### Threat Summary & Hypothesis" in (res.analysis or "")
                assert "### Recommended Manual Analyst Verification Steps" in (res.analysis or "")
                assert "ollama" in res.provider_used
                assert len(res.investigation_steps) >= 1

    @pytest.mark.asyncio
    async def test_simulated_timeout_returns_structured_fallback(self, test_db):
        """Simulated inference hang returns timeout advisory without crashing."""
        Detector().sync_rules_to_db(test_db)
        service = AIAssistantService()

        cfg = AIConfig(
            enabled=True,
            provider="ollama",
            base_url="http://127.0.0.1:11434",
            model="llama3.2",
            timeout_seconds=1.0,
        )

        incident = IncidentModel(
            id="inc-timeout-01",
            title="Suspicious Network Listener",
            rule_id="AGNI-R-NET-001",
            severity="High",
            entity_key="port:4444",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=1,
            summary="Reverse shell port listener",
            is_sample=False,
        )
        test_db.add(incident)
        test_db.commit()

        # Force TimeoutException
        with patch("httpx.AsyncClient.post", side_effect=httpx.ReadTimeout("Request timed out")):
            with patch.object(service, "get_config", return_value=cfg):
                res: AIInvestigationResponse = await service.investigate_incident(
                    incident=incident,
                    correlated_events=[],
                    db=test_db,
                    consent_given=True,
                )

                assert res.success is False
                assert "timed out" in (res.error or "")
                assert "T1499" in res.mitre_techniques
                assert "### Threat Summary & Hypothesis" in (res.analysis or "")


# ==============================================================================
# 5. Full REST API Endpoints Verification
# ==============================================================================
class TestAIRestEndpoints:
    """Verify all /api/v1/ai routes via FastAPI TestClient."""

    def test_get_ai_status(self, client):
        resp = client.get("/api/v1/ai/status")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "enabled" in data
        assert "provider" in data
        assert "base_url" in data
        assert "is_external" in data

    def test_update_ai_config_and_audit_log(self, client, test_db):
        resp = client.post(
            "/api/v1/ai/config",
            json={
                "enabled": True,
                "provider": "ollama",
                "base_url": "http://127.0.0.1:11434",
                "model": "llama3.2:latest",
                "consent_granted": True,
                "timeout_seconds": 15.0,
            },
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["enabled"] is True
        assert data["model"] == "llama3.2:latest"
        assert data["consent_granted"] is True

        # Verify audit log recorded
        audit_resp = client.get("/api/v1/audit/logs")
        assert audit_resp.status_code == 200
        actions = [item["action"] for item in audit_resp.json()["data"]["items"]]
        assert "CONFIG_UPDATED" in actions

    def test_preview_redaction_endpoint(self, client, test_db):
        # Create test incident
        rule = DetectionRuleModel(
            id="AGNI-R-PREV-01",
            name="Preview Test Rule",
            description="Desc",
            severity="Medium",
            category="process",
            source="agni_core",
            match_conditions={},
            explanation="Explanation",
            investigation_steps=[],
            version="1.0.0",
            enabled=True,
        )
        test_db.merge(rule)
        inc = IncidentModel(
            id="inc-prev-001",
            title="Redaction Preview Incident",
            rule_id="AGNI-R-PREV-01",
            severity="Medium",
            entity_key="user:admin",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=1,
            summary=r"User C:\Users\alice accessed IP 192.168.1.50 with token ghp_secret1234567890abcdef1234567890",
            is_sample=False,
        )
        test_db.merge(inc)
        test_db.commit()

        resp = client.post(
            "/api/v1/ai/preview-redaction",
            json={"incident_id": "inc-prev-001"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["incident_id"] == "inc-prev-001"
        assert "192.168.1.50" not in data["redacted_text_summary"]
        assert r"C:\Users\alice" not in data["redacted_text_summary"]
        assert data["redacted_items_count"]["total"] >= 2

    def test_investigate_incident_end_to_end(self, client, test_db):
        # Setup enabled Ollama config
        client.post(
            "/api/v1/ai/config",
            json={
                "enabled": True,
                "provider": "ollama",
                "base_url": "http://127.0.0.1:11434",
                "model": "llama3.2",
            },
        )

        rule = DetectionRuleModel(
            id="AGNI-R-E2E-01",
            name="E2E Rule",
            description="Desc",
            severity="High",
            category="network",
            source="vayu",
            match_conditions={},
            explanation="Explanation",
            investigation_steps=[],
            version="1.0.0",
            enabled=True,
        )
        test_db.merge(rule)
        evt = TelemetryEventModel(
            id="evt-e2e-01",
            category="network",
            action="connected",
            severity="High",
            source="vayu",
            hostname="host1",
            os_name="Windows",
            actor_name="cmd.exe",
            actor_pid=3333,
            target_identifier="198.51.100.20:4444",
        )
        test_db.merge(evt)
        inc = IncidentModel(
            id="inc-e2e-001",
            title="E2E Net Incident",
            rule_id="AGNI-R-E2E-01",
            severity="High",
            entity_key="port:4444",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            event_count=1,
            summary="Suspicious connection to remote host",
            is_sample=False,
        )
        test_db.merge(inc)
        alert = DetectionAlertModel(
            id="alert-e2e-01",
            incident_id="inc-e2e-001",
            rule_id="AGNI-R-E2E-01",
            severity="High",
            explanation="Connected to unusual port",
            triggering_event_id="evt-e2e-01",
        )
        test_db.merge(alert)
        test_db.commit()

        mock_analysis = (
            "### Threat Summary & Hypothesis\n"
            "Observed outbound socket to untrusted endpoint.\n\n"
            "### MITRE ATT&CK Mapping\n"
            "- T1071.001: Web Protocols\n\n"
            "### Potential Benign Explanations (False Positive Assessment)\n"
            "- Developer testing a local microservice.\n\n"
            "### Recommended Manual Analyst Verification Steps\n"
            "- Inspect PID 3333 memory map.\n"
            "- Verify domain reputation."
        )

        with patch.object(AIAssistantService, "_query_ollama", new_callable=AsyncMock, return_value=mock_analysis):
            resp = client.post(
                "/api/v1/ai/investigate-incident",
                json={
                    "incident_id": "inc-e2e-001",
                    "consent_given": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()["data"]
            assert data["success"] is True
            assert "T1071.001" in data["mitre_techniques"]
            assert len(data["investigation_steps"]) == 2
            assert data["redaction_summary"]["total"] >= 1

    def test_list_ai_models_endpoint(self, client):
        resp = client.get("/api/v1/ai/models")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "models" in data
        assert "status" in data
