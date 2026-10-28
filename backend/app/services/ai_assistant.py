"""
Safe AI Investigation Assistant & Telemetry Redaction Pipeline (R3)
Provides read-only, non-remediative threat analysis with automatic PII scrubbing.
"""
from __future__ import annotations

import getpass
import ipaddress
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import SystemSettingModel
from app.models.detection import IncidentModel
from app.models.telemetry import TelemetryEventModel
from app.schemas.ai import (
    AIConfig,
    AIInvestigationResponse,
    AIModelListResponse,
    AIProviderType,
    AIStatusRead,
)

logger = logging.getLogger("agni.ai_assistant")

# Mandatory advisory system prompt enforcing passive, non-remediative behavior
ADVISORY_SYSTEM_PROMPT = """You are Agni AI Analyst, a passive, read-only security operations assistant embedded within the Agni Threat Detection & Endpoint Monitoring Platform.
Your mission is to assist human security analysts by summarizing detected telemetry, hypothesizing potential attack vectors, mapping observations to the MITRE ATT&CK framework, and recommending non-destructive manual verification steps.

STRICT CONSTRAINTS:
1. You are strictly an ADVISORY tool. You DO NOT possess execution capabilities and must NEVER attempt to execute code.
2. NEVER output executable shell scripts, bash one-liners, PowerShell cmdlets, or automated remediation commands that make system changes.
3. NEVER recommend terminating processes, deleting files, killing network connections, or altering firewall rules automatically.
4. Always frame your analysis as hypotheses based on observed indicators, distinguishing confirmed facts from possible interpretations.
5. Format your output strictly in clean Markdown using these sections:
### Threat Summary & Hypothesis
### MITRE ATT&CK Mapping
### Potential Benign Explanations (False Positive Assessment)
### Recommended Manual Analyst Verification Steps
"""


class TelemetryRedactor:
    """
    Automated sanitization pipeline for scrubbing PII, network identities,
    usernames, home paths, and secrets before telemetry leaves trust boundaries.
    """

    IPV4_REGEX = re.compile(
        r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        r"(?::\d{1,5})?\b"
    )

    IPV6_CANDIDATE_REGEX = re.compile(
        r"(?<![0-9a-fA-F:])([0-9a-fA-F]{0,4}:[0-9a-fA-F:]+)(?![0-9a-fA-F:])"
    )

    WINDOWS_USER_PATH_REGEX = re.compile(
        r"[a-zA-Z]:\\Users\\[a-zA-Z0-9_\-\.]+",
        re.IGNORECASE,
    )

    UNIX_USER_PATH_REGEX = re.compile(
        r"/(?:home|Users)/[a-zA-Z0-9_\-\.]+",
    )

    SID_REGEX = re.compile(r"\bS-1-[0-59]-\d+(?:-\d+)+\b")

    CREDENTIAL_REGEXES = [
        re.compile(r"(--?(?:password|passwd|pwd)[=\s]+)([^\s\"']+)", re.IGNORECASE),
        re.compile(r"(--?(?:token|api[-_]?key|secret|auth)[=\s]+)([^\s\"']+)", re.IGNORECASE),
        re.compile(r"(-p\s+)([^\s\"']+)", re.IGNORECASE),
        re.compile(r"(Authorization:\s*(?:Bearer|Basic)\s+)([A-Za-z0-9\-_=.]+)", re.IGNORECASE),
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    ]

    UNC_PATH_REGEX = re.compile(r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._$-]+")

    def __init__(self, current_username: str | None = None) -> None:
        try:
            self._current_user = current_username or getpass.getuser()
        except Exception:
            self._current_user = "unknown"

    def redact_text(self, text: str) -> tuple[str, dict[str, int]]:
        """Scrub sensitive entities from a plain text string."""
        if not text:
            return "", {"ipv4": 0, "ipv6": 0, "user_paths": 0, "usernames": 0, "credentials": 0, "sids": 0, "unc_paths": 0, "total": 0}

        counts = {
            "ipv4": 0,
            "ipv6": 0,
            "user_paths": 0,
            "usernames": 0,
            "credentials": 0,
            "sids": 0,
            "unc_paths": 0,
            "total": 0,
        }
        ip_map: dict[str, str] = {}
        ip_counter = 1

        # 1. Scrub Windows SIDs
        def replace_sid(match: re.Match[str]) -> str:
            counts["sids"] += 1
            return "[REDACTED_SID]"

        text = self.SID_REGEX.sub(replace_sid, text)

        # 2. Scrub Credentials & Tokens
        for cred_regex in self.CREDENTIAL_REGEXES:
            def replace_cred(match: re.Match[str]) -> str:
                counts["credentials"] += 1
                if match.lastindex and match.lastindex >= 2:
                    return f"{match.group(1)}[REDACTED_CREDENTIAL]"
                return "[REDACTED_CREDENTIAL]"

            text = cred_regex.sub(replace_cred, text)

        # 3. Scrub UNC Paths
        def replace_unc(match: re.Match[str]) -> str:
            counts["unc_paths"] += 1
            return r"\\[REDACTED_UNC]\share"

        text = self.UNC_PATH_REGEX.sub(replace_unc, text)

        # 4. Scrub User Home Paths
        def replace_win_path(match: re.Match[str]) -> str:
            counts["user_paths"] += 1
            return r"[USER_HOME]"

        def replace_unix_path(match: re.Match[str]) -> str:
            counts["user_paths"] += 1
            return "/[USER_HOME]"

        text = self.WINDOWS_USER_PATH_REGEX.sub(replace_win_path, text)
        text = self.UNIX_USER_PATH_REGEX.sub(replace_unix_path, text)

        # 5. Scrub Current Username if present as a distinct word
        if self._current_user and len(self._current_user) >= 3 and self._current_user.lower() not in ("root", "admin", "system", "unknown"):
            user_regex = re.compile(rf"\b{re.escape(self._current_user)}\b", re.IGNORECASE)

            def replace_user(match: re.Match[str]) -> str:
                counts["usernames"] += 1
                return "[REDACTED_USER]"

            text = user_regex.sub(replace_user, text)

        # 6. Scrub IPv4 addresses with consistent synthetic token mapping
        def replace_ipv4(match: re.Match[str]) -> str:
            nonlocal ip_counter
            raw = match.group(0)
            host_part = raw.split(":")[0]
            port_part = f":{raw.split(':')[1]}" if ":" in raw else ""

            if host_part not in ip_map:
                if host_part in ("127.0.0.1", "0.0.0.0"):
                    token = "[IP_LOOPBACK]"
                else:
                    token = f"[IP_CLIENT_{ip_counter}]"
                    ip_counter += 1
                ip_map[host_part] = token
            counts["ipv4"] += 1
            return f"{ip_map[host_part]}{port_part}"

        text = self.IPV4_REGEX.sub(replace_ipv4, text)

        # 7. Scrub IPv6 addresses
        def replace_ipv6(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                ipaddress.IPv6Address(raw)
            except ValueError:
                return raw  # not a valid IPv6 address

            counts["ipv6"] += 1
            return "[IP_IPV6]"

        text = self.IPV6_CANDIDATE_REGEX.sub(replace_ipv6, text)

        counts["total"] = sum(v for k, v in counts.items() if k != "total")
        return text, counts

    def redact_data(self, data: Any) -> tuple[Any, dict[str, int]]:
        """Recursively redact strings inside dictionaries, lists, or primitives."""
        total_counts = {
            "ipv4": 0,
            "ipv6": 0,
            "user_paths": 0,
            "usernames": 0,
            "credentials": 0,
            "sids": 0,
            "unc_paths": 0,
            "total": 0,
        }

        def _merge(c: dict[str, int]) -> None:
            for k in total_counts:
                total_counts[k] += c.get(k, 0)

        def _walk(item: Any) -> Any:
            if isinstance(item, str):
                redacted, c = self.redact_text(item)
                _merge(c)
                return redacted
            if isinstance(item, dict):
                return {k: _walk(v) for k, v in item.items()}
            if isinstance(item, list):
                return [_walk(v) for v in item]
            return item

        result = _walk(data)
        total_counts["total"] = sum(v for k, v in total_counts.items() if k != "total")
        return result, total_counts


class AIAssistantService:
    """
    Safe advisory AI investigation service supporting Ollama and OpenAI endpoints.
    Enforces explicit consent barrier and non-remediative advisory framing.
    """

    def __init__(self, redactor: TelemetryRedactor | None = None) -> None:
        self.redactor = redactor or TelemetryRedactor()
        self.settings = get_settings()

    def get_config(self, db: Session) -> AIConfig:
        """Load active AI configuration from database with fallback to defaults."""
        items = db.query(SystemSettingModel).all()
        item_map = {it.key: it.value for it in items}

        provider = item_map.get("ai_provider", AIProviderType.NONE.value)
        enabled = provider != AIProviderType.NONE.value and item_map.get("ai_enabled", "true").lower() == "true"
        base_url = item_map.get("ai_endpoint") or "http://127.0.0.1:11434"
        model = item_map.get("ai_model", "llama3.2")
        api_key = item_map.get("ai_api_key")
        consent_granted = item_map.get("ai_consent_granted", "false").lower() == "true"

        try:
            timeout_seconds = float(item_map.get("ai_timeout_seconds", "12.0"))
        except ValueError:
            timeout_seconds = 12.0

        return AIConfig(
            enabled=enabled,
            provider=provider,
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            require_external_consent=True,
            consent_granted=consent_granted,
        )

    def is_external_endpoint(self, base_url: str, provider: str) -> bool:
        """Determines whether endpoint communicates outside the local host loopback."""
        if provider in (AIProviderType.OPENAI.value, AIProviderType.OPENAI_COMPATIBLE.value):
            return True
        try:
            parsed = urlparse(base_url)
            host = (parsed.hostname or "").lower()
            return host not in ("127.0.0.1", "localhost", "::1")
        except Exception:
            return True

    def get_status(self, db: Session) -> AIStatusRead:
        """Return public status of AI assistant with masked credentials."""
        cfg = self.get_config(db)
        is_external = self.is_external_endpoint(cfg.base_url, cfg.provider)

        masked_key = None
        if cfg.api_key:
            if len(cfg.api_key) > 8:
                masked_key = f"{cfg.api_key[:3]}...{cfg.api_key[-4:]}"
            else:
                masked_key = "***"

        return AIStatusRead(
            enabled=cfg.enabled,
            provider=cfg.provider,
            base_url=cfg.base_url,
            model=cfg.model,
            api_key_configured=bool(cfg.api_key),
            api_key_masked=masked_key,
            consent_granted=cfg.consent_granted,
            timeout_seconds=cfg.timeout_seconds,
            is_external=is_external,
        )

    def build_investigation_prompt(
        self,
        incident: IncidentModel,
        correlated_events: list[TelemetryEventModel],
        user_notes: str | None = None,
    ) -> str:
        """Constructs safe, contextually rich Markdown prompt for LLM analysis."""
        prompt_parts = [
            "### Incident Context for Review",
            f"- **Incident ID**: {incident.id}",
            f"- **Title**: {incident.title}",
            f"- **Severity**: {incident.severity}",
            f"- **Rule ID**: {incident.rule_id}",
            f"- **Entity Key**: {incident.entity_key}",
            f"- **First Seen**: {incident.first_seen.isoformat()}",
            f"- **Last Seen**: {incident.last_seen.isoformat()}",
            f"- **Total Correlated Event Count**: {incident.event_count}",
            f"- **Summary**: {incident.summary}",
        ]

        if incident.mitre_attack:
            prompt_parts.append(f"- **Initial MITRE Reference**: {incident.mitre_attack}")

        if user_notes:
            prompt_parts.append(f"- **Analyst Triage Notes**: {user_notes}")

        if correlated_events:
            prompt_parts.append("\n### Correlated Evidence Telemetry Events (Sample)")
            for i, evt in enumerate(correlated_events[:10], start=1):
                prompt_parts.append(
                    f"{i}. [{evt.timestamp.isoformat()}] Category: `{evt.category}` | "
                    f"Action: `{evt.action}` | Actor: `{evt.actor_name or 'unknown'}` "
                    f"(PID: {evt.actor_pid}) | Target: `{evt.target_identifier or 'N/A'}`"
                )

        prompt_parts.append(
            "\nPlease analyze this incident according to your system prompt instructions. "
            "Provide the four required markdown sections."
        )
        return "\n".join(prompt_parts)

    async def investigate_incident(
        self,
        incident: IncidentModel,
        correlated_events: list[TelemetryEventModel],
        db: Session,
        user_notes: str | None = None,
        consent_given: bool = False,
    ) -> AIInvestigationResponse:
        """
        Executes AI threat investigation with redaction, consent checks, and timeout resilience.
        """
        cfg = self.get_config(db)
        is_external = self.is_external_endpoint(cfg.base_url, cfg.provider)

        # 1. Validation & Consent Gate
        if not cfg.enabled:
            return AIInvestigationResponse(
                success=False,
                incident_id=incident.id,
                provider_used=cfg.provider,
                model_used=cfg.model,
                error="AI Assistant is disabled. Enable it in Settings to perform automated investigation.",
            )

        if is_external and not (consent_given or cfg.consent_granted):
            return AIInvestigationResponse(
                success=False,
                incident_id=incident.id,
                provider_used=cfg.provider,
                model_used=cfg.model,
                error="Explicit user consent required before sending telemetry to external AI endpoints.",
            )

        # 2. Build and Redact Prompt
        raw_prompt = self.build_investigation_prompt(incident, correlated_events, user_notes)
        redacted_prompt, redaction_summary = self.redactor.redact_text(raw_prompt)

        start_time = time.perf_counter()

        # 3. Query LLM Provider
        try:
            if cfg.provider == AIProviderType.OLLAMA.value:
                analysis = await self._query_ollama(cfg, redacted_prompt)
            elif cfg.provider in (AIProviderType.OPENAI.value, AIProviderType.OPENAI_COMPATIBLE.value):
                analysis = await self._query_openai(cfg, redacted_prompt)
            else:
                return AIInvestigationResponse(
                    success=False,
                    incident_id=incident.id,
                    provider_used=cfg.provider,
                    model_used=cfg.model,
                    error=f"Unsupported AI provider '{cfg.provider}'.",
                    redaction_summary=redaction_summary,
                )

            latency = round((time.perf_counter() - start_time) * 1000.0, 2)
            mitre_techniques = self._extract_mitre_techniques(analysis)
            steps = self._extract_steps(analysis)

            return AIInvestigationResponse(
                success=True,
                incident_id=incident.id,
                provider_used=cfg.provider,
                model_used=cfg.model,
                analysis=analysis,
                mitre_techniques=mitre_techniques,
                investigation_steps=steps,
                severity_assessment=incident.severity,
                confidence_score=0.85,
                latency_ms=latency,
                redaction_summary=redaction_summary,
            )

        except (httpx.ConnectError, httpx.ConnectTimeout) as e:
            logger.warning("AI provider connection failed: %s", e)
            return self._build_offline_fallback(incident.id, cfg, str(e), redaction_summary)
        except httpx.TimeoutException as e:
            logger.warning("AI provider query timed out after %ss: %s", cfg.timeout_seconds, e)
            return self._build_timeout_fallback(incident.id, cfg, redaction_summary)
        except Exception as e:
            logger.error("Unexpected error during AI investigation: %s", e, exc_info=True)
            return AIInvestigationResponse(
                success=False,
                incident_id=incident.id,
                provider_used=cfg.provider,
                model_used=cfg.model,
                error=f"Inference failure: {e}",
                analysis=self._build_static_advisory(incident),
                redaction_summary=redaction_summary,
            )

    async def _query_ollama(self, cfg: AIConfig, prompt: str) -> str:
        """Call Ollama /api/chat endpoint."""
        url = f"{cfg.base_url.rstrip('/')}/api/chat"
        payload = {
            "model": cfg.model,
            "messages": [
                {"role": "system", "content": ADVISORY_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }

        async with httpx.AsyncClient(timeout=cfg.timeout_seconds) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            # Handle chat format
            if "message" in data and "content" in data["message"]:
                return data["message"]["content"]
            # Handle generate format
            if "response" in data:
                return data["response"]
            return str(data)

    async def _query_openai(self, cfg: AIConfig, prompt: str) -> str:
        """Call OpenAI-compatible /v1/chat/completions endpoint."""
        url = f"{cfg.base_url.rstrip('/')}/v1/chat/completions"
        headers = {}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"

        payload = {
            "model": cfg.model,
            "messages": [
                {"role": "system", "content": ADVISORY_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        async with httpx.AsyncClient(timeout=cfg.timeout_seconds) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def list_available_models(self, db: Session) -> AIModelListResponse:
        """Query active endpoint for available LLM models."""
        cfg = self.get_config(db)
        models: list[str] = []

        try:
            if cfg.provider == AIProviderType.OLLAMA.value:
                url = f"{cfg.base_url.rstrip('/')}/api/tags"
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        data = resp.json()
                        models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
            elif cfg.provider in (AIProviderType.OPENAI.value, AIProviderType.OPENAI_COMPATIBLE.value):
                url = f"{cfg.base_url.rstrip('/')}/v1/models"
                headers = {"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else {}
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
        except Exception as e:
            logger.debug("Could not query model list from %s: %s", cfg.base_url, e)

        status_msg = f"Retrieved {len(models)} models" if models else "Endpoint offline or no models found"
        return AIModelListResponse(
            provider=cfg.provider,
            endpoint=cfg.base_url,
            models=models,
            status=status_msg,
        )

    def _extract_mitre_techniques(self, text: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs (e.g. T1059.001) from markdown text."""
        matches = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
        return sorted(set(matches))

    def _extract_steps(self, text: str) -> list[str]:
        """Extract bulleted verification steps from the recommended section."""
        steps = []
        in_steps_section = False
        for line in text.splitlines():
            line_str = line.strip()
            if "Recommended Manual Analyst Verification Steps" in line_str:
                in_steps_section = True
                continue
            if in_steps_section:
                if line_str.startswith("###"):
                    break
                if line_str.startswith(("-", "*", "1.", "2.", "3.", "4.", "5.")):
                    cleaned = re.sub(r"^[-*0-9.]+\s*", "", line_str)
                    if cleaned:
                        steps.append(cleaned)
        return steps[:8]

    def _build_offline_fallback(
        self, incident_id: str, cfg: AIConfig, error_msg: str, redaction_summary: dict[str, int]
    ) -> AIInvestigationResponse:
        """Return structured fallback advisory report when LLM daemon is offline."""
        analysis = (
            "### Threat Summary & Hypothesis\n"
            f"Automated AI investigation is currently offline. The configured provider ({cfg.provider}) "
            f"at `{cfg.base_url}` could not be reached.\n\n"
            "### MITRE ATT&CK Mapping\n"
            "- Diagnostic: Offline inference mode (No external API calls permitted).\n\n"
            "### Potential Benign Explanations (False Positive Assessment)\n"
            "- Local daemon may be stopped or not yet initialized.\n\n"
            "### Recommended Manual Analyst Verification Steps\n"
            f"- Verify local inference daemon is running: `{cfg.base_url}`\n"
            f"- For Ollama, run `ollama serve` and verify models with `ollama list`.\n"
            "- Review the incident details and correlated events directly in the Incidents view."
        )
        return AIInvestigationResponse(
            success=False,
            incident_id=incident_id,
            provider_used=cfg.provider,
            model_used=cfg.model,
            error=f"AI endpoint unreachable at {cfg.base_url}: {error_msg}",
            analysis=analysis,
            mitre_techniques=[],
            investigation_steps=[
                f"Verify {cfg.provider} process status at {cfg.base_url}",
                "Perform manual event triage using the Agni SOC Incidents view",
            ],
            redaction_summary=redaction_summary,
        )

    def _build_timeout_fallback(
        self, incident_id: str, cfg: AIConfig, redaction_summary: dict[str, int]
    ) -> AIInvestigationResponse:
        """Return structured fallback advisory report when inference times out."""
        analysis = (
            "### Threat Summary & Hypothesis\n"
            f"The AI investigation request timed out after {cfg.timeout_seconds} seconds. "
            "The model may be overloaded or allocating GPU memory.\n\n"
            "### MITRE ATT&CK Mapping\n"
            "- T1499: Endpoint resource exhaustion / inference delay.\n\n"
            "### Potential Benign Explanations (False Positive Assessment)\n"
            "- Heavy background system activity or model cold-start delay.\n\n"
            "### Recommended Manual Analyst Verification Steps\n"
            "- Increase the AI timeout parameter in Settings if running on CPU.\n"
            "- Inspect running processes manually via the Process Explorer view."
        )
        return AIInvestigationResponse(
            success=False,
            incident_id=incident_id,
            provider_used=cfg.provider,
            model_used=cfg.model,
            error=f"Inference request timed out after {cfg.timeout_seconds} seconds.",
            analysis=analysis,
            mitre_techniques=["T1499"],
            investigation_steps=[
                "Increase timeout in Settings",
                "Inspect process tree via Process Explorer",
            ],
            redaction_summary=redaction_summary,
        )

    def _build_static_advisory(self, incident: IncidentModel) -> str:
        """Basic fallback static text in case of unhandled error."""
        return (
            "### Threat Summary & Hypothesis\n"
            f"Incident `{incident.title}` requires manual verification by an analyst.\n\n"
            "### MITRE ATT&CK Mapping\n"
            f"- {incident.mitre_attack or 'T1059'}\n\n"
            "### Potential Benign Explanations (False Positive Assessment)\n"
            "- Administrative tool usage or scheduled maintenance task.\n\n"
            "### Recommended Manual Analyst Verification Steps\n"
            "- Review parent-child process relationship.\n"
            "- Validate network destination IP against known threat feeds."
        )
