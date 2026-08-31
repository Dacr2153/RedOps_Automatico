"""LLM orchestrator — decision engine powered by Ollama / Mistral.

``LLMOrchestrator`` is the central brain that analyses RECON data, selects
exploits, evaluates post-exploitation options, and generates report text.
Each call validates the LLM response against a Pydantic schema and retries
on malformed JSON.
"""

from __future__ import annotations

import json
import re
from typing import Any

import ollama
import structlog
from pydantic import BaseModel, ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential

from redops.config.constants import MSF_MODULES_CATALOG, PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus, LLMDecisionEvent
from redops.core.exceptions import OllamaConnectionError, OllamaResponseError
from redops.core.models import (
    OrchestratorDecision,
    ReportData,
    ServiceCompromised,
    SessionState,
    Target,
    Vulnerability,
)
from redops.orchestrator.context import SessionContext
from redops.orchestrator.prompts import (
    build_executive_summary_prompt,
    build_exploit_selection_prompt,
    build_post_exploit_prompt,
    build_recon_analysis_prompt,
    build_remediation_prompt,
)

log = structlog.get_logger(__name__)


class LLMOrchestrator:
    """Decision engine that delegates reasoning to a local LLM via Ollama.

    Args:
        settings: Application configuration.
        event_bus: Central event bus for publishing decisions.
    """

    def __init__(self, settings: Settings, event_bus: EventBus) -> None:
        self._settings = settings
        self._event_bus = event_bus
        self._context = SessionContext()
        self._client = ollama.AsyncClient(host=settings.ollama_base_url)

    async def health_check(self) -> bool:
        """Verify that Ollama is reachable and the configured model exists.

        Returns:
            ``True`` if healthy, ``False`` otherwise.
        """
        try:
            model_list = await self._client.list()
            names = [m.get("name", "") if isinstance(m, dict) else getattr(m, "model", "")
                     for m in getattr(model_list, "models", model_list.get("models", []))]
            available = any(self._settings.ollama_model in n for n in names)
            log.info("ollama_health", available=available, model=self._settings.ollama_model)
            return available
        except Exception as exc:
            log.error("ollama_health_failed", error=str(exc))
            return False

    async def analyze_recon(self, targets: list[Target]) -> OrchestratorDecision:
        """Analyse RECON results and decide on target prioritisation.

        Args:
            targets: Hosts discovered during reconnaissance.

        Returns:
            An ``OrchestratorDecision`` with reasoning and prioritised targets.
        """
        prompt = build_recon_analysis_prompt(targets, self._settings.target_network)
        raw = await self._call_llm_raw(prompt)
        decision = OrchestratorDecision(
            next_module="scan",
            module_options={"prioritized": _extract_json_value(raw, "prioritized_targets", [])},
            reasoning=raw.get("analysis_confidence", raw.get("reasoning", str(raw))),
            confidence=float(raw.get("analysis_confidence", 0.5)),
        )
        self._context.add_decision(decision)
        await self._event_bus.publish(
            LLMDecisionEvent(decision=decision, phase=PTESPhase.RECON)
        )
        return decision

    async def select_exploit(
        self,
        target: Target,
        vulnerabilities: list[Vulnerability],
        session_state: SessionState,
    ) -> OrchestratorDecision:
        """Select the next Metasploit module to execute.

        Args:
            target: Current exploitation target.
            vulnerabilities: Known vulnerabilities for this target.
            session_state: Current pipeline state.

        Returns:
            An ``OrchestratorDecision`` indicating which exploit to run.
        """
        prompt = build_exploit_selection_prompt(
            target=target,
            vulnerabilities=vulnerabilities,
            previous_attempts=session_state.exploit_attempts,
            compromised_services=session_state.compromised_services,
            min_required=self._settings.min_services_to_compromise,
            available_modules=MSF_MODULES_CATALOG,
        )
        raw = await self._call_llm_raw(prompt)
        decision = OrchestratorDecision(
            next_module=raw.get("next_module", ""),
            module_options=raw.get("module_options") or {},
            payload=raw.get("payload", ""),
            reasoning=raw.get("reasoning", ""),
            confidence=float(raw.get("confidence", 0.5)),
            alternative_modules=raw.get("alternative_modules") or [],
            skip_reason=raw.get("skip_reason"),
        )
        self._context.add_decision(decision)
        await self._event_bus.publish(
            LLMDecisionEvent(decision=decision, phase=PTESPhase.EXPLOIT)
        )
        return decision

    async def analyze_post_exploit(
        self, compromised: ServiceCompromised, session_output: str
    ) -> OrchestratorDecision:
        """Determine post-exploitation actions.

        Args:
            compromised: The service that was compromised.
            session_output: Raw shell output from the session.

        Returns:
            An ``OrchestratorDecision`` with PE vectors and evidence plan.
        """
        prompt = build_post_exploit_prompt(compromised, {}, session_output)
        raw = await self._call_llm_raw(prompt)
        decision = OrchestratorDecision(
            next_module="post_exploit",
            module_options={},
            reasoning=raw.get("reasoning", ""),
            confidence=0.8,
        )
        self._context.add_decision(decision)
        await self._event_bus.publish(
            LLMDecisionEvent(decision=decision, phase=PTESPhase.POST_EXPLOIT)
        )
        return decision

    async def generate_remediations(self, report_data: ReportData) -> dict[str, str]:
        """Generate remediation text for each vulnerability.

        Args:
            report_data: Complete report data.

        Returns:
            Mapping of CVE-ID to remediation text.
        """
        prompt = build_remediation_prompt(
            report_data.vulnerabilities, report_data.compromised_services
        )
        raw = await self._call_llm_raw(prompt)
        remediations_raw = raw.get("remediations", {})
        result: dict[str, str] = {}
        for cve_id, details in remediations_raw.items():
            if isinstance(details, dict):
                result[cve_id] = details.get("fix", str(details))
            else:
                result[cve_id] = str(details)
        return result

    async def generate_executive_summary(
        self, report_data: ReportData, duration: float
    ) -> str:
        """Generate a non-technical executive summary.

        Args:
            report_data: Complete report data.
            duration: Total engagement duration in seconds.

        Returns:
            Executive summary text.
        """
        prompt = build_executive_summary_prompt(report_data, duration)
        raw = await self._call_llm_raw(prompt)
        return str(raw.get("executive_summary", "Executive summary unavailable."))

    @property
    def context(self) -> SessionContext:
        """Expose the session context for external inspection."""
        return self._context

    # ── Private: Ollama call with retry and JSON extraction ────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def _call_llm_raw(self, prompt: str) -> dict[str, Any]:
        """Call Ollama and extract validated JSON from the response.

        Uses format='json' to force structured output, smaller context window
        for speed, and a single retry on parse failure.

        Args:
            prompt: The full prompt to send.

        Returns:
            Parsed JSON as a dictionary.

        Raises:
            OllamaConnectionError: If Ollama is unreachable.
            OllamaResponseError: If JSON cannot be parsed after retries.
        """
        try:
            response = await self._client.chat(
                model=self._settings.ollama_model,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={
                    "temperature": 0.1,   # lower = more deterministic JSON
                    "num_ctx": 2048,       # smaller context = faster inference
                    "num_predict": 512,    # cap output tokens
                },
            )
        except Exception as exc:
            log.error("ollama_call_failed", error=str(exc), exc_info=True)
            raise OllamaConnectionError(
                self._settings.ollama_host, self._settings.ollama_port
            ) from exc

        content = ""
        if isinstance(response, dict):
            msg = response.get("message", {})
            content = msg.get("content", "") if isinstance(msg, dict) else ""
        else:
            msg = getattr(response, "message", None)
            content = getattr(msg, "content", "") if msg else ""

        log.debug("llm_raw_response", length=len(content))
        parsed = _extract_json(content)
        if parsed is None:
            raise OllamaResponseError(f"No valid JSON in response: {content[:200]}")
        return parsed


# ── JSON extraction helpers ────────────────────────────────────────

def _extract_json(text: str) -> dict[str, Any] | None:
    """Attempt to parse JSON from LLM output, stripping markdown fences."""
    cleaned = re.sub(r"```(?:json)?\s*", "", text)
    cleaned = cleaned.replace("```", "").strip()
    try:
        result = json.loads(cleaned)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass
    return None


def _extract_json_value(data: dict[str, Any], key: str, default: Any) -> Any:
    """Safely extract a value from a parsed JSON dict."""
    return data.get(key, default)
