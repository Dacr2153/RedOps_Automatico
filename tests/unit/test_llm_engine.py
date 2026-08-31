"""Unit tests for the LLM orchestrator engine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from redops.config.settings import Settings
from redops.core.events import EventBus
from redops.core.exceptions import OllamaResponseError
from redops.core.models import CVSSVector, SessionState, Target, Vulnerability
from redops.orchestrator.llm_engine import LLMOrchestrator


@pytest.fixture()
def llm(settings: Settings, event_bus: EventBus) -> LLMOrchestrator:
    """Return an ``LLMOrchestrator`` bound to test settings."""
    return LLMOrchestrator(settings, event_bus)


# ── _call_llm_raw ──────────────────────────────────────────────────


class TestCallLLM:
    @pytest.mark.asyncio
    async def test_call_llm_raw_valid_json_returns_parsed_dict(self, llm: LLMOrchestrator) -> None:
        """A well-formed JSON response is returned directly."""
        # Arrange
        fake_resp = MagicMock()
        fake_resp.message.content = '{"answer": 42}'
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value=fake_resp)
        llm._client = mock_client

        # Act
        result = await llm._call_llm_raw("test prompt")

        # Assert
        assert result["answer"] == 42

    @pytest.mark.asyncio
    async def test_call_llm_raw_empty_response_raises_ollama_error(self, llm: LLMOrchestrator) -> None:
        """Empty responses trigger retries; after max retries raise."""
        # Arrange
        fake_resp = MagicMock()
        fake_resp.message.content = ""
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value=fake_resp)
        llm._client = mock_client

        # Act / Assert
        with pytest.raises(OllamaResponseError):
            await llm._call_llm_raw("test prompt")


# ── select_exploit ──────────────────────────────────────────────────


class TestSelectExploit:
    @pytest.mark.asyncio
    async def test_select_exploit_valid_json_returns_orchestrator_decision(
        self,
        llm: LLMOrchestrator,
        sample_target: Target,
        sample_vulnerabilities: list[Vulnerability],
    ) -> None:
        """select_exploit should parse JSON into OrchestratorDecision."""
        # Arrange
        json_response = (
            '{"next_module": "exploit/unix/ftp/vsftpd_234_backdoor", '
            '"module_options": {"RHOSTS": "192.168.56.101"}, '
            '"payload": "cmd/unix/interact", '
            '"reasoning": "Known backdoor", '
            '"confidence": 0.95, '
            '"alternative_modules": [], '
            '"skip_reason": null}'
        )
        fake_resp = MagicMock()
        fake_resp.message.content = json_response
        mock_client = AsyncMock()
        mock_client.chat = AsyncMock(return_value=fake_resp)
        llm._client = mock_client

        # Act
        decision = await llm.select_exploit(
            target=sample_target,
            vulnerabilities=sample_vulnerabilities,
            session_state=SessionState(),
        )

        # Assert
        assert decision.next_module == "exploit/unix/ftp/vsftpd_234_backdoor"
        assert decision.confidence == 0.95
