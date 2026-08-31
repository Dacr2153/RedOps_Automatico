"""Integration tests for the MSFClient singleton and ExploiterModule."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redops.config.constants import EvasionProfile, ExploitStatus, PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus
from redops.core.models import (
    ExploitAttempt,
    OrchestratorDecision,
    Port,
    ServiceCompromised,
    Target,
    Vulnerability,
)
from redops.evasion.evasion_engine import EvasionEngine
from redops.modules.exploiter import ExploiterModule, MSFClient


# ── MSFClient singleton ────────────────────────────────────────────


class TestMSFClientSingleton:
    @pytest.mark.asyncio
    async def test_singleton_get_instance_returns_same_object(self, settings: Settings) -> None:
        """Two calls to ``get_instance`` return the same object."""
        # Arrange
        MSFClient.reset()

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient") as MockRpc:
            MockRpc.return_value = MagicMock()
            inst1 = await MSFClient.get_instance(settings)
            inst2 = await MSFClient.get_instance(settings)

        # Assert
        assert inst1 is inst2
        MSFClient.reset()

    @pytest.mark.asyncio
    async def test_execute_module_session_opened_returns_success(self, settings: Settings) -> None:
        """execute_module returns SUCCESS when a session is opened."""
        # Arrange
        MSFClient.reset()
        mock_rpc = MagicMock()
        mock_module = MagicMock()
        mock_module.execute = MagicMock(return_value={"job_id": 1})
        mock_rpc.modules.use.return_value = mock_module
        mock_rpc.sessions.list = {"1": {"type": "shell", "info": "root"}}

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient", return_value=mock_rpc):
            client = await MSFClient.get_instance(settings)
            with patch.object(
                client,
                "_run_module",
                return_value={"session_id": "1", "output": "[*] Command shell session 1 opened"},
            ):
                result = await client.execute_module(
                    module_type="exploit",
                    module_path="exploit/unix/ftp/vsftpd_234_backdoor",
                    options={"RHOSTS": "192.168.56.101"},
                    payload="cmd/unix/interact",
                    timeout=30,
                )

        # Assert
        assert result.status == ExploitStatus.SUCCESS
        assert result.session_id == "1"
        MSFClient.reset()

    @pytest.mark.asyncio
    async def test_execute_module_no_session_returns_failure(self, settings: Settings) -> None:
        """execute_module returns FAILURE when no session is opened."""
        # Arrange
        MSFClient.reset()
        mock_rpc = MagicMock()

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient", return_value=mock_rpc):
            client = await MSFClient.get_instance(settings)
            with patch.object(
                client, "_run_module", return_value={"session_id": None, "output": "Exploit failed"}
            ):
                result = await client.execute_module(
                    module_type="exploit",
                    module_path="exploit/unix/ftp/vsftpd_234_backdoor",
                    options={"RHOSTS": "192.168.56.101"},
                    payload="cmd/unix/interact",
                    timeout=30,
                )

        # Assert
        assert result.status == ExploitStatus.FAILURE
        MSFClient.reset()

    @pytest.mark.asyncio
    async def test_list_sessions_returns_all_sessions(self, settings: Settings) -> None:
        """list_sessions wraps the RPC sessions.list call."""
        # Arrange
        MSFClient.reset()
        mock_rpc = MagicMock()
        mock_rpc.sessions.list = {"1": {"type": "shell"}, "2": {"type": "meterpreter"}}

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient", return_value=mock_rpc):
            client = await MSFClient.get_instance(settings)
            sessions = await client.list_sessions()

        # Assert
        assert len(sessions) == 2
        MSFClient.reset()

    @pytest.mark.asyncio
    async def test_run_session_command_returns_shell_output(self, settings: Settings) -> None:
        """run_session_command returns shell output."""
        # Arrange
        MSFClient.reset()
        mock_rpc = MagicMock()
        mock_rpc.sessions.session.return_value = MagicMock()

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient", return_value=mock_rpc):
            client = await MSFClient.get_instance(settings)
            with patch.object(
                client, "run_session_command", new_callable=AsyncMock,
                return_value="root@metasploitable:~#",
            ):
                output = await client.run_session_command("1", "whoami")

        # Assert
        assert "root" in output
        MSFClient.reset()


# ── ExploiterModule ─────────────────────────────────────────────────


class TestExploiterModule:
    @pytest.mark.asyncio
    async def test_exploit_service_delegates_to_msf_and_returns_success(
        self,
        settings: Settings,
        event_bus: EventBus,
        sample_target: Target,
    ) -> None:
        """exploit_service calls MSFClient.execute_module with correct args."""
        # Arrange
        evasion = EvasionEngine(EvasionProfile.AGGRESSIVE)
        llm = MagicMock()
        module = ExploiterModule(settings, evasion, event_bus, llm)

        decision = OrchestratorDecision(
            next_module="exploit/unix/ftp/vsftpd_234_backdoor",
            module_options={"RHOSTS": "192.168.56.101", "RPORT": "21"},
            payload="cmd/unix/interact",
            reasoning="vsftpd backdoor",
            confidence=0.95,
        )

        expected = ExploitAttempt(
            module_path="exploit/unix/ftp/vsftpd_234_backdoor",
            target_ip="192.168.56.101",
            status=ExploitStatus.SUCCESS,
            session_id="1",
            output="session opened",
        )

        MSFClient.reset()
        mock_rpc = MagicMock()

        # Act
        with patch("redops.modules.exploiter.MsfRpcClient", return_value=mock_rpc):
            client = await MSFClient.get_instance(settings)
            with patch.object(
                client, "execute_module", new_callable=AsyncMock,
                return_value=expected,
            ):
                result = await module.exploit_service(sample_target, decision)

        # Assert
        assert result.status == ExploitStatus.SUCCESS
        MSFClient.reset()
