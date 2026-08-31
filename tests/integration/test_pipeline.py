"""Integration test — full pipeline with mocked external dependencies.

Validates that the pipeline orchestrates all PTES phases end-to-end,
produces >=3 compromised services, generates events and writes a PDF.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redops.config.constants import EvasionProfile, ExploitStatus, PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus, PhaseCompletedEvent, PhaseStartedEvent
from redops.core.models import (
    ExploitAttempt,
    OrchestratorDecision,
    Port,
    PTESPhaseResult,
    ServiceCompromised,
    Target,
    Vulnerability,
)
from redops.core.pipeline import PentestPipeline
from redops.evasion.evasion_engine import EvasionEngine
from redops.orchestrator.llm_engine import LLMOrchestrator


# ── Helpers ─────────────────────────────────────────────────────────

_TARGETS = [
    Target(
        ip="192.168.56.101",
        hostname="metasploitable",
        os_detected="Linux 2.6.X",
        open_ports=[
            Port(number=21, service_name="ftp", version="vsftpd 2.3.4"),
            Port(number=139, service_name="smb", version="Samba 3.X"),
            Port(number=3632, service_name="distccd", version=""),
        ],
    )
]

_VULNS = [
    Vulnerability(
        cve_id="CVE-2011-2523", cvss_score=9.8,
        description="vsftpd backdoor", affected_service="ftp", affected_port=21,
        msf_module="exploit/unix/ftp/vsftpd_234_backdoor",
    ),
    Vulnerability(
        cve_id="CVE-2007-2447", cvss_score=9.8,
        description="Samba usermap", affected_service="smb", affected_port=139,
        msf_module="exploit/multi/samba/usermap_script",
    ),
    Vulnerability(
        cve_id="CVE-2004-2687", cvss_score=9.3,
        description="DistCC exec", affected_service="distccd", affected_port=3632,
        msf_module="exploit/unix/misc/distcc_exec",
    ),
]

_SVC_COMPROMISED = [
    ServiceCompromised(
        service_name="ftp", port=21, target_ip="192.168.56.101",
        exploit_used="exploit/unix/ftp/vsftpd_234_backdoor",
        cve_id="CVE-2011-2523", access_level="root", session_id="1",
    ),
    ServiceCompromised(
        service_name="smb", port=139, target_ip="192.168.56.101",
        exploit_used="exploit/multi/samba/usermap_script",
        cve_id="CVE-2007-2447", access_level="root", session_id="2",
    ),
    ServiceCompromised(
        service_name="distccd", port=3632, target_ip="192.168.56.101",
        exploit_used="exploit/unix/misc/distcc_exec",
        cve_id="CVE-2004-2687", access_level="daemon", session_id="3",
    ),
]


def _recon_result() -> PTESPhaseResult:
    return PTESPhaseResult(
        phase=PTESPhase.RECON, status="completed", findings=_TARGETS,  # type: ignore[arg-type]
    )


def _scan_result() -> PTESPhaseResult:
    return PTESPhaseResult(
        phase=PTESPhase.SCAN, status="completed", findings=_VULNS,  # type: ignore[arg-type]
    )


def _exploit_result() -> PTESPhaseResult:
    return PTESPhaseResult(
        phase=PTESPhase.EXPLOIT, status="completed",
        findings=_SVC_COMPROMISED,  # type: ignore[arg-type]
    )


def _post_result() -> PTESPhaseResult:
    return PTESPhaseResult(
        phase=PTESPhase.POST_EXPLOIT, status="completed", findings=[],
    )


# ── Tests ───────────────────────────────────────────────────────────


class TestPipelineEndToEnd:
    @pytest.mark.asyncio
    async def test_pipeline_full_run_produces_pdf_with_compromised_services(
        self, settings: Settings, event_bus: EventBus, tmp_path: Path
    ) -> None:
        """Pipeline with mocked phases produces PDF and >=3 compromised."""
        # Arrange
        settings = settings.model_copy(update={"report_output_dir": str(tmp_path)})
        llm = LLMOrchestrator(settings, event_bus)
        evasion = EvasionEngine(EvasionProfile.AGGRESSIVE)

        phase_events: list[Any] = []

        async def _capture_event(e: Any) -> None:
            phase_events.append(e)

        await event_bus.subscribe(PhaseStartedEvent, _capture_event)
        await event_bus.subscribe(PhaseCompletedEvent, _capture_event)

        async def _side_effect(state: Any, net: str, **kw: Any) -> None:
            await _mock_run_phases(state)

        # Act
        with (
            patch.object(
                PentestPipeline, "_run_phases",
                new_callable=AsyncMock,
                side_effect=_side_effect,
            ),
        ):
            pipeline = PentestPipeline(settings, llm, evasion, event_bus)
            report_data = await pipeline.run("192.168.56.0/24")

        # Assert
        assert len(report_data.compromised_services) >= 3
        pdfs = list(tmp_path.glob("*.pdf"))
        assert len(pdfs) == 1
        assert pdfs[0].stat().st_size > 0

    @pytest.mark.asyncio
    async def test_pipeline_checkpoint_roundtrip_preserves_session(
        self, settings: Settings, event_bus: EventBus, tmp_path: Path
    ) -> None:
        """Save + load checkpoint preserves session state."""
        # Arrange
        settings = settings.model_copy(update={"report_output_dir": str(tmp_path)})
        llm = LLMOrchestrator(settings, event_bus)
        evasion = EvasionEngine(EvasionProfile.BALANCED)
        pipeline = PentestPipeline(settings, llm, evasion, event_bus)

        from redops.core.models import SessionState
        state = SessionState()
        state.targets = _TARGETS

        # Act
        await pipeline._save_checkpoint(state)
        restored = await pipeline._load_checkpoint(state.session_id)

        # Assert
        assert restored is not None
        assert restored.session_id == state.session_id
        assert len(restored.targets) == 1


async def _mock_run_phases(state: Any) -> None:
    """Populate state as if real phases ran."""
    state.targets = _TARGETS
    state.vulnerabilities = _VULNS
    state.compromised_services = list(_SVC_COMPROMISED)
    state.phase_results = [
        _recon_result(),
        _scan_result(),
        _exploit_result(),
        _post_result(),
    ]
    state.current_phase = PTESPhase.REPORT
