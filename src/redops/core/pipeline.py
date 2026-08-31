"""PentestPipeline — Chain-of-Responsibility orchestrator for PTES phases.

Coordinates Recon → Scan → Exploit (loop) → Post-Exploit → Report,
delegating decisions to the LLMOrchestrator and applying evasion between
network operations.  Supports checkpoint/recovery and a global timeout.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from redops.config.constants import PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus
from redops.core.exceptions import PipelineTimeoutError, RedOpsError
from redops.core.models import (
    PTESPhaseResult,
    ReportData,
    ServiceCompromised,
    SessionState,
    Target,
)
from redops.evasion.evasion_engine import EvasionEngine
from redops.modules.exploiter import ExploiterModule, MSFClient
from redops.modules.post_exploit import PostExploitModule
from redops.modules.recon import ReconModule
from redops.modules.scanner import ScanDepth, ScannerModule
from redops.orchestrator.llm_engine import LLMOrchestrator
from redops.reporting.report_generator import ReportGenerator

log = structlog.get_logger(__name__)

_CHECKPOINT_DIR = Path("checkpoints")


class PentestPipeline:
    """End-to-end PTES pipeline with LLM-driven exploit loop.

    Args:
        settings: Application configuration.
        llm: LLM orchestrator for decision making.
        evasion: Evasion engine for timing / fragmentation.
        event_bus: Central event bus.
    """

    def __init__(
        self,
        settings: Settings,
        llm: LLMOrchestrator,
        evasion: EvasionEngine,
        event_bus: EventBus,
    ) -> None:
        self._settings = settings
        self._llm = llm
        self._evasion = evasion
        self._event_bus = event_bus
        self._report_gen = ReportGenerator(event_bus)

    # ── Public API ──────────────────────────────────────────────────

    async def run(
        self,
        target_network: str,
        *,
        resume_session_id: str | None = None,
        dry_run: bool = False,
    ) -> ReportData:
        """Execute the full pentesting pipeline end-to-end.

        Args:
            target_network: CIDR notation of the target network.
            resume_session_id: Resume from a checkpoint if provided.
            dry_run: If ``True``, skip real exploit execution.

        Returns:
            ``ReportData`` with all findings, decisions and the PDF path.

        Raises:
            PipelineTimeoutError: When the global timeout is exceeded.
        """
        state = await self._init_state(resume_session_id)
        log.info("pipeline_start", session=state.session_id, target=target_network)

        try:
            try:
                async with asyncio.timeout(self._settings.global_timeout_seconds):
                    await self._run_phases(state, target_network, dry_run=dry_run)
            except TimeoutError as exc:
                await self._save_checkpoint(state)
                raise PipelineTimeoutError(
                    self._settings.global_timeout_seconds
                ) from exc

            report_data = self._build_report_data(state)
            await self._report_gen.generate(report_data, self._settings.report_output_dir)
            log.info("pipeline_complete", session=state.session_id)
            return report_data
        finally:
            await self._teardown(state)

    # ── Phase runner ────────────────────────────────────────────────

    async def _run_phases(
        self,
        state: SessionState,
        target_network: str,
        *,
        dry_run: bool = False,
    ) -> None:
        """Walk through each PTES phase sequentially."""
        # — RECON —
        recon = ReconModule(self._settings, self._evasion, self._event_bus)
        recon_result = await recon.run(target_network)
        state.targets = recon_result.findings  # type: ignore[assignment]
        state.phase_results.append(recon_result)
        state.current_phase = PTESPhase.SCAN
        await self._save_checkpoint(state)

        # — SCAN —
        # Exclude the attacker's own IP so we never scan ourselves
        attacker_ip = self._settings.attacker_ip
        scan_targets = [t for t in state.targets if t.ip != attacker_ip]
        if not scan_targets:
            scan_targets = state.targets  # fallback: nothing was filtered
        if len(scan_targets) < len(state.targets):
            log.info(
                "scan_attacker_ip_excluded",
                excluded_ip=attacker_ip,
                remaining=len(scan_targets),
            )
        state.targets = scan_targets  # exploiter also uses filtered list

        # Map evasion profile → scan depth
        #   stealth    → top 100 ports  (slow, quiet)
        #   balanced   → top 1000 ports (fast enough for lab)
        #   aggressive → full 1-65535   (fastest, noisiest)
        _DEPTH_MAP: dict[str, ScanDepth] = {
            "stealth": ScanDepth.STEALTH,
            "balanced": ScanDepth.QUICK,
            "aggressive": ScanDepth.FULL,
        }
        scan_depth = _DEPTH_MAP.get(self._settings.evasion_profile, ScanDepth.QUICK)
        log.info("scan_depth_selected", profile=self._settings.evasion_profile, depth=scan_depth.value)

        scanner = ScannerModule(self._settings, self._evasion, self._event_bus)
        scan_result = await scanner.run(scan_targets, scan_depth=scan_depth)
        state.vulnerabilities = scan_result.findings  # type: ignore[assignment]
        state.phase_results.append(scan_result)
        state.current_phase = PTESPhase.EXPLOIT
        await self._save_checkpoint(state)

        # — EXPLOIT LOOP —
        if not dry_run:
            await self._exploit_loop(state)
        state.current_phase = PTESPhase.POST_EXPLOIT
        await self._save_checkpoint(state)

        # — POST-EXPLOIT —
        if state.compromised_services:
            post = PostExploitModule(self._settings, self._evasion, self._event_bus, self._llm)
            post_result = await post.run(state.compromised_services)
            state.phase_results.append(post_result)
            # Replace compromised_services with the post-exploit-enriched versions
            # (real access_level from whoami, real evidence from commands).
            enriched = [
                svc
                for svc in post_result.findings
                if isinstance(svc, ServiceCompromised)
            ]
            if enriched:
                state.compromised_services = enriched

        state.current_phase = PTESPhase.REPORT
        await self._save_checkpoint(state)

    # ── Exploit loop ────────────────────────────────────────────────

    async def _exploit_one_target(
        self,
        target: Target,
        state: SessionState,
        exploiter: ExploiterModule,
    ) -> None:
        """Run the exploit loop for a single target with exponential backoff."""
        backoff_delay = 0.0
        consecutive_failures = 0
        _MAX_BACKOFF = 20.0
        _MAX_ATTEMPTS = 5

        attempts = 0
        while attempts < _MAX_ATTEMPTS:
            if state.is_objective_met(self._settings.min_services_to_compromise):
                break
            if backoff_delay > 0:
                log.info("backpressure_delay", target=target.ip, delay_s=round(backoff_delay, 1))
                await asyncio.sleep(backoff_delay)

            exploit_result = await exploiter.run(target, state)
            state.phase_results.append(exploit_result)

            new_compromises = 0
            for finding in exploit_result.findings:
                if isinstance(finding, ServiceCompromised):
                    if finding not in state.compromised_services:
                        state.compromised_services.append(finding)
                        new_compromises += 1
                elif isinstance(finding, dict) and finding.get("session_id"):
                    state.compromised_services.append(ServiceCompromised(**finding))
                    new_compromises += 1

            if new_compromises > 0:
                consecutive_failures = 0
                backoff_delay = 0.0
            else:
                consecutive_failures += 1
                backoff_delay = min(_MAX_BACKOFF, 2.0 ** consecutive_failures)

            attempts += 1
            await self._save_checkpoint(state)

    async def _exploit_loop(self, state: SessionState) -> None:
        """LLM-driven exploit iteration — runs all targets concurrently (max 2).

        Each target's exploit sequence runs independently with its own backoff.
        Stops early when the overall objective is met.
        """
        exploiter = ExploiterModule(self._settings, self._evasion, self._event_bus, self._llm)

        # Run up to 2 targets concurrently; share state (protected by GIL/asyncio)
        sem = asyncio.Semaphore(2)

        async def _bounded(t: Target) -> None:
            async with sem:
                if not state.is_objective_met(self._settings.min_services_to_compromise):
                    await self._exploit_one_target(t, state, exploiter)

        await asyncio.gather(*[_bounded(t) for t in state.targets])

    # ── Checkpoint persistence ──────────────────────────────────────

    async def _save_checkpoint(self, state: SessionState) -> None:
        """Serialize ``SessionState`` to JSON on disk."""
        _CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
        path = _CHECKPOINT_DIR / f"session_{state.session_id}.json"
        data = state.model_dump_json(indent=2)
        path.write_text(data, encoding="utf-8")
        log.debug("checkpoint_saved", session=state.session_id, path=str(path))

    async def _load_checkpoint(self, session_id: str) -> SessionState | None:
        """Load checkpoint from disk if it exists."""
        path = _CHECKPOINT_DIR / f"session_{session_id}.json"
        if not path.exists():
            return None
        raw = path.read_text(encoding="utf-8")
        return SessionState.model_validate_json(raw)

    # ── State helpers ───────────────────────────────────────────────

    async def _init_state(self, resume_session_id: str | None) -> SessionState:
        """Create a new ``SessionState`` or restore from checkpoint."""
        if resume_session_id:
            restored = await self._load_checkpoint(resume_session_id)
            if restored:
                log.info("checkpoint_restored", session=resume_session_id)
                return restored
            log.warning("checkpoint_not_found", session=resume_session_id)
        return SessionState()

    def _build_report_data(self, state: SessionState) -> ReportData:
        """Assemble ``ReportData`` from the session state."""
        finished_at = datetime.now(UTC)
        total = (finished_at - state.started_at).total_seconds()
        return ReportData(
            session_id=state.session_id,
            generated_at=finished_at,
            targets=state.targets,
            vulnerabilities=state.vulnerabilities,
            compromised_services=state.compromised_services,
            phase_results=state.phase_results,
            decisions=state.decisions,
            total_duration_seconds=total,
        )

    async def _handle_phase_error(
        self,
        phase: PTESPhase,
        error: RedOpsError,
        state: SessionState,
    ) -> bool:
        """Handle an error in a phase. Return ``True`` to continue, ``False`` to abort."""
        log.error("phase_error", phase=phase.value, error=str(error), exc_info=True)
        await self._save_checkpoint(state)
        return phase != PTESPhase.RECON  # abort only if recon fails completely

    async def _teardown(self, state: SessionState) -> None:
        """Close all MSF sessions opened during this engagement.

        Called in the ``finally`` block of :meth:`run` — guaranteed to execute
        even on timeout, exception or KeyboardInterrupt.

        Only closes sessions recorded in ``state.compromised_services``.
        Pre-existing sessions are never touched.
        """
        session_ids = [
            svc.session_id
            for svc in state.compromised_services
            if svc.session_id
        ]
        if not session_ids:
            log.debug("teardown_no_sessions")
            return

        log.info("teardown_start", sessions=len(session_ids))
        try:
            msf = await MSFClient.get_instance(self._settings)
            await msf.close_sessions(session_ids)
        except Exception as exc:
            log.warning("teardown_error", error=str(exc))
        finally:
            MSFClient.reset()
            log.info("teardown_complete", sessions=len(session_ids))
