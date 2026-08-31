"""Abstract base module and factory for PTES phases.

Every pipeline phase implements the ``BasePTESModule`` protocol so that
the pipeline can treat them uniformly.  ``PTESModuleFactory`` provides
dependency-injection-aware construction.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from redops.config.constants import PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus
from redops.core.models import PTESPhaseResult
from redops.evasion.evasion_engine import EvasionEngine


# ── Protocol (interface) ───────────────────────────────────────────

@runtime_checkable
class BasePTESModule(Protocol):
    """Interface that every PTES module must satisfy."""

    async def run(self, *args: Any, **kwargs: Any) -> PTESPhaseResult:
        """Execute the phase and return a structured result."""
        ...


# ── Factory ────────────────────────────────────────────────────────

class PTESModuleFactory:
    """Creates PTES module instances with shared dependencies injected.

    Args:
        settings: Application configuration.
        evasion: Evasion engine instance.
        event_bus: Central event bus.
        llm: LLM orchestrator (optional, set after construction).
    """

    def __init__(
        self,
        settings: Settings,
        evasion: EvasionEngine,
        event_bus: EventBus,
        llm: Any = None,
    ) -> None:
        self._settings = settings
        self._evasion = evasion
        self._event_bus = event_bus
        self._llm = llm

    def set_llm(self, llm: Any) -> None:
        """Late-bind the LLM orchestrator after it is constructed.

        Args:
            llm: An ``LLMOrchestrator`` instance.
        """
        self._llm = llm

    def create(self, phase: PTESPhase) -> BasePTESModule:
        """Instantiate the module for *phase* with dependencies injected.

        Args:
            phase: The PTES phase to create a module for.

        Returns:
            A fully-configured module instance.

        Raises:
            ValueError: If *phase* has no registered module.
        """
        from redops.modules.exploiter import ExploiterModule
        from redops.modules.post_exploit import PostExploitModule
        from redops.modules.recon import ReconModule
        from redops.modules.scanner import ScannerModule

        registry: dict[PTESPhase, type] = {
            PTESPhase.RECON: ReconModule,
            PTESPhase.SCAN: ScannerModule,
            PTESPhase.EXPLOIT: ExploiterModule,
            PTESPhase.POST_EXPLOIT: PostExploitModule,
        }

        module_cls = registry.get(phase)
        if module_cls is None:
            raise ValueError(f"No module registered for phase: {phase}")

        return module_cls(
            settings=self._settings,
            evasion=self._evasion,
            event_bus=self._event_bus,
            llm=self._llm,
        )
