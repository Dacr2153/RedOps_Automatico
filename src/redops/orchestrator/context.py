"""Accumulative session context manager for the LLM orchestrator.

``SessionContext`` maintains a running log of phase results and LLM
decisions so that subsequent prompts can include relevant history.  The
context is automatically compressed via a sliding window to stay within
token budgets.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from redops.core.models import OrchestratorDecision, PTESPhaseResult

log = structlog.get_logger(__name__)

# Average English token is ~4 characters for most LLMs
_CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    """Estimate the number of LLM tokens in *text*."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


class SessionContext:
    """Manages the memory window fed to the LLM on each call.

    Aggregates phase results and orchestrator decisions using a sliding
    window.  Older entries are summarised when the context exceeds the
    token budget, keeping the most recent entries in full detail.
    """

    def __init__(self, max_tokens: int = 2000) -> None:
        self._phase_results: list[dict[str, Any]] = []
        self._decisions: list[dict[str, Any]] = []
        self._max_tokens = max_tokens
        self._archived_summary: str = ""

    def add_phase_result(self, result: PTESPhaseResult) -> None:
        """Record a completed phase result.

        Args:
            result: The PTES phase outcome to remember.
        """
        entry = {
            "phase": result.phase.value,
            "status": result.status,
            "findings_count": len(result.findings),
            "duration_s": round(result.duration_seconds, 1),
            "errors": result.errors[:3],
        }
        self._phase_results.append(entry)
        self._compact_if_needed()
        log.debug("context_phase_added", phase=result.phase.value)

    def add_decision(self, decision: OrchestratorDecision) -> None:
        """Record an LLM orchestrator decision.

        Args:
            decision: The decision to remember.
        """
        entry = {
            "module": decision.next_module,
            "confidence": decision.confidence,
            "reasoning_preview": decision.reasoning[:200],
        }
        self._decisions.append(entry)
        self._compact_if_needed()
        log.debug("context_decision_added", module=decision.next_module)

    def get_context_summary(self, max_tokens: int | None = None) -> str:
        """Return a JSON summary of accumulated context, truncated.

        Uses a ~4 chars/token estimation for accurate budget enforcement.

        Args:
            max_tokens: Override the default token budget.

        Returns:
            JSON-formatted context summary.
        """
        budget = max_tokens or self._max_tokens
        max_chars = budget * _CHARS_PER_TOKEN

        summary: dict[str, Any] = {
            "total_phases": len(self._phase_results),
            "total_decisions": len(self._decisions),
        }
        if self._archived_summary:
            summary["archived"] = self._archived_summary
        summary["recent_phases"] = self._phase_results[-5:]
        summary["recent_decisions"] = self._decisions[-5:]

        text = json.dumps(summary, indent=2)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... (truncated)"
        return text

    def clear(self) -> None:
        """Reset all accumulated context."""
        self._phase_results.clear()
        self._decisions.clear()
        self._archived_summary = ""

    def _compact_if_needed(self) -> None:
        """Archive older entries when the context grows beyond budget."""
        test_text = json.dumps({
            "phases": self._phase_results,
            "decisions": self._decisions,
        })
        if _estimate_tokens(test_text) <= self._max_tokens:
            return

        # Summarise old entries and keep only the last 5
        keep = 5
        if len(self._phase_results) > keep:
            old_phases = self._phase_results[:-keep]
            self._phase_results = self._phase_results[-keep:]
            phase_names = [p["phase"] for p in old_phases]
            self._archived_summary = (
                f"Archived: {len(old_phases)} phases ({', '.join(phase_names)})"
            )

        if len(self._decisions) > keep:
            old_decisions = self._decisions[:-keep]
            self._decisions = self._decisions[-keep:]
            modules = [d["module"] for d in old_decisions[-3:]]
            self._archived_summary += (
                f"; {len(old_decisions)} decisions (last: {', '.join(modules)})"
            )

        log.debug("context_compacted", archived=self._archived_summary)
