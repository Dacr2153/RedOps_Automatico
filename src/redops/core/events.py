"""Async event bus and typed event definitions (Observer pattern).

Components publish events (e.g. ``PhaseStartedEvent``) and other parts of
the system subscribe to react — enabling loose coupling between pipeline
phases, the CLI dashboard, logging hooks, and the report generator.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Coroutine

import structlog

from redops.config.constants import PTESPhase
from redops.core.models import (
    OrchestratorDecision,
    PTESPhaseResult,
    ServiceCompromised,
)

log = structlog.get_logger(__name__)


# ── Typed events ────────────────────────────────────────────────────

@dataclass(frozen=True)
class PhaseStartedEvent:
    """Emitted when a PTES phase begins execution."""

    phase: PTESPhase
    target: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class PhaseCompletedEvent:
    """Emitted when a PTES phase finishes."""

    phase: PTESPhase
    result: PTESPhaseResult
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ExploitSuccessEvent:
    """Emitted when a service is successfully compromised."""

    service: ServiceCompromised
    session_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class LLMDecisionEvent:
    """Emitted after the LLM orchestrator produces a decision."""

    decision: OrchestratorDecision
    phase: PTESPhase
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ReportGeneratedEvent:
    """Emitted after the PDF report is successfully written."""

    path: str
    compromised_count: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


# Type alias for async handler callables
EventHandler = Callable[..., Coroutine[Any, Any, None]]


# ── EventBus ────────────────────────────────────────────────────────

class EventBus:
    """Asynchronous publish / subscribe event bus.

    Subscribers are async callables keyed by event type.  ``publish``
    dispatches to all registered handlers concurrently.
    """

    def __init__(self) -> None:
        self._subscribers: dict[type, list[EventHandler]] = defaultdict(list)

    async def subscribe(self, event_type: type, handler: EventHandler) -> None:
        """Register *handler* for events of *event_type*.

        Args:
            event_type: The class of event to listen for.
            handler: An async callable that receives the event instance.
        """
        self._subscribers[event_type].append(handler)
        log.debug("event_subscribed", event_type=event_type.__name__)

    async def publish(self, event: Any) -> None:
        """Dispatch *event* to all subscribers of its type.

        Args:
            event: An event instance (any of the ``*Event`` dataclasses).
        """
        event_type = type(event)
        handlers = self._subscribers.get(event_type, [])
        if not handlers:
            return
        await asyncio.gather(
            *(handler(event) for handler in handlers),
            return_exceptions=True,
        )
        log.debug(
            "event_published",
            event_type=event_type.__name__,
            handler_count=len(handlers),
        )
