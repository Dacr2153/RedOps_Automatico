"""Time formatting and duration helpers used across the framework."""

from __future__ import annotations

from datetime import UTC, datetime


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to ``MM:SS`` or ``HH:MM:SS``.

    Args:
        seconds: Elapsed seconds (may be fractional).

    Returns:
        Human-readable duration string.
    """
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime.

    Returns:
        ``datetime`` with ``tzinfo=UTC``.
    """
    return datetime.now(UTC)


def elapsed_since(start: datetime) -> float:
    """Seconds elapsed since *start* (UTC-aware).

    Args:
        start: A timezone-aware ``datetime`` that marks the beginning.

    Returns:
        Seconds as a float. Returns ``0.0`` if *start* is in the future.
    """
    delta = datetime.now(UTC) - start
    return max(delta.total_seconds(), 0.0)


def iso_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string.

    Returns:
        ISO-formatted string (e.g. ``2024-06-15T12:34:56+00:00``).
    """
    return datetime.now(UTC).isoformat()
