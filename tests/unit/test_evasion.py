"""Unit tests for the evasion engine."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from redops.config.constants import EvasionProfile
from redops.core.exceptions import EvasionError
from redops.evasion.evasion_engine import (
    AggressiveEvasionStrategy,
    BalancedEvasionStrategy,
    EvasionEngine,
    StealthEvasionStrategy,
)


# ── Strategy instantiation ──────────────────────────────────────────


class TestEvasionEngine:
    def test_evasion_engine_stealth_profile_uses_stealth_strategy(self) -> None:
        """Stealth profile instantiates StealthEvasionStrategy."""
        engine = EvasionEngine(EvasionProfile.STEALTH)
        assert isinstance(engine._strategy, StealthEvasionStrategy)

    def test_evasion_engine_balanced_profile_uses_balanced_strategy(self) -> None:
        """Balanced profile instantiates BalancedEvasionStrategy."""
        engine = EvasionEngine(EvasionProfile.BALANCED)
        assert isinstance(engine._strategy, BalancedEvasionStrategy)

    def test_evasion_engine_aggressive_profile_uses_aggressive_strategy(self) -> None:
        """Aggressive profile instantiates AggressiveEvasionStrategy."""
        engine = EvasionEngine(EvasionProfile.AGGRESSIVE)
        assert isinstance(engine._strategy, AggressiveEvasionStrategy)


# ── fragment_ip_payload ─────────────────────────────────────────────


class TestFragmentation:
    def test_fragmentation_stealth_payload_produces_multiple_packets(self) -> None:
        """Fragmenting a 64-byte payload with 8-byte chunks produces 8 fragments."""
        # Arrange
        engine = EvasionEngine(EvasionProfile.STEALTH)
        payload = b"A" * 64

        # Act
        with patch("redops.evasion.evasion_engine.IP") as mock_ip, \
             patch("redops.evasion.evasion_engine.Raw") as mock_raw, \
             patch("redops.evasion.evasion_engine.fragment") as mock_frag:
            mock_ip.return_value = MagicMock()
            mock_raw.return_value = MagicMock()
            mock_ip.return_value.__truediv__ = MagicMock(return_value=MagicMock())
            mock_frag.return_value = [MagicMock()] * 8
            fragments = engine.fragment_ip_payload(
                destination="192.168.56.101", payload=payload, fragment_size=8
            )

        # Assert
        assert len(fragments) == 8

    def test_fragmentation_invalid_size_raises_evasion_error(self) -> None:
        """Fragment size not a multiple of 8 raises EvasionError."""
        # Arrange
        engine = EvasionEngine(EvasionProfile.BALANCED)

        # Act / Assert
        with pytest.raises(EvasionError, match="multiple of 8"):
            engine.fragment_ip_payload(
                destination="192.168.56.101", payload=b"A" * 32, fragment_size=10
            )


# ── Timing delays ──────────────────────────────────────────────────


class TestTimingDelay:
    @pytest.mark.asyncio
    async def test_timing_stealth_delay_within_expected_range(self) -> None:
        """Stealth delay is between 3.0 and ~10.4 seconds (base + jitter)."""
        # Arrange
        engine = EvasionEngine(EvasionProfile.STEALTH)

        # Act
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await engine.apply_timing_delay()

            # Assert
            mock_sleep.assert_awaited_once()
            delay = mock_sleep.call_args[0][0]
            assert 3.0 <= delay <= 10.4

    @pytest.mark.asyncio
    async def test_timing_aggressive_delay_within_expected_range(self) -> None:
        """Aggressive delay is between 0.1 and 0.5 seconds."""
        # Arrange
        engine = EvasionEngine(EvasionProfile.AGGRESSIVE)

        # Act
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await engine.apply_timing_delay()

            # Assert
            mock_sleep.assert_awaited_once()
            delay = mock_sleep.call_args[0][0]
            assert 0.1 <= delay <= 0.5

    @pytest.mark.asyncio
    async def test_timing_balanced_delay_within_expected_range(self) -> None:
        """Balanced delay is between 1.0 and 3.0 seconds."""
        # Arrange
        engine = EvasionEngine(EvasionProfile.BALANCED)

        # Act
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await engine.apply_timing_delay()

            # Assert
            mock_sleep.assert_awaited_once()
            delay = mock_sleep.call_args[0][0]
            assert 1.0 <= delay <= 3.0
