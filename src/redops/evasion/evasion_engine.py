"""IDS evasion engine with pluggable strategy profiles.

The engine wraps Scapy primitives for IP fragmentation, TCP segmentation,
decoy injection and adaptive timing delays.  Three concrete strategies
(Stealth / Balanced / Aggressive) implement the ``EvasionStrategy``
protocol and can be swapped at runtime through configuration.
"""

from __future__ import annotations

import asyncio
import random
from typing import Protocol, runtime_checkable

import structlog
from scapy.all import IP, TCP, Raw, fragment, send  # type: ignore[import-untyped]
from scapy.packet import Packet  # type: ignore[import-untyped]

from redops.config.constants import EVASION_PROFILES, EvasionProfile
from redops.core.exceptions import EvasionError

log = structlog.get_logger(__name__)


# ── Strategy protocol ──────────────────────────────────────────────

@runtime_checkable
class EvasionStrategy(Protocol):
    """Protocol that every evasion profile must satisfy."""

    @property
    def profile_name(self) -> str:
        """Human-readable profile label."""
        ...

    async def apply_timing_delay(self) -> None:
        """Insert an inter-operation delay appropriate for this profile."""
        ...

    def fragment_ip_payload(
        self, destination: str, payload: bytes, fragment_size: int
    ) -> list[Packet]:
        """Fragment *payload* into IP packets for *destination*."""
        ...

    async def send_with_decoys(self, packet: Packet, num_decoys: int) -> None:
        """Send *packet* intercalated with decoy source IPs."""
        ...


# ── Concrete strategies ────────────────────────────────────────────

class StealthEvasionStrategy:
    """Maximum evasion: long delays, small fragments, decoy injection."""

    profile_name: str = "stealth"

    def __init__(self) -> None:
        cfg = EVASION_PROFILES[EvasionProfile.STEALTH]
        self._min_delay: float = cfg["min_delay"]
        self._max_delay: float = cfg["max_delay"]
        self._fragment_size: int = cfg["fragment_size"]

    async def apply_timing_delay(self) -> None:
        """Exponential-jitter delay between 3–8 s."""
        base = random.uniform(self._min_delay, self._max_delay)
        jitter = random.uniform(0, base * 0.3)
        delay = base + jitter
        log.debug("evasion_delay", profile="stealth", delay_s=round(delay, 2))
        await asyncio.sleep(delay)

    def fragment_ip_payload(
        self, destination: str, payload: bytes, fragment_size: int
    ) -> list[Packet]:
        """Fragment with small 8-byte chunks."""
        _validate_fragment_size(fragment_size)
        pkt = IP(dst=destination) / Raw(load=payload)
        frags: list[Packet] = fragment(pkt, fragsize=fragment_size)
        log.debug("ip_fragmented", dst=destination, fragments=len(frags))
        return frags

    async def send_with_decoys(self, packet: Packet, num_decoys: int = 5) -> None:
        """Intercalate real packet among decoy-sourced packets."""
        decoy_ips = [_random_rfc1918_ip() for _ in range(num_decoys)]
        insert_pos = random.randint(0, num_decoys)
        for idx, decoy_ip in enumerate(decoy_ips):
            if idx == insert_pos:
                await _async_send(packet)
            decoy_pkt = IP(src=decoy_ip, dst=packet[IP].dst) / Raw(load=b"\x00" * 8)
            await _async_send(decoy_pkt)
        if insert_pos == num_decoys:
            await _async_send(packet)
        log.debug("decoys_sent", count=num_decoys)


class BalancedEvasionStrategy:
    """Moderate evasion: medium delays, 16-byte fragments, no decoys."""

    profile_name: str = "balanced"

    def __init__(self) -> None:
        cfg = EVASION_PROFILES[EvasionProfile.BALANCED]
        self._min_delay: float = cfg["min_delay"]
        self._max_delay: float = cfg["max_delay"]
        self._fragment_size: int = cfg["fragment_size"]

    async def apply_timing_delay(self) -> None:
        """Uniform random delay between 1–3 s."""
        delay = random.uniform(self._min_delay, self._max_delay)
        log.debug("evasion_delay", profile="balanced", delay_s=round(delay, 2))
        await asyncio.sleep(delay)

    def fragment_ip_payload(
        self, destination: str, payload: bytes, fragment_size: int
    ) -> list[Packet]:
        """Fragment with 16-byte chunks."""
        _validate_fragment_size(fragment_size)
        pkt = IP(dst=destination) / Raw(load=payload)
        frags: list[Packet] = fragment(pkt, fragsize=fragment_size)
        log.debug("ip_fragmented", dst=destination, fragments=len(frags))
        return frags

    async def send_with_decoys(self, packet: Packet, num_decoys: int = 0) -> None:
        """Balanced profile does not use decoys — send directly."""
        await _async_send(packet)


class AggressiveEvasionStrategy:
    """Minimal evasion: very short delays, large fragments, no decoys."""

    profile_name: str = "aggressive"

    def __init__(self) -> None:
        cfg = EVASION_PROFILES[EvasionProfile.AGGRESSIVE]
        self._min_delay: float = cfg["min_delay"]
        self._max_delay: float = cfg["max_delay"]
        self._fragment_size: int = cfg["fragment_size"]

    async def apply_timing_delay(self) -> None:
        """Very short uniform delay between 0.1–0.5 s."""
        delay = random.uniform(self._min_delay, self._max_delay)
        log.debug("evasion_delay", profile="aggressive", delay_s=round(delay, 2))
        await asyncio.sleep(delay)

    def fragment_ip_payload(
        self, destination: str, payload: bytes, fragment_size: int
    ) -> list[Packet]:
        """Large 32-byte fragments (fast throughput)."""
        _validate_fragment_size(fragment_size)
        pkt = IP(dst=destination) / Raw(load=payload)
        frags: list[Packet] = fragment(pkt, fragsize=fragment_size)
        log.debug("ip_fragmented", dst=destination, fragments=len(frags))
        return frags

    async def send_with_decoys(self, packet: Packet, num_decoys: int = 0) -> None:
        """Aggressive profile does not use decoys — send directly."""
        await _async_send(packet)


# ── Factory mapping ────────────────────────────────────────────────

_STRATEGY_MAP: dict[EvasionProfile, type[EvasionStrategy]] = {
    EvasionProfile.STEALTH: StealthEvasionStrategy,  # type: ignore[dict-item]
    EvasionProfile.BALANCED: BalancedEvasionStrategy,  # type: ignore[dict-item]
    EvasionProfile.AGGRESSIVE: AggressiveEvasionStrategy,  # type: ignore[dict-item]
}


# ── EvasionEngine facade ──────────────────────────────────────────

class EvasionEngine:
    """Facade that delegates to the active ``EvasionStrategy``.

    Args:
        profile: The evasion profile to use.
    """

    def __init__(self, profile: EvasionProfile) -> None:
        strategy_cls = _STRATEGY_MAP[profile]
        self._strategy: EvasionStrategy = strategy_cls()
        self._profile = profile
        log.info("evasion_engine_init", profile=profile.value)

    @property
    def profile(self) -> EvasionProfile:
        """Currently active evasion profile."""
        return self._profile

    async def apply_timing_delay(self) -> None:
        """Delegate timing delay to the active strategy."""
        await self._strategy.apply_timing_delay()

    def fragment_ip_payload(
        self, destination: str, payload: bytes, fragment_size: int | None = None
    ) -> list[Packet]:
        """Fragment *payload* into IP packets headed for *destination*.

        Args:
            destination: Target IPv4 address.
            payload: Raw bytes to fragment.
            fragment_size: Override fragment size (must be multiple of 8).
                If ``None``, uses the profile default.

        Returns:
            List of Scapy ``Packet`` objects ready to transmit.

        Raises:
            EvasionError: If *fragment_size* is not a multiple of 8.
        """
        size = fragment_size or EVASION_PROFILES[self._profile]["fragment_size"]
        return self._strategy.fragment_ip_payload(destination, payload, size)

    async def send_with_decoys(
        self, packet: Packet, num_decoys: int = 5
    ) -> None:
        """Send *packet* with optional decoy intercalation.

        Args:
            packet: Scapy packet to send.
            num_decoys: Number of decoy packets (only used in Stealth).
        """
        await self._strategy.send_with_decoys(packet, num_decoys)

    async def tcp_segment_http(
        self, destination: str, port: int, http_request: str
    ) -> int:
        """Send an HTTP request split across multiple TCP segments.

        This is a fire-and-forget operation that bypasses IDS by splitting
        the HTTP payload across multiple small TCP segments.  No response
        capture is attempted because reliable reassembly via raw sockets
        is impractical.

        Args:
            destination: Target IP.
            port: Target port.
            http_request: Full HTTP request string.

        Returns:
            Number of TCP segments sent.
        """
        chunk_size = max(8, EVASION_PROFILES[self._profile]["fragment_size"])
        data = http_request.encode()
        chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
        seq = 1000
        for chunk in chunks:
            pkt = (
                IP(dst=destination)
                / TCP(dport=port, sport=random.randint(1024, 65535), seq=seq, flags="PA")
                / Raw(load=chunk)
            )
            await _async_send(pkt)
            seq += len(chunk)
            await self.apply_timing_delay()
        log.debug(
            "tcp_segmented",
            dst=destination,
            port=port,
            segments=len(chunks),
        )
        return len(chunks)


# ── Private helpers ────────────────────────────────────────────────

def _validate_fragment_size(size: int) -> None:
    """Raise ``EvasionError`` if *size* is not a positive multiple of 8."""
    if size <= 0 or size % 8 != 0:
        raise EvasionError(
            f"fragment_size must be a positive multiple of 8, got {size}"
        )


def _random_rfc1918_ip() -> str:
    """Generate a random RFC-1918 private IP address for decoy packets."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


async def _async_send(packet: Packet) -> None:
    """Run Scapy ``send()`` in a thread executor to avoid blocking the loop."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: send(packet, verbose=0))
