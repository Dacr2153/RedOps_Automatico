"""RECON phase — host discovery, OS fingerprinting and banner grabbing.

Uses ``python-nmap`` for network sweeps and ``Scapy`` as a fallback for
ARP-based discovery and raw banner grabbing.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import nmap  # type: ignore[import-untyped]
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from redops.config.constants import BANNER_GRAB_PORTS, PTESPhase
from redops.config.settings import Settings
from redops.core.events import EventBus, PhaseCompletedEvent, PhaseStartedEvent
from redops.core.models import PTESPhaseResult, Port, Target
from redops.evasion.evasion_engine import EvasionEngine

log = structlog.get_logger(__name__)


class ReconModule:
    """Phase RECON of the PTES: host discovery and fingerprinting.

    Args:
        settings: Application configuration.
        evasion: Evasion engine for timing delays.
        event_bus: Event bus for publishing phase events.
        llm: LLM orchestrator (unused in RECON but kept for interface).
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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    async def discover_hosts(self, network: str) -> list[Target]:
        """Ping sweep with Nmap ``-sn`` to discover live hosts.

        Falls back to ARP scanning via Scapy if ICMP is blocked.

        Args:
            network: CIDR notation (e.g. ``192.168.56.0/24``).

        Returns:
            List of discovered ``Target`` objects.
        """
        log.info("recon_discover_start", network=network)
        scanner = nmap.PortScanner()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(hosts=network, arguments="-sn"),
        )
        targets: list[Target] = []
        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                hostname = scanner[host].hostname() or ""
                mac = ""
                addresses = scanner[host].get("addresses", {})
                if isinstance(addresses, dict):
                    mac = addresses.get("mac", "")
                target = Target(ip=host, hostname=hostname, mac_address=mac)
                targets.append(target)
                log.info("host_discovered", ip=host, hostname=hostname)
        # Single delay after full discovery — not per host
        if targets:
            await self._evasion.apply_timing_delay()
        log.info("recon_discover_done", hosts_found=len(targets))
        return targets

    async def fingerprint_and_grab(self, target: Target) -> Target:
        """Combined OS fingerprint + banner grab in a single nmap scan.

        Runs ``-O -sV --version-intensity 5`` on ``BANNER_GRAB_PORTS`` to
        detect services and OS simultaneously — avoids two sequential scans.

        Args:
            target: The host to fingerprint.

        Returns:
            Updated ``Target`` with ``os_detected`` and ``open_ports`` filled.
        """
        log.info("recon_fingerprint_grab", target=target.ip)
        ports_str = ",".join(str(p) for p in BANNER_GRAB_PORTS)
        scanner = nmap.PortScanner()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(
                hosts=target.ip,
                ports=ports_str,
                arguments="-O --osscan-guess -sV --version-intensity 5 -T4",
            ),
        )
        os_detected = ""
        ports: list[Port] = []
        try:
            os_matches = scanner[target.ip].get("osmatch", [])
            if os_matches:
                os_detected = os_matches[0].get("name", "")
            for proto in scanner[target.ip].all_protocols():
                for port_num in scanner[target.ip][proto]:
                    info = scanner[target.ip][proto][port_num]
                    if info.get("state") != "open":
                        continue
                    ports.append(Port(
                        number=port_num,
                        protocol=proto,
                        state="open",
                        service_name=info.get("name", ""),
                        version=info.get("version", ""),
                        banner=info.get("product", ""),
                    ))
        except KeyError:
            log.warning("fingerprint_grab_no_data", target=target.ip)
        log.info("fingerprint_done", target=target.ip, os=os_detected, ports=len(ports))
        return Target(
            ip=target.ip,
            hostname=target.hostname,
            mac_address=target.mac_address,
            os_detected=os_detected,
            open_ports=ports,
        )

    async def fingerprint_os(self, target_ip: str) -> str:
        """OS fingerprinting using Nmap ``-O`` flag (kept for standalone use)."""
        log.info("recon_os_fingerprint", target=target_ip)
        scanner = nmap.PortScanner()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(hosts=target_ip, arguments="-O --osscan-guess -T4"),
        )
        os_detected = ""
        try:
            os_matches = scanner[target_ip].get("osmatch", [])
            if os_matches:
                os_detected = os_matches[0].get("name", "")
        except KeyError:
            log.warning("os_fingerprint_failed", target=target_ip)
        return os_detected

    async def grab_banners(self, target: Target) -> list[Port]:
        """Banner grabbing on common ports (kept for standalone use)."""
        log.info("recon_banner_grab", target=target.ip)
        ports_str = ",".join(str(p) for p in BANNER_GRAB_PORTS)
        scanner = nmap.PortScanner()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(
                hosts=target.ip,
                ports=ports_str,
                arguments="-sV --version-intensity 5",
            ),
        )
        ports: list[Port] = []
        try:
            for proto in scanner[target.ip].all_protocols():
                for port_num in scanner[target.ip][proto]:
                    info = scanner[target.ip][proto][port_num]
                    state = info.get("state", "closed")
                    if state != "open":
                        continue
                    port = Port(
                        number=port_num,
                        protocol=proto,
                        state=state,
                        service_name=info.get("name", ""),
                        version=info.get("version", ""),
                        banner=info.get("product", ""),
                    )
                    ports.append(port)
                    log.debug("banner_grabbed", port=port_num, service=port.service_name)
        except KeyError:
            log.warning("banner_grab_no_data", target=target.ip)
        return ports

    async def run(self, network: str) -> PTESPhaseResult:
        """Execute the full RECON phase and return a structured result.

        Args:
            network: CIDR notation of the target network.

        Returns:
            ``PTESPhaseResult`` containing discovered targets.
        """
        started_at = datetime.now(UTC)
        await self._event_bus.publish(
            PhaseStartedEvent(phase=PTESPhase.RECON, target=network)
        )
        errors: list[str] = []
        targets: list[Target] = []
        try:
            raw_targets = await self.discover_hosts(network)
            # Fingerprint + banner-grab all hosts concurrently (max 3)
            sem = asyncio.Semaphore(3)

            async def _bounded(t: Target) -> Target:
                async with sem:
                    return await self.fingerprint_and_grab(t)

            targets = list(await asyncio.gather(*[_bounded(t) for t in raw_targets]))
        except nmap.PortScannerError as exc:
            errors.append(str(exc))
            log.error("recon_failed", error=str(exc), exc_info=True)
        finished_at = datetime.now(UTC)
        result = PTESPhaseResult(
            phase=PTESPhase.RECON,
            started_at=started_at,
            finished_at=finished_at,
            status="completed" if not errors else "partial",
            findings=targets,  # type: ignore[arg-type]
            errors=errors,
        )
        await self._event_bus.publish(PhaseCompletedEvent(phase=PTESPhase.RECON, result=result))
        return result
