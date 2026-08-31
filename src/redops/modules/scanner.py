"""SCAN phase — deep port scanning and vulnerability identification.

Executes SYN scans with version detection, correlates discovered services
against the curated ``MSF_MODULES_CATALOG`` and parses NSE vuln script
output to enumerate CVEs.

Supports three adaptive scan depths:

- **quick** — Top 1000 ports (``--top-ports 1000``), fastest.
- **full** — All 65 535 TCP ports plus UDP critical (default).
- **stealth** — Top 100 ports + UDP critical with slower timing.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import nmap  # type: ignore[import-untyped]
import structlog

from redops.config.constants import (
    MSF_MODULES_CATALOG,
    PTESPhase,
    UDP_CRITICAL_PORTS,
)
from redops.config.settings import Settings
from redops.core.events import EventBus, PhaseCompletedEvent, PhaseStartedEvent
from redops.core.models import PTESPhaseResult, Port, Target, Vulnerability
from redops.evasion.evasion_engine import EvasionEngine

log = structlog.get_logger(__name__)


class ScanDepth(str, Enum):
    """Scan intensity presets."""

    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"


class ScannerModule:
    """Phase SCAN of the PTES: port scanning and vulnerability detection.

    Args:
        settings: Application configuration.
        evasion: Evasion engine for packet fragmentation and timing.
        event_bus: Central event bus.
        llm: LLM orchestrator (unused in SCAN but kept for interface).
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

    async def scan_ports(
        self,
        target: Target,
        port_range: str | None = "1-65535",
        extra_args: str | None = None,
    ) -> list[Port]:
        """SYN scan with version detection (no slow NSE vuln scripts).

        Args:
            target: The host to scan.
            port_range: Port range string, or None when extra_args contains
                ``--top-ports``.
            extra_args: Additional nmap arguments.

        Returns:
            List of open ``Port`` objects with service information.
        """
        log.info("scan_ports_start", target=target.ip, range=port_range or "top-ports")
        scanner = nmap.PortScanner()
        # -sS SYN scan, -sV version detection (intensity 5), --open only open ports
        # Removed: --script=vuln (slow), -O (done in recon), -D RND:5 (decoy, adds noise)
        nmap_args = "-sS -sV --version-intensity 5 --open"
        if extra_args:
            nmap_args = f"{nmap_args} {extra_args}"
        loop = asyncio.get_running_loop()
        kwargs: dict[str, Any] = {"hosts": target.ip, "arguments": nmap_args}
        if port_range is not None:
            kwargs["ports"] = port_range
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(**kwargs),
        )
        ports: list[Port] = []
        try:
            for proto in scanner[target.ip].all_protocols():
                for port_num in scanner[target.ip][proto]:
                    info = scanner[target.ip][proto][port_num]
                    if info.get("state") != "open":
                        continue
                    port = Port(
                        number=port_num,
                        protocol=proto,
                        state="open",
                        service_name=info.get("name", ""),
                        version=info.get("version", ""),
                        banner=info.get("product", ""),
                    )
                    ports.append(port)
        except KeyError:
            log.warning("scan_no_data", target=target.ip)
        log.info("scan_ports_done", target=target.ip, open_ports=len(ports))
        return ports

    async def scan_udp_critical(self, target: Target) -> list[Port]:
        """UDP scan on critical service ports (DNS, SNMP, TFTP, etc.).

        Args:
            target: The host to scan.

        Returns:
            List of open UDP ``Port`` objects.
        """
        ports_str = ",".join(str(p) for p in UDP_CRITICAL_PORTS)
        log.info("scan_udp_start", target=target.ip, ports=ports_str)
        scanner = nmap.PortScanner()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: scanner.scan(
                hosts=target.ip,
                ports=ports_str,
                arguments="-sU -sV --open -T4",
            ),
        )
        ports: list[Port] = []
        try:
            for port_num in scanner[target.ip].get("udp", {}):
                info = scanner[target.ip]["udp"][port_num]
                if info.get("state") != "open":
                    continue
                ports.append(
                    Port(
                        number=port_num,
                        protocol="udp",
                        state="open",
                        service_name=info.get("name", ""),
                        version=info.get("version", ""),
                    )
                )
        except KeyError:
            log.debug("udp_scan_no_data", target=target.ip)
        log.info("scan_udp_done", target=target.ip, open_ports=len(ports))
        return ports

    async def identify_vulnerabilities(
        self, target: Target, ports: list[Port]
    ) -> list[Vulnerability]:
        """Correlate open services against ``MSF_MODULES_CATALOG``.

        Maps each detected service/port combination to known vulnerabilities,
        calculates CVSS scores and orders by exploitability.

        Args:
            target: The host being analysed.
            ports: Ports discovered in the scan phase.

        Returns:
            List of ``Vulnerability`` objects sorted by CVSS descending.
        """
        vulns: list[Vulnerability] = []
        for port in ports:
            for _key, catalog_entry in MSF_MODULES_CATALOG.items():
                if _port_matches_catalog(port, catalog_entry):
                    vuln = Vulnerability(
                        cve_id=catalog_entry["cve"],
                        cvss_score=catalog_entry["cvss_base"],
                        description=catalog_entry["description"],
                        affected_service=port.service_name or catalog_entry["service_match"],
                        affected_port=port.number,
                        msf_module=catalog_entry["module"],
                    )
                    vulns.append(vuln)
                    log.info(
                        "vuln_identified",
                        cve=vuln.cve_id,
                        service=vuln.affected_service,
                        port=vuln.affected_port,
                        cvss=vuln.cvss_score,
                    )
        vulns.sort(key=lambda v: v.cvss_score, reverse=True)
        return vulns

    async def run(
        self, targets: list[Target], scan_depth: ScanDepth = ScanDepth.FULL
    ) -> PTESPhaseResult:
        """Execute the full SCAN phase across all targets.

        Args:
            targets: Hosts discovered during RECON.
            scan_depth: Adaptive scan intensity (quick/full/stealth).

        Returns:
            ``PTESPhaseResult`` containing vulnerabilities as findings.
        """
        started_at = datetime.now(UTC)
        await self._event_bus.publish(
            PhaseStartedEvent(phase=PTESPhase.SCAN, target="all")
        )
        log.info("scan_phase_start", depth=scan_depth.value, targets=len(targets))
        all_vulns: list[Vulnerability] = []
        errors: list[str] = []

        # Determine scan parameters by depth
        if scan_depth == ScanDepth.QUICK:
            port_range = None          # will use --top-ports
            nmap_extra = "--top-ports 1000 -T4"
            include_udp = False        # skip UDP for speed
        elif scan_depth == ScanDepth.STEALTH:
            port_range = None
            nmap_extra = "--top-ports 100 -T2"
            include_udp = True
        else:  # FULL
            port_range = "1-65535"
            nmap_extra = "-T4"         # aggressive timing on full scan
            include_udp = True

        async def _scan_target(target: Target) -> tuple[list[Vulnerability], list[str], Target]:
            """Scan a single target: TCP + UDP concurrently, then correlate."""
            t_errors: list[str] = []
            try:
                # Run TCP and UDP scans concurrently
                tcp_task = self.scan_ports(target, port_range=port_range, extra_args=nmap_extra)
                if include_udp:
                    tcp_ports, udp_ports = await asyncio.gather(tcp_task, self.scan_udp_critical(target))
                else:
                    tcp_ports = await tcp_task
                    udp_ports = []
                all_ports = tcp_ports + udp_ports
                # Target is frozen — build an updated copy with the discovered ports
                updated_target = target.model_copy(update={"open_ports": all_ports})
                vulns = await self.identify_vulnerabilities(updated_target, all_ports)
                return vulns, t_errors, updated_target
            except nmap.PortScannerError as exc:
                t_errors.append(f"{target.ip}: {exc}")
                log.error("scan_failed", target=target.ip, error=str(exc), exc_info=True)
                return [], t_errors, target

        # Scan all targets with limited concurrency (max 2 simultaneous)
        sem = asyncio.Semaphore(2)

        async def _bounded(t: Target) -> tuple[list[Vulnerability], list[str], Target]:
            async with sem:
                return await _scan_target(t)

        results = await asyncio.gather(*[_bounded(t) for t in targets])
        updated_targets: list[Target] = []
        for vulns, t_errors, updated_target in results:
            all_vulns.extend(vulns)
            errors.extend(t_errors)
            updated_targets.append(updated_target)
        # Propagate port-enriched targets back to the pipeline in-place so that
        # state.targets (same list object as the caller's scan_targets) reflects
        # the full open_ports list needed by LLM prompts in the exploit phase.
        targets[:] = updated_targets
        finished_at = datetime.now(UTC)
        result = PTESPhaseResult(
            phase=PTESPhase.SCAN,
            started_at=started_at,
            finished_at=finished_at,
            status="completed" if not errors else "partial",
            findings=all_vulns,  # type: ignore[arg-type]
            errors=errors,
        )
        await self._event_bus.publish(PhaseCompletedEvent(phase=PTESPhase.SCAN, result=result))
        return result


def _port_matches_catalog(port: Port, entry: dict[str, Any]) -> bool:
    """Return True if a port matches a catalog entry by port number or service name."""
    if port.number == entry.get("port_match"):
        return True
    service_match = entry.get("service_match", "")
    if service_match and service_match.lower() in port.service_name.lower():
        return True
    return False
