"""Shared pytest fixtures for all RedOps tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from redops.config.constants import ExploitStatus
from redops.config.settings import Settings
from redops.core.events import EventBus
from redops.core.models import (
    CVSSVector,
    ExploitAttempt,
    Port,
    ServiceCompromised,
    Target,
    Vulnerability,
)


# ── Settings ────────────────────────────────────────────────────────


@pytest.fixture()
def settings() -> Settings:
    """Return a ``Settings`` instance with lab defaults."""
    return Settings(
        msf_host="127.0.0.1",
        msf_port=55553,
        msf_password="test_password",
        msf_ssl=False,
        ollama_host="127.0.0.1",
        ollama_port=11434,
        ollama_model="mistral",
        ollama_timeout=30,
        target_network="192.168.56.0/24",
        log_level="DEBUG",
        report_output_dir="./test_reports",
        scan_timing_min=0.1,
        scan_timing_max=0.5,
        evasion_profile="balanced",
        global_timeout_minutes=5,
        min_services_to_compromise=3,
        checkpoint_interval_seconds=60,
    )


# ── Event bus ───────────────────────────────────────────────────────


@pytest.fixture()
def event_bus() -> EventBus:
    """Return a real ``EventBus`` instance."""
    return EventBus()


# ── Sample domain objects ───────────────────────────────────────────


@pytest.fixture()
def sample_port() -> Port:
    """Return a sample open port."""
    return Port(
        number=21,
        protocol="tcp",
        state="open",
        service_name="ftp",
        version="vsftpd 2.3.4",
        banner="220 (vsFTPd 2.3.4)",
    )


@pytest.fixture()
def sample_target(sample_port: Port) -> Target:
    """Return a sample Metasploitable2-like target."""
    return Target(
        ip="192.168.56.101",
        hostname="metasploitable",
        os_detected="Linux 2.6.X",
        open_ports=[
            sample_port,
            Port(number=139, protocol="tcp", state="open", service_name="smb", version="Samba 3.X"),
            Port(number=3632, protocol="tcp", state="open", service_name="distccd", version=""),
        ],
    )


@pytest.fixture()
def sample_cvss_vector() -> CVSSVector:
    """Return the CVSSv3.1 vector for CVE-2011-2523 (vsftpd backdoor)."""
    return CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")


@pytest.fixture()
def sample_vulnerabilities() -> list[Vulnerability]:
    """Return a list of vulnerabilities with pre-calculated CVSS."""
    return [
        Vulnerability(
            cve_id="CVE-2011-2523",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="vsftpd 2.3.4 backdoor command execution",
            affected_service="ftp",
            affected_port=21,
            msf_module="exploit/unix/ftp/vsftpd_234_backdoor",
        ),
        Vulnerability(
            cve_id="CVE-2007-2447",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Samba username map script command execution",
            affected_service="smb",
            affected_port=139,
            msf_module="exploit/multi/samba/usermap_script",
        ),
        Vulnerability(
            cve_id="CVE-2004-2687",
            cvss_score=9.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="DistCC daemon command execution",
            affected_service="distccd",
            affected_port=3632,
            msf_module="exploit/unix/misc/distcc_exec",
        ),
    ]


@pytest.fixture()
def sample_compromised() -> ServiceCompromised:
    """Return a sample compromised service."""
    return ServiceCompromised(
        service_name="ftp",
        port=21,
        target_ip="192.168.56.101",
        exploit_used="exploit/unix/ftp/vsftpd_234_backdoor",
        cve_id="CVE-2011-2523",
        access_level="root",
        session_id="1",
        evidence={"whoami": "root"},
    )
