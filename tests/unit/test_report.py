"""Unit tests for PDF report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from redops.core.events import EventBus
from redops.core.models import (
    Port,
    ReportData,
    ServiceCompromised,
    Target,
    Vulnerability,
)
from redops.reporting.cvss_calculator import CVSSv31Calculator
from redops.reporting.report_generator import ReportGenerator


@pytest.fixture()
def report_data(sample_vulnerabilities: list[Vulnerability]) -> ReportData:
    """Produce a minimal ``ReportData`` suitable for PDF generation."""
    target = Target(
        ip="192.168.56.101",
        hostname="metasploitable",
        os_detected="Linux 2.6.X",
        open_ports=[
            Port(number=21, service_name="ftp", version="vsftpd 2.3.4"),
            Port(number=139, service_name="smb", version="Samba 3.X"),
        ],
    )
    svc = ServiceCompromised(
        service_name="ftp",
        port=21,
        target_ip="192.168.56.101",
        exploit_used="exploit/unix/ftp/vsftpd_234_backdoor",
        cve_id="CVE-2011-2523",
        access_level="root",
        session_id="1",
        evidence={"whoami": "root"},
    )
    return ReportData(
        session_id="test_session",
        targets=[target],
        vulnerabilities=sample_vulnerabilities,
        compromised_services=[svc],
        executive_summary="Test executive summary.",
        remediations={"CVE-2011-2523": "Upgrade vsftpd to latest version."},
        total_duration_seconds=120.0,
    )


class TestReportGenerator:
    @pytest.mark.asyncio
    async def test_report_pdf_generated_with_nonzero_size(
        self, tmp_path: Path, event_bus: EventBus, report_data: ReportData
    ) -> None:
        """Verify PDF is created and has non-zero size."""
        # Arrange
        gen = ReportGenerator(event_bus)

        # Act
        pdf_path = await gen.generate(report_data, str(tmp_path))

        # Assert
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0

    @pytest.mark.asyncio
    async def test_report_pdf_filename_contains_session_id(
        self, tmp_path: Path, event_bus: EventBus, report_data: ReportData
    ) -> None:
        """PDF filename includes the session ID."""
        # Arrange
        gen = ReportGenerator(event_bus)

        # Act
        pdf_path = await gen.generate(report_data, str(tmp_path))

        # Assert
        assert "test_session" in pdf_path.name


class TestCVSSCalculatorInReport:
    def test_cvss_calculator_vsftpd_score_returns_9_8(self) -> None:
        """CVSSv31Calculator should reproduce the expected score for CVE-2011-2523."""
        # Arrange
        from redops.core.models import CVSSVector

        calc = CVSSv31Calculator()
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")

        # Act / Assert
        assert calc.calculate_base_score(vec) == 9.8
