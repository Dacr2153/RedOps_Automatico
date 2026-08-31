"""Unit tests for the CVSSv3.1 calculator."""

from __future__ import annotations

import pytest

from redops.config.constants import Severity
from redops.core.models import CVSSVector
from redops.reporting.cvss_calculator import CVSSv31Calculator

calc = CVSSv31Calculator()


# ── Reference vectors from NIST NVD ────────────────────────────────


class TestCalculateBaseScore:
    """Validate against known CVE base scores."""

    def test_base_score_cve_2011_2523_vsftpd_returns_9_8(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8."""
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        assert calc.calculate_base_score(vec) == 9.8

    def test_base_score_cve_2021_44228_log4shell_returns_10_0(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0."""
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")
        assert calc.calculate_base_score(vec) == 10.0

    def test_base_score_cve_2017_0144_eternalblue_returns_8_1(self) -> None:
        """AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 8.1."""
        vec = CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="H")
        assert calc.calculate_base_score(vec) == 8.1

    def test_base_score_low_privileges_physical_returns_1_6(self) -> None:
        """AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → 1.6."""
        vec = CVSSVector(AV="P", AC="H", PR="H", UI="R", S="U", C="L", I="N", A="N")
        assert calc.calculate_base_score(vec) == 1.6

    def test_base_score_zero_impact_returns_0_0(self) -> None:
        """All CIA = None → 0.0."""
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
        assert calc.calculate_base_score(vec) == 0.0


# ── parse_vector_string ─────────────────────────────────────────────


class TestParseVectorString:
    def test_parse_vector_with_prefix_returns_correct_av(self) -> None:
        """CVSS:3.1/ prefix is stripped and vector is parsed."""
        vec = calc.parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert vec.AV == "N"
        assert calc.calculate_base_score(vec) == 9.8

    def test_parse_vector_without_prefix_returns_correct_av(self) -> None:
        """Vector string without CVSS:3.1/ prefix is still parsed."""
        vec = calc.parse_vector_string("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert vec.AV == "N"

    def test_parse_vector_invalid_string_raises_value_error(self) -> None:
        """Completely invalid string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid"):
            calc.parse_vector_string("NOT_A_VECTOR")

    def test_parse_vector_partial_string_raises_value_error(self) -> None:
        """Incomplete vector string raises ValueError."""
        with pytest.raises(ValueError, match="Invalid"):
            calc.parse_vector_string("AV:N/AC:L")


# ── severity_label ──────────────────────────────────────────────────


class TestSeverityLabel:
    def test_severity_label_9_8_returns_critical(self) -> None:
        """Score 9.8 maps to CRITICAL."""
        assert calc.severity_label(9.8) == Severity.CRITICAL

    def test_severity_label_7_5_returns_high(self) -> None:
        """Score 7.5 maps to HIGH."""
        assert calc.severity_label(7.5) == Severity.HIGH

    def test_severity_label_5_0_returns_medium(self) -> None:
        """Score 5.0 maps to MEDIUM."""
        assert calc.severity_label(5.0) == Severity.MEDIUM

    def test_severity_label_2_0_returns_low(self) -> None:
        """Score 2.0 maps to LOW."""
        assert calc.severity_label(2.0) == Severity.LOW

    def test_severity_label_0_0_returns_info(self) -> None:
        """Score 0.0 maps to INFO."""
        assert calc.severity_label(0.0) == Severity.INFO

    def test_severity_label_boundary_9_0_returns_critical(self) -> None:
        """9.0 is CRITICAL."""
        assert calc.severity_label(9.0) == Severity.CRITICAL

    def test_severity_label_boundary_7_0_returns_high(self) -> None:
        """7.0 is HIGH."""
        assert calc.severity_label(7.0) == Severity.HIGH
