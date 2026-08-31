"""Unit tests for Pydantic domain models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from redops.config.constants import ExploitStatus, PTESPhase, Severity
from redops.core.models import (
    CVSSVector,
    ExploitAttempt,
    Port,
    ReportData,
    SessionState,
    Target,
    Vulnerability,
)


# ── Port ────────────────────────────────────────────────────────────


class TestPort:
    def test_port_valid_defaults_returns_tcp_protocol(self) -> None:
        """A valid port defaults to TCP protocol."""
        # Arrange / Act
        port = Port(number=80, service_name="http")

        # Assert
        assert port.number == 80
        assert port.protocol == "tcp"

    def test_port_out_of_range_raises_validation_error(self) -> None:
        """Port numbers outside 1-65535 raise ValidationError."""
        with pytest.raises(ValidationError):
            Port(number=0)
        with pytest.raises(ValidationError):
            Port(number=70000)


# ── Target ──────────────────────────────────────────────────────────


class TestTarget:
    def test_target_valid_fields_returns_correct_values(self, sample_target: Target) -> None:
        """A valid target has correct IP and port count."""
        # Assert
        assert sample_target.ip == "192.168.56.101"
        assert len(sample_target.open_ports) == 3

    def test_target_frozen_model_raises_on_mutation(self, sample_target: Target) -> None:
        """Frozen model prevents attribute reassignment."""
        with pytest.raises(ValidationError):
            sample_target.ip = "1.2.3.4"  # type: ignore[misc]


# ── CVSSVector ──────────────────────────────────────────────────────


class TestCVSSVector:
    def test_cvss_vector_max_base_score_returns_9_8(self, sample_cvss_vector: CVSSVector) -> None:
        """CVE-2011-2523 vector (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) scores 9.8."""
        # Act
        score = sample_cvss_vector.calculate_base_score()

        # Assert
        assert score == 9.8

    def test_cvss_vector_changed_scope_returns_10_0(self) -> None:
        """Changed-scope vector with all-high CIA scores 10.0."""
        # Arrange
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")

        # Act
        score = vec.calculate_base_score()

        # Assert
        assert score == 10.0

    def test_cvss_vector_no_impact_returns_zero(self) -> None:
        """All CIA metrics None yields base score 0.0."""
        # Arrange
        vec = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")

        # Assert
        assert vec.calculate_base_score() == 0.0

    def test_cvss_vector_to_string_contains_prefix(self, sample_cvss_vector: CVSSVector) -> None:
        """Vector string starts with the CVSS:3.1/ prefix."""
        # Act
        s = sample_cvss_vector.to_vector_string()

        # Assert
        assert s.startswith("CVSS:3.1/")
        assert "AV:N" in s

    def test_cvss_vector_invalid_metric_raises_validation_error(self) -> None:
        """Invalid AV metric value raises ValidationError."""
        with pytest.raises(ValidationError):
            CVSSVector(AV="X", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")


# ── Vulnerability ───────────────────────────────────────────────────


class TestVulnerability:
    def test_vulnerability_critical_score_returns_critical_severity(self) -> None:
        """CVSS score 9.8 maps to CRITICAL severity."""
        # Arrange
        vuln = Vulnerability(
            cve_id="CVE-2011-2523",
            cvss_score=9.8,
            description="test",
            affected_service="ftp",
            affected_port=21,
        )

        # Assert
        assert vuln.cvss_severity() == Severity.CRITICAL

    def test_vulnerability_low_score_returns_low_severity(self) -> None:
        """CVSS score 2.0 maps to LOW severity."""
        # Arrange
        vuln = Vulnerability(
            cve_id="CVE-XXXX-XXXX",
            cvss_score=2.0,
            description="test",
            affected_service="http",
            affected_port=80,
        )

        # Assert
        assert vuln.cvss_severity() == Severity.LOW


# ── ExploitAttempt ──────────────────────────────────────────────────


class TestExploitAttempt:
    def test_exploit_attempt_with_finish_returns_correct_duration(self) -> None:
        """Duration is correctly calculated from start and finish timestamps."""
        # Arrange
        started = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        finished = datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC)

        # Act
        attempt = ExploitAttempt(
            module_path="exploit/test",
            target_ip="1.2.3.4",
            started_at=started,
            finished_at=finished,
            status=ExploitStatus.SUCCESS,
        )

        # Assert
        assert attempt.duration_seconds == 10.0

    def test_exploit_attempt_no_finish_returns_zero_duration(self) -> None:
        """Missing finish timestamp yields 0.0 seconds."""
        # Act
        attempt = ExploitAttempt(
            module_path="exploit/test",
            target_ip="1.2.3.4",
            status=ExploitStatus.ERROR,
        )

        # Assert
        assert attempt.duration_seconds == 0.0


# ── SessionState ────────────────────────────────────────────────────


class TestSessionState:
    def test_session_state_empty_returns_objective_not_met(self) -> None:
        """Empty state has not met the objective threshold."""
        # Arrange / Act
        state = SessionState()

        # Assert
        assert state.is_objective_met(3) is False

    def test_session_state_enough_services_returns_objective_met(self, sample_compromised) -> None:
        """State with enough compromised services meets the objective."""
        # Arrange
        state = SessionState()
        state.compromised_services = [sample_compromised] * 3

        # Assert
        assert state.is_objective_met(3) is True

    def test_session_state_json_roundtrip_preserves_id(self) -> None:
        """JSON serialization and deserialization preserves the session ID."""
        # Arrange
        state = SessionState()

        # Act
        json_str = state.model_dump_json()
        restored = SessionState.model_validate_json(json_str)

        # Assert
        assert restored.session_id == state.session_id


# ── ReportData ──────────────────────────────────────────────────────


class TestReportData:
    def test_report_data_empty_session_id_raises_validation_error(self) -> None:
        """Empty session_id is rejected by the model validator."""
        with pytest.raises(ValidationError):
            ReportData(session_id="")
