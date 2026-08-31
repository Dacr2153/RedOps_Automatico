"""Pydantic v2 domain models shared across all RedOps components.

Every data structure that travels between pipeline phases is defined here
with strict validation, immutability where appropriate, and helper methods
for serialization and display formatting.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redops.config.constants import (
    CVSS_THRESHOLDS,
    ExploitStatus,
    PTESPhase,
    Severity,
)


# ── Port ────────────────────────────────────────────────────────────

class Port(BaseModel):
    """Represents a single discovered network port."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", description="Transport protocol")
    state: str = Field(default="open", description="Port state")
    service_name: str = Field(default="", description="Service name")
    version: str = Field(default="", description="Detected version string")
    banner: str = Field(default="", description="Raw banner text")

    def to_markdown_row(self) -> str:
        """Format as a Markdown table row."""
        return (
            f"| {self.number} | {self.protocol} | {self.state} "
            f"| {self.service_name} | {self.version} |"
        )


# ── Target ──────────────────────────────────────────────────────────

class Target(BaseModel):
    """Represents a discovered host on the network."""

    model_config = ConfigDict(frozen=True)

    ip: str = Field(..., description="IPv4 address")
    hostname: str = Field(default="", description="Reverse DNS or NetBIOS name")
    os_detected: str = Field(default="", description="OS fingerprint string")
    open_ports: list[Port] = Field(default_factory=list, description="Discovered ports")
    mac_address: str = Field(default="", description="MAC address if available")

    def to_markdown_row(self) -> str:
        """Format as a Markdown table row."""
        port_count = len(self.open_ports)
        return f"| {self.ip} | {self.hostname} | {self.os_detected} | {port_count} |"


# ── CVSSVector ─────────────────────────────────────────────────────

class CVSSVector(BaseModel):
    """CVSSv3.1 base metric vector with score calculation."""

    model_config = ConfigDict(frozen=True)

    AV: str = Field(..., description="Attack Vector (N|A|L|P)")
    AC: str = Field(..., description="Attack Complexity (L|H)")
    PR: str = Field(..., description="Privileges Required (N|L|H)")
    UI: str = Field(..., description="User Interaction (N|R)")
    S: str = Field(..., description="Scope (U|C)")
    C: str = Field(..., description="Confidentiality (N|L|H)")
    I: str = Field(..., description="Integrity (N|L|H)")
    A: str = Field(..., description="Availability (N|L|H)")

    @field_validator("AV")
    @classmethod
    def validate_av(cls, v: str) -> str:
        """Validate Attack Vector metric."""
        if v not in ("N", "A", "L", "P"):
            raise ValueError(f"AV must be N|A|L|P, got {v}")
        return v

    @field_validator("AC")
    @classmethod
    def validate_ac(cls, v: str) -> str:
        """Validate Attack Complexity metric."""
        if v not in ("L", "H"):
            raise ValueError(f"AC must be L|H, got {v}")
        return v

    @field_validator("PR")
    @classmethod
    def validate_pr(cls, v: str) -> str:
        """Validate Privileges Required metric."""
        if v not in ("N", "L", "H"):
            raise ValueError(f"PR must be N|L|H, got {v}")
        return v

    @field_validator("UI")
    @classmethod
    def validate_ui(cls, v: str) -> str:
        """Validate User Interaction metric."""
        if v not in ("N", "R"):
            raise ValueError(f"UI must be N|R, got {v}")
        return v

    @field_validator("S")
    @classmethod
    def validate_s(cls, v: str) -> str:
        """Validate Scope metric."""
        if v not in ("U", "C"):
            raise ValueError(f"S must be U|C, got {v}")
        return v

    @field_validator("C", "I", "A")
    @classmethod
    def validate_cia(cls, v: str) -> str:
        """Validate CIA impact metrics."""
        if v not in ("N", "L", "H"):
            raise ValueError(f"CIA metric must be N|L|H, got {v}")
        return v

    def calculate_base_score(self) -> float:
        """Calculate CVSSv3.1 base score using the FIRST specification formula.

        Returns:
            Base score rounded up to one decimal place (0.0 – 10.0).
        """
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_values_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_values = {"N": 0.85, "R": 0.62}
        cia_values = {"N": 0.00, "L": 0.22, "H": 0.56}

        pr_map = pr_values_changed if self.S == "C" else pr_values_unchanged

        iss = 1.0 - (
            (1.0 - cia_values[self.C])
            * (1.0 - cia_values[self.I])
            * (1.0 - cia_values[self.A])
        )

        if self.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = (
            8.22 * av_values[self.AV] * ac_values[self.AC] * pr_map[self.PR] * ui_values[self.UI]
        )

        if impact <= 0:
            return 0.0

        if self.S == "U":
            raw = impact + exploitability
        else:
            raw = 1.08 * (impact + exploitability)

        capped = min(raw, 10.0)
        return _roundup(capped)

    def to_vector_string(self) -> str:
        """Serialize to standard CVSSv3.1 vector string notation."""
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )


def _roundup(value: float) -> float:
    """CVSSv3.1 Roundup function per FIRST specification."""
    return math.ceil(value * 10) / 10


# ── Vulnerability ──────────────────────────────────────────────────

class Vulnerability(BaseModel):
    """A vulnerability finding discovered during scanning."""

    model_config = ConfigDict(frozen=True)

    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSSv3.1 base score")
    cvss_vector: str = Field(default="", description="CVSSv3.1 vector string")
    description: str = Field(..., description="Technical description")
    affected_service: str = Field(..., description="Service name")
    affected_port: int = Field(..., ge=1, le=65535, description="Affected port number")
    msf_module: str = Field(default="", description="Metasploit module path")

    def cvss_severity(self) -> Severity:
        """Derive qualitative severity from the numeric CVSS score."""
        for label, (low, high) in CVSS_THRESHOLDS.items():
            if low <= self.cvss_score <= high:
                return Severity(label)
        return Severity.INFO

    def to_markdown_row(self) -> str:
        """Format as a Markdown table row."""
        sev = self.cvss_severity().value
        return (
            f"| {self.cve_id} | {self.cvss_score} | {sev} "
            f"| {self.affected_service} | {self.affected_port} |"
        )


# ── ExploitAttempt ─────────────────────────────────────────────────

class ExploitAttempt(BaseModel):
    """Records a single exploit execution attempt and its outcome."""

    model_config = ConfigDict(frozen=True)

    module_path: str = Field(..., description="MSF module path")
    target_ip: str = Field(..., description="Target IP address")
    options: dict[str, Any] = Field(default_factory=dict, description="Module options")
    payload: str = Field(default="", description="Payload name")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Start timestamp"
    )
    finished_at: datetime | None = Field(default=None, description="Finish timestamp")
    status: ExploitStatus = Field(default=ExploitStatus.ERROR, description="Result status")
    session_id: str | None = Field(default=None, description="MSF session ID on success")
    output: str = Field(default="", description="Console output")

    @property
    def duration_seconds(self) -> float:
        """Elapsed seconds between start and finish."""
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()


# ── ServiceCompromised ─────────────────────────────────────────────

class ServiceCompromised(BaseModel):
    """Evidence of a successfully compromised service."""

    model_config = ConfigDict(frozen=True)

    service_name: str = Field(..., description="Service name")
    port: int = Field(..., ge=1, le=65535, description="Service port")
    target_ip: str = Field(..., description="Target IP")
    exploit_used: str = Field(..., description="MSF module path used")
    cve_id: str = Field(default="", description="Associated CVE")
    access_level: str = Field(default="user", description="root | user | daemon")
    session_id: str = Field(default="", description="MSF session identifier")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Collected outputs")
    compromised_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Timestamp of compromise"
    )

    def to_markdown_row(self) -> str:
        """Format as a Markdown table row."""
        return (
            f"| {self.service_name} | {self.port} | {self.target_ip} "
            f"| {self.access_level} | {self.cve_id} |"
        )


# ── PTESPhaseResult ────────────────────────────────────────────────

class PTESPhaseResult(BaseModel):
    """Outcome of a single PTES phase execution."""

    model_config = ConfigDict(frozen=True)

    phase: PTESPhase = Field(..., description="PTES phase")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Phase start"
    )
    finished_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Phase end"
    )
    status: str = Field(default="completed", description="completed | partial | failed")
    findings: list[Any] = Field(default_factory=list, description="Phase-specific findings")
    errors: list[str] = Field(default_factory=list, description="Error messages")

    @property
    def duration_seconds(self) -> float:
        """Elapsed seconds for the phase."""
        return (self.finished_at - self.started_at).total_seconds()


# ── OrchestratorDecision ───────────────────────────────────────────

class OrchestratorDecision(BaseModel):
    """A decision made by the LLM Orchestrator."""

    model_config = ConfigDict(frozen=True)

    next_module: str = Field(..., description="MSF module to execute next")
    module_options: dict[str, Any] = Field(
        default_factory=dict, description="Options for the module"
    )
    payload: str = Field(default="", description="Payload to use")
    reasoning: str = Field(default="", description="Chain-of-thought reasoning")
    confidence: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Confidence score"
    )
    alternative_modules: list[str] = Field(
        default_factory=list, description="Fallback modules"
    )
    skip_reason: str | None = Field(
        default=None, description="If set, skip this exploit and why"
    )

    @field_validator("alternative_modules", mode="before")
    @classmethod
    def coerce_alternative_modules(cls, v: object) -> list[str]:
        """Accept None or missing from LLM; coerce to empty list."""
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        return []


# ── SessionState ───────────────────────────────────────────────────

class SessionState(BaseModel):
    """Complete serializable state of a pipeline session for checkpoint / recovery."""

    session_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12], description="Unique session ID"
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Session start"
    )
    targets: list[Target] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    exploit_attempts: list[ExploitAttempt] = Field(default_factory=list)
    compromised_services: list[ServiceCompromised] = Field(default_factory=list)
    decisions: list[OrchestratorDecision] = Field(default_factory=list)
    phase_results: list[PTESPhaseResult] = Field(default_factory=list)
    current_phase: PTESPhase = Field(default=PTESPhase.RECON)

    def is_objective_met(self, min_services: int) -> bool:
        """Return True when the minimum compromised services threshold is reached."""
        return len(self.compromised_services) >= min_services


# ── ReportData ─────────────────────────────────────────────────────

class ReportData(BaseModel):
    """All data required to generate the final PDF report."""

    model_config = ConfigDict(frozen=True)

    session_id: str = Field(..., description="Session identifier")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Generation timestamp"
    )
    targets: list[Target] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    compromised_services: list[ServiceCompromised] = Field(default_factory=list)
    phase_results: list[PTESPhaseResult] = Field(default_factory=list)
    decisions: list[OrchestratorDecision] = Field(default_factory=list)
    executive_summary: str = Field(default="", description="LLM generated summary")
    remediations: dict[str, str] = Field(default_factory=dict)
    total_duration_seconds: float = Field(default=0.0)

    @model_validator(mode="after")
    def validate_report_data(self) -> "ReportData":
        """Ensure report has at least one target and session ID is populated."""
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        return self
