"""Chain-of-thought prompt builders for the LLM orchestrator.

Each function constructs a fully-formed prompt string that instructs the
model to respond **exclusively** with valid JSON matching a defined schema.
"""

from __future__ import annotations

import json
from typing import Any

from redops.core.models import (
    ExploitAttempt,
    OrchestratorDecision,
    ReportData,
    ServiceCompromised,
    Target,
    Vulnerability,
)


def build_recon_analysis_prompt(targets: list[Target], network: str) -> str:
    """Build compact prompt for recon analysis."""
    t_list = [{"ip": t.ip, "os": t.os_detected or "unknown",
               "ports": [p.number for p in t.open_ports[:15]]} for t in targets]
    return (
        "Pentester JSON-only. Prioritise targets for exploitation.\n"
        f"Network: {network} Targets: {json.dumps(t_list)}\n"
        'Return: {"prioritized_targets":[{"ip":"x","priority_score":8,"reasoning":"why"}],'
        '"recommended_scan_depth":"quick","estimated_attack_vectors":["rce"],"analysis_confidence":0.8}'
    )


def build_exploit_selection_prompt(
    target: Target,
    vulnerabilities: list[Vulnerability],
    previous_attempts: list[ExploitAttempt],
    compromised_services: list[ServiceCompromised],
    min_required: int,
    available_modules: dict[str, Any],
) -> str:
    """Build compact prompt for exploit selection."""
    failed = [a.module_path for a in previous_attempts if a.status != "success"]
    vulns = [{"cve": v.cve_id, "cvss": v.cvss_score, "svc": v.affected_service,
              "port": v.affected_port, "mod": v.msf_module} for v in vulnerabilities]
    # Only send module path + cvss to save tokens
    modules = {k: {"mod": v["module"], "cvss": v["cvss_base"]}
               for k, v in available_modules.items()}
    return (
        "Metasploit expert JSON-only. Pick best unused exploit.\n"
        f"Target:{target.ip} OS:{target.os_detected or 'Linux'}\n"
        f"Compromised:{len(compromised_services)}/{min_required} Failed:{failed}\n"
        f"Vulns:{json.dumps(vulns)} Catalog:{json.dumps(modules)}\n"
        'Return: {"next_module":"exploit/path","module_options":{"RHOSTS":"ip","RPORT":0},'
        '"payload":"cmd/unix/interact","reasoning":"why","confidence":0.85,'
        '"alternative_modules":[],"skip_reason":null}'
    )


def build_post_exploit_prompt(
    compromised_service: ServiceCompromised,
    system_info: dict[str, str],
    session_output: str,
) -> str:
    """Build prompt for post-exploitation analysis.

    Args:
        compromised_service: The service that was compromised.
        system_info: Output of info-gathering commands.
        session_output: Raw session console output.

    Returns:
        Complete prompt string.
    """
    return (
        "Post-exploitation JSON-only. Analyse compromised service.\n"
        f"Service:{compromised_service.service_name} port:{compromised_service.port} "
        f"access:{compromised_service.access_level} target:{compromised_service.target_ip}\n"
        f"Session output:{session_output[:500]}\n"
        'Return: {"privilege_escalation_vectors":["suid","sudo"],'
        '"lateral_movement_targets":[],"evidence_to_collect":["passwd","shadow"],'
        '"risk_assessment":"high","reasoning":"why"}'
    )


def build_remediation_prompt(
    vulnerabilities: list[Vulnerability],
    compromised_services: list[ServiceCompromised],
) -> str:
    """Build prompt for generating prioritised remediations.

    Args:
        vulnerabilities: All findings.
        compromised_services: Services that were compromised.

    Returns:
        Complete prompt string.
    """
    vulns_json = json.dumps(
        [{"cve": v.cve_id, "cvss": v.cvss_score, "svc": v.affected_service} for v in vulnerabilities]
    )
    comp_json = json.dumps(
        [{"svc": s.service_name, "port": s.port} for s in compromised_services]
    )
    return (
        "Security consultant JSON-only. Write remediations.\n"
        f"Vulns:{vulns_json} Compromised:{comp_json}\n"
        "Return:\n"
        "{\n"
        '  "remediations": {\n'
        '    "CVE-XXXX-XXXX": {\n'
        '      "fix": "Specific remediation steps",\n'
        '      "effort": "low|medium|high",\n'
        '      "urgency": "critical|high|medium|low"\n'
        "    }\n"
        "  }\n"
        "}\n"
    )


def build_executive_summary_prompt(
    report_data: ReportData,
    engagement_duration: float,
) -> str:
    """Build prompt for generating a non-technical executive summary.

    Args:
        report_data: Complete report data.
        engagement_duration: Total pipeline duration in seconds.

    Returns:
        Complete prompt string.
    """
    summary_data = {
        "targets_scanned": len(report_data.targets),
        "vulnerabilities_found": len(report_data.vulnerabilities),
        "services_compromised": len(report_data.compromised_services),
        "critical_findings": sum(
            1 for v in report_data.vulnerabilities if v.cvss_score >= 9.0
        ),
        "duration_minutes": round(engagement_duration / 60, 1),
    }
    return (
        "[SYSTEM CONTEXT]\n"
        "You are writing an executive summary for a penetration test report. "
        "The audience is non-technical management. Use clear language, avoid jargon. "
        "Maximum 300 words. Respond ONLY with valid JSON.\n\n"
        "[ENGAGEMENT DATA]\n"
        f"{json.dumps(summary_data, indent=2)}\n\n"
        "[TASK]\n"
        "Write a concise executive summary covering:\n"
        "1. Scope of the assessment\n"
        "2. Key findings and their business impact\n"
        "3. Overall risk posture\n"
        "4. Top priority recommendations\n\n"
        "Respond with JSON:\n"
        "{\n"
        '  "executive_summary": "Your summary text here..."\n'
        "}\n"
    )
