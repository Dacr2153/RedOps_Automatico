"""Professional PDF report generator using ReportLab.

Produces a branded penetration-test report with cover page, table of
contents, executive summary, methodology, technical findings, timeline,
remediations and appendices.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from redops.config.constants import MITRE_ATTACK_MAP
from redops.core.events import EventBus, ReportGeneratedEvent
from redops.core.models import ReportData
from redops.reporting.cvss_calculator import CVSSv31Calculator
from redops.reporting.styles import (
    ALT_ROW_GREY,
    ALT_ROW_WHITE,
    BASE_TABLE_STYLE,
    BLACK,
    DARK_GREY,
    GREEN,
    HEADER_FOOTER_MARGIN,
    PAGE_MARGIN,
    RED,
    SEVERITY_COLORS,
    STYLE_BODY,
    STYLE_CODE,
    STYLE_DISCLAIMER,
    STYLE_FOOTER,
    STYLE_HEADER,
    STYLE_HEADING1,
    STYLE_HEADING2,
    STYLE_SUBTITLE,
    STYLE_TITLE,
    WHITE,
    alternating_row_colors,
)

log = structlog.get_logger(__name__)

WIDTH, HEIGHT = A4
_cvss = CVSSv31Calculator()


# ── Page callbacks ──────────────────────────────────────────────────


def _header_footer(canvas: Any, doc: Any) -> None:
    """Draw header and footer on every content page."""
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(RED)
    canvas.drawString(PAGE_MARGIN, HEIGHT - HEADER_FOOTER_MARGIN, "REDOPS — CONFIDENTIAL")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(DARK_GREY)
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    canvas.drawRightString(WIDTH - PAGE_MARGIN, HEADER_FOOTER_MARGIN, f"Page {doc.page}  |  {ts}")
    canvas.restoreState()


def _cover_background(canvas: Any, doc: Any) -> None:
    """Full-black cover page background."""
    canvas.saveState()
    canvas.setFillColor(BLACK)
    canvas.rect(0, 0, WIDTH, HEIGHT, fill=1, stroke=0)
    canvas.restoreState()


# ── Helpers ─────────────────────────────────────────────────────────


def _make_table(
    data: list[list[str]],
    col_widths: list[float] | None = None,
) -> Table:
    """Build a styled ``Table`` with alternating row colours."""
    tbl = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = list(BASE_TABLE_STYLE) + alternating_row_colors(len(data))
    tbl.setStyle(TableStyle(style_cmds))  # type: ignore[arg-type]
    return tbl


def _severity_badge(label: str) -> str:
    """Return an HTML-coloured severity badge for a Paragraph."""
    color = SEVERITY_COLORS.get(label, DARK_GREY)
    hex_color = color.hexval() if hasattr(color, "hexval") else "#4A4A4A"
    return f'<font color="{hex_color}"><b>{label}</b></font>'


# ── ReportGenerator ────────────────────────────────────────────────


class ReportGenerator:
    """Assembles and writes a branded PDF penetration-test report.

    Args:
        event_bus: Central event bus (publishes ``ReportGeneratedEvent``).
    """

    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus

    async def generate(self, data: ReportData, output_dir: str) -> Path:
        """Generate the PDF report and return the file path.

        Args:
            data: Fully populated ``ReportData`` model.
            output_dir: Directory where the PDF will be written.

        Returns:
            ``Path`` to the generated PDF file.
        """
        outdir = Path(output_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        filename = f"redops_report_{data.session_id}.pdf"
        filepath = outdir / filename

        story = self._build_story(data)

        doc = BaseDocTemplate(
            str(filepath),
            pagesize=A4,
            leftMargin=PAGE_MARGIN,
            rightMargin=PAGE_MARGIN,
            topMargin=PAGE_MARGIN + 8 * mm,
            bottomMargin=PAGE_MARGIN + 8 * mm,
        )
        content_frame = Frame(
            doc.leftMargin,
            doc.bottomMargin,
            doc.width,
            doc.height,
            id="content",
        )
        cover_frame = Frame(0, 0, WIDTH, HEIGHT, id="cover")

        doc.addPageTemplates(
            [
                PageTemplate(id="Cover", frames=[cover_frame], onPage=_cover_background),
                PageTemplate(id="Content", frames=[content_frame], onPage=_header_footer),
            ]
        )
        doc.build(story)

        log.info("pdf_generated", path=str(filepath), pages=doc.page)
        await self._event_bus.publish(ReportGeneratedEvent(path=str(filepath)))
        return filepath

    # ── Story assembly ──────────────────────────────────────────────

    def _build_story(self, data: ReportData) -> list[Any]:
        """Return the ordered list of Platypus flowables."""
        story: list[Any] = []
        self._add_cover(story, data)
        story.append(NextPageTemplate("Content"))
        story.append(PageBreak())
        self._add_executive_summary(story, data)
        self._add_methodology(story, data)
        self._add_findings(story, data)
        self._add_attack_paths(story, data)
        self._add_timeline(story, data)
        self._add_remediations(story, data)
        self._add_appendix(story, data)
        return story

    # ── Cover page ──────────────────────────────────────────────────

    def _add_cover(self, story: list[Any], data: ReportData) -> None:
        story.append(Spacer(1, 8 * cm))
        story.append(Paragraph("REDOPS AUTOMÁTICO", STYLE_TITLE))
        story.append(
            Paragraph("Penetration Test Report — CONFIDENTIAL", STYLE_SUBTITLE)
        )
        meta_lines = [
            f"Date: {data.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"Targets: {len(data.targets)}",
            f"Duration: {data.total_duration_seconds:.0f}s",
            f"Session: {data.session_id}",
        ]
        for line in meta_lines:
            story.append(Paragraph(line, STYLE_SUBTITLE))
        story.append(Spacer(1, 2 * cm))
        story.append(
            Paragraph(
                "⚠ ETHICAL LAB ENVIRONMENT ONLY ⚠",
                STYLE_DISCLAIMER,
            )
        )

    # ── Section 1 - Executive Summary ───────────────────────────────

    def _add_executive_summary(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("1. Executive Summary", STYLE_HEADING1))
        if data.executive_summary:
            story.append(Paragraph(data.executive_summary, STYLE_BODY))
        # Critical findings table
        if data.compromised_services:
            rows: list[list[str]] = [["Service", "Port", "Severity", "CVSS", "Status"]]
            for svc in data.compromised_services:
                vuln = next(
                    (v for v in data.vulnerabilities if v.cve_id == svc.cve_id), None
                )
                score = f"{vuln.cvss_score:.1f}" if vuln else "N/A"
                sev = vuln.cvss_severity().value if vuln else "INFO"
                rows.append([svc.service_name, str(svc.port), sev, score, "COMPROMISED"])
            story.append(_make_table(rows))
        story.append(Spacer(1, 6 * mm))

    # ── Section 2 - Methodology ─────────────────────────────────────

    def _add_methodology(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("2. Methodology", STYLE_HEADING1))
        story.append(
            Paragraph(
                "This assessment followed the Penetration Testing Execution "
                "Standard (PTES) methodology with LLM-assisted decision making.",
                STYLE_BODY,
            )
        )
        if data.phase_results:
            rows: list[list[str]] = [["Phase", "Start", "End", "Duration (s)", "Status"]]
            for pr in data.phase_results:
                rows.append(
                    [
                        pr.phase.value,
                        pr.started_at.strftime("%H:%M:%S"),
                        pr.finished_at.strftime("%H:%M:%S"),
                        f"{pr.duration_seconds:.1f}",
                        pr.status,
                    ]
                )
            story.append(_make_table(rows))
        story.append(Spacer(1, 6 * mm))

    # ── Section 3 - Technical Findings ──────────────────────────────

    def _add_findings(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("3. Technical Findings", STYLE_HEADING1))
        for svc in data.compromised_services:
            vuln = next(
                (v for v in data.vulnerabilities if v.cve_id == svc.cve_id), None
            )
            sev_label = vuln.cvss_severity().value if vuln else "INFO"
            badge = _severity_badge(sev_label)
            story.append(
                Paragraph(
                    f"{svc.service_name} (port {svc.port}) — {badge}",
                    STYLE_HEADING2,
                )
            )
            if vuln:
                story.append(
                    Paragraph(f"<b>CVE:</b> {vuln.cve_id}  |  <b>CVSS:</b> {vuln.cvss_score:.1f}", STYLE_BODY)
                )
                story.append(Paragraph(vuln.description, STYLE_BODY))
            # MITRE ATT&CK mapping
            mitre = MITRE_ATTACK_MAP.get(svc.cve_id)
            if mitre:
                story.append(
                    Paragraph(
                        f"<b>MITRE ATT&CK:</b> {mitre['technique']} — {mitre['name']}",
                        STYLE_BODY,
                    )
                )
            # Evidence snippet
            if svc.evidence:
                snippet = str(svc.evidence)[:500]
                story.append(Paragraph(f"<b>Evidence:</b>", STYLE_BODY))
                story.append(Paragraph(snippet, STYLE_CODE))
            # Remediation if available
            remediation = data.remediations.get(svc.cve_id, "")
            if remediation:
                story.append(
                    Paragraph(f"<b>Remediation:</b> {remediation}", STYLE_BODY)
                )
            story.append(Spacer(1, 4 * mm))

    # ── Section 4 - Attack Paths ────────────────────────────────────

    def _add_attack_paths(self, story: list[Any], data: ReportData) -> None:
        """Render a text-based attack path flowchart as a table.

        Each row represents one successful exploitation path:
        Network → Target → Service:Port → CVE → Exploit → Session
        """
        story.append(Paragraph("4. Attack Path Visualization", STYLE_HEADING1))
        if not data.compromised_services:
            story.append(Paragraph("No successful attack paths to display.", STYLE_BODY))
            story.append(Spacer(1, 6 * mm))
            return

        rows: list[list[str]] = [["#", "Target", "Service : Port", "CVE", "Exploit Module", "Session"]]
        for idx, svc in enumerate(data.compromised_services, 1):
            rows.append([
                str(idx),
                svc.target_ip,
                f"{svc.service_name} : {svc.port}",
                svc.cve_id or "—",
                svc.exploit_used.split("/")[-1] if svc.exploit_used else "—",
                svc.session_id or "—",
            ])

        story.append(_make_table(rows, col_widths=[25, 70, 80, 80, 120, 60]))
        story.append(Spacer(1, 4 * mm))

        # Text flowchart per path
        for idx, svc in enumerate(data.compromised_services, 1):
            chain = (
                f"Network → {svc.target_ip} → {svc.service_name}:{svc.port} → "
                f"{svc.cve_id or 'N/A'} → {svc.exploit_used} → session:{svc.session_id}"
            )
            story.append(
                Paragraph(f"<b>Path {idx}:</b> {chain}", STYLE_CODE)
            )
        story.append(Spacer(1, 6 * mm))

    # ── Section 5 - Attack Timeline ─────────────────────────────────

    def _add_timeline(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("5. Attack Timeline", STYLE_HEADING1))
        rows: list[list[str]] = [["Timestamp", "Phase", "Action", "Result", "LLM Reasoning"]]
        for dec in data.decisions:
            rows.append(
                [
                    "",  # timestamp not stored in decision; use order
                    "",
                    dec.next_module,
                    "scheduled",
                    dec.reasoning[:80] if dec.reasoning else "",
                ]
            )
        for pr in data.phase_results:
            rows.append(
                [
                    pr.started_at.strftime("%H:%M:%S"),
                    pr.phase.value,
                    f"Phase {pr.phase.value}",
                    pr.status,
                    "",
                ]
            )
        if len(rows) > 1:
            story.append(_make_table(rows, col_widths=[60, 60, 120, 60, 150]))
        story.append(Spacer(1, 6 * mm))

    # ── Section 6 - Remediations ────────────────────────────────────

    def _add_remediations(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("6. Prioritised Remediations", STYLE_HEADING1))
        if not data.remediations:
            story.append(Paragraph("No remediations recorded.", STYLE_BODY))
            return
        rows: list[list[str]] = [["CVE", "Severity", "Remediation"]]
        for cve_id, text in data.remediations.items():
            vuln = next((v for v in data.vulnerabilities if v.cve_id == cve_id), None)
            sev = vuln.cvss_severity().value if vuln else "INFO"
            rows.append([cve_id, sev, text[:120]])
        story.append(_make_table(rows, col_widths=[80, 60, 310]))
        story.append(Spacer(1, 6 * mm))

    # ── Appendix ────────────────────────────────────────────────────

    def _add_appendix(self, story: list[Any], data: ReportData) -> None:
        story.append(Paragraph("Appendix — Discovered Services", STYLE_HEADING1))
        rows: list[list[str]] = [["IP", "Port", "Protocol", "Service", "Version"]]
        for target in data.targets:
            for port in target.open_ports:
                rows.append(
                    [
                        target.ip,
                        str(port.number),
                        port.protocol,
                        port.service_name,
                        port.version,
                    ]
                )
        if len(rows) > 1:
            story.append(_make_table(rows))
        story.append(Spacer(1, 6 * mm))
