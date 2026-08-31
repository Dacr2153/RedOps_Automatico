"""ReportLab styles, colors and reusable table/paragraph configuration.

Centralises all visual constants for the PDF report so that
``report_generator.py`` stays focused on content assembly.
"""

from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm

# ── Brand colours ───────────────────────────────────────────────────

RED = colors.HexColor("#CC0000")
BLACK = colors.HexColor("#1A1A1A")
DARK_GREY = colors.HexColor("#4A4A4A")
GREEN = colors.HexColor("#2E7D32")
WHITE = colors.white
ALT_ROW_GREY = colors.HexColor("#F5F5F5")
ALT_ROW_WHITE = colors.HexColor("#FFFFFF")
ORANGE = colors.HexColor("#E65100")
YELLOW = colors.HexColor("#F9A825")

# ── Severity → colour mapping ──────────────────────────────────────

SEVERITY_COLORS: dict[str, colors.Color] = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
    "INFO": DARK_GREY,
}

# ── Page dimensions ────────────────────────────────────────────────

PAGE_MARGIN = 2.0 * cm
HEADER_FOOTER_MARGIN = 1.2 * cm

# ── Paragraph styles ───────────────────────────────────────────────

_base = getSampleStyleSheet()


def _style(
    name: str,
    parent: str = "Normal",
    **overrides: object,
) -> ParagraphStyle:
    """Create a ``ParagraphStyle`` derived from a builtin parent."""
    return ParagraphStyle(name, parent=_base[parent], **overrides)  # type: ignore[arg-type]


STYLE_TITLE = _style(
    "RO_Title",
    parent="Title",
    fontName="Helvetica-Bold",
    fontSize=28,
    textColor=RED,
    alignment=TA_CENTER,
    spaceAfter=12 * mm,
)

STYLE_SUBTITLE = _style(
    "RO_Subtitle",
    fontName="Helvetica",
    fontSize=14,
    textColor=WHITE,
    alignment=TA_CENTER,
    spaceAfter=6 * mm,
)

STYLE_HEADING1 = _style(
    "RO_H1",
    parent="Heading1",
    fontName="Helvetica-Bold",
    fontSize=18,
    textColor=RED,
    spaceBefore=14 * mm,
    spaceAfter=6 * mm,
)

STYLE_HEADING2 = _style(
    "RO_H2",
    parent="Heading2",
    fontName="Helvetica-Bold",
    fontSize=14,
    textColor=BLACK,
    spaceBefore=8 * mm,
    spaceAfter=4 * mm,
)

STYLE_BODY = _style(
    "RO_Body",
    fontName="Helvetica",
    fontSize=10,
    textColor=BLACK,
    leading=14,
    spaceAfter=4 * mm,
)

STYLE_CODE = _style(
    "RO_Code",
    fontName="Courier",
    fontSize=7,
    textColor=DARK_GREY,
    leading=9,
    leftIndent=8 * mm,
    spaceAfter=4 * mm,
)

STYLE_FOOTER = _style(
    "RO_Footer",
    fontName="Helvetica",
    fontSize=7,
    textColor=DARK_GREY,
    alignment=TA_RIGHT,
)

STYLE_HEADER = _style(
    "RO_Header",
    fontName="Helvetica-Bold",
    fontSize=7,
    textColor=RED,
    alignment=TA_LEFT,
)

STYLE_DISCLAIMER = _style(
    "RO_Disclaimer",
    fontName="Helvetica-Bold",
    fontSize=11,
    textColor=ORANGE,
    alignment=TA_CENTER,
    spaceBefore=6 * mm,
    spaceAfter=6 * mm,
)

# ── Table helpers ──────────────────────────────────────────────────


def alternating_row_colors(
    row_count: int,
    *,
    header_bg: colors.Color = RED,
    even: colors.Color = ALT_ROW_WHITE,
    odd: colors.Color = ALT_ROW_GREY,
) -> list[tuple[str, tuple[int, int], tuple[int, int], colors.Color]]:
    """Return ReportLab ``TableStyle`` background-colour commands.

    The first row (header) uses *header_bg*, subsequent rows alternate.

    Args:
        row_count: Total number of rows including header.
        header_bg: Background colour for the header row.
        even: Colour for even data rows (0-indexed after header).
        odd: Colour for odd data rows.

    Returns:
        List of ``('BACKGROUND', ...)`` style commands.
    """
    cmds: list[tuple[str, tuple[int, int], tuple[int, int], colors.Color]] = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
    ]
    for i in range(1, row_count):
        bg = even if i % 2 == 0 else odd
        cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
    return cmds


BASE_TABLE_STYLE: list[tuple[object, ...]] = [
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, 0), 9),
    ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
    ("FONTSIZE", (0, 1), (-1, -1), 8),
    ("TEXTCOLOR", (0, 1), (-1, -1), BLACK),
    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("GRID", (0, 0), (-1, -1), 0.25, DARK_GREY),
    ("TOPPADDING", (0, 0), (-1, -1), 4),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
]
