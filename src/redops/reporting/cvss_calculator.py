"""CVSSv3.1 base-score calculator implemented from the FIRST specification.

No external CVSS libraries are used — all constants, formulas and rounding
follow the official FIRST CVSSv3.1 document.
"""

from __future__ import annotations

import math
import re

from redops.config.constants import CVSS_THRESHOLDS, Severity
from redops.core.models import CVSSVector


# ── Value tables (FIRST CVSSv3.1 spec) ──────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

_VECTOR_RE = re.compile(
    r"(?:CVSS:3\.1/)?"
    r"AV:(?P<AV>[NALP])/"
    r"AC:(?P<AC>[LH])/"
    r"PR:(?P<PR>[NLH])/"
    r"UI:(?P<UI>[NR])/"
    r"S:(?P<S>[UC])/"
    r"C:(?P<C>[NLH])/"
    r"I:(?P<I>[NLH])/"
    r"A:(?P<A>[NLH])"
)


def _roundup(value: float) -> float:
    """CVSSv3.1 roundup function — ceiling to 1 decimal place."""
    return math.ceil(value * 10) / 10


class CVSSv31Calculator:
    """Stateless CVSSv3.1 base-score calculator following FIRST specification."""

    def calculate_base_score(self, vector: CVSSVector) -> float:
        """Compute the CVSSv3.1 base score for *vector*.

        Implements the official FIRST formula:
            ISS  = 1 - [(1 - C) * (1 - I) * (1 - A)]
            Impact (Unchanged) = 6.42 * ISS
            Impact (Changed)   = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15
            Exploitability     = 8.22 * AV * AC * PR * UI
            BaseScore = Roundup(min(combined, 10))

        Args:
            vector: Validated ``CVSSVector`` model.

        Returns:
            Base score in range 0.0 – 10.0.
        """
        pr_map = _PR_CHANGED if vector.S == "C" else _PR_UNCHANGED

        iss = 1.0 - (
            (1.0 - _CIA[vector.C])
            * (1.0 - _CIA[vector.I])
            * (1.0 - _CIA[vector.A])
        )

        if vector.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = (
            8.22
            * _AV[vector.AV]
            * _AC[vector.AC]
            * pr_map[vector.PR]
            * _UI[vector.UI]
        )

        if impact <= 0:
            return 0.0

        if vector.S == "U":
            raw = impact + exploitability
        else:
            raw = 1.08 * (impact + exploitability)

        return _roundup(min(raw, 10.0))

    def parse_vector_string(self, vector_string: str) -> CVSSVector:
        """Parse a CVSSv3.1 vector string into a ``CVSSVector`` model.

        Accepts formats with or without the ``CVSS:3.1/`` prefix.

        Args:
            vector_string: E.g. ``"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``.

        Returns:
            Validated ``CVSSVector`` instance.

        Raises:
            ValueError: When the string does not match the expected pattern.
        """
        match = _VECTOR_RE.fullmatch(vector_string.strip())
        if not match:
            raise ValueError(f"Invalid CVSSv3.1 vector string: {vector_string!r}")
        return CVSSVector(**match.groupdict())

    def severity_label(self, score: float) -> Severity:
        """Return the qualitative severity for a numeric CVSS score.

        Args:
            score: CVSSv3.1 base score (0.0 – 10.0).

        Returns:
            Corresponding ``Severity`` enum member.
        """
        for label, (low, high) in CVSS_THRESHOLDS.items():
            if low <= score <= high:
                return Severity(label)
        return Severity.INFO

    def format_vector_table(self, vector: CVSSVector) -> list[list[str]]:
        """Format a ``CVSSVector`` as table rows for PDF rendering.

        Args:
            vector: Validated CVSS vector.

        Returns:
            List of ``[Metric, Value, Description]`` rows.
        """
        labels = {
            "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
            "AC": {"L": "Low", "H": "High"},
            "PR": {"N": "None", "L": "Low", "H": "High"},
            "UI": {"N": "None", "R": "Required"},
            "S": {"U": "Unchanged", "C": "Changed"},
            "C": {"N": "None", "L": "Low", "H": "High"},
            "I": {"N": "None", "L": "Low", "H": "High"},
            "A": {"N": "None", "L": "Low", "H": "High"},
        }
        rows: list[list[str]] = []
        for metric in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            val: str = getattr(vector, metric) or ""
            desc = labels[metric].get(val, val)
            rows.append([metric, val, desc or ""])
        return rows
