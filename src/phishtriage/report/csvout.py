"""CSV indicator list for blocklists and SIEM watchlists."""

from __future__ import annotations

import csv
import io

from ..extract import defang_host, defang_url
from ..models import Analysis

FIELDS = ["type", "value", "defanged", "context", "verdict", "subject", "source_file"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe(cell: str) -> str:
    """Neutralise spreadsheet formula injection: the subject line and file
    names are attacker-controlled, and '=HYPERLINK(...)' in a CSV runs when
    an analyst opens it in Excel."""
    cell = str(cell)
    return "'" + cell if cell.startswith(_FORMULA_PREFIXES) else cell


def render(analyses: list[Analysis]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    for a in analyses:
        for ioc in a.iocs():
            value = ioc["value"]
            if ioc["type"] == "url":
                defanged = defang_url(value)
            elif ioc["type"] == "sha256":
                defanged = value
            else:
                defanged = defang_host(value)
            row = {"type": ioc["type"], "value": value, "defanged": defanged,
                   "context": ioc["context"], "verdict": a.verdict,
                   "subject": a.subject, "source_file": a.path}
            writer.writerow({key: _safe(cell) for key, cell in row.items()})
    return buffer.getvalue()
