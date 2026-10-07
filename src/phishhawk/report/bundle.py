"""Every report format for a set of analyses, rendered in memory, with the
manifest that lists them. The CLI writes these to files and the web app
stores them encrypted; one place decides what each format holds."""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .. import __version__
from ..models import Analysis
from . import csvout, html, markdown, misp, stix
from .common import report_id, safe_report_name, to_dict

REPORT_TYPES = {"json": "JSON report", "stix": "STIX 2.1 bundle", "misp": "MISP event", "md": "Markdown note",
                "csv": "CSV indicators", "html": "HTML report", "manifest": "Manifest"}
BEFORE_HTML = ("json", "stix", "misp", "md", "csv")  # the HTML report lists these, so they come first


@dataclass(frozen=True)
class RenderedFile:
    name: str
    kind: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def entry(self) -> dict[str, Any]:
        """How the manifest and the HTML report's Report files panel list it."""
        return {"name": self.name, "kind": self.kind, "type": REPORT_TYPES[self.kind],
                "size": len(self.content), "sha256": self.sha256}


def render(kind: str, analyses: list[Analysis], tlp: str = "amber") -> str:
    """One format other than HTML and the manifest, as text."""
    if kind == "json":
        payload: Any = to_dict(analyses[0]) if len(analyses) == 1 else {"reports": [to_dict(a) for a in analyses]}
        return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if kind == "stix":
        return json.dumps(stix.build_bundle(analyses), indent=2) + "\n"
    if kind == "misp":
        return json.dumps(misp.build(analyses, tlp), indent=2, ensure_ascii=False) + "\n"
    if kind == "md":
        return "\n---\n\n".join(markdown.render(a) for a in analyses)
    if kind == "csv":
        return csvout.render(analyses)
    raise ValueError("no renderer for %r" % kind)


def manifest(analyses: list[Analysis], files: list[dict[str, Any]]) -> dict[str, Any]:
    """What a run wrote, so a copy passed along can be checked against it."""
    return {
        "manifest_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "tool": "phishhawk",
        "tool_version": __version__,
        "messages": [{"report_id": report_id(a), "path": a.path, "sha256": a.evidence.get("sha256", ""),
                      "size": a.evidence.get("size", 0)} for a in analyses],
        "files": [{key: f[key] for key in ("name", "kind", "type", "size", "sha256")} for f in files],
    }


def render_bundle(analyses: list[Analysis], tlp: str = "amber", day: str | None = None) -> list[RenderedFile]:
    """All six formats and the manifest, named from hashes alone. The HTML
    report lists the other five beside it; the manifest lists all six."""
    day = day or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    files = [RenderedFile(safe_report_name(analyses, kind, day), kind, render(kind, analyses, tlp).encode("utf-8"))
             for kind in BEFORE_HTML]
    page = html.render(analyses, [dict(f.entry(), beside=True) for f in files])
    files.append(RenderedFile(safe_report_name(analyses, "html", day), "html", page.encode("utf-8")))
    listing = json.dumps(manifest(analyses, [f.entry() for f in files]), indent=2, ensure_ascii=False) + "\n"
    files.append(RenderedFile(safe_report_name(analyses, "manifest", day), "manifest", listing.encode("utf-8")))
    return files
