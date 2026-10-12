"""Serving stored exports. The HTML report opens in the browser inside a
sandbox; everything else, and the raw message, downloads as an attachment."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from fastapi.responses import Response

from ..security import REPORT_CSP
from ..store import BlobStore

MEDIA = {"json": "application/json", "stix": "application/json", "misp": "application/json",
         "manifest": "application/json", "md": "text/markdown; charset=utf-8", "csv": "text/csv; charset=utf-8",
         "html": "text/html; charset=utf-8"}


def serve_file(store: BlobStore, files: list[Any], name: str, download: bool) -> Response:
    """One of an analysis's files, or one of a batch's combined exports."""
    entry = next((f for f in files if f["name"] == name), None)
    if entry is None:
        raise HTTPException(404, "no such file")
    if not entry.get("blob"):
        raise HTTPException(410, "deleted after the retention period")
    content = store.get(entry["blob"])
    if entry["kind"] == "html" and not download:
        return Response(content, media_type=MEDIA["html"], headers={"Content-Security-Policy": REPORT_CSP})
    return Response(content, media_type=MEDIA[entry["kind"]],
                    headers={"Content-Disposition": 'attachment; filename="%s"' % entry["name"]})
