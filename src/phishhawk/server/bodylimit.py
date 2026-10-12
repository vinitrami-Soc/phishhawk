"""Request bodies stay in memory: a message must never reach the disk in clear
(spec 5.2), and Starlette spools an uploaded file past 1 MB to a temporary
file. So uploads are never spooled, and a body larger than the limit is
refused from its Content-Length before any of it is read."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from starlette.formparsers import MultiPartParser

MB = 1024 * 1024
BATCH_FACTOR = 4  # a whole upload (several files, an .mbox or a .zip) may be this many times MAX_UPLOAD_MB
FORM_OVERHEAD = 64 * 1024  # the other form fields and the multipart framing

# The body limit below bounds what a request can hold, so the spooled file never needs the disk.
MultiPartParser.spool_max_size = 1 << 62


class BodyLimit:
    """ASGI middleware. limit() is the largest upload in bytes, read for each request (an admin can change it)."""

    def __init__(self, app: Any, limit: Callable[[], int]) -> None:
        self.app, self.limit = app, limit

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        length = headers.get(b"content-length")
        if length is None:
            if b"transfer-encoding" in headers:
                await _refuse(scope, send, 411, "length_required", "send the upload with its Content-Length")
                return
        else:
            limit = self.limit()
            if not length.isdigit():
                await _refuse(scope, send, 400, "bad_request", "the Content-Length is not a number")
                return
            if int(length) > limit + FORM_OVERHEAD:
                await _refuse(scope, send, 413, "too_large", "the upload is larger than %d MB" % (limit // MB))
                return
        await self.app(scope, receive, send)


async def _refuse(scope: dict[str, Any], send: Any, status: int, code: str, detail: str) -> None:
    if scope["path"].startswith("/api/"):
        body, kind = json.dumps({"error": code, "detail": detail}).encode(), b"application/json"
    else:
        body, kind = (detail[0].upper() + detail[1:] + ".").encode(), b"text/plain; charset=utf-8"
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", kind), (b"content-length", str(len(body)).encode()),
                            (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})
