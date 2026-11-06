"""Hand a sandbox pack to a self-hosted CAPE sandbox over its REST API.

PhishHawk runs nothing itself. `phishhawk sandbox submit --cape URL PACK.zip`
posts each pack written with --sandbox to CAPE's apiv2 file endpoint,
`POST /apiv2/tasks/create/file/`, as the `file` field with the option
`password=infected`, the password every pack is encrypted with. CAPE unpacks
it and makes a task per file it can run; the task ids come back in
`data.task_ids`. The API token is read from $PHISHHAWK_CAPE_TOKEN, never the
command line, and goes as `Authorization: Token <key>`. It is sent over HTTPS,
or over plain HTTP only to this machine or a private network address, and
redirects are not followed, so it reaches CAPE and nowhere else.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

from .enrich.base import new_session
from .sandbox import PASSWORD

SUBMIT_PATH = "/apiv2/tasks/create/file/"
MAX_PACK_BYTES = 200 * 1024 * 1024  # a pack holds at most 50 MB of files; anything far larger is not one


class CapeError(Exception):
    pass


def check_url(url: str) -> str:
    """The CAPE base URL without a trailing slash, or CapeError."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise CapeError("--cape needs a URL such as https://cape.example.org")
    if parts.scheme == "http" and not _local(host):
        raise CapeError("%s is plain HTTP over the internet: the API token would travel in clear text; use https"
                        % url)
    return url.strip().rstrip("/")


def _local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def submit(base_url: str, token: str, pack_path: str, session: Any = None, timeout: float = 120) -> dict[str, Any]:
    """{'status': 'ok', 'task_ids', 'message'} or {'status': 'error', 'detail'}."""
    url = check_url(base_url) + SUBMIT_PATH
    try:
        size = os.path.getsize(pack_path)
        if size > MAX_PACK_BYTES:
            return {"status": "error", "detail": "%s is %d MB, too large for a pack" % (pack_path, size >> 20)}
        with open(pack_path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        return {"status": "error", "detail": "could not read %s: %s" % (pack_path, exc.strerror or exc)}
    headers = {"Authorization": "Token " + token} if token else {}
    session = session if session is not None else new_session()
    try:
        response = session.post(url, headers=headers, timeout=timeout, allow_redirects=False,
                                files={"file": (os.path.basename(pack_path), data, "application/zip")},
                                data={"options": "password=" + PASSWORD.decode()})
    except Exception as exc:  # a network failure is a result to report, not a crash
        return {"status": "error", "detail": "%s: %s" % (type(exc).__name__, exc)}
    if response.status_code >= 300:
        return {"status": "error", "detail": "CAPE answered HTTP %d%s" % (
            response.status_code, " (the token was refused)" if response.status_code in (401, 403) else "")}
    try:
        body = response.json()
    except ValueError:
        return {"status": "error", "detail": "CAPE's answer is not JSON"}
    if not isinstance(body, dict):
        return {"status": "error", "detail": "CAPE's answer is not JSON"}
    task_ids = (body.get("data") or {}).get("task_ids") if isinstance(body.get("data"), dict) else None
    if body.get("error") is True or not task_ids:
        return {"status": "error", "detail": str(body.get("error_value") or "CAPE made no task")}
    return {"status": "ok", "task_ids": [int(t) for t in task_ids if str(t).isdigit()],
            "message": str((body.get("data") or {}).get("message", ""))}
