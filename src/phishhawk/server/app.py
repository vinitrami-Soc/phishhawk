"""The web application: services, security headers, error pages, routes."""

from __future__ import annotations

import json
import shutil
from importlib.resources import files
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from starlette.middleware.gzip import GZipMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from .. import __version__
from ..report.common import printable
from .auth import LoginThrottle
from .config import ServerSettings, load_settings
from .crypto import Box
from .db import make_engine, make_sessionmaker, transaction
from .frontend import Frontend
from .models import Job
from .processing import Services
from .security import APP_CSP, BASE_HEADERS, HSTS
from .store import BlobStore


def build_services(settings: ServerSettings) -> Services:
    """Refuses to start without a valid encryption key (fail closed)."""
    box = Box.from_b64(settings.encryption_key.get_secret_value())
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return Services(settings, make_sessionmaker(make_engine(settings.db_url)), box,
                    BlobStore(settings.data_dir / "blobs", box))


def create_app(settings: ServerSettings | None = None, services: Services | None = None) -> FastAPI:
    services = services or build_services(settings or load_settings())
    app = FastAPI(title="PhishHawk", version=__version__, docs_url=None, redoc_url=None)
    app.state.services = services
    app.state.throttle = LoginThrottle()
    templates = Jinja2Templates(directory=str(files("phishhawk.server") / "templates"))
    templates.env.filters["printable"] = lambda value: printable(str(value)) if value is not None else ""
    app.state.templates = templates

    @app.middleware("http")
    async def https_only(request: Request, call_next: Any) -> Response:
        """With Secure cookies on, a browser that reaches the server over plain HTTP, and not through a
        proxy, is sent to HTTPS; a proxy redirects its own HTTP port. Browsers accept Secure cookies over
        HTTP on this machine's own names, so those stay, as does the health check."""
        host = request.url.hostname or ""
        if (services.settings.cookie_secure and request.url.scheme == "http" and request.url.path != "/healthz"
                and "x-forwarded-proto" not in request.headers
                and host not in LOCAL_NAMES and not host.endswith(".localhost")):
            return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)
        response: Response = await call_next(request)
        return response

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", APP_CSP)
        for name, value in BASE_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", HSTS)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        if request.url.path.startswith("/api/"):
            body = {"error": _code(exc.status_code), "detail": exc.detail}
            return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=303)
        context = {"status": exc.status_code, "detail": exc.detail, "actor": None}
        return templates.TemplateResponse(request, "error.html", context, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> Response:
        return JSONResponse({"error": "invalid", "detail": "the request is not valid"}, status_code=422)

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> PlainTextResponse:
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        with transaction(services.sessions) as db:
            db.execute(text("SELECT 1"))
            queued = db.scalar(select(func.count()).select_from(Job).where(Job.status == "queued")) or 0
            beat = db.scalar(select(func.max(Job.heartbeat_at)))
        disk = shutil.disk_usage(services.settings.data_dir)
        return {"status": "ok", "version": __version__, "queue": queued,
                "last_heartbeat": beat.isoformat() if beat else None, "disk_free_mb": disk.free // (1024 * 1024)}

    from .routes import api, pages

    if services.settings.frontend_dir:
        @app.get("/", include_in_schema=False)
        def open_frontend() -> RedirectResponse:
            """With a frontend of its own, the server's address opens it; the built-in pages stay at /login,
            /queue and the rest, as the backup and admin interface."""
            return RedirectResponse("/app/", status_code=307)

    app.include_router(api.router)
    app.include_router(pages.router)
    # files only: they hold no secret, so compressing them cannot leak one (BREACH); API answers stay as they are
    static = StaticFiles(directory=str(files("phishhawk.server") / "static"))
    app.mount("/static", GZipMiddleware(static, minimum_size=1024), name="static")
    if services.settings.frontend_dir:
        app.mount("/app", GZipMiddleware(Frontend(services.settings.frontend_dir), minimum_size=1024),
                  name="frontend")
    # outermost: the scheme and the client's address come from a trusted reverse proxy's X-Forwarded-* headers
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=services.settings.trusted_proxies)
    return app


def openapi_json(app: FastAPI) -> str:
    """The API description as docs/api/openapi.json holds it: versioned as
    the API (v1), not the release, so a version bump alone does not change
    the contract."""
    document = app.openapi()
    document["info"]["version"] = "v1"
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


LOCAL_NAMES = ("localhost", "127.0.0.1", "::1", "[::1]")
ERROR_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
               410: "gone", 413: "too_large", 415: "unsupported", 422: "invalid", 429: "throttled"}


def _code(status: int) -> str:
    return ERROR_CODES.get(status, "error")


def html_response(request: Request, template: str, context: dict[str, Any], status: int = 200) -> HTMLResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(request, template, context, status_code=status)
