"""The web application: services, security headers, errors, routes."""

from __future__ import annotations

import shutil
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select, text

from .. import __version__
from .auth import LoginThrottle
from .config import ServerSettings, load_settings
from .crypto import Box
from .db import make_engine, make_sessionmaker, transaction
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
        body = {"error": _code(exc.status_code), "detail": exc.detail}
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> Response:
        return JSONResponse({"error": "invalid", "detail": "the request is not valid"}, status_code=422)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        with transaction(services.sessions) as db:
            db.execute(text("SELECT 1"))
            queued = db.scalar(select(func.count()).select_from(Job).where(Job.status == "queued")) or 0
            beat = db.scalar(select(func.max(Job.heartbeat_at)))
        disk = shutil.disk_usage(services.settings.data_dir)
        return {"status": "ok", "version": __version__, "queue": queued,
                "last_heartbeat": beat.isoformat() if beat else None, "disk_free_mb": disk.free // (1024 * 1024)}

    from .routes import api

    app.include_router(api.router)
    return app


ERROR_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict",
               410: "gone", 413: "too_large", 415: "unsupported", 422: "invalid", 429: "throttled"}


def _code(status: int) -> str:
    return ERROR_CODES.get(status, "error")
