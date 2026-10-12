"""A frontend built elsewhere (docs/FRONTEND.md), served from this origin at
/app/: its files, and its index.html for any path without a file extension,
so the frontend's own routes survive a reload. Everything else in the build
folder's parent stays out of reach. Vite names every file in assets/ after
its content, so those are cached for a year; the page itself is checked on
every load, so a new build is picked up at once."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

IMMUTABLE = "public, max-age=31536000, immutable"


class Frontend(StaticFiles):
    def __init__(self, directory: str) -> None:
        super().__init__(directory=directory, html=True)

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or "." in path.rsplit("/", 1)[-1]:
                raise
            response = await super().get_response("index.html", scope)
        response.headers["Cache-Control"] = IMMUTABLE if path.startswith("assets/") else "no-cache"
        return response
