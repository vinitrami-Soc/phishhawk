"""A frontend built elsewhere (docs/FRONTEND.md), served from this origin at
/app/: its files, and its index.html for any path without a file extension,
so the frontend's own routes survive a reload. Everything else in the build
folder's parent stays out of reach."""

from __future__ import annotations

from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope


class Frontend(StaticFiles):
    def __init__(self, directory: str) -> None:
        super().__init__(directory=directory, html=True)

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404 and "." not in path.rsplit("/", 1)[-1]:
                return await super().get_response("index.html", scope)
            raise
