"""Request dependencies: the database session (committed before the response
is sent), who is asking, CSRF for browser sessions, and roles."""

from __future__ import annotations

import hmac
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from . import auth
from .auth import Actor
from .processing import Services

COOKIE = "phishhawk_session"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def services(request: Request) -> Services:
    found: Services = request.app.state.services
    return found


def secret(request: Request) -> str:
    return services(request).settings.secret_key.get_secret_value()


def get_db(request: Request) -> Iterator[Session]:
    with services(request).sessions() as db, db.begin():
        yield db


DB = Annotated[Session, Depends(get_db, scope="function")]


def optional_actor(request: Request, db: DB) -> Actor | None:
    header = request.headers.get("authorization", "")
    if header[:7].lower() == "bearer ":
        actor = auth.find_token(db, header[7:].strip())
        if actor is None:
            raise HTTPException(401, "that API token is not valid")
        return actor
    cookie = request.cookies.get(COOKIE)
    if not cookie:
        return None
    return auth.find_session(db, cookie, secret(request), services(request).settings.session_idle_minutes)


async def require_actor(request: Request, current: Annotated[Actor | None, Depends(optional_actor)]) -> Actor:
    if current is None:
        raise HTTPException(401, "log in first")
    if request.method in SAFE_METHODS:
        return current
    if current.via == "token":
        if current.scope != "submit":
            raise HTTPException(403, "this API token can only read")
        return current
    sent = request.headers.get("x-csrf-token", "")
    if not sent and request.headers.get("content-type", "").startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")):
        sent = str((await request.form()).get("csrf_token", ""))
    if not sent or not hmac.compare_digest(sent.encode(), current.csrf.encode()):
        raise HTTPException(403, "the form is out of date: reload the page and try again")
    return current


def require_admin(current: Annotated[Actor, Depends(require_actor)]) -> Actor:
    if not current.is_admin:
        raise HTTPException(403, "only an admin can do that")
    return current


CurrentActor = Annotated[Actor, Depends(require_actor)]
Admin = Annotated[Actor, Depends(require_admin)]
