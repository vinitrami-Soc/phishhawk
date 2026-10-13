"""The JSON API for getting in: setup, sign-up, invites, joining and the profile. The rules are in accounts.py.
A successful setup, sign-up or join signs the person in, as POST /api/v1/session does."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from .. import accounts, auth
from ..deps import DB, secret, services
from ..models import User
from . import api

router = APIRouter(prefix="/api/v1")


def address(request: Request) -> str:
    return "ip:" + (request.client.host if request.client else "")


def _throttled(wait: float) -> HTTPException:
    return HTTPException(429, "too many attempts: wait %d s" % (wait + 1),
                         headers={"Retry-After": str(int(wait) + 1)})


def signed_in(request: Request, db: DB, user: User, status: int = 201) -> Response:
    """A session for someone who just got an account, as a login opens one."""
    cookie, session = auth.open_session(db, user, secret(request))
    response = JSONResponse({"csrf": session.csrf_token}, status_code=status)
    api.set_cookie(request, response, cookie)
    return response


class Setup(BaseModel):
    code: str
    username: str
    password: str
    first_name: str = ""
    last_name: str = ""
    location: str = ""
    organization: str = ""
    job_title: str = ""
    signup_open: bool = False


@router.get("/setup")
def setup_state(request: Request, db: DB) -> dict[str, Any]:
    """Whether this server still waits for its owner (no one has an account yet)."""
    return {"open": accounts.setup_code(db, services(request).box) is not None}


@router.post("/setup", status_code=201)
def set_up(request: Request, db: DB, body: Setup) -> Response:
    """The owner's account and organization, with the code from the server's log or `phishhawk server setup-code`.
    403 for a wrong code (and wrong codes are throttled), 404 once the server is set up."""
    throttle = request.app.state.throttle
    wait = throttle.wait(address(request))
    if wait > 0:
        raise _throttled(wait)
    try:
        user = accounts.set_up(db, services(request).box, body.model_dump())
    except accounts.AccountError as exc:
        if exc.status == 403:
            throttle.failed(address(request))
        raise HTTPException(exc.status, exc.detail) from None
    throttle.succeeded(address(request))
    return signed_in(request, db, user)


class SignUp(BaseModel):
    kind: str
    username: str
    password: str
    first_name: str = ""
    last_name: str = ""
    location: str = ""
    organization: str = ""
    job_title: str = ""


@router.get("/signup")
def signup_state(db: DB) -> dict[str, Any]:
    """Whether anyone may create an account now; the owner decides."""
    return {"open": accounts.signup_open(db)}


@router.post("/signup", status_code=201)
def sign_up(request: Request, db: DB, body: SignUp) -> Response:
    """A workspace of its own for an individual, or a new organization, with the caller as its admin; then signed
    in. 404 while sign-up is closed; 429 past 3 an hour from one address, or past the server's daily cap."""
    if not accounts.signup_open(db):
        raise HTTPException(404, "sign-up is closed: ask an admin for an invitation")
    signups = request.app.state.signups
    wait = signups.wait(address(request))
    if wait > 0:
        raise _throttled(wait)
    wait = accounts.cap_wait(db)
    if wait > 0:
        raise HTTPException(429, "no more accounts can be made today: try again later",
                            headers={"Retry-After": str(int(wait) + 1)})
    try:
        user = accounts.sign_up(db, body.model_dump())
    except accounts.AccountError as exc:
        if exc.status == 409:  # asking whether a username exists counts as a try
            signups.add(address(request))
        raise HTTPException(exc.status, exc.detail) from None
    signups.add(address(request))
    return signed_in(request, db, user)
