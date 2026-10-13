"""The JSON API for getting in: setup, sign-up, invites, joining and the profile. The rules are in accounts.py.
A successful setup, sign-up or join signs the person in, as POST /api/v1/session does."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from .. import accounts, auth, scope, views
from ..deps import DB, Admin, secret, services
from ..models import Invite, User, Workspace
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


class NewInvite(BaseModel):
    role: str
    note: str = ""


class Join(BaseModel):
    username: str
    password: str
    first_name: str = ""
    last_name: str = ""
    location: str = ""
    job_title: str = ""


def _invite_view(row: Invite, names: dict[int, str]) -> dict[str, Any]:
    return {"id": row.id, "role": row.role, "note": row.note, "created_at": row.created_at.isoformat(),
            "expires_at": row.expires_at.isoformat(), "created_by_name": names.get(row.created_by or 0)}


def _refused(exc: accounts.AccountError) -> HTTPException:
    return HTTPException(exc.status, exc.detail)


@router.get("/invites")
def list_invites(db: DB, actor: Admin) -> list[dict[str, Any]]:
    """The invitations of the caller's organization that can still be used; never their tokens."""
    names = views.usernames(db, actor.workspace_id)
    return [_invite_view(row, names) for row in accounts.pending(db, actor.workspace_id)]


@router.post("/invites", status_code=201)
def create_invite(db: DB, actor: Admin, body: NewInvite) -> dict[str, Any]:
    """An invitation with a role and a note for whoever sends it on. `link` (and `token`) are shown once: the
    server keeps only a hash. It works once, within 7 days. 403 in an individual workspace."""
    try:
        row, token = accounts.invite(db, actor, body.role, body.note)
    except accounts.AccountError as exc:
        raise _refused(exc) from None
    return _invite_view(row, views.usernames(db, actor.workspace_id)) | {"token": token,
                                                                          "link": "/app/join/" + token}


@router.delete("/invites/{invite_id}", status_code=204)
def revoke_invite(db: DB, actor: Admin, invite_id: int) -> Response:
    try:
        accounts.revoke(db, actor, scope.invite(db, actor, invite_id))
    except accounts.AccountError as exc:
        raise _refused(exc) from None
    return Response(status_code=204)


@router.get("/join/{token}")
def invitation(db: DB, token: str) -> dict[str, Any]:
    """Which organization an invitation opens, and with which role; 404 when it cannot be used."""
    try:
        row = accounts.open_invite(db, token)
    except accounts.AccountError as exc:
        raise _refused(exc) from None
    workspace = db.get(Workspace, row.workspace_id)
    return {"organization": workspace.name if workspace else "", "role": row.role}


@router.post("/join/{token}", status_code=201)
def join(request: Request, db: DB, token: str, body: Join) -> Response:
    """The new member's account in the invitation's organization, with its role; then signed in."""
    try:
        user = accounts.join(db, token, body.model_dump())
    except accounts.AccountError as exc:
        raise _refused(exc) from None
    return signed_in(request, db, user)
