"""The JSON API under /api/v1: what the pages use and what IntelPulse will
call. Every route is in the role matrix test (tests/server/test_rbac.py)."""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated, Any

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select

from .. import appsettings, audit, auth, batches, campaigns, intake, jobs, retention, views
from ..bodylimit import BATCH_FACTOR
from ..deps import COOKIE, DB, Admin, CurrentActor, secret, services
from ..models import Analysis, ApiToken, AuditRecord, Batch, Campaign, Message, Submission, User, utcnow
from .files import serve_file

router = APIRouter(prefix="/api/v1")
MB = 1024 * 1024


class Login(BaseModel):
    username: str
    password: str


def login_response(request: Request, db: DB, username: str, password: str) -> tuple[str, str] | JSONResponse:
    """(cookie, csrf) on success; a JSON error response otherwise (committed, so failures are audited)."""
    throttle = request.app.state.throttle
    keys = ("user:" + username, "ip:" + (request.client.host if request.client else ""))
    wait = throttle.wait(*keys)
    if wait > 0:
        return JSONResponse({"error": "throttled", "detail": "too many attempts: wait %d s" % (wait + 1)},
                            status_code=429, headers={"Retry-After": str(int(wait) + 1)})
    user = auth.check_login(db, username, password)
    if user is None:
        throttle.failed(*keys)
        audit.record(db, username[:64] or "?", "login_failed")
        return JSONResponse({"error": "unauthorized", "detail": "wrong username or password"}, status_code=401)
    throttle.succeeded(*keys)
    cookie, session = auth.open_session(db, user, secret(request))
    audit.record(db, user.username, "login")
    return cookie, session.csrf_token


def set_cookie(request: Request, response: Response, cookie: str) -> None:
    settings = services(request).settings
    response.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="strict",
                        max_age=settings.session_idle_minutes * 60, path="/")


@router.post("/session")
def create_session(request: Request, db: DB, body: Login) -> Response:
    outcome = login_response(request, db, body.username, body.password)
    if isinstance(outcome, JSONResponse):
        return outcome
    response = JSONResponse({"csrf": outcome[1]})
    set_cookie(request, response, outcome[0])
    return response


@router.get("/session")
def current_session(actor: CurrentActor) -> dict[str, Any]:
    """Who is calling, for a frontend after a reload; the CSRF token too."""
    return {"user_id": actor.user_id, "username": actor.username, "role": actor.role, "via": actor.via,
            "scope": actor.scope, "csrf": actor.csrf}


@router.delete("/session", status_code=204)
def delete_session(request: Request, db: DB, actor: CurrentActor) -> Response:
    auth.close_session(db, request.cookies.get(COOKIE, ""), secret(request))
    audit.record(db, actor.label, "logout")
    response = Response(status_code=204)
    response.delete_cookie(COOKIE, path="/")
    return response


@router.post("/submissions", status_code=202)
async def submit(request: Request, db: DB, actor: CurrentActor,
                 file: Annotated[UploadFile | None, File()] = None,
                 files: Annotated[list[UploadFile] | None, File()] = None,
                 raw: Annotated[str, Form()] = "", offline: Annotated[bool, Form()] = False) -> dict[str, Any]:
    """One message (a file or pasted text) is one submission. Several (several files, an .mbox or a .zip) are a
    batch: the answer then holds the batch ID and the submissions' IDs."""
    return accept_upload(request, db, actor, await read_uploads(request, db, [file, *(files or [])]), raw, offline)


async def read_uploads(request: Request, db: DB, uploads: list[UploadFile | None]) -> list[bytes]:
    """Every uploaded file's bytes; a form's empty file field is no file."""
    limit = BATCH_FACTOR * appsettings.limit(db, services(request).settings, "max_upload_mb") * MB
    return [await f.read(limit + 1) for f in uploads if f is not None and (f.filename or f.size)]


def accept_upload(request: Request, db: DB, actor: Any, uploads: list[bytes], raw: str,
                  offline: bool) -> dict[str, Any]:
    s = services(request)
    limit = appsettings.limit(db, s.settings, "max_upload_mb") * MB
    common = {"user_id": actor.user_id, "actor": actor.label, "offline": offline, "max_bytes": limit}
    try:
        if not uploads:
            return submission_view(db, intake.accept(db, s.store, raw.encode(), source="paste", **common))
        split = batches.split(uploads, max_messages=appsettings.limit(db, s.settings, "max_batch_messages"),
                              max_message_bytes=limit, max_total=BATCH_FACTOR * limit)
        if len(split.messages) == 1:
            return submission_view(db, intake.accept(db, s.store, split.messages[0], source="upload",
                                                     known_message=True, **common))
        return batches.created_view(db, batches.accept(db, s.store, split.messages, **common), split.skipped)
    except (intake.IntakeError, batches.BatchError) as exc:
        raise HTTPException(exc.status, str(exc)) from exc


def submission_view(db: DB, submission: Submission) -> dict[str, Any]:
    analysis = db.scalars(select(Analysis.id).where(Analysis.submission_id == submission.id)).first()
    return {"id": submission.id, "status": submission.status, "error": submission.error,
            "analysis_id": analysis, "submitted_at": submission.submitted_at.isoformat(),
            "batch_id": submission.batch_id}


@router.get("/submissions/{submission_id}")
def get_submission(db: DB, actor: CurrentActor, submission_id: int) -> dict[str, Any]:
    submission = db.get(Submission, submission_id)
    if submission is None:
        raise HTTPException(404, "no such submission")
    return submission_view(db, submission)


@router.get("/batches/{batch_id}")
def get_batch(db: DB, actor: CurrentActor, batch_id: int) -> dict[str, Any]:
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(404, "no such batch")
    return batches.view(db, batch, views.usernames(db).get(batch.user_id or 0))


@router.get("/batches/{batch_id}/files/{name}")
def get_batch_file(request: Request, db: DB, actor: CurrentActor, batch_id: int, name: str,
                   download: bool = False) -> Response:
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(404, "no such batch")
    audit.record(db, actor.label, "download", "batch", batch_id, {"file": name})
    return serve_file(services(request).store, batch.files, name, download)


@router.get("/campaigns")
def list_campaigns(db: DB, actor: CurrentActor) -> list[dict[str, Any]]:
    """Largest first. A shared subject or display name has the value null here: the campaign itself shows it,
    while one of its messages' content still exists."""
    return campaigns.listing(db)


@router.get("/campaigns/{campaign_id}")
def get_campaign(request: Request, db: DB, actor: CurrentActor, campaign_id: int) -> dict[str, Any]:
    campaign = db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(404, "no such campaign")
    s = services(request)
    return campaigns.detail(db, s.store, campaign, appsettings.trait_key(db, s.box))


@router.get("/analyses")
def list_analyses(request: Request, db: DB, actor: CurrentActor, q: str = "", verdict: str = "",
                  offset: Annotated[int, Query(ge=0)] = 0, source: str = "", user: int | None = None,
                  since: dt.date | None = None, until: dt.date | None = None) -> list[dict[str, Any]]:
    """Newest first, 50 at a time. q searches SHA-256, report ID and indicators; source is upload, paste or
    batch; user a user's ID; since and until are days (UTC), both included."""
    return views.listing(db, services(request).store, q, verdict, offset, source, user, since, until)


def _found(db: DB, analysis_id: int) -> tuple[Any, Message, Submission]:
    found = views.find(db, analysis_id)
    if found is None:
        raise HTTPException(404, "no such analysis")
    return found


@router.get("/analyses/{analysis_id}")
def get_analysis(request: Request, db: DB, actor: CurrentActor, analysis_id: int) -> dict[str, Any]:
    analysis, message, submission = _found(db, analysis_id)
    return views.summary(services(request).store, analysis, message, submission, with_report=True,
                         submitter=views.submitter_of(db, submission))


@router.get("/analyses/{analysis_id}/files/{name}")
def get_file(request: Request, db: DB, actor: CurrentActor, analysis_id: int, name: str,
             download: bool = False) -> Response:
    analysis, _, _ = _found(db, analysis_id)
    audit.record(db, actor.label, "download", "analysis", analysis_id, {"file": name})
    return serve_file(services(request).store, analysis.files, name, download)


@router.post("/analyses/{analysis_id}/reanalyze", status_code=202)
def reanalyze(db: DB, actor: CurrentActor, analysis_id: int) -> dict[str, Any]:
    _, message, old = _found(db, analysis_id)
    if message.raw_blob is None:
        raise HTTPException(410, "the message was deleted after the retention period")
    submission = Submission(message_id=message.id, user_id=actor.user_id, source=old.source, offline=old.offline)
    db.add(submission)
    db.flush()
    jobs.enqueue(db, "analyze", {"submission_id": submission.id})
    audit.record(db, actor.label, "reanalyze", "analysis", analysis_id, {"submission": submission.id})
    return submission_view(db, submission)


def _session_only(actor: Any, what: str) -> None:
    """Raw messages and deletions need a person at a browser, never an API token."""
    if actor.via != "session":
        raise HTTPException(403, "an API token cannot %s" % what)


def _message(db: DB, message_id: int) -> Message:
    message = db.get(Message, message_id)
    if message is None:
        raise HTTPException(404, "no such message")
    return message


@router.get("/messages/{message_id}/raw")
def get_raw(request: Request, db: DB, actor: CurrentActor, message_id: int) -> Response:
    _session_only(actor, "download a raw message")
    message = _message(db, message_id)
    if not actor.is_admin and not views.is_owner(db, message_id, actor.user_id):
        raise HTTPException(403, "only the submitter or an admin can download the raw message")
    if message.raw_blob is None:
        raise HTTPException(410, "deleted after the retention period")
    audit.record(db, actor.label, "download_raw", "message", message_id)
    return Response(services(request).store.get(message.raw_blob), media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="%s.eml"' % message.sha256[:16]})


@router.delete("/messages/{message_id}")
def delete_message(request: Request, db: DB, actor: CurrentActor, message_id: int,
                   scope: Annotated[str, Query(pattern="^(tier1|all)$")] = "tier1") -> dict[str, Any]:
    _session_only(actor, "delete messages")
    message, store = _message(db, message_id), services(request).store
    if message.hold:
        raise HTTPException(409, "this message is on hold; an admin must release it first")
    if scope == "all":
        if not actor.is_admin:
            raise HTTPException(403, "only an admin can delete completely")
        sha256 = retention.delete_completely(db, store, message)
        campaigns.queue_rebuild(db)  # its record is gone
        audit.record(db, actor.label, "delete_completely", "message", message_id, {"sha256": sha256})
        return {"deleted": "all"}
    if not actor.is_admin and not views.is_owner(db, message_id, actor.user_id):
        raise HTTPException(403, "only the submitter or an admin can delete this message")
    retention.delete_tier1(db, store, message, "manual")
    audit.record(db, actor.label, "delete_tier1", "message", message_id, {"sha256": message.sha256})
    return {"deleted": "tier1"}


@router.post("/messages/{message_id}/hold")
def hold(db: DB, actor: Admin, message_id: int) -> dict[str, Any]:
    _message(db, message_id).hold = True
    audit.record(db, actor.label, "hold", "message", message_id)
    return {"hold": True}


@router.delete("/messages/{message_id}/hold")
def release(db: DB, actor: Admin, message_id: int) -> dict[str, Any]:
    _message(db, message_id).hold = False
    audit.record(db, actor.label, "release", "message", message_id)
    return {"hold": False}


class SettingsPatch(BaseModel):
    providers: list[str] | None = None
    protected_domains: list[str] | None = None
    allow_domains: list[str] | None = None
    block_domains: list[str] | None = None
    trusted_authserv: list[str] | None = None
    retention_days: int | None = None
    max_upload_mb: int | None = None
    max_batch_messages: int | None = None
    campaign_window_days: int | None = None
    keys: dict[str, str] | None = None  # provider -> new key ("" removes it)


@router.get("/settings")
def get_settings(request: Request, db: DB, actor: Admin) -> dict[str, Any]:
    s = services(request)
    return appsettings.public_view(db, s.box, s.settings)


@router.patch("/settings")
def patch_settings(request: Request, db: DB, actor: Admin, body: SettingsPatch) -> dict[str, Any]:
    s = services(request)
    changed = apply_settings(db, s, body)
    audit.record(db, actor.label, "settings", details={"changed": changed})
    return appsettings.public_view(db, s.box, s.settings)


DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")


def domain(value: str) -> str:
    """A domain as the engine compares it: lower case, IDNA (xn--), no final dot; 422 for anything else."""
    name = value.strip().lower().rstrip(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        name = ""
    if len(name) > 253 or not DOMAIN.fullmatch(name):
        raise HTTPException(422, "not a domain: %s" % value.strip()[:100])
    return name


def apply_settings(db: DB, s: Any, body: SettingsPatch) -> list[str]:
    """Checks everything first, so a rejected value leaves every setting as it was."""
    lists: dict[str, list[str]] = {}
    for name in appsettings.LISTS:
        value = getattr(body, name)
        if value is not None:
            values = [v for v in value if v.strip()]
            lists[name] = sorted({v.strip().lower() if name == "providers" else domain(v) for v in values})
    limits = {name: getattr(body, name) for name in appsettings.LIMITS if getattr(body, name) is not None}
    for name, number in limits.items():
        if not 1 <= number <= 100000:
            raise HTTPException(422, "%s must be between 1 and 100000" % name)
    for provider in body.keys or {}:
        if provider not in appsettings.KEYED:
            raise HTTPException(422, "no API key for %s" % provider)
    changed: list[str] = []
    for name, values in lists.items():
        appsettings.set_value(db, name, values)
        changed.append(name)
    for name, number in limits.items():
        appsettings.set_value(db, name, number)
        changed.append(name)
    for provider, key in (body.keys or {}).items():
        appsettings.set_secret(db, s.box, "key:" + provider, key.strip())
        changed.append("key:" + provider)  # the key itself is never audited
    return changed


class NewUser(BaseModel):
    username: str
    password: str
    role: str


class UserPatch(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None


def _user_view(user: User) -> dict[str, Any]:
    return {"id": user.id, "username": user.username, "role": user.role, "disabled": user.disabled,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None}


@router.get("/users")
def list_users(db: DB, actor: Admin) -> list[dict[str, Any]]:
    return [_user_view(u) for u in db.scalars(select(User).order_by(User.username))]


@router.post("/users", status_code=201)
def create_user(db: DB, actor: Admin, body: NewUser) -> dict[str, Any]:
    try:
        user = auth.create_user(db, body.username, body.password, body.role)
    except auth.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "user_create", "user", user.id, {"username": user.username, "role": user.role})
    return _user_view(user)


@router.patch("/users/{user_id}")
def patch_user(db: DB, actor: Admin, user_id: int, body: UserPatch) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "no such user")
    if user.id == actor.user_id and (body.disabled or (body.role and body.role != "admin")):
        raise HTTPException(422, "you cannot disable yourself or remove your own admin role")
    if body.role is not None:
        if body.role not in auth.ROLES:
            raise HTTPException(422, "role must be admin or analyst")
        user.role = body.role
    if body.disabled is not None:
        user.disabled = body.disabled
    if body.password:
        try:
            auth.set_password(user, body.password)
        except auth.AuthError as exc:
            raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "user_change", "user", user.id,
                 {"role": body.role, "disabled": body.disabled, "password_changed": bool(body.password)})
    return _user_view(user)


class NewToken(BaseModel):
    name: str
    scope: str
    user_id: int


@router.get("/tokens")
def list_tokens(db: DB, actor: Admin) -> list[dict[str, Any]]:
    return [{"id": t.id, "name": t.name, "scope": t.scope, "user_id": t.user_id,
             "created_at": t.created_at.isoformat(), "revoked": t.revoked_at is not None}
            for t in db.scalars(select(ApiToken).order_by(ApiToken.id))]


@router.post("/tokens", status_code=201)
def create_token(db: DB, actor: Admin, body: NewToken) -> dict[str, Any]:
    user = db.get(User, body.user_id)
    if user is None:
        raise HTTPException(404, "no such user")
    try:
        token = auth.create_token(db, user, body.name, body.scope)
    except auth.AuthError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit.record(db, actor.label, "token_create", "user", user.id, {"name": body.name, "scope": body.scope})
    return {"token": token, "note": "shown once: store it now"}


@router.delete("/tokens/{token_id}")
def revoke_token(db: DB, actor: Admin, token_id: int) -> dict[str, Any]:
    token = db.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(404, "no such token")
    token.revoked_at = token.revoked_at or utcnow()
    audit.record(db, actor.label, "token_revoke", "token", token_id, {"name": token.name})
    return {"revoked": True}


@router.get("/audit")
def list_audit(db: DB, actor: CurrentActor, offset: Annotated[int, Query(ge=0)] = 0) -> list[dict[str, Any]]:
    query = select(AuditRecord).order_by(AuditRecord.id.desc())
    if not actor.is_admin:
        query = query.where(AuditRecord.actor == actor.label)
    return [{"id": r.id, "at": r.at.isoformat(), "actor": r.actor, "action": r.action,
             "object_type": r.object_type, "object_id": r.object_id, "details": r.details}
            for r in db.scalars(query.offset(offset).limit(100))]
