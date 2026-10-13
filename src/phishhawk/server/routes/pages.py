"""HTML pages. Every form works without JavaScript and carries the CSRF
token; the pages call the same helpers as the JSON API."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from .. import accounts, appsettings, audit, auth, mailboxes, scope, views
from ..app import html_response
from ..deps import COOKIE, DB, Admin, CurrentActor, optional_actor, secret, services
from ..models import Analysis, ApiToken, AuditRecord, Mailbox, User, Workspace
from . import accounts as account_routes
from . import api

router = APIRouter(include_in_schema=False)  # the API is documented; pages are not
VERDICTS = ("NO STRONG INDICATORS", "SUSPICIOUS", "LIKELY PHISHING", "MALICIOUS")
SOURCES = ("upload", "paste", "batch", "mailbox")


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


@router.get("/login")
def login_page(request: Request, db: DB) -> Response:
    if optional_actor(request, db) is not None:
        return _see_other("/")
    return html_response(request, "login.html", {"actor": None, "error": "",
                                                 "signup_open": accounts.signup_open(db)})


@router.post("/login")
def login(request: Request, db: DB, username: Annotated[str, Form()],
          password: Annotated[str, Form()]) -> Response:
    outcome = api.login_response(request, db, username, password)
    if not isinstance(outcome, tuple):
        detail = ("Wrong username or password." if outcome.status_code == 401
                  else "Too many attempts: wait a little.")
        return html_response(request, "login.html", {"actor": None, "error": detail,
                                                     "signup_open": accounts.signup_open(db)}, outcome.status_code)
    response = _see_other("/")
    api.set_cookie(request, response, outcome[0])
    return response


@router.post("/logout")
def logout(request: Request, db: DB, actor: CurrentActor) -> Response:
    api.delete_session(request, db, actor)
    response = _see_other("/login")
    response.delete_cookie(COOKIE, path="/")
    return response


@router.get("/")
def home(request: Request, db: DB, actor: CurrentActor) -> Response:
    recent = views.listing(db, services(request).store, actor.workspace_id)[:10]
    return html_response(request, "home.html", {"actor": actor, "recent": recent, "error": ""})


@router.post("/")
async def submit(request: Request, db: DB, actor: CurrentActor,
                 files: Annotated[list[UploadFile] | None, File()] = None, raw: Annotated[str, Form()] = "",
                 offline: Annotated[bool, Form()] = False) -> Response:
    try:
        outcome = api.accept_upload(request, db, actor, await api.read_uploads(request, db, list(files or [])),
                                    raw, offline)
    except HTTPException as exc:
        recent = views.listing(db, services(request).store, actor.workspace_id)[:10]
        return html_response(request, "home.html", {"actor": actor, "recent": recent, "error": exc.detail},
                             exc.status_code)
    if "submission_ids" in outcome:
        return _see_other("/batches/%d" % outcome["batch_id"])
    return _see_other("/submissions/%d" % outcome["id"])


@router.get("/batches/{batch_id}")
def batch_page(request: Request, db: DB, actor: CurrentActor, batch_id: int) -> Response:
    return html_response(request, "batch.html", {"actor": actor, "b": api.get_batch(db, actor, batch_id)})


@router.get("/batches/{batch_id}/files/{name}")
def batch_file(request: Request, db: DB, actor: CurrentActor, batch_id: int, name: str,
               download: bool = False) -> Response:
    return api.get_batch_file(request, db, actor, batch_id, name, download)


@router.get("/submissions/{submission_id}")
def submission_page(request: Request, db: DB, actor: CurrentActor, submission_id: int) -> Response:
    view = api.submission_view(db, scope.submission(db, actor, submission_id))
    if view["analysis_id"]:
        return _see_other("/analyses/%d" % view["analysis_id"])
    return html_response(request, "submission.html", {"actor": actor, "submission": view})


def _day(value: str) -> dt.date | None:
    """A form's date field: empty, or a day that is not one, filters nothing."""
    try:
        return dt.date.fromisoformat(value) if value else None
    except ValueError:
        return None


@router.get("/queue")
def queue(request: Request, db: DB, actor: CurrentActor, q: str = "", verdict: str = "",
          offset: Annotated[int, Query(ge=0)] = 0, source: str = "", user: str = "", since: str = "",
          until: str = "") -> Response:
    chosen = int(user) if user.isdigit() else None
    rows = views.listing(db, services(request).store, actor.workspace_id, q, verdict, offset, source, chosen,
                         _day(since), _day(until))
    filters = {"q": q, "verdict": verdict, "source": source, "user": user, "since": since, "until": until}
    return html_response(request, "queue.html", {"actor": actor, "rows": rows, "verdicts": VERDICTS,
                                                 "sources": SOURCES,
                                                 "users": views.usernames(db, actor.workspace_id),
                                                 "offset": offset, "page": views.PAGE, "f": filters,
                                                 "query": urlencode({k: v for k, v in filters.items() if v})})


@router.get("/campaigns")
def campaigns_page(request: Request, db: DB, actor: CurrentActor) -> Response:
    return html_response(request, "campaigns.html", {"actor": actor, "rows": api.list_campaigns(db, actor)})


@router.get("/campaigns/{campaign_id}")
def campaign_page(request: Request, db: DB, actor: CurrentActor, campaign_id: int) -> Response:
    return html_response(request, "campaign.html", {"actor": actor,
                                                    "c": api.get_campaign(request, db, actor, campaign_id)})


@router.get("/analyses/{analysis_id}")
def analysis_page(request: Request, db: DB, actor: CurrentActor, analysis_id: int) -> Response:
    analysis, message, submission = scope.analysis(db, actor, analysis_id)
    view = views.summary(services(request).store, analysis, message, submission)
    report = next((f for f in view["files"] if f["kind"] == "html"), None)
    can_delete = actor.is_admin or views.is_owner(db, message.id, actor.user_id)
    submitter = views.submitter_of(db, submission) or ""
    return html_response(request, "analysis.html", {"actor": actor, "a": view, "report": report,
                                                    "can_delete": can_delete, "submitter": submitter})


@router.get("/analyses/{analysis_id}/files/{name}")
def analysis_file(request: Request, db: DB, actor: CurrentActor, analysis_id: int, name: str,
                  download: bool = False) -> Response:
    return api.get_file(request, db, actor, analysis_id, name, download)


@router.post("/analyses/{analysis_id}/reanalyze")
def reanalyze(db: DB, actor: CurrentActor, analysis_id: int) -> Response:
    return _see_other("/submissions/%d" % api.reanalyze(db, actor, analysis_id)["id"])


@router.post("/messages/{message_id}/delete")
def delete(request: Request, db: DB, actor: CurrentActor, message_id: int,
           extent: Annotated[str, Form(alias="scope", pattern="^(tier1|all)$")] = "tier1") -> Response:
    api.delete_message(request, db, actor, message_id, extent)
    analysis_id = db.scalars(select(Analysis.id).where(Analysis.message_id == message_id)
                             .order_by(Analysis.id.desc())).first()
    return _see_other("/queue" if extent == "all" or analysis_id is None else "/analyses/%d" % analysis_id)


@router.post("/messages/{message_id}/hold")
def hold(db: DB, actor: Admin, message_id: int, hold: Annotated[bool, Form()] = True) -> Response:
    (api.hold if hold else api.release)(db, actor, message_id)
    analysis_id = db.scalars(select(Analysis.id).where(Analysis.message_id == message_id)
                             .order_by(Analysis.id.desc())).first()
    return _see_other("/analyses/%d" % analysis_id if analysis_id else "/queue")


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.replace(",", "\n").splitlines() if line.strip()]


@router.get("/settings")
def settings_page(request: Request, db: DB, actor: Admin, saved: bool = False) -> Response:
    s = services(request)
    view = appsettings.public_view(db, s.box, s.settings, actor.workspace_id)
    return html_response(request, "settings.html", {"actor": actor, "s": view, "saved": saved, "error": "",
                                                    "providers": appsettings.PROVIDERS_ALL})


@router.post("/settings")
async def save_settings(request: Request, db: DB, actor: Admin) -> Response:
    form = await request.form()
    fields: dict[str, Any] = {name: _lines(str(form.get(name, ""))) for name in appsettings.LISTS}
    fields["providers"] = [p for p in appsettings.PROVIDERS_ALL if form.get("provider_" + p)]
    fields.update({name: int(str(form.get(name))) for name in appsettings.LIMITS
                   if str(form.get(name, "")).isdigit()})
    fields["keys"] = {p: str(form.get("key_" + p, "")) for p in appsettings.KEYED
                      if form.get("key_" + p) or form.get("remove_" + p)}
    body = api.SettingsPatch.model_validate(fields)
    try:
        api.patch_settings(request, db, actor, body)
    except HTTPException as exc:
        s = services(request)
        view = appsettings.public_view(db, s.box, s.settings, actor.workspace_id)
        return html_response(request, "settings.html", {"actor": actor, "providers": appsettings.PROVIDERS_ALL,
                                                        "s": view, "saved": False, "error": exc.detail},
                             exc.status_code)
    return _see_other("/settings?saved=1")


def _users_page(request: Request, db: DB, actor: Any, new_token: str = "", error: str = "",
                status: int = 200, new_invite: str = "") -> Response:
    users = db.scalars(select(User).where(User.workspace_id == actor.workspace_id).order_by(User.username)).all()
    workspace = db.get(Workspace, actor.workspace_id)
    organization = workspace is not None and workspace.kind == "organization"  # an individual works alone
    tokens = db.scalars(select(ApiToken).join(User, ApiToken.user_id == User.id)
                        .where(User.workspace_id == actor.workspace_id).order_by(ApiToken.id)).all()
    return html_response(request, "users.html", {"actor": actor, "users": users, "tokens": tokens,
                                                 "names": views.usernames(db, actor.workspace_id),
                                                 "new_token": new_token,
                                                 "error": error, "roles": auth.ROLES,
                                                 "scopes": auth.TOKEN_SCOPES, "new_invite": new_invite,
                                                 "invites": accounts.pending(db, actor.workspace_id),
                                                 "can_invite": organization,
                                                 "workspace_name": workspace.name if workspace else ""}, status)


@router.get("/users")
def users_page(request: Request, db: DB, actor: Admin) -> Response:
    return _users_page(request, db, actor)


@router.post("/users")
def add_user(request: Request, db: DB, actor: Admin, username: Annotated[str, Form()],
             password: Annotated[str, Form()], role: Annotated[str, Form()]) -> Response:
    try:
        api.create_user(db, actor, api.NewUser(username=username, password=password, role=role))
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _see_other("/users")


@router.post("/users/{user_id}")
def change_user(request: Request, db: DB, actor: Admin, user_id: int, role: Annotated[str, Form()] = "",
                disabled: Annotated[bool, Form()] = False, password: Annotated[str, Form()] = "") -> Response:
    try:
        api.patch_user(db, actor, user_id, api.UserPatch(role=role or None, disabled=disabled,
                                                         password=password or None))
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _see_other("/users")


@router.post("/tokens")
def add_token(request: Request, db: DB, actor: Admin, name: Annotated[str, Form()],
              scope: Annotated[str, Form()], user_id: Annotated[int, Form()]) -> Response:
    try:
        token = api.create_token(db, actor, api.NewToken(name=name, scope=scope, user_id=user_id))["token"]
    except HTTPException as exc:
        return _users_page(request, db, actor, error=str(exc.detail), status=exc.status_code)
    return _users_page(request, db, actor, new_token=token)


@router.post("/tokens/{token_id}/revoke")
def revoke(db: DB, actor: Admin, token_id: int) -> Response:
    api.revoke_token(db, actor, token_id)
    return _see_other("/users")


def _mailboxes_page(request: Request, db: DB, actor: Any, error: str = "", status: int = 200) -> Response:
    rows = [mailboxes.view(m) for m in db.scalars(select(Mailbox).where(Mailbox.workspace_id == actor.workspace_id)
                                                  .order_by(Mailbox.name))]
    return html_response(request, "mailboxes.html", {"actor": actor, "rows": rows, "error": error}, status)


def _mailbox_form(form: Any, kind: str) -> dict[str, Any]:
    """The fields of a mailbox form as the API takes them; an empty field is left out (kept, or the default)."""
    config: dict[str, Any] = {name: str(form.get(name, "")).strip() for name in mailboxes.CONNECTION[kind]
                              if name != "starttls" and str(form.get(name, "")).strip()}
    if kind == "imap":
        config["starttls"] = form.get("starttls") == "true"
    fields: dict[str, Any] = {"config": config, "enabled": form.get("enabled", "true") == "true",
                              "secret": str(form.get("secret", ""))}
    for name in ("name", "interval_minutes"):
        if str(form.get(name, "")).strip():
            fields[name] = str(form.get(name)).strip()
    return fields


@router.get("/mailboxes")
def mailboxes_page(request: Request, db: DB, actor: Admin) -> Response:
    return _mailboxes_page(request, db, actor)


@router.post("/mailboxes")
async def add_mailbox(request: Request, db: DB, actor: Admin) -> Response:
    form = await request.form()
    kind = str(form.get("kind", ""))
    try:
        fields = _mailbox_form(form, kind) if kind in mailboxes.KINDS else {}
        api.create_mailbox(request, db, actor, api.NewMailbox.model_validate(fields | {"kind": kind}))
    except (HTTPException, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else "kind must be imap, graph or gmail"
        return _mailboxes_page(request, db, actor, str(detail), getattr(exc, "status_code", 422))
    return _see_other("/mailboxes")


@router.post("/mailboxes/{mailbox_id}")
async def change_mailbox(request: Request, db: DB, actor: Admin, mailbox_id: int) -> Response:
    form = await request.form()
    mailbox = scope.mailbox(db, actor, mailbox_id)
    try:
        api.patch_mailbox(request, db, actor, mailbox_id,
                          api.MailboxPatch.model_validate(_mailbox_form(form, mailbox.kind)))
    except HTTPException as exc:
        return _mailboxes_page(request, db, actor, str(exc.detail), exc.status_code)
    return _see_other("/mailboxes")


@router.post("/mailboxes/{mailbox_id}/poll")
def poll_mailbox(request: Request, db: DB, actor: Admin, mailbox_id: int) -> Response:
    try:
        api.poll_mailbox(db, actor, mailbox_id)
    except HTTPException as exc:
        return _mailboxes_page(request, db, actor, str(exc.detail), exc.status_code)
    return _see_other("/mailboxes")


@router.post("/mailboxes/{mailbox_id}/delete")
def delete_mailbox(db: DB, actor: Admin, mailbox_id: int) -> Response:
    api.delete_mailbox(db, actor, mailbox_id)
    return _see_other("/mailboxes")


@router.get("/audit")
def audit_page(request: Request, db: DB, actor: CurrentActor, offset: Annotated[int, Query(ge=0)] = 0) -> Response:
    query = select(AuditRecord).where(audit.visible_to(db, actor)).order_by(AuditRecord.id.desc())
    if not actor.is_admin:
        query = query.where(AuditRecord.actor == actor.label)
    rows = db.scalars(query.offset(offset).limit(100)).all()
    return html_response(request, "audit.html", {"actor": actor, "rows": rows, "offset": offset})


# getting in: setup, sign-up, invitations, joining and the profile (the rules are in accounts.py)


def _fields(form: Any) -> dict[str, Any]:
    return {name: str(value) for name, value in form.items() if name != "csrf_token"}


def _entered(fields: dict[str, Any]) -> dict[str, Any]:
    """What a refused form shows again: never a password or a code."""
    return {name: value for name, value in fields.items() if name not in ("password", "current_password", "code")}


def _signed_in_page(request: Request, db: DB, user: User) -> Response:
    cookie, _ = auth.open_session(db, user, secret(request))
    response = _see_other("/")
    api.set_cookie(request, response, cookie)
    return response


@router.get("/setup")
def setup_page(request: Request, db: DB) -> Response:
    if accounts.setup_code(db, services(request).box) is None:
        raise HTTPException(404, "this server is set up already: log in")
    return html_response(request, "setup.html", {"actor": None, "error": "", "f": {}})


@router.post("/setup")
async def setup(request: Request, db: DB) -> Response:
    fields = _fields(await request.form())
    fields["signup_open"] = fields.get("signup_open") == "true"
    try:
        user = account_routes.setup_user(request, db, fields)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise
        return html_response(request, "setup.html", {"actor": None, "error": exc.detail, "f": _entered(fields)},
                             exc.status_code)
    return _signed_in_page(request, db, user)


@router.get("/signup")
def signup_page(request: Request, db: DB) -> Response:
    if not accounts.signup_open(db):
        raise HTTPException(404, "sign-up is closed: ask an admin for an invitation")
    return html_response(request, "signup.html", {"actor": None, "error": "", "f": {}})


@router.post("/signup")
async def signup(request: Request, db: DB) -> Response:
    fields = _fields(await request.form())
    try:
        user = account_routes.signup_user(request, db, fields)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise
        return html_response(request, "signup.html", {"actor": None, "error": exc.detail, "f": _entered(fields)},
                             exc.status_code)
    return _signed_in_page(request, db, user)


def _invitation(db: DB, token: str) -> dict[str, Any]:
    try:
        row = accounts.open_invite(db, token)
    except accounts.AccountError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    workspace = db.get(Workspace, row.workspace_id)
    return {"organization": workspace.name if workspace else "", "role": row.role, "token": token}


@router.get("/join/{token}")
def join_page(request: Request, db: DB, token: str) -> Response:
    return html_response(request, "join.html", {"actor": None, "error": "", "f": {}} | _invitation(db, token))


@router.post("/join/{token}")
async def join(request: Request, db: DB, token: str) -> Response:
    invitation = _invitation(db, token)
    fields = _fields(await request.form())
    try:
        user = accounts.join(db, token, fields)
    except accounts.AccountError as exc:
        return html_response(request, "join.html", {"actor": None, "error": exc.detail, "f": _entered(fields)}
                             | invitation, exc.status)
    return _signed_in_page(request, db, user)


@router.post("/invites")
def add_invite(request: Request, db: DB, actor: Admin, role: Annotated[str, Form()],
               note: Annotated[str, Form()] = "") -> Response:
    try:
        _, token = accounts.invite(db, actor, role, note)
    except accounts.AccountError as exc:
        return _users_page(request, db, actor, error=exc.detail, status=exc.status)
    return _users_page(request, db, actor, new_invite=str(request.base_url) + "join/" + token)


@router.post("/invites/{invite_id}/revoke")
def revoke_invite(db: DB, actor: Admin, invite_id: int) -> Response:
    try:
        accounts.revoke(db, actor, scope.invite(db, actor, invite_id))
    except accounts.AccountError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    return _see_other("/users")


def _profile_page(request: Request, db: DB, actor: Any, error: str = "", status: int = 200, saved: bool = False,
                  entered: dict[str, Any] | None = None) -> Response:
    user, workspace = db.get(User, actor.user_id), db.get(Workspace, actor.workspace_id)
    assert user is not None and workspace is not None
    shown = entered if entered is not None else accounts.profile_view(user) | {"organization": workspace.name}
    return html_response(request, "profile.html", {
        "actor": actor, "f": shown, "workspace": workspace, "error": error, "saved": saved,
        "can_rename": actor.is_admin and workspace.kind == "organization"}, status)


@router.get("/profile")
def profile_page(request: Request, db: DB, actor: CurrentActor, saved: bool = False) -> Response:
    return _profile_page(request, db, actor, saved=saved)


@router.post("/profile")
async def save_profile(request: Request, db: DB, actor: CurrentActor) -> Response:
    api._session_only(actor, "change a profile")
    fields = _fields(await request.form())
    user = db.get(User, actor.user_id)
    assert user is not None
    data = {name: fields.get(name) for name in (*accounts.PROFILE, "organization")}
    try:  # everything is checked before anything is changed: all of it is saved, or none
        values = accounts.check_profile(db, actor, user, data)
        if fields.get("password"):
            account_routes.change_password(request, db, actor, user, fields["password"],
                                           fields.get("current_password", ""))
    except accounts.AccountError as exc:
        return _profile_page(request, db, actor, exc.detail, exc.status, entered=_entered(fields))
    except HTTPException as exc:
        return _profile_page(request, db, actor, str(exc.detail), exc.status_code, entered=_entered(fields))
    changed = accounts.apply_profile(db, user, values)
    if changed:
        api._audit(db, actor, "profile", "user", user.id, {"changed": changed})
    return _see_other("/profile?saved=1")
