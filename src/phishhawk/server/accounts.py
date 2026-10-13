"""Getting into PhishHawk: the owner's setup with a one-time code, sign-up for
an individual or an organization, invitations into an organization, and each
person's profile. The routes are in routes/accounts.py; the rules are here.

Server-wide values are settings of workspace 0: whether sign-up is open, the
daily sign-up cap, and the setup code (sealed, like a provider key)."""

from __future__ import annotations

import base64
import datetime as dt
import hmac
import secrets
import unicodedata
from collections.abc import Mapping
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from . import appsettings, audit, auth
from .crypto import Box
from .models import SERVER, Invite, User, Workspace, utcnow

FIELD_MAX = 80
KINDS = ("individual", "organization")
DAILY_CAP = 100  # sign-ups a day for the whole server, until the owner sets another
INVITE_DAYS = 7
NOTE_MAX = 120
PROFILE = ("first_name", "last_name", "location", "job_title")
OPTIONAL = ("job_title",)


class AccountError(Exception):
    """A request that cannot be done: an HTTP status and a reason that names the field."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


def clean(field: str, value: object, required: bool = True, most: int = FIELD_MAX) -> str:
    """A profile field: trimmed, at most 80 characters, no control or formatting characters (which could hide
    or reorder what another person reads)."""
    text = value.strip() if isinstance(value, str) else ""
    if required and not text:
        raise AccountError(422, "%s: required" % field)
    if len(text) > most:
        raise AccountError(422, "%s: %d characters at most" % (field, most))
    if any(unicodedata.category(c) in ("Cc", "Cf") for c in text):
        raise AccountError(422, "%s: control characters are not allowed" % field)
    return text


def profile(data: Mapping[str, Any]) -> dict[str, str]:
    return {name: clean(name, data.get(name), name not in OPTIONAL) for name in PROFILE}


def _credentials(db: Session, data: Mapping[str, Any]) -> tuple[str, str]:
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not auth.USERNAME_RE.match(username):
        raise AccountError(422, "username: 3 to 64 lowercase letters, digits, dots, dashes or underscores")
    if not isinstance(password, str) or len(password) < auth.MIN_PASSWORD:
        raise AccountError(422, "password: at least %d characters" % auth.MIN_PASSWORD)
    if db.scalars(select(User.id).where(User.username == username)).first() is not None:
        raise AccountError(409, "username: that username is taken")
    return username, password


def _new_user(db: Session, data: Mapping[str, Any], role: str, workspace_id: int,
              fields: dict[str, str]) -> User:
    username, password = _credentials(db, data)
    user = auth.create_user(db, username, password, role, workspace_id=workspace_id)
    for name, value in fields.items():
        setattr(user, name, value)
    return user


def _new_code() -> str:
    """80 random bits as four groups of four letters and digits, easy to read out and type."""
    letters = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
    return "-".join(letters[i:i + 4] for i in range(0, 16, 4))


def setup_code(db: Session, box: Box) -> str | None:
    """The one-time setup code while no one has an account (made the first time it is asked for), else None."""
    if db.scalars(select(User.id).limit(1)).first() is not None:
        return None
    code = appsettings.get_secret(db, box, SERVER, "setup_code")
    if not code:
        code = _new_code()
        appsettings.set_secret(db, box, SERVER, "setup_code", code)
        db.flush()
    return code


def set_up(db: Session, box: Box, data: Mapping[str, Any]) -> User:
    """The owner's account, in the default organization renamed after theirs; the setup code then stops working."""
    code = setup_code(db, box)
    if code is None:
        raise AccountError(404, "this server is set up already: sign in")
    sent = data.get("code")
    if not isinstance(sent, str) or not hmac.compare_digest(sent.strip().upper().encode(), code.encode()):
        raise AccountError(403, "that setup code is not right")
    fields = profile(data)
    organization = clean("organization", data.get("organization"))
    workspace = db.get(Workspace, auth.default_workspace(db))
    assert workspace is not None
    user = _new_user(db, data, "admin", workspace.id, fields)
    user.owner = True
    workspace.name = organization
    signup_open = data.get("signup_open") is True
    appsettings.set_value(db, SERVER, "signup_open", signup_open)
    appsettings.set_secret(db, box, SERVER, "setup_code", "")
    audit.record(db, user.username, "setup", details={"signup_open": signup_open}, workspace_id=SERVER)
    return user


def signup_open(db: Session) -> bool:
    """Off until the owner opens it: at setup, or in the server settings. An upgraded server stays closed."""
    return appsettings.get_value(db, SERVER, "signup_open", False) is True


def cap_wait(db: Session, now: dt.datetime | None = None) -> float:
    """Seconds until another workspace may be made under the daily cap; 0 when one may be made now. Counted from
    the database, so it holds however many processes serve sign-ups."""
    now = now or utcnow()
    since = now - dt.timedelta(days=1)
    cap = appsettings.get_value(db, SERVER, "signup_daily_cap", DAILY_CAP)
    made = db.scalar(select(func.count()).select_from(Workspace).where(Workspace.created_at >= since)) or 0
    if made < cap:
        return 0.0
    oldest = db.scalar(select(func.min(Workspace.created_at)).where(Workspace.created_at >= since))
    if oldest is None:
        return 0.0
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=dt.timezone.utc)
    return max(1.0, (oldest + dt.timedelta(days=1) - now).total_seconds())


def sign_up(db: Session, data: Mapping[str, Any]) -> User:
    """A new workspace of the kind asked for, and its first admin. Everything is checked before anything is made,
    and each problem names its field."""
    kind = data.get("kind")
    if kind not in KINDS:
        raise AccountError(422, "kind: individual or organization")
    fields = profile(data)
    organization = clean("organization", data.get("organization"), required=kind == "organization")
    _credentials(db, data)
    name = organization if kind == "organization" else "%s %s" % (fields["first_name"], fields["last_name"])
    workspace = Workspace(name=name[:FIELD_MAX], kind=kind)
    db.add(workspace)
    db.flush()
    user = _new_user(db, data, "admin", workspace.id, fields)
    audit.record(db, user.username, "signup", details={"kind": kind, "workspace": workspace.id},
                 workspace_id=SERVER)
    return user


def invite(db: Session, actor: auth.Actor, role: object, note: object) -> tuple[Invite, str]:
    """An invitation into the actor's organization, and its token, which is never stored and so shown once."""
    workspace = db.get(Workspace, actor.workspace_id)
    if workspace is None or workspace.kind != "organization":
        raise AccountError(403, "an individual workspace has one member: create an organization to work as a team")
    if role not in auth.ROLES:
        raise AccountError(422, "role: admin or analyst")
    text = clean("note", note, required=False, most=NOTE_MAX)
    token = secrets.token_urlsafe(32)
    row = Invite(workspace_id=workspace.id, token_hash=auth.digest(token), role=role, note=text,
                 created_by=actor.user_id, expires_at=utcnow() + dt.timedelta(days=INVITE_DAYS))
    db.add(row)
    db.flush()
    audit.record(db, actor.label, "invite_create", "invite", row.id, {"role": role, "note": text},
                 workspace_id=workspace.id)
    return row, token


def _pending() -> Any:
    return (Invite.used_at.is_(None), Invite.revoked_at.is_(None), Invite.expires_at > utcnow())


def pending(db: Session, workspace_id: int) -> list[Invite]:
    return list(db.scalars(select(Invite).where(Invite.workspace_id == workspace_id, *_pending())
                           .order_by(Invite.id)))


def revoke(db: Session, actor: auth.Actor, row: Invite) -> None:
    if row.used_at is not None:
        raise AccountError(409, "this invitation was used already")
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        audit.record(db, actor.label, "invite_revoke", "invite", row.id, {"role": row.role},
                     workspace_id=row.workspace_id)


def open_invite(db: Session, token: str) -> Invite:
    """The invitation a token opens, while it is unused, not withdrawn and within its 7 days; 404 otherwise."""
    row = db.scalars(select(Invite).where(Invite.token_hash == auth.digest(token), *_pending())).first()
    if row is None:
        raise AccountError(404, "this invitation is not valid: it was used, withdrawn, or is over %d days old"
                           % INVITE_DAYS)
    return row


def join(db: Session, token: str, data: Mapping[str, Any]) -> User:
    """The new member, with the invitation's role in its organization. The invitation is taken first, so two
    people with one link cannot both join; a refused request leaves it unused (the transaction rolls back)."""
    row = open_invite(db, token)
    fields = profile(data)
    _credentials(db, data)
    taken = db.execute(update(Invite).where(Invite.id == row.id, Invite.used_at.is_(None))
                       .values(used_at=utcnow()))
    if taken.rowcount != 1:  # type: ignore[attr-defined]
        raise AccountError(404, "this invitation was used already")
    user = _new_user(db, data, row.role, row.workspace_id, fields)
    row.used_by = user.id
    audit.record(db, user.username, "join", "invite", row.id, {"role": row.role}, workspace_id=row.workspace_id)
    return user


def profile_view(user: User) -> dict[str, str]:
    return {name: getattr(user, name) for name in PROFILE}


def check_profile(db: Session, actor: auth.Actor, user: User, data: Mapping[str, Any]) -> dict[str, str]:
    """The fields sent (None leaves one as it is), checked; nothing is changed yet. An organization's admin may
    also rename it."""
    values = {name: clean(name, data[name], name not in OPTIONAL)
              for name in PROFILE if data.get(name) is not None}
    if data.get("organization") is not None:
        workspace = db.get(Workspace, user.workspace_id)
        if workspace is None or workspace.kind != "organization" or not actor.is_admin:
            raise AccountError(403, "only an admin of an organization can rename it")
        values["organization"] = clean("organization", data["organization"])
    return values


def apply_profile(db: Session, user: User, values: dict[str, str]) -> list[str]:
    """The checked values written; the names of those changed."""
    for name, value in values.items():
        if name == "organization":
            workspace = db.get(Workspace, user.workspace_id)
            assert workspace is not None
            workspace.name = value
        else:
            setattr(user, name, value)
    return list(values)


def update_profile(db: Session, actor: auth.Actor, user: User, data: Mapping[str, Any]) -> list[str]:
    return apply_profile(db, user, check_profile(db, actor, user, data))


SERVER_LIMITS = ("signup_daily_cap", "max_upload_mb", "max_batch_messages")


def server_view(db: Session, settings: Any) -> dict[str, Any]:
    """What the owner sets for the whole server."""
    return {"signup_open": signup_open(db),
            "signup_daily_cap": appsettings.get_value(db, SERVER, "signup_daily_cap", DAILY_CAP),
            "max_upload_mb": appsettings.limit(db, settings, "max_upload_mb"),
            "max_batch_messages": appsettings.limit(db, settings, "max_batch_messages")}


def update_server(db: Session, data: Mapping[str, Any]) -> list[str]:
    """The values sent, checked first; the names of those changed."""
    for name in SERVER_LIMITS:
        number = data.get(name)
        if number is not None and not 1 <= number <= 100000:
            raise AccountError(422, "%s: between 1 and 100000" % name)
    changed = [name for name in ("signup_open", *SERVER_LIMITS) if data.get(name) is not None]
    for name in changed:
        appsettings.set_value(db, SERVER, name, data[name])
    return changed
