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

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import appsettings, audit, auth
from .crypto import Box
from .models import SERVER, User, Workspace, utcnow

FIELD_MAX = 80
KINDS = ("individual", "organization")
DAILY_CAP = 100  # sign-ups a day for the whole server, until the owner sets another
PROFILE = ("first_name", "last_name", "location", "job_title")
OPTIONAL = ("job_title",)


class AccountError(Exception):
    """A request that cannot be done: an HTTP status and a reason that names the field."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


def clean(field: str, value: object, required: bool = True) -> str:
    """A profile field: trimmed, at most 80 characters, no control or formatting characters (which could hide
    or reorder what another person reads)."""
    text = value.strip() if isinstance(value, str) else ""
    if required and not text:
        raise AccountError(422, "%s: required" % field)
    if len(text) > FIELD_MAX:
        raise AccountError(422, "%s: %d characters at most" % (field, FIELD_MAX))
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
