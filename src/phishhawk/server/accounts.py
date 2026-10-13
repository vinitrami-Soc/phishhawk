"""Getting into PhishHawk: the owner's setup with a one-time code, sign-up for
an individual or an organization, invitations into an organization, and each
person's profile. The routes are in routes/accounts.py; the rules are here.

Server-wide values are settings of workspace 0: whether sign-up is open, the
daily sign-up cap, and the setup code (sealed, like a provider key)."""

from __future__ import annotations

import base64
import hmac
import secrets
import unicodedata
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import appsettings, audit, auth
from .crypto import Box
from .models import SERVER, User, Workspace

FIELD_MAX = 80
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
