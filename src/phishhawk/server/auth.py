"""Local users, sessions, API tokens and the login throttle. Passwords are
argon2id; session cookies and API tokens are random and only a hash of each
is stored (an HMAC under SECRET_KEY for sessions, SHA-256 for tokens), so a
copy of the database logs nobody in."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from .models import ApiToken, Session, User, utcnow

ROLES = ("admin", "analyst")
TOKEN_SCOPES = ("read", "submit")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MIN_PASSWORD = 12
_hasher = PasswordHasher()


class AuthError(ValueError):
    """A username, password, role or scope that is not acceptable."""


@dataclass(frozen=True)
class Actor:
    user_id: int
    username: str
    role: str
    via: str  # "session" or "token"
    scope: str  # "full" for a session, else the token's scope
    csrf: str = ""
    label: str = ""  # how the audit log names this actor

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and self.via == "session"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_id(secret: str, cookie: str) -> str:
    """Sessions are keyed by an HMAC under SECRET_KEY, so a new key ends them all."""
    return hmac.new(secret.encode("utf-8"), cookie.encode("utf-8"), hashlib.sha256).hexdigest()


def create_user(db: DbSession, username: str, password: str, role: str) -> User:
    if not USERNAME_RE.match(username):
        raise AuthError("usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores")
    if len(password) < MIN_PASSWORD:
        raise AuthError("passwords need at least %d characters" % MIN_PASSWORD)
    if role not in ROLES:
        raise AuthError("role must be admin or analyst")
    if db.scalars(select(User).where(User.username == username)).first() is not None:
        raise AuthError("that username is taken")
    user = User(username=username, password_hash=_hasher.hash(password), role=role)
    db.add(user)
    db.flush()
    return user


def set_password(user: User, password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError("passwords need at least %d characters" % MIN_PASSWORD)
    user.password_hash = _hasher.hash(password)


def check_login(db: DbSession, username: str, password: str) -> User | None:
    user = db.scalars(select(User).where(User.username == username)).first()
    if user is None or user.disabled:
        _hasher.hash(password)  # the same work either way, so timing does not reveal usernames
        return None
    try:
        _hasher.verify(user.password_hash, password)
    except (VerificationError, InvalidHashError):
        return None
    return user


def open_session(db: DbSession, user: User, secret: str) -> tuple[str, Session]:
    cookie = secrets.token_urlsafe(32)
    session = Session(id=session_id(secret, cookie), user_id=user.id, csrf_token=secrets.token_urlsafe(32))
    db.add(session)
    user.last_login_at = utcnow()
    return cookie, session


def find_session(db: DbSession, cookie: str, secret: str, idle_minutes: int) -> Actor | None:
    session = db.get(Session, session_id(secret, cookie))
    if session is None:
        return None
    user = db.get(User, session.user_id)
    now = utcnow()
    if user is None or user.disabled or now - session.last_seen_at > dt.timedelta(minutes=idle_minutes):
        db.delete(session)
        return None
    session.last_seen_at = now
    return Actor(user.id, user.username, user.role, "session", "full", session.csrf_token, user.username)


def close_session(db: DbSession, cookie: str, secret: str) -> None:
    db.execute(delete(Session).where(Session.id == session_id(secret, cookie)))


def create_token(db: DbSession, user: User, name: str, scope: str) -> str:
    if scope not in TOKEN_SCOPES:
        raise AuthError("scope must be read or submit")
    if not 1 <= len(name) <= 64:
        raise AuthError("a token needs a name of 1 to 64 characters")
    token = "phk_" + secrets.token_urlsafe(32)
    db.add(ApiToken(user_id=user.id, name=name, token_hash=digest(token), scope=scope))
    db.flush()
    return token


def find_token(db: DbSession, token: str) -> Actor | None:
    row = db.scalars(select(ApiToken).where(ApiToken.token_hash == digest(token))).first()
    if row is None or row.revoked_at is not None:
        return None
    user = db.get(User, row.user_id)
    if user is None or user.disabled:
        return None
    row.last_used_at = utcnow()
    return Actor(user.id, user.username, user.role, "token", row.scope, "", "token:%s" % row.name)


class LoginThrottle:
    """After three failures for a username or an address, each new attempt
    waits twice as long as the last (1 s, 2 s, 4 s ... up to 5 minutes)."""

    def __init__(self, clock: object = time.monotonic) -> None:
        self._clock = clock
        self._failures: dict[str, tuple[int, float]] = {}

    def wait(self, *keys: str) -> float:
        now = self._clock()  # type: ignore[operator]
        return max([0.0] + [until - now for count, until in (self._failures.get(k, (0, 0.0)) for k in keys)])

    def failed(self, *keys: str) -> None:
        now = self._clock()  # type: ignore[operator]
        for key in keys:
            count = self._failures.get(key, (0, 0.0))[0] + 1
            delay = 0.0 if count < 3 else min(2.0 ** (count - 3), 300.0)
            self._failures[key] = (count, now + delay)

    def succeeded(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)
