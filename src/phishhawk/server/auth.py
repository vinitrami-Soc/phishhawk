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

from .models import ApiToken, Session, User, Workspace, utcnow

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
    session: str = ""  # the session's stored ID, when via is "session"
    workspace_id: int = 0  # everything this actor reads or changes is in this workspace
    owner: bool = False  # runs the server

    @property
    def is_admin(self) -> bool:
        return self.role == "admin" and self.via == "session"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_id(secret: str, cookie: str) -> str:
    """Sessions are keyed by an HMAC under SECRET_KEY, so a new key ends them all."""
    return hmac.new(secret.encode("utf-8"), cookie.encode("utf-8"), hashlib.sha256).hexdigest()


DEFAULT_WORKSPACE = "Default organization"


def default_workspace(db: DbSession) -> int:
    """The organization an upgraded server's data went to (migration 0004), made here if there is none yet: users
    created without a workspace (the CLI's create-admin, tests) join it."""
    found = db.scalars(select(Workspace.id).where(Workspace.kind == "organization").order_by(Workspace.id)).first()
    if found is not None:
        return found
    workspace = Workspace(name=DEFAULT_WORKSPACE, kind="organization")
    db.add(workspace)
    db.flush()
    return workspace.id


def create_user(db: DbSession, username: str, password: str, role: str, workspace_id: int | None = None) -> User:
    """The server's first admin becomes its owner. An account made here (the command line, or an admin's Add
    user) has no setup after sign-up to go through."""
    if not USERNAME_RE.match(username):
        raise AuthError("usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores")
    if len(password) < MIN_PASSWORD:
        raise AuthError("passwords need at least %d characters" % MIN_PASSWORD)
    if role not in ROLES:
        raise AuthError("role must be admin or analyst")
    if db.scalars(select(User).where(User.username == username)).first() is not None:
        raise AuthError("that username is taken")
    owned = db.scalars(select(User.id).where(User.owner.is_(True)).limit(1)).first() is not None
    user = User(username=username, password_hash=_hasher.hash(password), role=role,
                workspace_id=default_workspace(db) if workspace_id is None else workspace_id,
                owner=role == "admin" and not owned, onboarded_at=utcnow())
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
    return Actor(user.id, user.username, user.role, "session", "full", session.csrf_token, user.username,
                 session.id, user.workspace_id, user.owner)


def close_session(db: DbSession, cookie: str, secret: str) -> None:
    db.execute(delete(Session).where(Session.id == session_id(secret, cookie)))


def end_sessions(db: DbSession, user_id: int, keep: str = "") -> None:
    """Every session of a user, but the one whose stored ID is keep: after a new password or a disable."""
    db.execute(delete(Session).where(Session.user_id == user_id, Session.id != keep))


def end_idle_sessions(db: DbSession, idle_minutes: int) -> None:
    """Sessions nobody has used for longer than the idle limit: no cookie can bring them back."""
    db.execute(delete(Session).where(Session.last_seen_at < utcnow() - dt.timedelta(minutes=idle_minutes)))


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
    return Actor(user.id, user.username, user.role, "token", row.scope, "", "token:%s" % row.name,
                 workspace_id=user.workspace_id, owner=user.owner)


class LoginThrottle:
    """After three failures for a username or an address, each new attempt
    waits twice as long as the last (1 s, 2 s, 4 s ... up to 5 minutes). It
    remembers at most `limit` names and addresses, forgetting the one that
    failed longest ago first, so a flood of made-up usernames cannot use up
    the memory."""

    def __init__(self, clock: object = time.monotonic, limit: int = 10000) -> None:
        self._clock = clock
        self._limit = limit
        self._failures: dict[str, tuple[int, float]] = {}

    def __len__(self) -> int:
        return len(self._failures)

    def wait(self, *keys: str) -> float:
        now = self._clock()  # type: ignore[operator]
        return max([0.0] + [until - now for count, until in (self._failures.get(k, (0, 0.0)) for k in keys)])

    def failed(self, *keys: str) -> None:
        now = self._clock()  # type: ignore[operator]
        for key in keys:
            count = self._failures.pop(key, (0, 0.0))[0] + 1  # popped, so it moves to the newest end
            delay = 0.0 if count < 3 else min(2.0 ** (count - 3), 300.0)
            self._failures[key] = (count, now + delay)
        while len(self._failures) > self._limit:
            del self._failures[next(iter(self._failures))]

    def succeeded(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)


class SignupThrottle:
    """At most `per_hour` sign-ups from one address in an hour. It remembers at most `limit` addresses,
    forgetting the one seen longest ago first."""

    def __init__(self, per_hour: int = 3, clock: object = time.monotonic, limit: int = 10000) -> None:
        self._per_hour, self._clock, self._limit = per_hour, clock, limit
        self._seen: dict[str, list[float]] = {}

    def _recent(self, key: str, now: float) -> list[float]:
        return [at for at in self._seen.get(key, []) if now - at < 3600]

    def wait(self, key: str) -> float:
        """Seconds until this address may sign up again; 0 when it may now."""
        now = self._clock()  # type: ignore[operator]
        recent = self._recent(key, now)
        return 0.0 if len(recent) < self._per_hour else 3600 - (now - recent[0])

    def add(self, key: str) -> None:
        now = self._clock()  # type: ignore[operator]
        recent = self._recent(key, now) + [now]
        self._seen.pop(key, None)  # popped, so it moves to the newest end
        self._seen[key] = recent
        while len(self._seen) > self._limit:
            del self._seen[next(iter(self._seen))]
