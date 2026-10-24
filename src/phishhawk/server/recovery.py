"""An email address on each account, and getting back in without the password (docs/SERVER.md, "Email and
password reset").

An address is confirmed by a link before anything else is sent to it: a mistyped address must not hand a
stranger a way into the account. A reset link goes only to a confirmed address, lasts an hour, works once, and
ends every session of the account. Links are built from PHISHHAWK_PUBLIC_URL, never from the request, so a
forged Host header cannot point one elsewhere. Mail goes out through the worker, which makes each token as it
sends it: only the token's hash is ever stored, and a request never waits on the mail server."""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from . import audit, auth, jobs, mailer
from .accounts import AccountError
from .config import ServerSettings
from .db import transaction
from .models import EmailToken, User, utcnow
from .processing import Services

RESET_MINUTES = 60
VERIFY_HOURS = 24
COOLDOWN = dt.timedelta(minutes=2)  # one reset link at a time for an account
LINKS_PER_HOUR = 5  # of each kind, for an account: no one makes this server mail a stranger without end
KINDS = {"email_verify": "verify", "email_reset": "reset"}  # job kind: token purpose


def available(settings: ServerSettings) -> bool:
    """Whether this server sends mail: the SMTP host, the From address and the public URL are all set."""
    return bool(settings.smtp_host and settings.smtp_from and settings.public_url)


def confirm_later(db: Session, settings: ServerSettings, user: User) -> None:
    """A confirmation link for the account's address, when it has one and this server sends mail."""
    if user.email and user.email_verified_at is None and available(settings):
        jobs.enqueue(db, "email_verify", {"user_id": user.id}, user.workspace_id)


def set_email(db: Session, settings: ServerSettings, user: User, email: str) -> None:
    """A new address (or "" for none), unconfirmed until its link is opened."""
    if email == user.email and user.email_verified_at is not None:
        return
    user.email, user.email_verified_at = email, None
    confirm_later(db, settings, user)


def request_reset(db: Session, settings: ServerSettings, login: str) -> None:
    """A reset link for the account with this username, or for each with this confirmed address. The caller
    answers the same whatever is found, so no one learns who has an account here."""
    login = login.strip().lower()
    if not login:
        return
    column = User.email if "@" in login else User.username
    now = utcnow()
    for user in db.scalars(select(User).where(column == login, User.disabled.is_(False),
                                              User.email != "", User.email_verified_at.is_not(None))):
        if user.reset_requested_at is not None and now - user.reset_requested_at < COOLDOWN:
            continue
        user.reset_requested_at = now
        jobs.enqueue(db, "email_reset", {"user_id": user.id}, user.workspace_id)
        audit.record(db, "anonymous", "password_reset_request", "user", user.id, {"username": user.username},
                     workspace_id=user.workspace_id)


def _mail(purpose: str, username: str, link: str) -> tuple[str, str]:
    if purpose == "reset":
        return ("Reset your PhishHawk password",
                "Someone asked to reset the password of the PhishHawk account %s.\n\n"
                "To choose a new one, open this link within %d minutes. It works once:\n%s\n\n"
                "If it was not you, ignore this email: your password stays as it is.\n\n"
                "PhishHawk never asks for your password by email.\n" % (username, RESET_MINUTES, link))
    return ("Confirm your email for PhishHawk",
            "This address was given for the PhishHawk account %s.\n\n"
            "To confirm it, open this link within %d hours:\n%s\n\n"
            "Until then, no password reset link is sent to it. If you did not expect this, ignore it.\n"
            % (username, VERIFY_HOURS, link))


def deliver(services: Services, kind: str, payload: dict[str, Any]) -> None:
    """The worker's part: a fresh token for the account, then its link by email. Nothing is sent when the
    account is gone or disabled, has no address, (for a reset) has not confirmed it, or had LINKS_PER_HOUR
    links of this kind in the last hour."""
    settings = services.settings
    purpose = KINDS[kind]
    with transaction(services.sessions) as db:
        user = db.get(User, int(payload["user_id"]))
        if (user is None or user.disabled or not user.email or not available(settings)
                or (purpose == "reset" and user.email_verified_at is None)):
            return
        recent = db.scalar(select(func.count()).select_from(EmailToken).where(
            EmailToken.user_id == user.id, EmailToken.purpose == purpose,
            EmailToken.created_at > utcnow() - dt.timedelta(hours=1)))
        if (recent or 0) >= LINKS_PER_HOUR:
            return
        token = secrets.token_urlsafe(32)
        lasts = dt.timedelta(minutes=RESET_MINUTES) if purpose == "reset" else dt.timedelta(hours=VERIFY_HOURS)
        db.add(EmailToken(user_id=user.id, purpose=purpose, token_hash=auth.digest(token), email=user.email,
                          expires_at=utcnow() + lasts))
        to, username = user.email, user.username
    page = "reset" if purpose == "reset" else "verify-email"
    subject, body = _mail(purpose, username, "%s/app/%s/%s" % (settings.public_url.rstrip("/"), page, token))
    mailer.send(settings, to, subject, body)


def prune(db: Session, older_than: dt.timedelta) -> None:
    """Links long past their expiry, used or not: none can be used again, and the table would only grow."""
    db.execute(delete(EmailToken).where(EmailToken.expires_at < utcnow() - older_than))


def open_token(db: Session, purpose: str, token: str) -> tuple[EmailToken, User]:
    """The link's token and its account, while the link can be used; 404 otherwise."""
    row = db.scalars(select(EmailToken).where(EmailToken.token_hash == auth.digest(token),
                                              EmailToken.purpose == purpose, EmailToken.used_at.is_(None),
                                              EmailToken.expires_at > utcnow())).first()
    user = db.get(User, row.user_id) if row is not None else None
    if row is None or user is None or user.disabled or row.email != user.email:
        raise AccountError(404, "this link is not valid: it was used, is too old, or is for another address")
    return row, user


def _take(db: Session, row: EmailToken) -> None:
    """The token used up, once: two requests with one link cannot both go through."""
    taken = db.execute(update(EmailToken).where(EmailToken.id == row.id, EmailToken.used_at.is_(None))
                       .values(used_at=utcnow()))
    if getattr(taken, "rowcount", 0) != 1:
        raise AccountError(404, "this link was used already")


def reset(db: Session, token: str, password: str) -> User:
    """A new password from a reset link; every session of the account ends, and its other links stop working."""
    row, user = open_token(db, "reset", token)
    if len(password) < auth.MIN_PASSWORD:
        raise AccountError(422, "password: at least %d characters" % auth.MIN_PASSWORD)
    _take(db, row)
    auth.set_password(user, password)
    auth.end_sessions(db, user.id)
    db.execute(update(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == "reset",
                                        EmailToken.used_at.is_(None)).values(used_at=utcnow()))
    audit.record(db, user.username, "password_reset", "user", user.id, workspace_id=user.workspace_id)
    return user


def verify(db: Session, token: str) -> User:
    """The account's address confirmed by its link."""
    row, user = open_token(db, "verify", token)
    _take(db, row)
    user.email_verified_at = utcnow()
    audit.record(db, user.username, "email_verified", "user", user.id, workspace_id=user.workspace_id)
    return user
