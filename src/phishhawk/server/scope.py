"""Rows of the caller's workspace, found by ID, or 404. Every route and page
reads a row named in its URL through here: a row of another workspace looks
exactly like one that does not exist, so its existence does not leak."""

from __future__ import annotations

from typing import Any, TypeVar

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .auth import Actor
from .models import Analysis, ApiToken, Batch, Campaign, Mailbox, Message, Submission, User

Row = TypeVar("Row", Analysis, Batch, Campaign, Mailbox, Message, Submission, User)


def _get(db: Session, model: type[Row], ident: int, actor: Actor, what: str) -> Row:
    row = db.get(model, ident)
    if row is None or row.workspace_id != actor.workspace_id:
        raise HTTPException(404, "no such %s" % what)
    return row


def analysis(db: Session, actor: Actor, ident: int) -> tuple[Analysis, Message, Submission]:
    found = _get(db, Analysis, ident, actor, "analysis")
    message, submission = db.get(Message, found.message_id), db.get(Submission, found.submission_id)
    if message is None or submission is None:
        raise HTTPException(404, "no such analysis")
    return found, message, submission


def submission(db: Session, actor: Actor, ident: int) -> Submission:
    return _get(db, Submission, ident, actor, "submission")


def batch(db: Session, actor: Actor, ident: int) -> Batch:
    return _get(db, Batch, ident, actor, "batch")


def campaign(db: Session, actor: Actor, ident: int) -> Campaign:
    return _get(db, Campaign, ident, actor, "campaign")


def message(db: Session, actor: Actor, ident: int) -> Message:
    return _get(db, Message, ident, actor, "message")


def mailbox(db: Session, actor: Actor, ident: int) -> Mailbox:
    return _get(db, Mailbox, ident, actor, "mailbox")


def user(db: Session, actor: Actor, ident: int) -> User:
    return _get(db, User, ident, actor, "user")


def token(db: Session, actor: Actor, ident: int) -> ApiToken:
    """A token belongs to the workspace of the user it acts for."""
    row = db.get(ApiToken, ident)
    owner: Any = db.get(User, row.user_id) if row is not None else None
    if row is None or owner is None or owner.workspace_id != actor.workspace_id:
        raise HTTPException(404, "no such token")
    return row
