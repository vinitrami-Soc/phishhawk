"""Queries the API and the pages share. Every listing is of one workspace."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import feedback
from .models import Analysis, Indicator, Mailbox, Message, Submission, User
from .store import BlobStore

PAGE = 50


def report_data(store: BlobStore, analysis: Analysis) -> dict[str, Any] | None:
    """The full JSON report while tier 1 exists."""
    if analysis.data_blob is None:
        return None
    data: dict[str, Any] = json.loads(store.get(analysis.data_blob))
    return data


def summary(store: BlobStore, analysis: Analysis, message: Message, submission: Submission,
            with_report: bool = False, submitter: str | None = None) -> dict[str, Any]:
    report = report_data(store, analysis)
    view = {
        "id": analysis.id, "message_id": message.id, "submission_id": submission.id,
        "submitted_by": submission.user_id, "submitted_by_name": submitter, "source": submission.source,
        "offline": submission.offline,
        "sha256": message.sha256, "report_id": analysis.report_id, "verdict": analysis.verdict,
        "score": analysis.score, "sender": message.sender, "sender_domain": message.sender_domain,
        "subject": report["subject"] if report else None, "created_at": analysis.created_at.isoformat(),
        "providers": analysis.providers, "lookups": analysis.lookups, "techniques": analysis.techniques,
        "hold": message.hold, "tier1_deleted_at": message.tier1_deleted_at.isoformat()
        if message.tier1_deleted_at else None,
        "files": [{k: f[k] for k in ("name", "kind", "type", "size", "sha256")} | {"available": bool(f["blob"])}
                  for f in analysis.files],
    }
    if with_report:
        view["report"] = report
    return view


def listing(db: Session, store: BlobStore, workspace_id: int, q: str = "", verdict: str = "", offset: int = 0,
            source: str = "", user: int | None = None, since: dt.date | None = None,
            until: dt.date | None = None, disputed: bool = False) -> list[dict[str, Any]]:
    """Newest first. since and until are days (UTC), both included; disputed keeps the analyses someone said
    were wrong."""
    query = (select(Analysis, Message, Submission).join(Message, Analysis.message_id == Message.id)
             .join(Submission, Analysis.submission_id == Submission.id)
             .where(Analysis.workspace_id == workspace_id).order_by(Analysis.id.desc()))
    if verdict:
        query = query.where(Analysis.verdict == verdict)
    if source:
        query = query.where(Submission.source == source)
    if user is not None:
        query = query.where(Submission.user_id == user)
    if disputed:
        query = query.where(Analysis.id.in_(feedback.disputed_ids()))
    if since is not None:
        query = query.where(Analysis.created_at >= dt.datetime.combine(since, dt.time(), dt.timezone.utc))
    if until is not None:
        next_day = dt.datetime.combine(until + dt.timedelta(days=1), dt.time(), dt.timezone.utc)
        query = query.where(Analysis.created_at < next_day)
    q = q.strip()
    if q:
        query = query.where(or_(Message.sha256.startswith(q.lower(), autoescape=True),
                                Analysis.report_id == q.upper(),
                                Analysis.id.in_(select(Indicator.analysis_id)
                                                .where(Indicator.value.contains(q, autoescape=True)))))
    rows = db.execute(query.offset(max(0, offset)).limit(PAGE)).all()
    names, boxes = usernames(db, workspace_id), mailbox_names(db, workspace_id)
    return [summary(store, a, m, s, submitter=submitter(s, names, boxes)) for a, m, s in rows]


def is_owner(db: Session, message_id: int, user_id: int) -> bool:
    return db.scalars(select(Submission.id).where(Submission.message_id == message_id,
                                                  Submission.user_id == user_id).limit(1)).first() is not None


def usernames(db: Session, workspace_id: int) -> dict[int, str]:
    return {u.id: u.username for u in db.scalars(select(User).where(User.workspace_id == workspace_id))}


def mailbox_names(db: Session, workspace_id: int) -> dict[int, str]:
    return {m.id: m.name for m in db.scalars(select(Mailbox).where(Mailbox.workspace_id == workspace_id))}


def submitter(submission: Submission, names: dict[int, str], boxes: dict[int, str]) -> str | None:
    """Who submitted it: a user, or the mailbox it was imported from."""
    if submission.user_id is not None:
        return names.get(submission.user_id)
    return boxes.get(submission.mailbox_id or 0)


def submitter_of(db: Session, submission: Submission) -> str | None:
    workspace_id = submission.workspace_id
    return submitter(submission, usernames(db, workspace_id), mailbox_names(db, workspace_id))
