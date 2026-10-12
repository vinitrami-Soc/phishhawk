"""Queries the API and the pages share."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Analysis, Indicator, Message, Submission, User
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


def find(db: Session, analysis_id: int) -> tuple[Analysis, Message, Submission] | None:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        return None
    message, submission = db.get(Message, analysis.message_id), db.get(Submission, analysis.submission_id)
    if message is None or submission is None:
        return None
    return analysis, message, submission


def listing(db: Session, store: BlobStore, q: str = "", verdict: str = "", offset: int = 0, source: str = "",
            user: int | None = None, since: dt.date | None = None,
            until: dt.date | None = None) -> list[dict[str, Any]]:
    """Newest first. since and until are days (UTC), both included."""
    query = (select(Analysis, Message, Submission).join(Message, Analysis.message_id == Message.id)
             .join(Submission, Analysis.submission_id == Submission.id).order_by(Analysis.id.desc()))
    if verdict:
        query = query.where(Analysis.verdict == verdict)
    if source:
        query = query.where(Submission.source == source)
    if user is not None:
        query = query.where(Submission.user_id == user)
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
    names = usernames(db)
    return [summary(store, a, m, s, submitter=names.get(s.user_id or 0)) for a, m, s in rows]


def is_owner(db: Session, message_id: int, user_id: int) -> bool:
    return db.scalars(select(Submission.id).where(Submission.message_id == message_id,
                                                  Submission.user_id == user_id).limit(1)).first() is not None


def usernames(db: Session) -> dict[int, str]:
    return {u.id: u.username for u in db.scalars(select(User))}
