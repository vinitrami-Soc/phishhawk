"""Feedback, both kinds (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md, section 7).

General feedback is a note to the server's owner: a bug, an idea, a question or anything else, with the page it
was sent from. Its sender and the owner see it; the owner marks it done; either of them deletes it. Each person
sends at most 10 an hour. Verdict feedback is each person's word on one analysis: right, missed (it was
phishing) or false_alarm (it was not), with an optional note. Everyone in the workspace reads it; its author
changes or deletes it, and so can a workspace admin. The owner's export of disputed verdicts holds no message,
note or person."""

from __future__ import annotations

import csv
import datetime as dt
import io
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from . import audit
from .auth import Actor
from .models import Analysis, Feedback, Message, User, VerdictFeedback, Workspace, utcnow

KINDS = ("bug", "idea", "question", "other")
STATUSES = ("open", "done")
OPINIONS = ("right", "missed", "false_alarm")
DISPUTING = ("missed", "false_alarm")
MESSAGE_MAX, NOTE_MAX = 4000, 1000
HOURLY = 10
PAGE_RE = re.compile(r"/(?!/)[\x21-\x7e]{0,199}")  # a path in the app, as the browser shows it; never //host
# bidirectional embeddings, overrides and isolates: they reorder what the next reader sees
BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
CSV_FIELDS = ("workspace_id", "analysis_id", "report_id", "sha256", "verdict", "score", "right", "missed",
              "false_alarm", "last_answer_at")


class FeedbackError(Exception):
    """A request that cannot be done: an HTTP status, a reason that names the field, and for 429 the wait."""

    def __init__(self, status: int, detail: str, retry_after: int = 0) -> None:
        super().__init__(detail)
        self.status, self.detail, self.retry_after = status, detail, retry_after


def text(field: str, value: object, most: int, required: bool = True) -> str:
    """Free text: trimmed, at most `most` characters; lines and tabs, but no other control characters and no
    bidirectional overrides."""
    written = value.strip() if isinstance(value, str) else ""
    if required and not written:
        raise FeedbackError(422, "%s: required" % field)
    if len(written) > most:
        raise FeedbackError(422, "%s: %d characters at most" % (field, most))
    if any((unicodedata.category(c) == "Cc" and c not in "\n\r\t") or c in BIDI for c in written):
        raise FeedbackError(422, "%s: control characters are not allowed" % field)
    return written


def _hour_wait(db: Session, user_id: int) -> int:
    """Seconds until the sender may send again, or 0."""
    since = utcnow() - dt.timedelta(hours=1)
    recent = db.scalars(select(Feedback.created_at).where(Feedback.user_id == user_id, Feedback.created_at > since)
                        .order_by(Feedback.created_at.desc()).limit(HOURLY)).all()
    if len(recent) < HOURLY:
        return 0
    return max(1, int((recent[-1] - since).total_seconds()) + 1)


def send(db: Session, actor: Actor, data: Mapping[str, Any]) -> Feedback:
    kind = data.get("kind")
    if kind not in KINDS:
        raise FeedbackError(422, "kind: bug, idea, question or other")
    message = text("message", data.get("message"), MESSAGE_MAX)
    page = data.get("page") or ""
    if not isinstance(page, str) or (page and not PAGE_RE.fullmatch(page)):
        raise FeedbackError(422, "page: a path in this app, such as /app/analyses/3")
    wait = _hour_wait(db, actor.user_id)
    if wait:
        raise FeedbackError(429, "%d messages an hour at most: wait %d s" % (HOURLY, wait), wait)
    row = Feedback(workspace_id=actor.workspace_id, user_id=actor.user_id, kind=kind, message=message, page=page)
    db.add(row)
    db.flush()
    audit.record(db, actor.label, "feedback", "feedback", row.id, {"kind": kind}, workspace_id=actor.workspace_id)
    return row


def visible(db: Session, actor: Actor) -> list[Feedback]:
    """All of it for the owner; anyone else's own. Newest first."""
    query = select(Feedback).order_by(Feedback.id.desc())
    if not actor.owner:
        query = query.where(Feedback.user_id == actor.user_id)
    return list(db.scalars(query))


def find(db: Session, actor: Actor, ident: int) -> Feedback:
    """Feedback the caller may see, or 404: someone else's looks like none at all."""
    row = db.get(Feedback, ident)
    if row is None or not (actor.owner or row.user_id == actor.user_id):
        raise FeedbackError(404, "no such feedback")
    return row


def mark(db: Session, actor: Actor, row: Feedback, status: object) -> None:
    if not actor.owner:
        raise FeedbackError(403, "only the server's owner marks feedback done")
    if status not in STATUSES:
        raise FeedbackError(422, "status: open or done")
    row.status = str(status)
    audit.record(db, actor.label, "feedback_status", "feedback", row.id, {"status": row.status},
                 workspace_id=actor.workspace_id)


def remove(db: Session, actor: Actor, row: Feedback) -> None:
    audit.record(db, actor.label, "feedback_delete", "feedback", row.id, workspace_id=actor.workspace_id)
    db.delete(row)


def view(row: Feedback, names: Mapping[int, str], workspaces: Mapping[int, str]) -> dict[str, Any]:
    return {"id": row.id, "kind": row.kind, "message": row.message, "page": row.page, "status": row.status,
            "created_at": row.created_at.isoformat(), "username": names.get(row.user_id),
            "workspace": {"id": row.workspace_id, "name": workspaces.get(row.workspace_id, "")}}


def views(db: Session, rows: list[Feedback]) -> list[dict[str, Any]]:
    names = {u.id: u.username for u in db.scalars(select(User).where(User.id.in_({r.user_id for r in rows})))}
    spaces = {r.workspace_id for r in rows}
    workspaces = {w.id: w.name for w in db.scalars(select(Workspace).where(Workspace.id.in_(spaces)))}
    return [view(r, names, workspaces) for r in rows]


# Verdict feedback

def answer(db: Session, actor: Actor, analysis: Analysis, data: Mapping[str, Any]) -> VerdictFeedback:
    """The caller's answer on this analysis, made or changed."""
    opinion = data.get("opinion")
    if opinion not in OPINIONS:
        raise FeedbackError(422, "opinion: right, missed or false_alarm")
    note = text("note", data.get("note"), NOTE_MAX, required=False)
    row = db.scalars(select(VerdictFeedback).where(VerdictFeedback.analysis_id == analysis.id,
                                                   VerdictFeedback.user_id == actor.user_id)).first()
    if row is None:
        row = VerdictFeedback(workspace_id=analysis.workspace_id, analysis_id=analysis.id, user_id=actor.user_id,
                              opinion=opinion, note=note)
        db.add(row)
    else:
        row.opinion, row.note, row.updated_at = str(opinion), note, utcnow()
    db.flush()
    audit.record(db, actor.label, "verdict_feedback", "analysis", analysis.id, {"opinion": opinion},
                 workspace_id=actor.workspace_id)
    return row


def answer_view(row: VerdictFeedback, names: Mapping[int, str]) -> dict[str, Any]:
    return {"id": row.id, "user_id": row.user_id, "username": names.get(row.user_id), "opinion": row.opinion,
            "note": row.note, "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat()}


def answers(db: Session, actor: Actor, analysis: Analysis) -> dict[str, Any]:
    rows = list(db.scalars(select(VerdictFeedback).where(VerdictFeedback.analysis_id == analysis.id)
                           .order_by(VerdictFeedback.id)))
    names = {u.id: u.username for u in db.scalars(select(User).where(User.workspace_id == analysis.workspace_id))}
    mine = next((r for r in rows if r.user_id == actor.user_id), None)
    counts = {o: sum(1 for r in rows if r.opinion == o) for o in OPINIONS}
    return {"mine": answer_view(mine, names) if mine else None, "answers": [answer_view(r, names) for r in rows],
            "counts": counts}


def withdraw(db: Session, actor: Actor, analysis: Analysis, answer_id: int | None = None) -> None:
    """The caller's own answer; or, by its ID, anyone's, which only its author or an admin may remove."""
    if answer_id is None:
        row = db.scalars(select(VerdictFeedback).where(VerdictFeedback.analysis_id == analysis.id,
                                                       VerdictFeedback.user_id == actor.user_id)).first()
        if row is None:
            return
    else:
        found = db.get(VerdictFeedback, answer_id)
        if found is None or found.analysis_id != analysis.id:
            raise FeedbackError(404, "no such answer")
        if found.user_id != actor.user_id and not actor.is_admin:
            raise FeedbackError(403, "only its author or an admin removes an answer")
        row = found
    audit.record(db, actor.label, "verdict_feedback_delete", "analysis", analysis.id, {"answer": row.id},
                 workspace_id=actor.workspace_id)
    db.delete(row)


def _tally() -> Any:
    """Each analysis with answers: how many of each, and when the last one came."""
    return (select(VerdictFeedback.analysis_id,
                   *[func.sum(case((VerdictFeedback.opinion == o, 1), else_=0)).label(o) for o in OPINIONS],
                   func.max(VerdictFeedback.updated_at).label("last"))
            .group_by(VerdictFeedback.analysis_id))


def disputed_ids() -> Any:
    """The analyses at least one person disputes."""
    return select(VerdictFeedback.analysis_id).where(VerdictFeedback.opinion.in_(DISPUTING))


def summary(db: Session, workspace_id: int) -> dict[str, Any]:
    """For a workspace's admins: how many of each answer, and the disputed analyses, latest answer first."""
    tally = _tally().where(VerdictFeedback.workspace_id == workspace_id).subquery()
    rows = db.execute(select(tally, Analysis).join(Analysis, Analysis.id == tally.c.analysis_id)
                      .order_by(tally.c.last.desc())).all()
    counts = {o: sum(int(getattr(r, o)) for r in rows) for o in OPINIONS}
    disputed = [{"analysis_id": r.analysis_id, "report_id": r.Analysis.report_id, "verdict": r.Analysis.verdict,
                 "score": r.Analysis.score, **{o: int(getattr(r, o)) for o in OPINIONS},
                 "last_answer_at": r.last.isoformat()}
                for r in rows if int(r.missed) + int(r.false_alarm) > 0]
    return {"counts": counts, "disputed": disputed}


def disputed_csv(db: Session) -> str:
    """For the owner, to improve the engine: every workspace's disputed verdicts, with no message, note or
    person in it."""
    tally = _tally().subquery()
    rows = db.execute(select(tally, Analysis, Message.sha256).join(Analysis, Analysis.id == tally.c.analysis_id)
                      .join(Message, Message.id == Analysis.message_id).order_by(tally.c.analysis_id)).all()
    out = io.StringIO()
    writer = csv.DictWriter(out, CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for r in rows:
        if int(r.missed) + int(r.false_alarm) == 0:
            continue
        writer.writerow({"workspace_id": r.Analysis.workspace_id, "analysis_id": r.analysis_id,
                         "report_id": r.Analysis.report_id, "sha256": r.sha256, "verdict": r.Analysis.verdict,
                         "score": r.Analysis.score, **{o: int(getattr(r, o)) for o in OPINIONS},
                         "last_answer_at": r.last.isoformat()})
    return out.getvalue()
