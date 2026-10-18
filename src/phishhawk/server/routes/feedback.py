"""The feedback API: notes to the server's owner, and each person's word on a verdict (feedback.py).

The request bodies have no required fields, so that a missing one is answered like a wrong one, naming it, and
only after the row in the URL is found: a row of another workspace stays a 404 whatever is sent."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from .. import feedback, scope
from ..deps import DB, Admin, CurrentActor
from . import api

router = APIRouter(prefix="/api/v1")


def _refused(exc: feedback.FeedbackError) -> HTTPException:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return HTTPException(exc.status, exc.detail, headers=headers)


class NewFeedback(BaseModel):
    kind: str = ""
    message: str = ""
    page: str = ""


class FeedbackPatch(BaseModel):
    status: str = ""


class VerdictAnswer(BaseModel):
    opinion: str = ""
    note: str = ""


@router.post("/feedback", status_code=201)
def send_feedback(db: DB, actor: CurrentActor, body: NewFeedback) -> dict[str, Any]:
    """A bug, an idea, a question or other, for the server's owner; `page` is where it was sent from. 10 an hour
    for each person (429 with Retry-After past that)."""
    api._session_only(actor, "send feedback")
    try:
        row = feedback.send(db, actor, body.model_dump())
    except feedback.FeedbackError as exc:
        raise _refused(exc) from None
    return feedback.views(db, [row])[0]


@router.get("/feedback")
def list_feedback(db: DB, actor: CurrentActor) -> list[dict[str, Any]]:
    """The owner gets everyone's, with their workspace; anyone else what they sent. Newest first."""
    api._session_only(actor, "read feedback")
    return feedback.views(db, feedback.visible(db, actor))


@router.get("/feedback/verdicts")
def verdict_summary(db: DB, actor: Admin, format: str = "json") -> Any:
    """The workspace's answers on verdicts: how many of each and the disputed analyses. `format=csv` is the
    owner's: every workspace's disputed verdicts, without messages, notes or people."""
    if format == "csv":
        if not actor.owner:
            raise HTTPException(403, "only the server's owner downloads every workspace's disputed verdicts")
        api._audit(db, actor, "verdict_feedback_export")
        return Response(feedback.disputed_csv(db), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="phishhawk-disputed-verdicts.csv"'})
    return feedback.summary(db, actor.workspace_id)


@router.patch("/feedback/{feedback_id}")
def mark_feedback(db: DB, actor: CurrentActor, feedback_id: int, body: FeedbackPatch) -> dict[str, Any]:
    """The owner marks it open or done."""
    api._session_only(actor, "change feedback")
    try:
        row = feedback.find(db, actor, feedback_id)
        feedback.mark(db, actor, row, body.status)
    except feedback.FeedbackError as exc:
        raise _refused(exc) from None
    return feedback.views(db, [row])[0]


@router.delete("/feedback/{feedback_id}", status_code=204)
def delete_feedback(db: DB, actor: CurrentActor, feedback_id: int) -> Response:
    """Its sender or the owner deletes it."""
    api._session_only(actor, "delete feedback")
    try:
        feedback.remove(db, actor, feedback.find(db, actor, feedback_id))
    except feedback.FeedbackError as exc:
        raise _refused(exc) from None
    return Response(status_code=204)


@router.get("/analyses/{analysis_id}/feedback")
def verdict_answers(db: DB, actor: CurrentActor, analysis_id: int) -> dict[str, Any]:
    """Everyone's answer on this analysis's verdict, the caller's own (`mine`), and how many of each."""
    analysis, _, _ = scope.analysis(db, actor, analysis_id)
    return feedback.answers(db, actor, analysis)


@router.put("/analyses/{analysis_id}/feedback")
def answer_verdict(db: DB, actor: CurrentActor, analysis_id: int, body: VerdictAnswer) -> dict[str, Any]:
    """Was the verdict right? `opinion` is right, missed (it was phishing) or false_alarm (it was not); `note`
    is optional. One answer for each person, changed by sending another."""
    analysis, _, _ = scope.analysis(db, actor, analysis_id)
    api._session_only(actor, "answer for a person")
    try:
        row = feedback.answer(db, actor, analysis, body.model_dump())
    except feedback.FeedbackError as exc:
        raise _refused(exc) from None
    names = {actor.user_id: actor.username}
    return feedback.answer_view(row, names)


@router.delete("/analyses/{analysis_id}/feedback", status_code=204)
def withdraw_answer(db: DB, actor: CurrentActor, analysis_id: int) -> Response:
    """The caller's own answer on this analysis, if they gave one."""
    analysis, _, _ = scope.analysis(db, actor, analysis_id)
    api._session_only(actor, "answer for a person")
    feedback.withdraw(db, actor, analysis)
    return Response(status_code=204)


@router.delete("/analyses/{analysis_id}/feedback/{answer_id}", status_code=204)
def remove_answer(db: DB, actor: CurrentActor, analysis_id: int, answer_id: int) -> Response:
    """Anyone's answer on this analysis: its author's to remove, or a workspace admin's."""
    analysis, _, _ = scope.analysis(db, actor, analysis_id)
    api._session_only(actor, "remove an answer")
    try:
        feedback.withdraw(db, actor, analysis, answer_id)
    except feedback.FeedbackError as exc:
        raise _refused(exc) from None
    return Response(status_code=204)
