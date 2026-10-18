"""The daily limit on the messages each workspace submits (docs/superpowers/specs/2026-10-13-workspaces-signup-
feedback-design.md, section 8): by default 500 a day for an organization and 100 for someone on their own; the
server's owner sets both. Every submission counts: an upload or a paste, each message of a batch, a new analysis
of a message, and a message imported from a report mailbox. The day is UTC. Past the limit an upload answers
429 with the seconds until the day ends, and a mailbox poll stops; what it left in the mailbox comes the next
day. Counted from the database, so it holds however many processes take submissions."""

from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import appsettings
from .models import SERVER, Submission, Workspace, utcnow

DEFAULTS = {"organization": 500, "individual": 100}
SETTINGS = {kind: "daily_messages_%s" % kind for kind in DEFAULTS}


class DailyLimit(Exception):
    """The workspace has submitted all the messages it may today; retry_after is the seconds to midnight UTC."""

    def __init__(self, detail: str, retry_after: int) -> None:
        super().__init__(detail)
        self.detail, self.retry_after = detail, retry_after


def limit(db: Session, kind: str) -> int:
    return int(appsettings.get_value(db, SERVER, SETTINGS.get(kind, SETTINGS["organization"]),
                                     DEFAULTS.get(kind, DEFAULTS["organization"])))


def used(db: Session, workspace_id: int, now: dt.datetime | None = None) -> tuple[int, int, int]:
    """The workspace's limit, how many it submitted today, and the seconds until today (UTC) ends."""
    now = now or utcnow()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    workspace = db.get(Workspace, workspace_id)
    cap = limit(db, workspace.kind if workspace is not None else "organization")
    count = db.scalar(select(func.count()).select_from(Submission).where(
        Submission.workspace_id == workspace_id, Submission.submitted_at >= start)) or 0
    return cap, int(count), max(1, int((start + dt.timedelta(days=1) - now).total_seconds()))


def room(db: Session, workspace_id: int) -> int:
    """How many more messages the workspace may submit today."""
    cap, count, _ = used(db, workspace_id)
    return max(0, cap - count)


def check(db: Session, workspace_id: int, adding: int = 1) -> None:
    """Raises DailyLimit unless `adding` more messages fit today."""
    cap, count, wait = used(db, workspace_id)
    if count + adding <= cap:
        return
    what = "this message" if adding == 1 else "these %d messages" % adding
    raise DailyLimit("this workspace may submit %d messages a day and has submitted %d today, so %s cannot be "
                     "added: more after 00:00 UTC" % (cap, count, what), wait)
