"""The job queue: a table. A worker claims a queued job in one transaction
(SQLite: one writer at a time; Postgres: SKIP LOCKED). Workspaces take turns:
the one served longest ago goes first, and within it the oldest job, so a busy
workspace cannot hold up a quiet one even with a single worker. At most
RUNNING_EACH jobs of one workspace run at once (with several workers on
Postgres, two claiming at the same moment can each take one past it). The
server's own jobs, which name no workspace, are never held back."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, aliased

from .models import Job, utcnow

KINDS = ("analyze", "batch_finalize", "campaign_rebuild", "mailbox_poll", "retention_sweep", "email_verify",
         "email_reset")
MAX_ATTEMPTS = 3
RUNNING_EACH = 2  # jobs of one workspace that run at once


def enqueue(db: Session, kind: str, payload: dict[str, Any] | None = None, workspace_id: int | None = None) -> Job:
    if kind not in KINDS:
        raise ValueError("unknown job kind %r" % kind)
    job = Job(kind=kind, payload=payload or {}, workspace_id=workspace_id)
    db.add(job)
    db.flush()
    return job


def claim(db: Session) -> Job | None:
    earlier = aliased(Job)
    full = (select(earlier.workspace_id).where(earlier.status == "running", earlier.workspace_id.is_not(None))
            .group_by(earlier.workspace_id).having(func.count() >= RUNNING_EACH))
    served = (select(func.max(earlier.started_at)).where(earlier.workspace_id == Job.workspace_id)
              .correlate(Job).scalar_subquery())
    job = db.scalars(select(Job).where(Job.status == "queued",
                                       or_(Job.workspace_id.is_(None), Job.workspace_id.not_in(full)))
                     .order_by(served.is_not(None), served, Job.id).limit(1)
                     .with_for_update(skip_locked=True, of=Job)).first()
    if job is not None:
        job.status, job.attempts = "running", job.attempts + 1
        job.started_at = job.heartbeat_at = utcnow()
    return job


def heartbeat(db: Session, job_id: int) -> None:
    job = db.get(Job, job_id)
    if job is not None:
        job.heartbeat_at = utcnow()


def finish(db: Session, job_id: int, error: str = "") -> None:
    job = db.get(Job, job_id)
    if job is not None:
        job.status = "failed" if error else "done"
        job.error, job.finished_at = error[:500], utcnow()


def requeue_stale(db: Session, stale_after: dt.timedelta, given_up: list[Job] | None = None) -> int:
    """Running jobs whose worker stopped sending heartbeats: back to the
    queue, or failed after MAX_ATTEMPTS (and added to given_up)."""
    cutoff, moved = utcnow() - stale_after, 0
    for job in db.scalars(select(Job).where(Job.status == "running", Job.heartbeat_at < cutoff)):
        if job.attempts >= MAX_ATTEMPTS:
            job.status, job.finished_at = "failed", utcnow()
            job.error = "the worker stopped %d times" % job.attempts
            if given_up is not None:
                given_up.append(job)
        else:
            job.status = "queued"
        moved += 1
    return moved


def prune(db: Session, older_than: dt.timedelta) -> None:
    """Finished jobs, kept a while to show what ran, then removed: the table would only grow."""
    db.execute(delete(Job).where(Job.status.in_(("done", "failed")), Job.finished_at < utcnow() - older_than))


def pending(db: Session, kind: str) -> bool:
    return db.scalars(select(Job.id).where(Job.kind == kind, Job.status.in_(("queued", "running")))
                      .limit(1)).first() is not None


def last_finished(db: Session, kind: str) -> dt.datetime | None:
    return db.scalars(select(Job.finished_at).where(Job.kind == kind, Job.finished_at.is_not(None))
                      .order_by(Job.finished_at.desc()).limit(1)).first()
