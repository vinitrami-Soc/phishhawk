"""The job queue: a table. A worker claims the oldest queued job in one
transaction (SQLite: one writer at a time; Postgres: SKIP LOCKED)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Job, utcnow

KINDS = ("analyze", "batch_finalize", "retention_sweep")  # M2 adds campaign_rebuild, M3 mailbox_poll
MAX_ATTEMPTS = 3


def enqueue(db: Session, kind: str, payload: dict[str, Any] | None = None) -> Job:
    if kind not in KINDS:
        raise ValueError("unknown job kind %r" % kind)
    job = Job(kind=kind, payload=payload or {})
    db.add(job)
    db.flush()
    return job


def claim(db: Session) -> Job | None:
    job = db.scalars(select(Job).where(Job.status == "queued").order_by(Job.id).limit(1)
                     .with_for_update(skip_locked=True)).first()
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


def pending(db: Session, kind: str) -> bool:
    return db.scalars(select(Job.id).where(Job.kind == kind, Job.status.in_(("queued", "running")))
                      .limit(1)).first() is not None


def last_finished(db: Session, kind: str) -> dt.datetime | None:
    return db.scalars(select(Job.finished_at).where(Job.kind == kind, Job.finished_at.is_not(None))
                      .order_by(Job.finished_at.desc()).limit(1)).first()
