"""The worker process: requeues jobs whose worker died, schedules the hourly
retention sweep, and runs one job at a time."""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from . import appsettings, audit, batches, jobs
from .db import transaction
from .models import Job, Submission, utcnow
from .processing import Services, process_submission
from .retention import sweep

STALE_AFTER = dt.timedelta(minutes=2)
SWEEP_EVERY = dt.timedelta(hours=1)


def schedule(services: Services) -> None:
    with transaction(services.sessions) as db:
        given_up: list[Job] = []
        jobs.requeue_stale(db, STALE_AFTER, given_up)
        for job in given_up:
            if job.kind == "analyze":
                _submission_ended(db, int(job.payload["submission_id"]), job.error)
            elif job.kind == "batch_finalize":
                batches.failed(db, int(job.payload["batch_id"]), job.error)
        last = jobs.last_finished(db, "retention_sweep")
        if not jobs.pending(db, "retention_sweep") and (last is None or utcnow() - last >= SWEEP_EVERY):
            jobs.enqueue(db, "retention_sweep")


def run_one(services: Services) -> bool:
    """Claim and run one job; False when the queue was empty."""
    with transaction(services.sessions) as db:
        job = jobs.claim(db)
        if job is None:
            return False
        job_id, kind, payload = job.id, job.kind, dict(job.payload)

    def beat() -> None:
        with transaction(services.sessions) as db:
            jobs.heartbeat(db, job_id)

    error = stopped = ""
    try:
        if kind == "analyze":
            process_submission(services, int(payload["submission_id"]), beat)
        elif kind == "batch_finalize":
            batches.finalize(services, int(payload["batch_id"]), beat)
        elif kind == "retention_sweep":
            with transaction(services.sessions) as db:
                days = appsettings.limit(db, services.settings, "retention_days")
                count = sweep(db, services.store, days)
                audit.record(db, "system", "retention_sweep", details={"deleted": count, "days": days})
    except Exception as exc:  # a bug in a handler must not stop the worker
        error = "%s: %s" % (type(exc).__name__, exc)
        stopped = "the analysis stopped: %s" % type(exc).__name__  # its text may quote the message
    with transaction(services.sessions) as db:
        jobs.finish(db, job_id, error)
        if kind == "analyze":
            _submission_ended(db, int(payload["submission_id"]), stopped if error else "")
        elif kind == "batch_finalize" and error:
            batches.failed(db, int(payload["batch_id"]), stopped)
    return True


def _submission_ended(db: Session, submission_id: int, failure: str) -> None:
    """A submission whose job ended: failed if the job never finished it, and its batch finished if it was the
    last."""
    submission = db.get(Submission, submission_id)
    if submission is None:
        return
    if failure and submission.status in ("queued", "running"):
        submission.status, submission.error = "failed", failure
    batches.after_submission(db, submission)


def run_forever(services: Services, should_stop: Callable[[], bool] = lambda: False, idle: float = 1.0) -> None:
    next_schedule = 0.0
    while not should_stop():
        if time.monotonic() >= next_schedule:
            schedule(services)
            next_schedule = time.monotonic() + 30
        if not run_one(services):
            time.sleep(idle)
