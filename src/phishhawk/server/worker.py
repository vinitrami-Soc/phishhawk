"""The worker process: requeues jobs whose worker died, schedules the hourly
retention sweep and campaign rebuild and each mailbox's polls, and runs one
job at a time."""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import appsettings, audit, auth, batches, campaigns, jobs, mailbox
from .db import transaction
from .models import SERVER, Campaign, Job, Submission, Workspace, utcnow
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
            elif job.kind == "mailbox_poll":
                mailbox.gave_up(db, int(job.payload["mailbox_id"]), job.error)
        last = jobs.last_finished(db, "retention_sweep")
        if not jobs.pending(db, "retention_sweep") and (last is None or utcnow() - last >= SWEEP_EVERY):
            jobs.enqueue(db, "retention_sweep")
        # messages leave the window as time passes: a workspace's campaigns are made again hourly
        stale = (select(Campaign.workspace_id).group_by(Campaign.workspace_id)
                 .having(func.max(Campaign.rebuilt_at) <= utcnow() - SWEEP_EVERY))
        for workspace_id in db.scalars(stale).all():
            campaigns.queue_rebuild(db, workspace_id)
        for mailbox_id in mailbox.due(db):
            mailbox.queue_poll(db, mailbox_id)


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
        elif kind == "mailbox_poll":
            mailbox.poll(services, int(payload["mailbox_id"]), beat)
        elif kind == "campaign_rebuild":
            with transaction(services.sessions) as db:
                # a job queued before workspaces names none: every workspace is rebuilt
                targets = ([payload["workspace_id"]] if "workspace_id" in payload
                           else list(db.scalars(select(Workspace.id))))
                for workspace_id in targets:
                    campaigns.rebuild(db, workspace_id, appsettings.limit(db, services.settings,
                                                                          "campaign_window_days", workspace_id))
        elif kind == "retention_sweep":
            with transaction(services.sessions) as db:
                total = 0
                for workspace_id in db.scalars(select(Workspace.id)).all():
                    days = appsettings.limit(db, services.settings, "retention_days", workspace_id)
                    count = sweep(db, services.store, days, workspace_id)
                    total += count
                    if count:  # the workspace's admins see what went
                        audit.record(db, "system", "retention_sweep", details={"deleted": count, "days": days},
                                     workspace_id=workspace_id)
                auth.end_idle_sessions(db, services.settings.session_idle_minutes)
                audit.record(db, "system", "retention_sweep", details={"deleted": total}, workspace_id=SERVER)
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
