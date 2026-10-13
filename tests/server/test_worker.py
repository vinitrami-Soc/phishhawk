"""The worker's own schedule: the hourly retention sweep, requeueing jobs
whose worker stopped, and carrying on after a handler fails."""

import datetime as dt

from sqlalchemy import select

from phishhawk.server import intake, jobs, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER, Analysis, AuditRecord, Job, Message

from .serverkit import home
from conftest import sample


def _submit(services):
    with open(sample("sample_phish.eml"), "rb") as handle:
        raw = handle.read()
    with transaction(services.sessions) as s:
        return intake.accept(s, services.store, raw, source="upload", user_id=None, actor="alice", offline=True,
                             workspace_id=home(s), max_bytes=25 * 1024 * 1024).id


def _sweeps(services):
    with transaction(services.sessions) as s:
        return s.scalars(select(Job).where(Job.kind == "retention_sweep").order_by(Job.id)).all()


def test_the_retention_sweep_is_scheduled_once_then_hourly(services):
    worker.schedule(services)
    worker.schedule(services)
    assert len(_sweeps(services)) == 1  # not twice while one is queued
    assert worker.run_one(services)
    worker.schedule(services)
    assert len(_sweeps(services)) == 1  # finished less than an hour ago
    with transaction(services.sessions) as s:
        s.scalars(select(Job)).one().finished_at -= dt.timedelta(minutes=61)
    worker.schedule(services)
    assert len(_sweeps(services)) == 2


def test_the_sweep_deletes_tier1_after_the_retention_period_and_audits_the_count(services):
    _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        s.scalars(select(Message)).one().first_seen_at -= dt.timedelta(days=31)
    worker.schedule(services)
    while worker.run_one(services):  # the campaign rebuild the analysis queued, then the sweep
        pass
    with transaction(services.sessions) as s:
        assert s.scalars(select(Message)).one().raw_blob is None
        assert s.scalars(select(Analysis)).one().verdict == "LIKELY PHISHING"  # tier 2 stays
        # the workspace's own record, which its admins see, and the server's
        entry = s.scalars(select(AuditRecord).where(AuditRecord.action == "retention_sweep",
                                                    AuditRecord.workspace_id != SERVER)).one()
        assert (entry.actor, entry.details) == ("system", {"deleted": 1, "days": 30})
        server = s.scalars(select(AuditRecord).where(AuditRecord.action == "retention_sweep",
                                                     AuditRecord.workspace_id == SERVER)).one()
        assert server.details == {"deleted": 1}


def test_a_job_whose_worker_stopped_is_queued_again_by_the_schedule(services):
    _submit(services)
    with transaction(services.sessions) as s:
        job = jobs.claim(s)
        job.heartbeat_at -= dt.timedelta(minutes=5)
    worker.schedule(services)
    with transaction(services.sessions) as s:
        assert s.scalars(select(Job).where(Job.kind == "analyze")).one().status == "queued"


def test_a_failing_handler_fails_its_job_and_the_worker_carries_on(services, monkeypatch):
    def broken(*args):
        raise RuntimeError("boom")

    monkeypatch.setattr(worker, "process_submission", broken)
    _submit(services)
    assert worker.run_one(services)
    with transaction(services.sessions) as s:
        job = s.scalars(select(Job)).one()
        assert (job.status, job.error) == ("failed", "RuntimeError: boom")
    assert not worker.run_one(services)
