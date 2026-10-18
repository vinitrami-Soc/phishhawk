"""The job table: claim order, one claim per job, stale requeue."""

import datetime as dt

from phishhawk.server import jobs
from phishhawk.server.db import transaction
from phishhawk.server.models import Job, Workspace


def test_jobs_are_claimed_oldest_first_and_only_once(db):
    with transaction(db) as s:
        first = jobs.enqueue(s, "analyze", {"submission_id": 1}).id
        jobs.enqueue(s, "analyze", {"submission_id": 2})
    with transaction(db) as s:
        job = jobs.claim(s)
        assert (job.id, job.status, job.attempts) == (first, "running", 1)
    with transaction(db) as s:
        assert jobs.claim(s).payload == {"submission_id": 2}
    with transaction(db) as s:
        assert jobs.claim(s) is None


def test_a_job_whose_worker_stopped_is_requeued_then_failed(db):
    with transaction(db) as s:
        job_id = jobs.enqueue(s, "retention_sweep").id
    for attempt in range(1, 4):
        with transaction(db) as s:
            assert jobs.claim(s).id == job_id
            s.get(Job, job_id).heartbeat_at -= dt.timedelta(minutes=5)
        with transaction(db) as s:
            assert jobs.requeue_stale(s, dt.timedelta(minutes=2)) == 1
            assert s.get(Job, job_id).status == ("failed" if attempt == 3 else "queued")


def test_finish_records_success_or_the_error(db):
    with transaction(db) as s:
        ok, bad = jobs.enqueue(s, "analyze").id, jobs.enqueue(s, "analyze").id
        jobs.finish(s, ok)
        jobs.finish(s, bad, "boom")
    with transaction(db) as s:
        assert s.get(Job, ok).status == "done" and s.get(Job, bad).status == "failed"
        assert s.get(Job, bad).error == "boom"


def _two_workspaces(s):
    other = Workspace(name="Busy Ltd", kind="organization")
    s.add(other)
    s.flush()
    return 1, other.id


def _claim(db):
    with transaction(db) as s:
        job = jobs.claim(s)
        return None if job is None else (job.workspace_id, job.payload["n"])


def _finish(db, workspace_id, n):
    with transaction(db) as s:
        job = s.query(Job).filter(Job.workspace_id == workspace_id, Job.status == "running").all()
        jobs.finish(s, next(j.id for j in job if j.payload["n"] == n))


def test_a_busy_workspace_does_not_starve_another(db):
    """One worker, five jobs of a busy workspace queued before one of a quiet one: the quiet one's job runs
    second, not sixth. The workspace served longest ago goes first; within a workspace, the oldest job."""
    with transaction(db) as s:
        quiet, busy = _two_workspaces(s)
        for n in range(5):
            jobs.enqueue(s, "analyze", {"n": n}, workspace_id=busy)
        jobs.enqueue(s, "analyze", {"n": 0}, workspace_id=quiet)
    order = []
    while (claimed := _claim(db)) is not None:
        order.append(claimed)
        _finish(db, *claimed)
    assert order == [(busy, 0), (quiet, 0), (busy, 1), (busy, 2), (busy, 3), (busy, 4)]


def test_at_most_two_jobs_of_one_workspace_run_at_once(db):
    with transaction(db) as s:
        quiet, busy = _two_workspaces(s)
        for n in range(3):
            jobs.enqueue(s, "analyze", {"n": n}, workspace_id=busy)
    assert [_claim(db), _claim(db), _claim(db)] == [(busy, 0), (busy, 1), None]  # the third waits
    with transaction(db) as s:
        jobs.enqueue(s, "retention_sweep", {"n": 9})  # the server's own work is never held back
        jobs.enqueue(s, "analyze", {"n": 0}, workspace_id=quiet)
    assert [_claim(db), _claim(db), _claim(db)] == [(None, 9), (quiet, 0), None]
    _finish(db, busy, 0)
    assert _claim(db) == (busy, 2)
