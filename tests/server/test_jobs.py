"""The job table: claim order, one claim per job, stale requeue."""

import datetime as dt

from phishhawk.server import jobs
from phishhawk.server.db import transaction
from phishhawk.server.models import Job


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
