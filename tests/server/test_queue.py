"""The queue's filters: verdict, source, who submitted and when, with search by hash, report ID or indicator
(spec 8)."""

import datetime as dt

from phishhawk.server import worker
from phishhawk.server.db import transaction
from phishhawk.server.models import Analysis

from conftest import build_eml


def _queue(services, alice, bob):
    alice.post("/api/v1/submissions", data={"offline": "true"},
               files={"file": ("a.eml", build_eml(subject="Uploaded"), "message/rfc822")})
    bob.post("/api/v1/submissions", data={"offline": "true", "raw": build_eml(subject="Pasted").decode()})
    alice.post("/api/v1/submissions", data={"offline": "true"},
               files=[("files", ("b%d.eml" % i, build_eml(subject="Batch %d" % i), "message/rfc822"))
                      for i in range(2)])
    while worker.run_one(services):
        pass


def _subjects(client, query=""):
    answer = client.get("/api/v1/analyses" + query)
    assert answer.status_code == 200, answer.text
    return sorted(a["subject"] for a in answer.json())


def test_the_queue_filters_by_source_and_by_who_submitted(alice, bob, services):
    _queue(services, alice, bob)
    assert _subjects(alice, "?source=batch") == ["Batch 0", "Batch 1"]
    assert _subjects(alice, "?source=paste") == ["Pasted"]
    bob_id = bob.get("/api/v1/session").json()["user_id"]
    assert _subjects(alice, "?user=%d" % bob_id) == ["Pasted"]
    assert _subjects(alice, "?source=upload&user=%d" % bob_id) == []


def test_the_queue_filters_by_day(alice, bob, services):
    _queue(services, alice, bob)
    with transaction(services.sessions) as s:
        for analysis in s.query(Analysis):
            if analysis.id == 1:
                analysis.created_at = dt.datetime(2026, 9, 30, 23, 59, tzinfo=dt.timezone.utc)
    assert _subjects(alice, "?until=2026-09-30") == ["Uploaded"]
    assert len(_subjects(alice, "?since=2026-10-01")) == 3
    assert _subjects(alice, "?since=2026-09-30&until=2026-09-30") == ["Uploaded"]
    assert alice.get("/api/v1/analyses?since=yesterday").status_code == 422


def test_the_queue_page_has_every_filter(alice, bob, services):
    _queue(services, alice, bob)
    page = alice.get("/queue?source=batch").text
    for field in ('name="q"', 'name="verdict"', 'name="source"', 'name="user"', 'name="since"', 'name="until"'):
        assert field in page, field
    assert page.count('href="/analyses/') == 2
    assert alice.get("/queue?until=2026-09-30").text.count('href="/analyses/') == 0
