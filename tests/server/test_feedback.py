"""Feedback, both kinds (docs/superpowers/specs/2026-10-13-workspaces-signup-feedback-design.md, section 7):
anyone signed in tells the owner about a bug, an idea or a question; on any analysis, each person says once
whether its verdict was right, and can change it."""

import csv
import io

from sqlalchemy import select

from phishhawk.server.db import transaction
from phishhawk.server.models import AuditRecord

from .test_workspaces import _invoices, _submit, beta  # noqa: F401 - beta is a fixture

IDEA = {"kind": "idea", "message": "Dark mode for the reports,\nplease.", "page": "/app/analyses/3"}


def test_anyone_signed_in_sends_feedback_and_sees_only_their_own(alice, bob, admin):
    sent = alice.post("/api/v1/feedback", json=IDEA)
    assert sent.status_code == 201, sent.text
    mine = sent.json()
    assert {k: mine[k] for k in ("kind", "message", "page", "status", "username")} == {
        "kind": "idea", "message": "Dark mode for the reports,\nplease.", "page": "/app/analyses/3",
        "status": "open", "username": "alice"}
    assert mine["workspace"]["name"] == "Default organization"
    assert alice.get("/api/v1/feedback").json() == [mine]
    assert bob.get("/api/v1/feedback").json() == []
    assert admin.get("/api/v1/feedback").json() == [mine]  # the owner reads all of it


def test_feedback_names_the_field_that_is_wrong(alice):
    for field, value in (("kind", "rant"), ("message", ""), ("message", " \n "), ("message", "x" * 4001),
                         ("message", "a\x00b"), ("message", "rtl \u202e trick"), ("page", "javascript:alert(1)"),
                         ("page", "//evil.example/x"), ("page", "/" + "a" * 200)):
        refused = alice.post("/api/v1/feedback", json=IDEA | {field: value})
        assert refused.status_code == 422, (field, value)
        assert refused.json()["detail"].startswith(field + ": "), (field, refused.json())
    assert alice.post("/api/v1/feedback", json=IDEA | {"page": ""}).status_code == 201  # from no page at all


def test_feedback_is_limited_to_ten_an_hour_for_each_person(alice, bob):
    for _ in range(10):
        assert alice.post("/api/v1/feedback", json=IDEA).status_code == 201
    too_many = alice.post("/api/v1/feedback", json=IDEA)
    assert too_many.status_code == 429 and int(too_many.headers["Retry-After"]) > 0
    assert bob.post("/api/v1/feedback", json=IDEA).status_code == 201  # someone else is not held back


def test_the_owner_marks_feedback_done_and_whoever_may_see_it_deletes_it(alice, bob, admin, services):
    sent = alice.post("/api/v1/feedback", json=IDEA).json()
    url = "/api/v1/feedback/%d" % sent["id"]
    assert alice.patch(url, json={"status": "done"}).status_code == 403  # theirs, but not theirs to close
    assert bob.patch(url, json={"status": "done"}).status_code == 404  # not even there for someone else
    assert admin.patch(url, json={"status": "maybe"}).status_code == 422
    done = admin.patch(url, json={"status": "done"})
    assert done.status_code == 200 and done.json()["status"] == "done"
    assert alice.get("/api/v1/feedback").json()[0]["status"] == "done"
    assert bob.delete(url).status_code == 404
    assert alice.delete(url).status_code == 204
    assert admin.get("/api/v1/feedback").json() == []
    with transaction(services.sessions) as s:
        actions = s.scalars(select(AuditRecord.action).where(AuditRecord.object_type == "feedback")).all()
    assert actions == ["feedback", "feedback_status", "feedback_delete"]


def _analyses(alice, services, n):
    created = _submit(alice, services, _invoices(n))
    batch = alice.get("/api/v1/batches/%d" % created["batch_id"]).json()
    return [m["analysis_id"] for m in batch["messages"]]


def test_each_person_answers_once_per_analysis_and_can_change_it(alice, bob, admin, services):
    analysis = _analyses(alice, services, 2)[0]
    url = "/api/v1/analyses/%d/feedback" % analysis
    assert alice.put(url, json={"opinion": "right"}).status_code == 200
    changed = alice.put(url, json={"opinion": "false_alarm", "note": "Our own newsletter."})
    assert changed.status_code == 200
    assert (changed.json()["opinion"], changed.json()["note"]) == ("false_alarm", "Our own newsletter.")
    assert bob.put(url, json={"opinion": "missed"}).status_code == 200
    seen = alice.get(url).json()
    assert seen["counts"] == {"right": 0, "missed": 1, "false_alarm": 1}
    assert seen["mine"]["opinion"] == "false_alarm"
    assert sorted((a["username"], a["opinion"]) for a in seen["answers"]) == [("alice", "false_alarm"),
                                                                              ("bob", "missed")]
    for body, field in (({"opinion": "maybe"}, "opinion"), ({"opinion": "right", "note": "x" * 1001}, "note"),
                        ({"opinion": "right", "note": "a\x00b"}, "note")):
        refused = alice.put(url, json=body)
        assert refused.status_code == 422 and refused.json()["detail"].startswith(field + ": "), body
    bobs = next(a["id"] for a in seen["answers"] if a["username"] == "bob")
    assert alice.delete("%s/%d" % (url, bobs)).status_code == 403  # an analyst removes only their own
    assert alice.delete(url).status_code == 204
    assert admin.delete("%s/%d" % (url, bobs)).status_code == 204  # an admin removes anyone's
    nothing = {"mine": None, "answers": [], "counts": {"right": 0, "missed": 0, "false_alarm": 0}}
    assert alice.get(url).json() == nothing
    with transaction(services.sessions) as s:
        actions = s.scalars(select(AuditRecord.action).where(AuditRecord.object_type == "analysis",
                                                             AuditRecord.action.like("verdict%"))).all()
    assert actions == ["verdict_feedback"] * 3 + ["verdict_feedback_delete"] * 2


def test_the_queue_shows_the_analyses_someone_disputes(alice, bob, services):
    first, second = _analyses(alice, services, 2)
    alice.put("/api/v1/analyses/%d/feedback" % first, json={"opinion": "right"})
    bob.put("/api/v1/analyses/%d/feedback" % second, json={"opinion": "missed"})
    assert [a["id"] for a in alice.get("/api/v1/analyses", params={"disputed": "true"}).json()] == [second]
    assert len(alice.get("/api/v1/analyses").json()) == 2


def test_admins_see_a_summary_and_the_owner_downloads_every_workspaces_disputed_verdicts(
        alice, admin, beta, services):  # noqa: F811
    first, second = _analyses(alice, services, 2)
    alice.put("/api/v1/analyses/%d/feedback" % first, json={"opinion": "right"})
    alice.put("/api/v1/analyses/%d/feedback" % second, json={"opinion": "false_alarm", "note": "Invoice run"})
    theirs = _submit(beta, services, [_invoices(1)[0].replace(b"Invoice 0", b"Beta invoice")])
    theirs_id = beta.get("/api/v1/submissions/%d" % theirs["id"]).json()["analysis_id"]
    beta.put("/api/v1/analyses/%d/feedback" % theirs_id, json={"opinion": "missed"})

    assert alice.get("/api/v1/feedback/verdicts").status_code == 403  # admins only
    summary = admin.get("/api/v1/feedback/verdicts").json()
    assert summary["counts"] == {"right": 1, "missed": 0, "false_alarm": 1}
    assert [(d["analysis_id"], d["false_alarm"], d["missed"]) for d in summary["disputed"]] == [(second, 1, 0)]
    assert [d["analysis_id"] for d in beta.get("/api/v1/feedback/verdicts").json()["disputed"]] == [theirs_id]

    assert beta.get("/api/v1/feedback/verdicts", params={"format": "csv"}).status_code == 403  # the owner's only
    download = admin.get("/api/v1/feedback/verdicts", params={"format": "csv"})
    assert download.status_code == 200 and download.headers["content-type"].startswith("text/csv")
    assert "attachment" in download.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(download.text)))
    assert sorted(int(r["analysis_id"]) for r in rows) == sorted([second, theirs_id])  # every workspace's
    assert set(rows[0]) == {"workspace_id", "analysis_id", "report_id", "sha256", "verdict", "score", "right",
                            "missed", "false_alarm", "last_answer_at"}
    for text in ("Invoice", "Beta invoice", "Invoice run", "alice"):  # no message, no note, no person
        assert text not in download.text
