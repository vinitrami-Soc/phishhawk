"""Batches: several files, an .mbox or a .zip become one batch with one submission and one analysis per
message, split in memory within limits; names inside an archive are never used (spec 6.2)."""

import io
import json
import mailbox
import zipfile

import pytest

from phishhawk.server import batches, worker
from phishhawk.server.security import REPORT_CSP

from conftest import build_eml, sample

MB = 1024 * 1024
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _raw(name="sample_phish.eml"):
    with open(sample(name), "rb") as handle:
        return handle.read()


def _mails(n):
    return [build_eml(subject="Message %d" % i, sender="<s%d@sender%d.example>" % (i, i)) for i in range(n)]


def _mbox(messages, eol=b"\n"):
    return b"".join(b"From sender@example.com Mon Oct  5 09:00:00 2026" + eol + m.replace(b"\r\n", eol) + eol
                    for m in messages)


def _zip(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _split(files, max_messages=500, max_message=25 * MB, max_total=100 * MB):
    return batches.split(files, max_messages=max_messages, max_message_bytes=max_message, max_total=max_total)


MBOXES = [
    _mbox(_mails(3)),
    b"junk before the first message\n" + _mbox(_mails(2)),  # ignored, as Python's mailbox module does
    _mbox(_mails(2)).rstrip(b"\n"),  # no newline at the end
    _mbox(_mails(2), eol=b"\r\n"),
    b"From a@b Mon Oct  5 09:00:00 2026\nFrom c@d Mon Oct  5 09:00:00 2026\nSubject: x\n\nbody\n",
    _mbox([b"Subject: quoted\n\nA line\n>From the start of a line, quoted\n"]),
]


@pytest.mark.parametrize("data", MBOXES)
def test_an_mbox_splits_as_pythons_mailbox_module_reads_it(tmp_path, data):
    """The CLI reads an .mbox with Python's mailbox module: the same bytes, so the same hashes and verdicts."""
    path = tmp_path / "box.mbox"
    path.write_bytes(data)
    box = mailbox.mbox(str(path), create=False)
    assert batches.mbox_messages(data) == [box.get_bytes(key) for key in box.iterkeys()]


def test_a_zip_gives_its_messages_and_never_uses_their_names():
    eml, msg = _raw(), OLE + b"\x00" * 512
    data = _zip([("../../etc/evil.eml", eml), ("deep/dir/report.msg", msg), ("notes.txt", b"not a message"),
                 ("inner.zip", _zip([("x.eml", eml)])), ("export.mbox", _mbox(_mails(2)))])
    split = _split([data])
    assert split.messages == [eml, msg] + batches.mbox_messages(_mbox(_mails(2)))
    assert split.skipped == 2  # the text file and the archive inside the archive


def test_several_files_and_plain_messages():
    first, second = _mails(2)
    assert _split([first, _mbox([second])]).messages == [first, second.replace(b"\r\n", b"\n")]


def test_an_archive_bomb_is_refused_before_it_is_inflated():
    bomb = _zip([("big.eml", b"Subject: x\n\n" + b"\0" * (64 * MB))])
    assert len(bomb) < MB
    with pytest.raises(batches.BatchError) as refused:
        _split([bomb], max_message=MB)
    assert refused.value.status == 413 and "larger than 1 MB" in str(refused.value)


def test_an_archive_of_countless_entries_is_refused_before_it_is_read():
    with pytest.raises(batches.BatchError) as refused:
        _split([_zip([("%d.txt" % i, b"") for i in range(2000)])], max_messages=500)
    assert refused.value.status == 413


@pytest.mark.parametrize("limits, files, words", [
    ({"max_messages": 3}, [_mbox(_mails(4))], "4 messages: the limit is 3"),
    ({"max_message": 1000}, [_raw()], "larger than 0 MB"),
    ({"max_total": 600}, _mails(5), "larger than 0 MB in all"),  # each is under 200 bytes
])
def test_the_limits(limits, files, words):
    with pytest.raises(batches.BatchError) as refused:
        _split(files, **limits)
    assert refused.value.status == 413 and words in str(refused.value)


@pytest.mark.parametrize("files", [[b"just some text"], [_zip([("a.txt", b"text")])], [b""]])
def test_an_upload_without_a_message_is_refused(files):
    with pytest.raises(batches.BatchError) as refused:
        _split(files)
    assert refused.value.status in (400, 415)


def _post(client, *files, url="/api/v1/submissions", **data):
    uploads = [("files", (name, content, "application/octet-stream")) for name, content in files]
    return client.post(url, files=uploads, data={"offline": "true", **data}, follow_redirects=False)


def test_several_files_become_one_batch_analysed_message_by_message(alice, services):
    sent = _mails(3)
    answer = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(sent)])
    assert answer.status_code == 202, answer.text
    created = answer.json()
    assert created["total"] == 3 and len(created["submission_ids"]) == 3 and created["skipped"] == 0
    batch = alice.get("/api/v1/batches/%d" % created["batch_id"]).json()
    assert batch["total"] == 3 and batch["counts"]["queued"] == 3 and batch["submitted_by_name"] == "alice"
    assert [m["position"] for m in batch["messages"]] == [1, 2, 3]
    for _ in sent:
        assert worker.run_one(services)
    batch = alice.get("/api/v1/batches/%d" % created["batch_id"]).json()
    assert batch["counts"]["done"] == 3 and all(m["analysis_id"] and m["verdict"] for m in batch["messages"])
    first = alice.get("/api/v1/analyses/%d" % batch["messages"][0]["analysis_id"]).json()
    assert first["source"] == "batch" and first["subject"] == "Message 0"


def test_an_mbox_upload_keeps_its_order(alice, services):
    created = _post(alice, ("reported.mbox", _mbox(_mails(3)))).json()
    rows = alice.get("/api/v1/batches/%d" % created["batch_id"]).json()["messages"]
    assert [r["submission_id"] for r in rows] == created["submission_ids"]


def test_one_message_is_not_a_batch(alice):
    answer = _post(alice, ("one.eml", _raw()))
    assert answer.status_code == 202 and answer.json()["batch_id"] is None and answer.json()["status"] == "queued"


def test_a_batch_over_the_limit_is_refused_with_the_reason(alice, admin):
    admin.patch("/api/v1/settings", json={"max_batch_messages": 2})
    answer = _post(alice, ("box.mbox", _mbox(_mails(3))))
    assert answer.status_code == 413 and answer.json()["detail"] == "3 messages: the limit is 2"


def test_the_home_page_takes_several_files_and_opens_the_batch_page(alice, services):
    page = _post(alice, ("a.eml", _mails(1)[0]), ("b.mbox", _mbox(_mails(2))), url="/",
                 csrf_token=alice.headers["X-CSRF-Token"])
    assert page.status_code == 303 and page.headers["location"].startswith("/batches/")
    batch = alice.get(page.headers["location"])
    assert batch.status_code == 200 and "3 messages" in batch.text and 'http-equiv="refresh"' in batch.text
    for _ in range(3):
        worker.run_one(services)
    batch = alice.get(page.headers["location"])
    assert batch.text.count("/analyses/") == 3


def test_every_entry_of_an_mbox_is_a_message_as_the_cli_reads_it(alice):
    """An mbox says where each message starts; one that looks odd is still analysed, as the CLI does."""
    odd = b"this entry has no header lines at all\n"
    created = _post(alice, ("box.mbox", _mbox([_mails(1)[0], odd]))).json()
    assert created["total"] == 2


def _run_all(services):
    while worker.run_one(services):
        pass


def _batch(client, batch_id):
    return client.get("/api/v1/batches/%d" % batch_id).json()


def test_when_every_message_is_done_the_batch_gets_combined_exports(alice, services):
    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(2) + [_raw()])]).json()
    _run_all(services)
    batch = _batch(alice, created["batch_id"])
    assert batch["status"] == "done" and batch["finished_at"]
    assert [f["kind"] for f in batch["files"]] == ["json", "stix", "misp", "md", "csv", "html", "manifest"]
    names = {f["kind"]: f["name"] for f in batch["files"]}
    url = "/api/v1/batches/%d/files/" % created["batch_id"]
    assert len(json.loads(alice.get(url + names["manifest"]).content)["messages"]) == 3
    assert len(json.loads(alice.get(url + names["json"]).content)["reports"]) == 3
    report = alice.get(url + names["html"])
    assert report.status_code == 200 and report.headers["content-security-policy"] == REPORT_CSP
    csv = alice.get(url + names["csv"])
    assert csv.headers["content-disposition"] == 'attachment; filename="%s"' % names["csv"]
    assert alice.get(url + "nothing.html").status_code == 404
    page = alice.get("/batches/%d" % created["batch_id"]).text
    assert page.count('href="/batches/%d/files/' % created["batch_id"]) == 7 and "http-equiv" not in page


def test_a_message_deleted_before_its_analysis_does_not_stop_the_batch(alice, services):
    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(3))]).json()
    second = _batch(alice, created["batch_id"])["messages"][1]["message_id"]
    assert alice.delete("/api/v1/messages/%d" % second).status_code == 200
    _run_all(services)
    batch = _batch(alice, created["batch_id"])
    assert batch["status"] == "done" and batch["counts"] == {"queued": 0, "running": 0, "done": 2, "failed": 1}
    manifest = next(f for f in batch["files"] if f["kind"] == "manifest")
    listed = alice.get("/api/v1/batches/%d/files/%s" % (created["batch_id"], manifest["name"])).json()
    assert len(listed["messages"]) == 2


def test_deleting_a_message_deletes_the_combined_exports_that_hold_it(alice, services):
    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(2))]).json()
    _run_all(services)
    first = _batch(alice, created["batch_id"])["messages"][0]["message_id"]
    alice.delete("/api/v1/messages/%d" % first)
    batch = _batch(alice, created["batch_id"])
    assert batch["files_deleted_at"] and not any(f["available"] for f in batch["files"])
    name = batch["files"][0]["name"]
    assert alice.get("/api/v1/batches/%d/files/%s" % (created["batch_id"], name)).status_code == 410


def test_combined_exports_are_deleted_after_the_retention_period(alice, services):
    from phishhawk.server import retention
    from phishhawk.server.db import transaction
    from phishhawk.server.models import Batch, Message

    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(2))]).json()
    _run_all(services)
    with transaction(services.sessions) as s:
        batch = s.get(Batch, created["batch_id"])
        batch.created_at = batch.created_at.replace(year=2000)
        for message in s.query(Message):
            message.hold = True  # the messages stay; the combined exports still go
    with transaction(services.sessions) as s:
        retention.sweep(s, services.store, days=30)
    assert _batch(alice, created["batch_id"])["files_deleted_at"]


def test_a_crash_while_analysing_fails_that_message_and_the_batch_still_finishes(alice, services, monkeypatch):
    real, calls = worker.process_submission, []

    def crashes_once(*args):
        calls.append(args)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return real(*args)

    monkeypatch.setattr(worker, "process_submission", crashes_once)
    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(2))]).json()
    _run_all(services)
    batch = _batch(alice, created["batch_id"])
    assert batch["status"] == "done" and batch["messages"][0]["status"] == "failed"
    assert batch["messages"][0]["error"] == "the analysis stopped: RuntimeError"


def test_a_message_whose_worker_died_three_times_fails_and_the_batch_still_finishes(alice, services):
    import datetime as dt

    from phishhawk.server import jobs
    from phishhawk.server.db import transaction

    created = _post(alice, *[("m%d.eml" % i, m) for i, m in enumerate(_mails(2))]).json()
    with transaction(services.sessions) as s:
        job = jobs.claim(s)
        job.attempts, job.heartbeat_at = jobs.MAX_ATTEMPTS, job.heartbeat_at - dt.timedelta(minutes=5)
    worker.schedule(services)
    _run_all(services)
    batch = _batch(alice, created["batch_id"])
    assert batch["status"] == "done" and batch["messages"][0]["status"] == "failed"
