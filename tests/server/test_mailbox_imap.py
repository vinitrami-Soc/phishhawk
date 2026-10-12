"""Mailbox import over IMAP (spec 6.3, 11 M3), against a real IMAP server over TLS that answers only reads
(fakeimap.py): new messages become submissions, nothing is changed in the mailbox, a credential failure leaves a
sanitised reason and backs off, and no message is imported twice."""

import datetime as dt
import imaplib
import secrets
import ssl

import pytest
from sqlalchemy import select

from phishhawk.server import appsettings, intake, mailbox, mailboxes, worker
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditRecord, Job, Mailbox, MailboxItem, Submission, utcnow

from .fakeimap import FakeImapServer
from conftest import build_eml

USER = "soc@example-corp.co.uk"


def report(number, **headers):
    message_id = ("Message-ID", "<report-%d@mail.example-corp.co.uk>" % number)
    return build_eml(subject="Report %d" % number, sender="<user%d@staff.example-corp.co.uk>" % number,
                     text="Is this real? https://login.example-%d.top/verify" % number,
                     headers=[message_id, *headers.items()])


@pytest.fixture
def server(tmp_path, monkeypatch):
    password = secrets.token_hex(10)
    fake = FakeImapServer(tmp_path / "imap", USER, password)
    fake.password_for_tests = password
    monkeypatch.setenv("SSL_CERT_FILE", str(fake.ca_file))  # the client verifies the test CA as any other
    yield fake
    fake.close()
    assert fake.violations == []  # nothing but reads, in every test


def _mailbox(services, server, name="Reports", **config):
    with transaction(services.sessions) as s:
        made = mailboxes.create(s, services.box, {
            "name": name, "kind": "imap", "secret": config.pop("secret", server.password_for_tests),
            "config": {"host": "127.0.0.1", "port": server.port, "user": USER, **config}})
        return made.id


def _state(services, mailbox_id):
    with transaction(services.sessions) as s:
        return mailboxes.view(s.get(Mailbox, mailbox_id)) | {"cursor": dict(s.get(Mailbox, mailbox_id).cursor)}


def _submissions(services):
    with transaction(services.sessions) as s:
        return [(sub.source, sub.mailbox_id, sub.user_id) for sub in s.scalars(select(Submission))]


def test_the_first_poll_imports_the_newest_50_then_only_what_arrives(services, server):
    for number in range(60):
        server.add(report(number))
    box = _mailbox(services, server)
    assert mailbox.poll(services, box) == {"imported": 50, "duplicates": 0, "skipped": 0}
    assert _submissions(services) == [("mailbox", box, None)] * 50
    with transaction(services.sessions) as s:
        remote = sorted(int(i.remote_id.split(":")[1]) for i in s.scalars(select(MailboxItem)))
    assert remote == list(range(11, 61))  # the newest 50
    state = _state(services, box)
    assert (state["status"], state["error"], state["cursor"]) == ("ok", "", {"uidvalidity": 1, "uid": 60})
    assert state["last_counts"] == {"imported": 50, "duplicates": 0, "skipped": 0}

    server.add(report(60))
    server.add(report(61))
    assert mailbox.poll(services, box)["imported"] == 2
    assert len(_submissions(services)) == 52
    assert worker.run_one(services) and worker.run_one(services)  # analysed like uploads
    with transaction(services.sessions) as s:
        submitted = s.scalars(select(AuditRecord).where(AuditRecord.action == "submit")).all()
        assert {r.actor for r in submitted} == {"mailbox:Reports"} and len(submitted) == 52
        assert s.scalars(select(AuditRecord).where(AuditRecord.action == "analyze")).first() is not None
    assert all(c.split()[0] in ("CAPABILITY", "LOGIN", "EXAMINE", "UID", "LOGOUT") for c in server.commands)
    assert any(c.startswith("EXAMINE") for c in server.commands)


def test_a_wrong_password_leaves_a_sanitised_reason_and_backs_off(services, server):
    server.add(report(1))
    wrong = secrets.token_hex(10)
    box = _mailbox(services, server, secret=wrong)
    waits = []
    for _ in range(5):
        assert mailbox.poll(services, box) == {"imported": 0, "duplicates": 0, "skipped": 0}
        state = _state(services, box)
        assert state["status"] == "error" and "sign-in refused" in state["error"]
        waits.append(dt.datetime.fromisoformat(state["next_poll_at"]) - dt.datetime.fromisoformat(
            state["last_poll_at"]))
    assert [w.total_seconds() // 60 for w in waits] == [10, 20, 40, 60, 60]
    with transaction(services.sessions) as s:
        failed = s.scalars(select(AuditRecord).where(AuditRecord.action == "mailbox_poll_failed")).all()
        assert len(failed) == 5 and all("sign-in refused" in r.details["reason"] for r in failed)
        everything = repr([(r.details, r.object_id) for r in s.scalars(select(AuditRecord))])
        everything += repr([j.error for j in s.scalars(select(Job))])
    everything += repr(_state(services, box))
    assert wrong not in everything and server.password_for_tests not in everything

    with transaction(services.sessions) as s:  # the right password: the next poll works and the backoff ends
        mailboxes.update(s, services.box, s.get(Mailbox, box), {"secret": server.password_for_tests})
    assert mailbox.poll(services, box)["imported"] == 1
    state = _state(services, box)
    assert (state["status"], state["error"]) == ("ok", "")
    assert dt.datetime.fromisoformat(state["next_poll_at"]) - dt.datetime.fromisoformat(
        state["last_poll_at"]) == dt.timedelta(minutes=5)


def test_two_polls_in_a_row_import_nothing_twice(services, server):
    for number in range(3):
        server.add(report(number))
    box = _mailbox(services, server)
    assert mailbox.poll(services, box)["imported"] == 3
    assert mailbox.poll(services, box) == {"imported": 0, "duplicates": 0, "skipped": 0}


def test_a_new_uidvalidity_starts_again_without_importing_twice(services, server):
    for number in range(3):
        server.add(report(number))
    box = _mailbox(services, server)
    mailbox.poll(services, box)
    server.renumber()
    assert mailbox.poll(services, box) == {"imported": 0, "duplicates": 3, "skipped": 0}
    assert _state(services, box)["cursor"]["uidvalidity"] == 2


def test_the_same_message_in_two_mailboxes_is_imported_once(services, server):
    server.add(report(1))
    server.add(report(1), folder="Phish reports")
    first, second = _mailbox(services, server), _mailbox(services, server, "Other", folder="Phish reports")
    assert mailbox.poll(services, first)["imported"] == 1
    assert mailbox.poll(services, second) == {"imported": 0, "duplicates": 1, "skipped": 0}


def test_a_message_uploaded_before_is_not_imported(services, server):
    with transaction(services.sessions) as s:
        intake.accept(s, services.store, report(1), source="upload", user_id=None, actor="alice", offline=True,
                      max_bytes=25 * 1024 * 1024)
    server.add(report(1))
    assert mailbox.poll(services, _mailbox(services, server)) == {"imported": 0, "duplicates": 1, "skipped": 0}


def test_the_same_message_id_with_other_bytes_is_imported_once(services, server):
    server.add(report(1))
    box = _mailbox(services, server)
    mailbox.poll(services, box)
    server.add(b"Received: from relay.example-corp.co.uk\r\n" + report(1))  # delivered again, one more header
    assert mailbox.poll(services, box) == {"imported": 0, "duplicates": 1, "skipped": 0}


def test_a_message_over_the_limit_is_skipped_and_counted(services, server):
    with transaction(services.sessions) as s:
        appsettings.set_value(s, "max_upload_mb", 1)
    server.add(build_eml(subject="Large", text="x" * (2 * 1024 * 1024)))
    server.add(report(1))
    box = _mailbox(services, server)
    assert mailbox.poll(services, box) == {"imported": 1, "duplicates": 0, "skipped": 1}
    assert _state(services, box)["status"] == "ok"
    assert mailbox.poll(services, box) == {"imported": 0, "duplicates": 0, "skipped": 0}  # skipped for good


def test_a_dropped_connection_keeps_the_cursor_at_the_last_message_handled(services, server):
    uids = [server.add(report(number)) for number in range(5)]
    box = _mailbox(services, server)
    server.drop_after_fetches = 2
    assert mailbox.poll(services, box)["imported"] == 2
    state = _state(services, box)
    assert state["status"] == "error" and state["cursor"]["uid"] == uids[1]
    server.drop_after_fetches = None
    assert mailbox.poll(services, box) == {"imported": 3, "duplicates": 0, "skipped": 0}


def test_starttls_on_port_143(services, tmp_path, monkeypatch):
    password = secrets.token_hex(10)
    fake = FakeImapServer(tmp_path / "starttls", USER, password, starttls=True)
    monkeypatch.setenv("SSL_CERT_FILE", str(fake.ca_file))
    fake.add(report(1))
    with transaction(services.sessions) as s:
        box = mailboxes.create(s, services.box, {
            "name": "Plain port", "kind": "imap", "secret": password,
            "config": {"host": "127.0.0.1", "port": fake.port, "starttls": True, "user": USER}}).id
    assert mailbox.poll(services, box)["imported"] == 1
    assert fake.commands[:2] == ["CAPABILITY", "STARTTLS"] and fake.violations == []
    fake.close()


def test_a_certificate_no_one_trusts_is_refused(services, server, tmp_path, monkeypatch):
    other = FakeImapServer(tmp_path / "other-ca", USER, "unused")  # its CA, not the server's
    monkeypatch.setenv("SSL_CERT_FILE", str(other.ca_file))
    server.add(report(1))
    box = _mailbox(services, server)
    mailbox.poll(services, box)
    state = _state(services, box)
    assert state["status"] == "error" and "certificate" in state["error"] and _submissions(services) == []
    other.close()


def test_a_missing_folder_is_an_error(services, server):
    box = _mailbox(services, server, folder="Nowhere")
    mailbox.poll(services, box)
    state = _state(services, box)
    assert state["status"] == "error" and "no folder 'Nowhere'" in state["error"]


def test_the_scheduler_polls_each_mailbox_when_it_is_due_and_once_at_a_time(services, server):
    server.add(report(1))
    box = _mailbox(services, server)
    off = _mailbox(services, server, "Switched off")
    with transaction(services.sessions) as s:
        s.get(Mailbox, off).enabled = False

    def polls():
        with transaction(services.sessions) as s:
            return [(j.payload["mailbox_id"], j.status) for j in s.scalars(select(Job).where(
                Job.kind == "mailbox_poll"))]

    worker.schedule(services)
    worker.schedule(services)
    assert polls() == [(box, "queued")]  # one, and never the disabled mailbox
    while worker.run_one(services):
        pass
    assert polls() == [(box, "done")] and _state(services, box)["last_counts"]["imported"] == 1
    worker.schedule(services)
    assert polls() == [(box, "done")]  # not due yet
    with transaction(services.sessions) as s:
        s.get(Mailbox, box).next_poll_at = utcnow() - dt.timedelta(seconds=1)
    worker.schedule(services)
    assert polls() == [(box, "done"), (box, "queued")]


def test_the_double_refuses_anything_but_reads(server):
    """The fake server itself: SELECT (read-write) and a FETCH that sets \\Seen are refused and recorded."""
    server.add(report(1))
    client = imaplib.IMAP4_SSL("127.0.0.1", server.port, ssl_context=ssl.create_default_context(), timeout=5)
    client.login(USER, server.password_for_tests)
    with pytest.raises(imaplib.IMAP4.error):
        client.select("INBOX")
    client.select('"INBOX"', readonly=True)
    with pytest.raises(imaplib.IMAP4.error):
        client.uid("FETCH", "1", "(BODY[])")
    client.logout()
    assert server.violations == ["SELECT", "UID FETCH (BODY[])"]
    server.violations.clear()  # seen; the fixture checks the rest


def test_the_queue_names_the_mailbox_and_filters_by_it(services, server, admin):
    server.add(report(1))
    mailbox.poll(services, _mailbox(services, server))
    while worker.run_one(services):
        pass
    [row] = admin.get("/api/v1/analyses?source=mailbox").json()
    assert (row["source"], row["submitted_by"], row["submitted_by_name"]) == ("mailbox", None, "Reports")
    assert admin.get("/api/v1/analyses/%d" % row["id"]).json()["submitted_by_name"] == "Reports"
    assert admin.get("/api/v1/analyses?source=upload").json() == []
    assert '<option value="mailbox">mailbox</option>' in admin.get("/queue").text
    assert "by Reports (mailbox)" in admin.get("/analyses/%d" % row["id"]).text


def test_a_credential_that_does_not_open_is_an_error_not_a_crash(services, server):
    """Copied from another row, or sealed under another key: the mailbox says so and backs off."""
    first, second = _mailbox(services, server), _mailbox(services, server, "Other")
    with transaction(services.sessions) as s:
        s.get(Mailbox, second).secret = s.get(Mailbox, first).secret
    assert mailbox.poll(services, second) == {"imported": 0, "duplicates": 0, "skipped": 0}
    state = _state(services, second)
    assert state["status"] == "error" and "cannot be opened" in state["error"]
    assert state["next_poll_at"] is not None


def test_a_real_server_and_worker_import_from_the_mailbox(server, tmp_path):
    """phishhawk server run as a process: Poll now queues a poll, its worker reads the mailbox over TLS and the
    messages are analysed."""
    import time

    import requests

    from .serverkit import PASSWORD, running_server

    server.add(report(1))
    server.add(report(2))
    (tmp_path / "server").mkdir()
    with running_server(tmp_path / "server") as running:
        web = requests.Session()
        session = web.post(running.base + "/api/v1/session", json={"username": "root", "password": PASSWORD})
        web.headers["X-CSRF-Token"] = session.json()["csrf"]
        made = web.post(running.base + "/api/v1/mailboxes", json={
            "name": "Reports", "kind": "imap", "secret": server.password_for_tests,
            "config": {"host": "127.0.0.1", "port": server.port, "user": USER}}).json()
        assert web.post(running.base + "/api/v1/mailboxes/%d/poll" % made["id"]).status_code == 202
        deadline = time.monotonic() + 90
        while len(web.get(running.base + "/api/v1/analyses?source=mailbox").json()) < 2:
            assert time.monotonic() < deadline, running.log.read_text("utf-8", "replace")
            time.sleep(0.5)
        state = web.get(running.base + "/api/v1/mailboxes/%d" % made["id"]).json()
        assert (state["status"], state["last_counts"]["imported"]) == ("ok", 2)
