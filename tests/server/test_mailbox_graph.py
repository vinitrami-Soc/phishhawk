"""Mailbox import through Microsoft Graph (spec 6.3, 11 M3), against a fake Graph that allows only GET and one POST
for the token (fakehttp.py): a token per poll by the client-credentials flow, messages through a delta query, the
delta link as the cursor, and the same guarantees as IMAP."""

import datetime as dt
import secrets

import pytest
from sqlalchemy import select

from phishhawk.server import appsettings, mailbox, mailboxes
from phishhawk.server.db import transaction
from phishhawk.server.models import SERVER, AuditRecord, Mailbox, Submission

from .fakehttp import GRAPH, LOGIN, FakeGraph
from .serverkit import home
from .test_mailbox_imap import report
from .test_mailboxes import CLIENT, TENANT

ADDRESS = "phish@example-corp.co.uk"


@pytest.fixture
def graph():
    fake = FakeGraph(TENANT, CLIENT, secrets.token_urlsafe(30), ADDRESS)
    yield fake
    assert fake.violations == []  # GET to Graph and one POST to the token URL, nothing else


def _mailbox(services, fake, name="M365 reports", secret=None, **config):
    with transaction(services.sessions) as s:
        return mailboxes.create(s, services.box, {
            "name": name, "kind": "graph", "secret": secret or fake.secret,
            "config": {"tenant_id": TENANT, "client_id": CLIENT, "address": ADDRESS, **config}}, home(s)).id


def _state(services, mailbox_id):
    with transaction(services.sessions) as s:
        return mailboxes.view(s.get(Mailbox, mailbox_id)) | {"cursor": dict(s.get(Mailbox, mailbox_id).cursor)}


def test_messages_come_through_a_delta_query_and_the_delta_link_is_kept(services, graph):
    for number in range(3):
        graph.add(report(number))
    box = _mailbox(services, graph)
    assert mailbox.poll(services, box, session=graph) == {"imported": 3, "duplicates": 0, "skipped": 0}
    posts = [call for call in graph.calls if call[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "%s/%s/oauth2/v2.0/token" % (LOGIN, TENANT)
    assert posts[0][4]["client_secret"] == graph.secret  # in the body, never in a URL
    assert not any(graph.secret in url for _, url, *_ in graph.calls)
    gets = [call for call in graph.calls if call[0] == "GET"]
    assert all(c[1].startswith(GRAPH + "/") and c[3]["Authorization"] == "Bearer " + graph.token for c in gets)
    assert gets[0][1] == "%s/users/%s/mailFolders/inbox/messages/delta" % (GRAPH, ADDRESS)
    cursor = _state(services, box)["cursor"]
    assert cursor["delta"].startswith(GRAPH + "/") and "$deltatoken=3" in cursor["delta"]

    graph.calls.clear()
    graph.add(report(3))
    assert mailbox.poll(services, box, session=graph)["imported"] == 1
    delta = [c[1] for c in graph.calls if c[0] == "GET" and "/delta" in c[1]]
    assert delta == [cursor["delta"]] and len(graph.downloads()) == 1
    with transaction(services.sessions) as s:
        assert [(sub.source, sub.mailbox_id) for sub in s.scalars(select(Submission))] == [("mailbox", box)] * 4


def test_a_named_folder_is_found_by_its_name(services, graph):
    graph.add(report(1), folder="Phish reports")
    box = _mailbox(services, graph, folder="Phish reports")
    assert mailbox.poll(services, box, session=graph)["imported"] == 1
    assert any("/mailFolders/AAMkPhishReports/messages/delta" in c[1] for c in graph.calls)


def test_the_first_poll_imports_the_newest_50(services, graph):
    numbers = {graph.add(report(number)): number for number in range(60)}
    box = _mailbox(services, graph)
    assert mailbox.poll(services, box, session=graph)["imported"] == 50
    assert sorted(numbers[i] for i in graph.downloads()) == list(range(10, 60))
    assert mailbox.poll(services, box, session=graph) == {"imported": 0, "duplicates": 0, "skipped": 0}


def test_more_than_a_poll_takes_waits_for_the_next_poll_without_downloading_twice(services, graph):
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)  # an empty folder: the cursor is set
    with transaction(services.sessions) as s:
        appsettings.set_value(s, SERVER, "max_batch_messages", 2)
    for number in range(5):
        graph.add(report(number))
    assert [mailbox.poll(services, box, session=graph)["imported"] for _ in range(4)] == [2, 2, 1, 0]
    assert len(graph.downloads()) == len(set(graph.downloads())) == 5


def test_removed_items_are_ignored(services, graph):
    kept = graph.add(report(1))
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)
    gone = graph.add(report(2))
    graph.remove(gone)
    graph.remove(kept)
    assert mailbox.poll(services, box, session=graph) == {"imported": 1, "duplicates": 0, "skipped": 0}
    assert graph.downloads() == [kept, gone]


def test_a_next_link_to_another_host_stops_the_paging(services, graph):
    graph.page_size, graph.next_link_host = 2, "https://graph.evil.example/v1.0"
    for number in range(3):
        graph.add(report(number))
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)
    state = _state(services, box)
    assert state["status"] == "error" and "another host" in state["error"]
    assert not any("evil" in url for _, url, *_ in graph.calls)  # the token went to Graph only
    assert graph.downloads() == []


def test_paging_follows_next_links_on_graph(services, graph):
    graph.page_size = 2
    for number in range(5):
        graph.add(report(number))
    assert mailbox.poll(services, _mailbox(services, graph), session=graph)["imported"] == 5


def test_an_expired_delta_link_starts_again_without_duplicates(services, graph):
    for number in range(3):
        graph.add(report(number))
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)
    graph.expired.add("3")
    graph.add(report(3))
    assert mailbox.poll(services, box, session=graph) == {"imported": 1, "duplicates": 0, "skipped": 0}
    assert "$deltatoken=4" in _state(services, box)["cursor"]["delta"]


def test_a_wrong_client_secret_is_refused_without_showing_it(services, graph):
    wrong = secrets.token_urlsafe(30)
    box = _mailbox(services, graph, secret=wrong)
    mailbox.poll(services, box, session=graph)
    state = _state(services, box)
    assert state["status"] == "error" and "sign-in refused (invalid_client)" in state["error"]
    assert "AADSTS" not in state["error"]  # Microsoft's own text is not shown
    with transaction(services.sessions) as s:
        audit = repr([r.details for r in s.scalars(select(AuditRecord))])
    assert wrong not in repr(state) + audit and graph.secret not in repr(state) + audit
    assert dt.datetime.fromisoformat(state["next_poll_at"]) > dt.datetime.fromisoformat(state["last_poll_at"])


def test_a_token_without_mail_read_says_so(services, graph):
    graph.status_for_messages = 403
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)
    assert "Mail.Read" in _state(services, box)["error"]


def test_throttling_backs_off(services, graph):
    graph.status_for_messages = 429
    box = _mailbox(services, graph)
    mailbox.poll(services, box, session=graph)
    state = _state(services, box)
    assert state["status"] == "error" and "throttling" in state["error"]
    assert dt.datetime.fromisoformat(state["next_poll_at"]) - dt.datetime.fromisoformat(
        state["last_poll_at"]) == dt.timedelta(minutes=10)


def test_the_double_refuses_anything_but_reads(graph):
    graph.patch(GRAPH + "/users/%s/messages/x" % ADDRESS, json={"isRead": True})
    graph.post(GRAPH + "/users/%s/messages/x/move" % ADDRESS, data={})
    graph.get("https://graph.evil.example/v1.0/users")
    assert len(graph.violations) == 3
    graph.violations.clear()


def test_a_reason_never_carries_a_credential_or_a_token():
    secret, token = secrets.token_urlsafe(20), secrets.token_urlsafe(20)
    reason = mailbox.sanitise("refused %s; sent Authorization: Bearer %s \x1b[2J‮" % (secret, token), [secret])
    assert secret not in reason and token not in reason and "\x1b" not in reason and "‮" not in reason
    assert len(mailbox.sanitise("x" * 5000, [])) == 300
