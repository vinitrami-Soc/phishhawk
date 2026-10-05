"""Mailbox sweep: find the other copies of a reported message, read-only.

The HTTP layer is faked (see test_mailapi); the contract that matters: only
GET requests, the token only in the Authorization header and only to the
API's own host, and every value an attacker wrote is treated as data."""

import json

import requests

from phishhawk import sweep
from phishhawk.cli import main
from phishhawk.pipeline import triage_bytes
from test_mailapi import GMAIL, GRAPH, Api, Response

from conftest import build_eml

PHISH = build_eml(subject="Unusual sign-in activity on your account",
                  sender='"Security" <alerts@m1crosoft-security.top>',
                  text="Verify your account now: https://login.m1crosoft-security.top/verify and "
                       "https://www.microsoft.com/privacy",
                  headers=[("Message-ID", "<abc.123@m1crosoft-security.top>"),
                           ("Reply-To", "<collect@payout-desk.top>")])


def _criteria():
    return sweep.criteria_from(triage_bytes(PHISH, "reported.eml"))


def test_criteria_come_from_the_reported_message_but_not_from_trusted_names():
    c = _criteria()
    assert c.senders == ["alerts@m1crosoft-security.top", "collect@payout-desk.top"]
    assert c.subjects == ["Unusual sign-in activity on your account"]
    assert c.domains == ["m1crosoft-security.top"]  # microsoft.com is the brand's own: never swept for
    assert c.message_ids == ["<abc.123@m1crosoft-security.top>"]


def _graph_message(i, conversation="conv-1", folder="f-inbox", read=False, subject=None,
                   sender="alerts@m1crosoft-security.top", when="2026-10-05T08:00:00Z"):
    return {"id": "AAMk%d" % i, "subject": subject or "Unusual sign-in activity on your account",
            "from": {"emailAddress": {"name": "Security", "address": sender}},
            "receivedDateTime": when, "isRead": read, "conversationId": conversation,
            "internetMessageId": "<abc.123@m1crosoft-security.top>", "parentFolderId": folder}


def _graph_routes(base):
    found = Response(payload={"value": [_graph_message(1), _graph_message(2, "conv-2", "f-junk", read=True)]})
    return {
        (base + "/messages", (("$search", '"from:alerts@m1crosoft-security.top"'),)): found,
        (base + "/messages", (("$filter", "internetMessageId eq '<abc.123@m1crosoft-security.top>'"),)):
            Response(payload={"value": [_graph_message(1)]}),
        (base + "/mailFolders/f-inbox", ()): Response(payload={"id": "f-inbox", "displayName": "Inbox"}),
        (base + "/mailFolders/f-junk", ()): Response(payload={"id": "f-junk", "displayName": "Junk Email"}),
        (base + "/mailFolders/sentitems/messages", (("$filter", "conversationId eq 'conv-1'"),)):
            Response(payload={"value": [{"id": "sent-1"}]}),
        (base + "/mailFolders/sentitems/messages", (("$filter", "conversationId eq 'conv-2'"),)):
            Response(payload={"value": []}),
    }


def _empty_search(base):
    return {(base + "/messages", ()): Response(payload={"value": []})}


def test_graph_finds_copies_with_folder_read_state_and_replies():
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    routes.update(_empty_search(base))
    api = Api(routes)
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=api)
    assert box["error"] == ""
    first, second = box["matches"]
    assert (first["folder"], first["read"], first["replied"]) == ("Inbox", False, True)
    assert (second["folder"], second["read"], second["replied"]) == ("Junk Email", True, False)
    assert first["matched"] == ["message-id <abc.123@m1crosoft-security.top>",
                                "sender alerts@m1crosoft-security.top"]
    assert {method for method, *_ in api.calls} == {"GET"}
    assert all(url.startswith(GRAPH + "/") and headers == {"Authorization": "Bearer t0k3n"}
               for _, url, _, headers in api.calls)


def test_graph_checks_what_its_free_text_search_returned():
    base = GRAPH + "/users/bob@corp.example"
    other = _graph_message(9, subject="Lunch on Friday", sender="friend@corp.example")
    other["internetMessageId"] = "<lunch.1@corp.example>"
    routes = {(base + "/messages", ()): Response(payload={"value": [other]})}
    [box] = sweep.sweep_graph("t0k3n", ["bob@corp.example"], _criteria(), session=Api(routes))
    assert box["matches"] == []  # a search hit that is not from the sender nor has the subject is dropped


def test_graph_never_follows_a_next_link_off_graph():
    base = GRAPH + "/users/carol@corp.example"
    page = {"value": [_graph_message(1)], "@odata.nextLink": "https://evil.example/steal?page=2"}
    routes = {(base + "/messages", ()): Response(payload=page),
              (base + "/mailFolders/f-inbox", ()): Response(payload={"displayName": "Inbox"}),
              (base + "/mailFolders/sentitems/messages", ()): Response(payload={"value": []})}
    api = Api(routes)
    sweep.sweep_graph("t0k3n", ["carol@corp.example"], _criteria(), session=api)
    assert not any("evil.example" in url for _, url, *_ in api.calls)


def test_one_refused_mailbox_does_not_stop_the_sweep():
    good = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(good)
    routes.update(_empty_search(good))
    routes[(GRAPH + "/users/locked@corp.example/messages", ())] = Response(
        403, {"error": {"code": "ErrorAccessDenied"}})
    boxes = sweep.sweep_graph("t0k3n", ["locked@corp.example", "alice@corp.example"], _criteria(),
                              session=Api(routes))
    assert "Mail.Read" in boxes[0]["error"] and boxes[0]["matches"] == []
    assert len(boxes[1]["matches"]) == 2


def test_graph_search_values_cannot_break_out_of_their_quotes():
    criteria = sweep.Criteria(senders=['a"b@x.example'], subjects=['Pay "now" \\ OR from:boss'],
                              domains=[], message_ids=["<it's@x.example>"])
    api = Api({(GRAPH + "/me/messages", ()): Response(payload={"value": []})})
    sweep.sweep_graph("t0k3n", ["me"], criteria, session=api)
    searches = [params.get("$search") for _, _, params, _ in api.calls if "$search" in params]
    assert searches and all(s.count('"') == 2 and "\\" not in s for s in searches)
    filters = [params.get("$filter") for _, _, params, _ in api.calls if "$filter" in params]
    assert "internetMessageId eq '<it''s@x.example>'" in filters


def test_graph_drops_matches_before_since():
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    routes.update(_empty_search(base))
    import datetime as dt

    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), since=dt.date(2026, 10, 6),
                              session=Api(routes))
    assert box["matches"] == []


def _gmail_routes(base):
    meta = {"id": "m1", "threadId": "t1", "labelIds": ["SPAM"], "internalDate": "1759651200000",
            "payload": {"headers": [{"name": "From", "value": "Security <alerts@m1crosoft-security.top>"},
                                    {"name": "Subject", "value": "Unusual sign-in activity on your account"},
                                    {"name": "Message-ID", "value": "<abc.123@m1crosoft-security.top>"}]}}
    return {
        (base + "/messages", (("q", "in:anywhere from:alerts@m1crosoft-security.top"),)):
            Response(payload={"messages": [{"id": "m1", "threadId": "t1"}]}),
        (base + "/messages", ()): Response(payload={}),
        (base + "/messages/m1", (("format", "metadata"),)): Response(payload=meta),
        (base + "/threads/t1", (("format", "minimal"),)):
            Response(payload={"messages": [{"id": "m1", "labelIds": ["SPAM"]},
                                           {"id": "m2", "labelIds": ["SENT"]}]}),
    }


def test_gmail_searches_everywhere_and_reads_labels():
    base = GMAIL + "/users/me"
    api = Api(_gmail_routes(base))
    [box] = sweep.sweep_gmail("t0k3n", ["me"], _criteria(), session=api)
    [match] = box["matches"]
    assert (match["folder"], match["read"], match["replied"]) == ("Spam", True, True)
    assert match["received"] == "2025-10-05T08:00:00Z"
    queries = [params["q"] for _, url, params, _ in api.calls if url == base + "/messages"]
    assert all(q.startswith("in:anywhere ") for q in queries)
    assert 'in:anywhere subject:"Unusual sign-in activity on your account"' in queries
    assert {method for method, *_ in api.calls} == {"GET"}


def test_the_command_reads_the_token_from_the_environment_and_reports(monkeypatch, tmp_path, capsys):
    reported = tmp_path / "reported.eml"
    reported.write_bytes(PHISH)
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    routes.update(_empty_search(base))
    monkeypatch.setattr(requests, "Session", lambda: Api(routes))
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    out = tmp_path / "sweep.csv"
    code = main(["sweep", "graph", "--like", str(reported), "--mailbox", "alice@corp.example",
                 "--json", "-", "--csv", str(out), "--no-color"])
    assert code == 1  # copies were found
    payload = json.loads(capsys.readouterr().out)
    [box] = payload["mailboxes"]
    assert box["mailbox"] == "alice@corp.example" and len(box["matches"]) == 2
    assert "alerts@m1crosoft-security.top" in payload["criteria"]["senders"]
    assert out.read_text().splitlines()[0].startswith("mailbox,")


def test_the_command_needs_something_to_look_for(monkeypatch, capsys):
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    try:
        main(["sweep", "graph", "--mailbox", "a@corp.example"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "nothing to look for" in capsys.readouterr().err


def test_the_command_refuses_without_a_token(monkeypatch, capsys):
    monkeypatch.delenv("PHISHHAWK_GMAIL_TOKEN", raising=False)
    try:
        main(["sweep", "gmail", "--from", "x@evil.example", "--no-color"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "PHISHHAWK_GMAIL_TOKEN" in capsys.readouterr().err


def test_a_mailbox_list_file_is_read(monkeypatch, tmp_path, capsys):
    boxes = tmp_path / "boxes.txt"
    boxes.write_text("alice@corp.example\n\n# comment\nbob@corp.example\n")
    api = Api({})
    monkeypatch.setattr(requests, "Session", lambda: api)
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    assert main(["sweep", "graph", "--from", "x@evil.example", "--mailboxes", str(boxes), "--no-color"]) == 3
    swept = {url.split("/users/")[1].split("/")[0] for _, url, *_ in api.calls if "/users/" in url}
    assert swept == {"alice@corp.example", "bob@corp.example"}


class Endless(Api):
    """An API that keeps offering another empty page."""

    def get(self, url, params=None, stream=False, timeout=None, headers=None):
        self.calls.append(("GET", url, dict(params or {}), dict(headers or {})))
        if len(self.calls) > 500:
            raise AssertionError("still paging after 500 requests")
        if "gmail" in url:
            return Response(payload={"messages": [], "nextPageToken": "again"})
        return Response(payload={"value": [], "@odata.nextLink": url + "?page=again"})


def test_empty_pages_offered_for_ever_end_the_search():
    for search in (sweep.sweep_graph, sweep.sweep_gmail):
        api = Endless({})
        [box] = search("t0k3n", ["me"], sweep.Criteria(senders=["x@evil.example"]), session=api)
        assert len(api.calls) <= sweep.MAX_PAGES + 5


def test_the_triage_readers_stop_paging_too():
    from phishhawk import mailapi

    for fetch in (mailapi.fetch_graph, mailapi.fetch_gmail):
        api = Endless({})
        list(fetch(mailapi.ApiSource(token="t0k3n"), 1024, session=api))
        assert len(api.calls) <= mailapi.MAX_PAGES + 5


def test_a_mailbox_that_is_not_an_address_or_id_is_refused_unsent():
    api = Api({(GRAPH + "/users/alice@corp.example/messages", ()): Response(payload={"value": []})})
    criteria = sweep.Criteria(senders=["x@e.example"])
    boxes = sweep.sweep_graph("t0k3n", ["..", "a/b", "alice@corp.example"], criteria, session=api)
    assert [bool(box["error"]) for box in boxes] == [True, True, False]
    assert all("/users/alice@corp.example/" in url for _, url, *_ in api.calls)
