"""Mailbox sweep: find the other copies of a reported message, read-only.

The HTTP layer is faked (see test_mailapi); the contract that matters: only
GET requests, the token only in the Authorization header and only to the
API's own host, and every value an attacker wrote is treated as data."""

import json

import pytest
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
            Response(payload={"value": [{"id": "sent-1", "toRecipients": [
                {"emailAddress": {"address": "alerts@m1crosoft-security.top"}}]}]}),
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
        (base + "/threads/t1", (("format", "metadata"),)):
            Response(payload={"messages": [{"id": "m1", "labelIds": ["SPAM"]},
                                           {"id": "m2", "labelIds": ["SENT"], "payload": {"headers": [
                                               {"name": "To", "value": "alerts@m1crosoft-security.top"}]}}]}),
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


# ------------------------------------------------- 2.2 independent review --

def test_a_platform_customer_is_searched_by_host_never_by_the_platform():
    shop = build_eml(subject="Your order is on hold", sender="<orders@evil-store.myshopify.com>",
                     text="Pay now: https://evil-store.myshopify.com/pay and https://pay.x.co.com/now")
    c = sweep.criteria_from(triage_bytes(shop, "r.eml"))
    assert "myshopify.com" not in c.domains and "co.com" not in c.domains
    assert "evil-store.myshopify.com" in c.domains


def test_graph_domain_hits_must_name_the_domain_itself():
    base = GRAPH + "/users/alice@corp.example"

    def item(i, body):
        message = _graph_message(i, conversation="c%d" % i)
        message["internetMessageId"] = "<other.%d@corp.example>" % i
        message["from"] = {"emailAddress": {"address": "someone@corp.example"}}
        message["subject"] = "Unrelated %d" % i
        message["body"] = {"content": body}
        return message
    bodies = ["<a href='https://login.evil.example/x'>go</a>", "visit notevil.example today",
              "evil.example.attacker.net is not it", "EVIL.EXAMPLE in capitals"]
    routes = {(base + "/messages", (("$search", '"body:evil.example"'),)):
              Response(payload={"value": [item(i, b) for i, b in enumerate(bodies)]})}
    routes.update(_empty_search(base))
    criteria = sweep.Criteria(domains=["evil.example"])
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], criteria, session=Api(routes))
    assert sorted(m["subject"] for m in box["matches"]) == ["Unrelated 0", "Unrelated 3"]


def test_one_failing_search_keeps_the_rest_of_the_mailbox():
    base = GRAPH + "/users/alice@corp.example"
    routes = {(base + "/messages", (("$search", '"Unusual sign-in activity on your account"'),)):
              Response(400, {"error": {"code": "BadRequest"}})}
    routes.update(_graph_routes(base))
    routes.update(_empty_search(base))
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=Api(routes))
    assert box["error"] == "" and len(box["matches"]) == 2
    assert any("subject" in warning and "BadRequest" in warning for warning in box["warnings"])


def test_a_gmail_copy_deleted_during_the_sweep_is_skipped_not_fatal():
    base = GMAIL + "/users/me"
    routes = _gmail_routes(base)
    routes[(base + "/messages", (("q", "in:anywhere from:alerts@m1crosoft-security.top"),))] = Response(
        payload={"messages": [{"id": "gone", "threadId": "t9"}, {"id": "m1", "threadId": "t1"}]})
    [box] = sweep.sweep_gmail("t0k3n", ["me"], _criteria(), session=Api(routes))
    assert [m["id"] for m in box["matches"]] == ["m1"] and box["error"] == ""


def test_a_forward_to_the_soc_is_not_a_reply_to_the_attacker():
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    sent = {"id": "s1", "toRecipients": [{"emailAddress": {"address": "soc@corp.example"}}], "ccRecipients": []}
    routes[(base + "/mailFolders/sentitems/messages", (("$filter", "conversationId eq 'conv-1'"),))] = Response(
        payload={"value": [sent]})
    routes.update(_empty_search(base))
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=Api(routes))
    assert [m["replied"] for m in box["matches"]] == [False, False]


def test_a_reply_to_the_attackers_reply_to_address_counts():
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    hit = _graph_message(1)
    hit["replyTo"] = [{"emailAddress": {"address": "collect@payout-desk.top"}}]
    routes[(base + "/messages", (("$search", '"from:alerts@m1crosoft-security.top"'),))] = Response(
        payload={"value": [hit]})
    sent = {"id": "s1", "toRecipients": [{"emailAddress": {"address": "Collect@Payout-Desk.top"}}]}
    routes[(base + "/mailFolders/sentitems/messages", (("$filter", "conversationId eq 'conv-1'"),))] = Response(
        payload={"value": [sent]})
    routes.update(_empty_search(base))
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=Api(routes))
    assert box["matches"][0]["replied"] is True


def test_gmail_replies_are_judged_by_who_they_went_to():
    base = GMAIL + "/users/me"
    routes = _gmail_routes(base)
    thread = {"messages": [{"id": "m1", "labelIds": ["SPAM"]},
                           {"id": "m2", "labelIds": ["SENT"],
                            "payload": {"headers": [{"name": "To", "value": "SOC <soc@corp.example>"}]}}]}
    routes[(base + "/threads/t1", (("format", "metadata"),))] = Response(payload=thread)
    [box] = sweep.sweep_gmail("t0k3n", ["me"], _criteria(), session=Api(routes))
    assert box["matches"][0]["replied"] is False
    assert box["matches"][0]["from"] == "alerts@m1crosoft-security.top"  # the address, as Graph gives it


def test_gmail_domain_hits_say_they_were_not_checked_again():
    base = GMAIL + "/users/me"
    routes = {(base + "/messages", (("q", 'in:anywhere "m1crosoft-security.top"'),)): Response(
        payload={"messages": [{"id": "m1", "threadId": "t1"}]})}
    routes.update(_gmail_routes(base))
    [box] = sweep.sweep_gmail("t0k3n", ["me"], sweep.Criteria(domains=["m1crosoft-security.top"]),
                              session=Api(routes))
    assert box["matches"][0]["matched"] == ["domain m1crosoft-security.top (Gmail's search, not checked again)"]


def test_answers_of_the_wrong_shape_are_an_error_not_a_crash():
    base = GRAPH + "/users/alice@corp.example"
    odd = [{"value": 5}, {"value": [{"id": "x", "from": "a string", "body": 7, "receivedDateTime": 3}]},
           {"value": [{"id": "y", "from": {"emailAddress": "nope"}, "replyTo": "x"}]}]
    for payload in odd:
        routes = {(base + "/messages", ()): Response(payload=payload),
                  (base + "/mailFolders/sentitems/messages", ()): Response(payload={"value": "x"})}
        [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=Api(routes))
        assert isinstance(box["matches"], list)
    gbase = GMAIL + "/users/me"
    weird = {(gbase + "/messages", ()): Response(payload={"messages": [{"id": "m1"}]}),
             (gbase + "/messages/m1", ()): Response(payload={"payload": "x", "labelIds": "UNREAD",
                                                             "internalDate": "soon"})}
    [box] = sweep.sweep_gmail("t0k3n", ["me"], _criteria(), session=Api(weird))
    assert isinstance(box["matches"], list)


def test_graph_times_with_seven_fraction_digits_are_read():
    assert sweep._iso("2026-10-05T08:00:00.1234567Z") == "2026-10-05T08:00:00Z"
    assert sweep._iso("2026-10-05T08:00:00.5Z") == "2026-10-05T08:00:00Z"


def test_search_words_cannot_act_as_operators_and_lengths_are_capped():
    criteria = sweep.Criteria(subjects=["NOT a test OR x AND y " + "z" * 600], senders=["a" * 400 + "@x.example"])
    api = Api({(GRAPH + "/me/messages", ()): Response(payload={"value": []})})
    sweep.sweep_graph("t0k3n", ["me"], criteria, session=api)
    searches = [params["$search"] for _, _, params, _ in api.calls if "$search" in params]
    assert searches and all(" OR " not in s and " AND " not in s and "NOT " not in s for s in searches)
    assert all(len(s) <= sweep.MAX_TERM + 10 for s in searches)


def test_lookups_past_the_cap_are_said_not_dropped_silently(monkeypatch):
    monkeypatch.setattr(sweep, "MAX_LOOKUPS", 1)
    base = GRAPH + "/users/alice@corp.example"
    routes = _graph_routes(base)
    routes.update(_empty_search(base))
    [box] = sweep.sweep_graph("t0k3n", ["alice@corp.example"], _criteria(), session=Api(routes))
    assert any("folder" in w and "first 1" in w for w in box["warnings"])


def test_an_incomplete_sweep_exits_3(monkeypatch, tmp_path, capsys):
    base = GRAPH + "/users/alice@corp.example"
    routes = {(base + "/messages", (("$search", '"from:x@evil.example"'),)): Response(429, {})}
    routes.update(_empty_search(base))
    monkeypatch.setattr(requests, "Session", lambda: Api(routes))
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    assert main(["sweep", "graph", "--from", "x@evil.example", "--mailbox", "alice@corp.example",
                 "--no-color"]) == 3
    assert "throttling" in capsys.readouterr().out


def test_a_partly_failed_mailbox_is_shown_and_exits_3(monkeypatch, tmp_path, capsys):
    reported = tmp_path / "reported.eml"
    reported.write_bytes(PHISH)
    base = GRAPH + "/users/alice@corp.example"
    routes = {(base + "/messages", (("$search", '"Unusual sign-in activity on your account"'),)):
              Response(429, {})}
    routes.update(_graph_routes(base))
    routes.update(_empty_search(base))
    monkeypatch.setattr(requests, "Session", lambda: Api(routes))
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    assert main(["sweep", "graph", "--like", str(reported), "--mailbox", "alice@corp.example", "--no-color"]) == 3
    out = capsys.readouterr().out
    assert "throttling" in out and "2 copies" in out


def test_too_many_mailboxes_are_refused_not_cut_silently(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sweep, "MAX_MAILBOXES", 2)
    boxes = tmp_path / "boxes.txt"
    boxes.write_text("a@corp.example\nb@corp.example\nc@corp.example\n")
    monkeypatch.setattr(requests, "Session", lambda: Api({}))
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    with pytest.raises(SystemExit):
        main(["sweep", "graph", "--from", "x@evil.example", "--mailboxes", str(boxes)])
    assert "at most 2 mailboxes" in capsys.readouterr().err
