"""2.1: reported mail read through Microsoft Graph and the Gmail API.

The HTTP layer is faked with the answers each API documents; everything
above it (paging, ordering, size limits, errors, the CLI) is the real code.
The contract that matters most: only GET requests, the token only ever in
the Authorization header and only ever sent to the API's own host."""

import base64
import datetime as dt
import json

import pytest
import requests

from phishhawk import mailapi
from phishhawk.cli import main

from conftest import build_eml

PHISH = build_eml(subject="Unusual sign-in", sender="<alerts@m1crosoft-security.top>",
                  text="Verify your account: https://m1crosoft-security.top/login")
LUNCH = build_eml(subject="Lunch", text="See you at noon")
GRAPH = "https://graph.microsoft.com/v1.0"
GMAIL = "https://gmail.googleapis.com/gmail/v1"


class Response:
    """What requests returns: a status, a JSON body or a streamed one."""

    def __init__(self, status=200, payload=None, body=b""):
        self.status_code, self._payload, self._body, self.closed = status, payload, body, False

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload

    def iter_content(self, size):
        for start in range(0, len(self._body), size):
            yield self._body[start:start + size]

    def close(self):
        self.closed = True


class Api:
    """A fake HTTP session answering from a {(url, frozen params): Response} table."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, params=None, stream=False, timeout=None, headers=None):
        self.calls.append(("GET", url, dict(params or {}), dict(headers or {})))
        for (route, wanted), response in self.routes.items():
            if route == url and all((params or {}).get(k) == v for k, v in wanted):
                return response
        return Response(404, {"error": {"code": "ErrorItemNotFound"}})

    def post(self, *args, **kwargs):  # never used: a read-only client has no reason to
        self.calls.append(("POST",) + args)
        raise AssertionError("POST sent")

    patch = delete = put = post


def graph_page(ids, next_link=None):
    page = {"@odata.context": GRAPH + "/$metadata#users('me')/mailFolders('inbox')/messages(id,receivedDateTime)",
            "value": [{"@odata.etag": 'W/"CQAAABYAAAB"', "id": i, "receivedDateTime": "2026-09-30T10:00:00Z"}
                      for i in ids]}
    if next_link:
        page["@odata.nextLink"] = next_link
    return Response(payload=page)


def source(**kw):
    return mailapi.ApiSource(token="t0k3n", **kw)


# ------------------------------------------------------------------- Graph --

def test_graph_reads_the_inbox_oldest_first_as_mime():
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): graph_page(["AAMk-new", "AAMk-old"]),
               (GRAPH + "/me/messages/AAMk-new/$value", ()): Response(body=PHISH),
               (GRAPH + "/me/messages/AAMk-old/$value", ()): Response(body=LUNCH)})
    got = list(mailapi.fetch_graph(source(), 1 << 20, session=api))
    assert [(message_id, data) for _, message_id, data in got] == [("AAMk-old", LUNCH), ("AAMk-new", PHISH)]


def test_graph_sends_only_gets_with_the_token_in_a_header():
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): graph_page(["A1"]),
               (GRAPH + "/me/messages/A1/$value", ()): Response(body=LUNCH)})
    list(mailapi.fetch_graph(source(), 1 << 20, session=api))
    assert {call[0] for call in api.calls} == {"GET"}
    assert all(call[3] == {"Authorization": "Bearer t0k3n"} for call in api.calls)
    assert not any("t0k3n" in call[1] or "t0k3n" in json.dumps(call[2]) for call in api.calls)


def test_graph_follows_next_links_but_never_off_graph():
    listing = GRAPH + "/me/mailFolders/inbox/messages"
    on_graph = listing + "?$skiptoken=page2"
    api = Api({(listing, (("$top", 3),)): graph_page(["A1"], next_link=on_graph),
               (on_graph, ()): graph_page(["A2"], next_link="https://evil.example/steal?$skiptoken=3"),
               (GRAPH + "/me/messages/A1/$value", ()): Response(body=LUNCH),
               (GRAPH + "/me/messages/A2/$value", ()): Response(body=LUNCH)})
    got = list(mailapi.fetch_graph(source(limit=3), 1 << 20, session=api))
    assert [message_id for _, message_id, _ in got] == ["A2", "A1"]
    assert not any("evil.example" in call[1] for call in api.calls)


def test_graph_finds_a_folder_by_name_inside_the_inbox():
    api = Api({(GRAPH + "/me/mailFolders", (("$filter", "displayName eq 'Phish reports'"),)):
               Response(payload={"value": []}),
               (GRAPH + "/me/mailFolders/inbox/childFolders", (("$filter", "displayName eq 'Phish reports'"),)):
               Response(payload={"value": [{"id": "AQMk-folder", "displayName": "Phish reports"}]}),
               (GRAPH + "/me/mailFolders/AQMk-folder/messages", ()): graph_page(["A1"]),
               (GRAPH + "/me/messages/A1/$value", ()): Response(body=PHISH)})
    got = list(mailapi.fetch_graph(source(folder="Phish reports"), 1 << 20, session=api))
    assert [data for _, _, data in got] == [PHISH]


def test_graph_quotes_a_folder_name_inside_the_filter():
    api = Api({})
    with pytest.raises(mailapi.MailApiError):
        list(mailapi.fetch_graph(source(folder="O'Brien's reports"), 1 << 20, session=api))
    assert api.calls[0][2]["$filter"] == "displayName eq 'O''Brien''s reports'"


def test_graph_filters_by_date_and_unread():
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): graph_page([])})
    list(mailapi.fetch_graph(source(since=dt.date(2026, 9, 1), unread=True), 1 << 20, session=api))
    assert api.calls[0][2]["$filter"] == "receivedDateTime ge 2026-09-01T00:00:00Z and isRead eq false"


def test_graph_skips_a_message_bigger_than_the_limit_without_cutting_it():
    big = Response(body=b"x" * 5000)
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): graph_page(["BIG", "OK"]),
               (GRAPH + "/me/messages/BIG/$value", ()): big,
               (GRAPH + "/me/messages/OK/$value", ()): Response(body=LUNCH)})
    got = {message_id: data for _, message_id, data in mailapi.fetch_graph(source(), 4096, session=api)}
    assert isinstance(got["BIG"], ValueError) and big.closed
    assert got["OK"] == LUNCH


def test_graph_names_the_missing_permission_when_the_token_is_refused():
    refused = Response(401, {"error": {"code": "InvalidAuthenticationToken"}})
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): refused})
    with pytest.raises(mailapi.MailApiError, match="Mail.Read"):
        list(mailapi.fetch_graph(source(), 1 << 20, session=api))


def test_graph_encodes_the_mailbox_and_message_ids_in_the_path():
    mailbox = GRAPH + "/users/soc@example.com"
    api = Api({(mailbox + "/mailFolders/inbox/messages", ()): graph_page(["AA/..?x=1#y"]),
               (mailbox + "/messages/AA%2F..%3Fx%3D1%23y/$value", ()): Response(body=LUNCH)})
    got = list(mailapi.fetch_graph(source(mailbox="soc@example.com"), 1 << 20, session=api))
    assert [data for _, _, data in got] == [LUNCH]


def test_messages_already_seen_are_not_read_again():
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): graph_page(["A2", "A1"]),
               (GRAPH + "/me/messages/A2/$value", ()): Response(body=LUNCH)})
    got = list(mailapi.fetch_graph(source(), 1 << 20, seen={"A1"}, session=api))
    assert [message_id for _, message_id, _ in got] == ["A2"]
    assert not any(call[1].endswith("/A1/$value") for call in api.calls)


# ------------------------------------------------------------------- Gmail --

def gmail_message(message_id, raw=None, size=None):
    body = {"id": message_id, "threadId": message_id, "labelIds": ["INBOX", "UNREAD"], "snippet": "",
            "sizeEstimate": size if size is not None else len(raw or b""), "historyId": "9",
            "internalDate": "1759225200000"}
    if raw is not None:
        body["raw"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return Response(payload=body)


@pytest.mark.parametrize("options, query", [
    ({}, "in:inbox"),
    ({"folder": "Phish reports"}, 'label:"Phish reports"'),
    ({"since": dt.date(2026, 9, 1), "unread": True, "query": "has:attachment"},
     "in:inbox after:2026/09/01 is:unread has:attachment"),
])
def test_gmail_search_terms(options, query):
    api = Api({(GMAIL + "/users/me/messages", ()): Response(payload={"resultSizeEstimate": 0})})
    list(mailapi.fetch_gmail(source(**options), 1 << 20, session=api))
    assert api.calls[0][2]["q"] == query


def test_gmail_reads_raw_messages_across_pages_oldest_first():
    listing = GMAIL + "/users/me/messages"
    api = Api({(listing, (("pageToken", "081"),)): Response(payload={"messages": [{"id": "m1", "threadId": "m1"}],
                                                                     "resultSizeEstimate": 2}),
               (listing, ()): Response(payload={"messages": [{"id": "m2", "threadId": "m2"}],
                                                "nextPageToken": "081", "resultSizeEstimate": 2}),
               (listing + "/m1", (("format", "minimal"),)): gmail_message("m1", size=len(PHISH)),
               (listing + "/m1", (("format", "raw"),)): gmail_message("m1", raw=PHISH),
               (listing + "/m2", (("format", "minimal"),)): gmail_message("m2", size=len(LUNCH)),
               (listing + "/m2", (("format", "raw"),)): gmail_message("m2", raw=LUNCH)})
    got = list(mailapi.fetch_gmail(source(), 1 << 20, session=api))
    assert [(message_id, data) for _, message_id, data in got] == [("m1", PHISH), ("m2", LUNCH)]
    assert {call[0] for call in api.calls} == {"GET"}


def test_gmail_checks_the_size_before_downloading():
    listing = GMAIL + "/users/me/messages"
    api = Api({(listing, ()): Response(payload={"messages": [{"id": "big", "threadId": "big"}]}),
               (listing + "/big", (("format", "minimal"),)): gmail_message("big", size=50 * 1024 * 1024)})
    got = list(mailapi.fetch_gmail(source(), 1 << 20, session=api))
    assert isinstance(got[0][2], ValueError)
    assert not any(call[2].get("format") == "raw" for call in api.calls)


def test_gmail_names_the_missing_scope_when_the_token_is_refused():
    api = Api({(GMAIL + "/users/me/messages", ()): Response(403, {"error": {"code": 403}})})
    with pytest.raises(mailapi.MailApiError, match="gmail.readonly"):
        list(mailapi.fetch_gmail(source(), 1 << 20, session=api))


def test_gmail_a_message_that_will_not_decode_is_skipped_not_fatal():
    listing = GMAIL + "/users/me/messages"
    broken = gmail_message("bad", raw=b"x")
    broken._payload["raw"] = "!!! not base64 !!!"
    api = Api({(listing, ()): Response(payload={"messages": [{"id": "bad"}, {"id": "ok"}]}),
               (listing + "/bad", (("format", "minimal"),)): gmail_message("bad", size=10),
               (listing + "/bad", (("format", "raw"),)): broken,
               (listing + "/ok", (("format", "minimal"),)): gmail_message("ok", size=len(LUNCH)),
               (listing + "/ok", (("format", "raw"),)): gmail_message("ok", raw=LUNCH)})
    got = {message_id: data for _, message_id, data in mailapi.fetch_gmail(source(), 1 << 20, session=api)}
    assert isinstance(got["bad"], ValueError) and got["ok"] == LUNCH


# --------------------------------------------------------------------- CLI --

def run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_the_token_is_taken_only_from_the_environment(monkeypatch, capsys):
    monkeypatch.delenv("PHISHHAWK_GRAPH_TOKEN", raising=False)
    with pytest.raises(SystemExit) as stop:
        main(["graph", "--offline", "-q"])
    assert stop.value.code == 2 and "PHISHHAWK_GRAPH_TOKEN" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["graph", "--token", "t0k3n"])  # there is no such option


def test_gmail_command_triages_each_message_and_writes_reports(monkeypatch, tmp_path, capsys):
    listing = GMAIL + "/users/soc@example.com/messages"
    api = Api({(listing, ()): Response(payload={"messages": [{"id": "m2"}, {"id": "m1"}]}),
               (listing + "/m1", (("format", "minimal"),)): gmail_message("m1", size=len(PHISH)),
               (listing + "/m1", (("format", "raw"),)): gmail_message("m1", raw=PHISH),
               (listing + "/m2", (("format", "minimal"),)): gmail_message("m2", size=len(LUNCH)),
               (listing + "/m2", (("format", "raw"),)): gmail_message("m2", raw=LUNCH)})
    monkeypatch.setattr(requests, "Session", lambda: api)
    monkeypatch.setenv("PHISHHAWK_GMAIL_TOKEN", "t0k3n")
    code, out, _ = run(["gmail", "--mailbox", "soc@example.com", "--offline", "-q", "--no-color",
                        "--out", str(tmp_path)], capsys)
    assert code == 1 and "gmail://soc@example.com/m1" in out and "gmail://soc@example.com/m2" in out
    assert sorted(p.name for p in tmp_path.iterdir()) == ["gmail-m1.html", "gmail-m1.json", "gmail-m2.html",
                                                          "gmail-m2.json"]
    assert json.loads((tmp_path / "gmail-m1.json").read_text())["verdict"] != "NO STRONG INDICATORS"


def test_an_api_refusal_is_an_error_not_a_crash(monkeypatch, capsys):
    refused = Response(403, {"error": {"code": "ErrorAccessDenied"}})
    api = Api({(GRAPH + "/me/mailFolders/inbox/messages", ()): refused})
    monkeypatch.setattr(requests, "Session", lambda: api)
    monkeypatch.setenv("PHISHHAWK_GRAPH_TOKEN", "t0k3n")
    code, _, err = run(["graph", "--offline", "-q", "--no-color"], capsys)
    assert code == 3 and "Mail.Read" in err and "Traceback" not in err
