"""Fake HTTP sessions for the mailbox tests (spec 7.5): each stands in for `requests.Session`, records every call,
and allows only GET to its API's host and POST to its one token URL. Anything else (PATCH, DELETE, a POST to the
API, a request to another host) is recorded as a violation and refused."""

from __future__ import annotations

import datetime as dt
import secrets
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"


class Response:
    def __init__(self, status: int = 200, payload: Any = None, body: bytes = b"") -> None:
        self.status_code, self._payload, self._body, self.closed = status, payload, body, False

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON")
        return self._payload

    def iter_content(self, size: int):  # noqa: ANN201
        for start in range(0, len(self._body), size):
            yield self._body[start:start + size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    """GET under `api` and POST to `token_url` reach `answer()`; everything else is a violation."""

    def __init__(self, api: str, token_url: str) -> None:
        self.api, self.token_url = api, token_url
        self.calls: list[tuple[str, str, dict, dict, dict]] = []  # method, url, params, headers, form
        self.violations: list[str] = []

    def get(self, url: str, params: dict | None = None, headers: dict | None = None, stream: bool = False,
            timeout: float | None = None) -> Response:
        self.calls.append(("GET", url, dict(params or {}), dict(headers or {}), {}))
        if not url.startswith(self.api + "/"):
            self.violations.append("GET " + url)
            return Response(400, {"error": {"code": "NotThisHost"}})
        return self.answer("GET", url, dict(params or {}), dict(headers or {}), {})

    def post(self, url: str, data: dict | None = None, headers: dict | None = None, timeout: float | None = None,
             **_: Any) -> Response:
        self.calls.append(("POST", url, {}, dict(headers or {}), dict(data or {})))
        if url != self.token_url:
            self.violations.append("POST " + url)
            return Response(405, {"error": "not_allowed"})
        return self.answer("POST", url, {}, dict(headers or {}), dict(data or {}))

    def _refused(self, method: str):  # noqa: ANN202
        def call(url: str, *args: Any, **kwargs: Any) -> Response:
            self.calls.append((method, url, {}, {}, {}))
            self.violations.append("%s %s" % (method, url))
            return Response(405, {"error": "not_allowed"})
        return call

    def __getattr__(self, name: str) -> Any:
        if name in ("put", "patch", "delete", "head", "options", "request"):
            return self._refused(name.upper())
        raise AttributeError(name)

    def answer(self, method: str, url: str, params: dict, headers: dict, form: dict) -> Response:
        raise NotImplementedError

    def close(self) -> None:
        pass


class FakeGraph(FakeSession):
    """One tenant with one report mailbox: an app registration that signs in with a client secret, folders of
    messages read through a delta query (pages of `page_size`, a delta link per state), and each message's MIME."""

    def __init__(self, tenant: str, client_id: str, secret: str, address: str) -> None:
        super().__init__(GRAPH, "%s/%s/oauth2/v2.0/token" % (LOGIN, tenant))
        self.client_id, self.secret, self.address = client_id, secret, address
        self.token = secrets.token_urlsafe(24)
        self.folders: dict[str, list[dict]] = {"inbox": []}  # each: {"id", "received", "raw"} or removed
        self.folder_names = {"Phish reports": "AAMkPhishReports"}
        self.page_size = 10
        self.status_for_messages: int | None = None  # answer every message listing with this status
        self.next_link_host = GRAPH  # where next links point
        self.expired: set[str] = set()  # delta tokens that are no longer valid
        self.clock = dt.datetime(2026, 10, 1, 9, 0, tzinfo=dt.timezone.utc)

    def add(self, raw: bytes, folder: str = "inbox") -> str:
        self.clock += dt.timedelta(minutes=1)
        message_id = "AAMk%s" % secrets.token_hex(8)
        self.folders.setdefault(folder, []).append({"id": message_id, "received": self.clock.isoformat(),
                                                    "raw": raw})
        return message_id

    def remove(self, message_id: str, folder: str = "inbox") -> None:
        self.folders[folder].append({"id": message_id, "removed": True})

    def downloads(self) -> list[str]:
        return [url.split("/messages/")[1].split("/")[0] for method, url, *_ in self.calls
                if method == "GET" and url.endswith("/$value")]

    def answer(self, method: str, url: str, params: dict, headers: dict, form: dict) -> Response:
        if method == "POST":
            if form.get("grant_type") != "client_credentials" or form.get("scope") != (
                    "https://graph.microsoft.com/.default") or form.get("client_id") != self.client_id:
                return Response(400, {"error": "invalid_request", "error_description": "AADSTS900144"})
            if form.get("client_secret") != self.secret:
                return Response(401, {"error": "invalid_client", "error_description":
                                      "AADSTS7000215: Invalid client secret: %s" % form.get("client_secret")})
            return Response(200, {"token_type": "Bearer", "expires_in": 3599, "access_token": self.token})
        if headers.get("Authorization") != "Bearer " + self.token:
            return Response(401, {"error": {"code": "InvalidAuthenticationToken"}})
        path = urlsplit(url).path.removeprefix("/v1.0")
        base = "/users/%s" % quote(self.address, safe="@")
        if not path.startswith(base + "/"):
            return Response(404, {"error": {"code": "ErrorInvalidUser"}})
        rest = path[len(base):]
        if rest == "/mailFolders":
            wanted = params.get("$filter", "").removeprefix("displayName eq '").removesuffix("'")
            wanted = wanted.replace("''", "'")
            found = self.folder_names.get(wanted)
            return Response(200, {"value": [{"id": found, "displayName": wanted}] if found else []})
        if rest.startswith("/mailFolders/inbox/childFolders"):
            return Response(200, {"value": []})
        if rest.startswith("/mailFolders/") and rest.endswith("/messages/delta"):
            if self.status_for_messages:
                return Response(self.status_for_messages, {"error": {"code": "ErrorAccessDenied"}})
            folder = rest.split("/")[2]
            folder = next((name for name, fid in self.folder_names.items() if fid == folder), folder)
            query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
            return self._delta(folder, path, query)
        if rest.startswith("/messages/") and rest.endswith("/$value"):
            message_id = rest.split("/")[2]
            for messages in self.folders.values():
                for message in messages:
                    if message["id"] == message_id and "raw" in message:
                        return Response(200, body=message["raw"])
            return Response(404, {"error": {"code": "ErrorItemNotFound"}})
        return Response(404, {"error": {"code": "ResourceNotFound"}})

    def _delta(self, folder: str, path: str, query: dict) -> Response:
        """The changes after a delta token (all of them without one), a page at a time."""
        changes = self.folders.get(folder, [])
        if "$skiptoken" in query:
            first = int(query["$skiptoken"])
        elif "$deltatoken" in query:
            if query["$deltatoken"] in self.expired:
                return Response(410, {"error": {"code": "SyncStateNotFound"}})
            first = int(query["$deltatoken"])
        else:
            first = 0
        page = changes[first:first + self.page_size]
        items = [{"id": m["id"], "@removed": {"reason": "deleted"}} if m.get("removed")
                 else {"id": m["id"], "receivedDateTime": m["received"]} for m in page]
        if first + self.page_size < len(changes):
            return Response(200, {"value": items, "@odata.nextLink": "%s%s?$skiptoken=%d" % (
                self.next_link_host, path, first + self.page_size)})
        link = "%s%s?$deltatoken=%d" % (GRAPH, path, len(changes))
        return Response(200, {"value": items, "@odata.deltaLink": link})
