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


GMAIL = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
READONLY = "https://www.googleapis.com/auth/gmail.readonly"


def _unb64(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeGmail(FakeSession):
    """One Google Workspace mailbox reached through a service account with domain-wide delegation: the token comes
    for a JWT signed with the account's key, the mailbox has labels, a history, and each message's raw MIME."""

    def __init__(self, client_email: str, public_key, address: str) -> None:  # noqa: ANN001
        super().__init__(GMAIL, GOOGLE_TOKEN)
        self.client_email, self.public_key, self.address = client_email, public_key, address
        self.token = secrets.token_urlsafe(24)
        self.messages: list[dict] = []  # {"id", "history", "labels", "raw"}, oldest first
        self.history_id = 1000
        self.oldest_history = 0  # a startHistoryId before this is too old (404)
        self.labels = {"INBOX": "INBOX", "Phish reports": "Label_7"}
        self.page_size = 100
        self.assertions: list[tuple[dict, dict]] = []  # (header, claims) of every JWT it was sent

    def add(self, raw: bytes, label: str = "INBOX") -> str:
        self.history_id += 3
        message_id = secrets.token_hex(8)
        self.messages.append({"id": message_id, "history": self.history_id, "labels": [self.labels[label]],
                              "raw": raw})
        return message_id

    def downloads(self) -> list[str]:
        return [url.rsplit("/", 1)[1] for method, url, params, *_ in self.calls
                if method == "GET" and "/messages/" in url and params.get("format") == "raw"]

    def _verify(self, assertion: str) -> dict | None:
        import json

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            header_text, claims_text, signature = assertion.split(".")
            header, claims = json.loads(_unb64(header_text)), json.loads(_unb64(claims_text))
            self.public_key.verify(_unb64(signature), ("%s.%s" % (header_text, claims_text)).encode("ascii"),
                                   padding.PKCS1v15(), hashes.SHA256())
        except (ValueError, InvalidSignature):
            return None
        self.assertions.append((header, claims))
        return claims

    def answer(self, method: str, url: str, params: dict, headers: dict, form: dict) -> Response:
        if method == "POST":
            claims = self._verify(form.get("assertion", ""))
            if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" or claims is None:
                return Response(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
            if claims.get("iss") != self.client_email or claims.get("aud") != GOOGLE_TOKEN:
                return Response(400, {"error": "invalid_grant", "error_description": "Invalid issuer or audience"})
            if claims.get("scope") != READONLY or claims.get("sub") != self.address:
                return Response(401, {"error": "unauthorized_client", "error_description": "Not delegated"})
            return Response(200, {"access_token": self.token, "expires_in": 3599, "token_type": "Bearer"})
        if headers.get("Authorization") != "Bearer " + self.token:
            return Response(401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}})
        base = "%s/users/%s" % (GMAIL, quote(self.address, safe="@"))
        if not url.startswith(base + "/"):
            return Response(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        rest = url[len(base):]
        if rest == "/profile":
            return Response(200, {"emailAddress": self.address, "historyId": str(self.history_id)})
        if rest == "/labels":
            return Response(200, {"labels": [{"id": i, "name": n, "type": "system" if i == n else "user"}
                                             for n, i in self.labels.items()]})
        if rest == "/messages":
            listed = [m for m in reversed(self.messages) if params.get("labelIds") in m["labels"]]
            return Response(200, {"messages": [{"id": m["id"], "threadId": m["id"]}
                                               for m in listed[:int(params.get("maxResults", 100))]],
                                  "resultSizeEstimate": len(listed)})
        if rest == "/history":
            start = int(params["startHistoryId"])
            if start < self.oldest_history:
                return Response(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
            after = [m for m in self.messages if m["history"] > start and params.get("labelId") in m["labels"]]
            first = int(params.get("pageToken") or 0)
            page = after[first:first + self.page_size]
            body = {"history": [{"id": str(m["history"]), "messagesAdded": [{"message": {
                "id": m["id"], "threadId": m["id"], "labelIds": m["labels"]}}]} for m in page],
                "historyId": str(self.history_id)}
            if first + self.page_size < len(after):
                body["nextPageToken"] = str(first + self.page_size)
            return Response(200, body)
        if rest.startswith("/messages/"):
            import base64

            found = next((m for m in self.messages if m["id"] == rest.split("/")[2]), None)
            if found is None:
                return Response(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
            if params.get("format") == "minimal":
                return Response(200, {"id": found["id"], "sizeEstimate": len(found["raw"])})
            if params.get("format") == "raw":
                return Response(200, {"id": found["id"],
                                      "raw": base64.urlsafe_b64encode(found["raw"]).decode("ascii")})
        return Response(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
