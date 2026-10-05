"""Read reported mail through the Microsoft Graph and Gmail APIs, read-only.

Many mailboxes no longer allow IMAP. These readers only ever send GET
requests, so nothing is marked read, moved or deleted: Graph's `$value`
returns a message's MIME without touching it, and so does Gmail's
`format=raw`. The access token comes from the environment
($PHISHHAWK_GRAPH_TOKEN, $PHISHHAWK_GMAIL_TOKEN), never the command line,
travels only in the Authorization header, and is only ever sent to the
API's own host. It needs Mail.Read (Graph) or gmail.readonly (Gmail);
getting one is left to your identity platform.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

GRAPH = "https://graph.microsoft.com/v1.0"
GMAIL = "https://gmail.googleapis.com/gmail/v1"
MAX_LISTED = 10_000
# Folders Graph knows by name in every mailbox, whatever its language.
WELL_KNOWN = {"inbox", "junkemail", "deleteditems", "archive", "drafts", "sentitems", "outbox", "clutter"}
PERMISSION = {"Graph": "Mail.Read", "Gmail": "gmail.readonly"}


class MailApiError(Exception):
    pass


@dataclass
class ApiSource:
    token: str
    mailbox: str = "me"  # a user id or address; "me" is the token's own mailbox
    folder: str = ""  # Graph: a folder name or id (the Inbox); Gmail: a label (the inbox)
    query: str = ""  # Gmail: more search terms, as typed in Gmail's search box
    since: dt.date | None = None
    unread: bool = False
    limit: int = 50
    timeout: float = 30


class _Client:
    def __init__(self, source: ApiSource, service: str, session: Any) -> None:
        # Such a header is refused, and the refusal quotes it: never let it get that far.
        if not source.token or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in source.token):
            raise MailApiError("%s: the access token is empty or contains spaces or control characters "
                               "(check how it was copied)" % service)
        if session is None:
            import requests  # noqa: PLC0415 - only these commands need it

            session = requests.Session()
        self.source, self.service, self.session = source, service, session

    def get(self, url: str, params: dict[str, Any] | None = None, stream: bool = False) -> Any:
        try:
            response = self.session.get(url, params=params, stream=stream, timeout=self.source.timeout,
                                        headers={"Authorization": "Bearer " + self.source.token})
        except OSError as exc:  # requests' errors are OSErrors: no route, TLS, timeout
            raise MailApiError("%s: %s" % (self.service, exc)) from exc
        status = response.status_code
        if status in (401, 403):
            raise MailApiError("%s refused the token (HTTP %d): it needs %s"
                               % (self.service, status, PERMISSION[self.service]))
        if status == 404:
            raise MailApiError("%s: nothing at %s" % (self.service, url))
        if status == 429:
            raise MailApiError("%s is throttling requests: try again later" % self.service)
        if status >= 400:
            raise MailApiError("%s answered HTTP %d%s" % (self.service, status, _error_code(response)))
        return response

    def json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            body = self.get(url, params).json()
        except ValueError as exc:
            raise MailApiError("%s answered with something that is not JSON" % self.service) from exc
        if not isinstance(body, dict):
            raise MailApiError("%s answered with something unexpected" % self.service)
        return body


def _error_code(response: Any) -> str:
    """ (InefficientFilter): what an API error calls itself, made printable.
    Graph puts it in error.code, Gmail in error.status."""
    try:
        error = response.json().get("error")
    except (ValueError, AttributeError):
        return ""
    if not isinstance(error, dict):
        return ""
    code = error.get("status") if isinstance(error.get("status"), str) else error.get("code")
    code = "".join(ch for ch in str(code or "") if ch.isalnum() or ch in "._-")[:60]
    return " (%s)" % code if code and not code.isdigit() else ""


def _too_big(max_bytes: int) -> ValueError:
    return ValueError("larger than %d MB" % max(1, max_bytes // (1024 * 1024)))


def _download(response: Any, max_bytes: int, service: str) -> bytes | Exception:
    """A streamed body; one past max_bytes is skipped, never cut short, and
    one whose connection breaks off is skipped, to be asked for again."""
    chunks, total = [], 0
    try:
        for chunk in response.iter_content(64 * 1024):
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                response.close()
                return _too_big(max_bytes)
    except OSError as exc:  # requests' errors are OSErrors: a dropped connection, a broken chunk
        return MailApiError("%s: the download broke off (%s)" % (service, type(exc).__name__))
    return b"".join(chunks)


def _ids(items: Any) -> list[str]:
    return [str(item["id"]) for item in items or [] if isinstance(item, dict) and item.get("id")]


# ------------------------------------------------------------------- Graph --

def _graph_folder(client: _Client, base: str) -> str:
    folder = client.source.folder or "inbox"
    if folder.lower() in WELL_KNOWN:
        return folder.lower()
    # A folder you made: at the top level, or inside the Inbox.
    wanted = {"$filter": "displayName eq '%s'" % folder.replace("'", "''"), "$select": "id,displayName"}
    for parent in (base + "/mailFolders", base + "/mailFolders/inbox/childFolders"):
        found = _ids(client.json(parent, wanted).get("value"))
        if found:
            return found[0]
    if not any(ch.isspace() for ch in folder):  # a folder id, as Graph and Outlook show them
        try:
            found = _ids([client.json("%s/mailFolders/%s" % (base, quote(folder, safe="")), {"$select": "id"})])
        except MailApiError:
            found = []
        if found:
            return found[0]
    raise MailApiError("Graph: no folder called %r at the top level or in the Inbox" % folder)


def fetch_graph(source: ApiSource, max_bytes: int, seen: set[str] | frozenset[str] = frozenset(),
                session: Any = None) -> Iterator[tuple[str, str, bytes | Exception]]:
    """(label, message id, raw message or why it was skipped), oldest first."""
    client = _Client(source, "Graph", session)
    mailbox = source.mailbox or "me"
    base = GRAPH + "/me" if mailbox == "me" else "%s/users/%s" % (GRAPH, quote(mailbox, safe="@"))
    folder = _graph_folder(client, base)
    params: dict[str, Any] | None = {"$select": "id,receivedDateTime", "$orderby": "receivedDateTime desc",
                                     "$top": min(source.limit, 100) if source.limit else 100}
    filters = []
    if source.since or source.unread:
        # Graph refuses to sort by receivedDateTime unless the filter starts with it.
        filters.append("receivedDateTime ge %sT00:00:00Z" % (source.since or dt.date(1900, 1, 1)).isoformat())
    if source.unread:
        filters.append("isRead eq false")
    if filters and params is not None:
        params["$filter"] = " and ".join(filters)
    url = "%s/mailFolders/%s/messages" % (base, quote(folder, safe=""))
    wanted = min(source.limit or MAX_LISTED, MAX_LISTED)
    listed: list[str] = []
    while url and len(listed) < wanted:
        page = client.json(url, params)
        listed += _ids(page.get("value"))
        url, params = str(page.get("@odata.nextLink") or ""), None  # a next link carries its own query
        if not url.startswith(GRAPH + "/"):
            break  # the token goes to Graph and nowhere else
    # Only the newest `wanted` are looked at: a --watch round with nothing new
    # must not walk back through the folder.
    for message_id in reversed([i for i in listed[:wanted] if i not in seen]):
        label = "graph://%s/%s/%s" % (mailbox, source.folder or "inbox", message_id)
        try:
            response = client.get("%s/messages/%s/$value" % (base, quote(message_id, safe="")), stream=True)
            yield label, message_id, _download(response, max_bytes, "Graph")
        except MailApiError as exc:
            yield label, message_id, exc


# ------------------------------------------------------------------- Gmail --

def _gmail_query(source: ApiSource) -> str:
    terms = ['label:"%s"' % source.folder.replace('"', "")] if source.folder else ["in:inbox"]
    if source.since:
        terms.append("after:%s" % source.since.strftime("%Y/%m/%d"))
    if source.unread:
        terms.append("is:unread")
    if source.query:
        terms.append(source.query)
    return " ".join(terms)


def fetch_gmail(source: ApiSource, max_bytes: int, seen: set[str] | frozenset[str] = frozenset(),
                session: Any = None) -> Iterator[tuple[str, str, bytes | Exception]]:
    """(label, message id, raw message or why it was skipped), oldest first."""
    client = _Client(source, "Gmail", session)
    mailbox = source.mailbox or "me"
    base = "%s/users/%s/messages" % (GMAIL, quote(mailbox, safe="@"))
    wanted = min(source.limit or MAX_LISTED, MAX_LISTED)
    params: dict[str, Any] = {"q": _gmail_query(source), "maxResults": min(wanted, 500)}
    listed: list[str] = []
    while len(listed) < wanted:
        page = client.json(base, params)
        listed += _ids(page.get("messages"))
        if not page.get("nextPageToken"):
            break
        params = dict(params, pageToken=str(page["nextPageToken"]))
    for message_id in reversed([i for i in listed[:wanted] if i not in seen]):  # the newest only, as for Graph
        label = "gmail://%s/%s" % (mailbox, message_id)
        url = "%s/%s" % (base, quote(message_id, safe=""))
        try:
            size = client.json(url, {"format": "minimal"}).get("sizeEstimate")
            if isinstance(size, int) and size > max_bytes:  # checked before anything is downloaded
                yield label, message_id, _too_big(max_bytes)
                continue
            raw = client.json(url, {"format": "raw"}).get("raw")
            if not isinstance(raw, str):
                yield label, message_id, ValueError("Gmail returned no message")
                continue
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
            yield label, message_id, data if len(data) <= max_bytes else _too_big(max_bytes)
        except (MailApiError, binascii.Error, ValueError) as exc:
            yield label, message_id, exc
