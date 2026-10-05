"""Mailbox sweep: who else received a reported message, and what they did.

Searches mailboxes through Microsoft Graph or the Gmail API for copies of a
reported message (its Message-ID, sender and reply-to addresses, subject,
and the phishing domains it links to) and reports, for each copy, where it
sits, whether it was read and whether the mailbox's owner replied in its
thread. Read-only, like the graph and gmail commands: GET requests only,
the token only in the Authorization header and only to the API's own host.
Graph's search matches loosely, so its hits are checked against what was
asked for before they are reported. Whether anyone opened an attachment
or clicked a link is not in the mailbox: that is in EDR and proxy logs.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from .campaign import normalise_subject, traits
from .mailapi import GMAIL, GRAPH, MAX_PAGES, ApiSource, MailApiError, _Client
from .models import Analysis

MAX_MAILBOXES = 10_000
MAX_LOOKUPS = 200  # folder names and reply checks per mailbox
GRAPH_FIELDS = "id,subject,from,receivedDateTime,isRead,conversationId,internetMessageId,parentFolderId"
_MAILBOX_RE = re.compile(r"[A-Za-z0-9._%+=@-]{1,320}")  # an address, a user id, a GUID or "me"
GMAIL_FOLDERS = (("SPAM", "Spam"), ("TRASH", "Trash"), ("INBOX", "Inbox"), ("SENT", "Sent"), ("DRAFT", "Drafts"))


@dataclass
class Criteria:
    senders: list[str] = field(default_factory=list)
    subjects: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    message_ids: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.senders or self.subjects or self.domains or self.message_ids)


def criteria_from(a: Analysis) -> Criteria:
    """What to look for, from a reported message: never a brand's own domain
    or address, a shared service, or a subject too short to mean anything."""
    found = traits(a)
    senders = [address for address in (a.from_address.lower(), a.reply_to.lower())
               if address and address in found.get("sender", set()) | found.get("reply-to", set())]
    domains = sorted(found.get("domain", set()) | found.get("host", set()))[:10]
    subject = " ".join(a.subject.split())
    return Criteria(senders=list(dict.fromkeys(senders)),
                    subjects=[subject] if normalise_subject(subject) else [],
                    domains=[d for d in domains if "/" not in d],
                    message_ids=[a.message_id] if a.message_id else [])


def _kql(value: str) -> str:
    """A $search value that stays inside its quotes; hits are checked afterwards anyway."""
    return '"%s"' % " ".join(value.replace('"', " ").replace("\\", " ").split())


def _odata(value: str) -> str:
    return "'%s'" % value.replace("'", "''")


def _gmail_phrase(value: str) -> str:
    return '"%s"' % " ".join(value.replace('"', " ").replace("\\", " ").split())


def _subject_matches(subject: str, wanted: str) -> bool:
    asked = normalise_subject(wanted)
    return bool(asked) and asked in normalise_subject(subject)


def _field_is(name: str, wanted: str) -> Callable[[dict[str, Any]], bool]:
    return lambda match: match[name] == wanted


def _subject_is(wanted: str) -> Callable[[dict[str, Any]], bool]:
    return lambda match: _subject_matches(match["subject"], wanted)


def _iso(value: str) -> str:
    try:
        moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _since_ok(received: str, since: dt.date | None) -> bool:
    return since is None or not received or received[:10] >= since.isoformat()


def _merge(found: dict[str, dict[str, Any]], match: dict[str, Any], label: str) -> None:
    entry = found.setdefault(match["id"], match)
    if label not in entry["matched"]:
        entry["matched"].append(label)


def _checked(mailbox: str) -> str:
    if not _MAILBOX_RE.fullmatch(mailbox) or set(mailbox) <= {"."}:
        raise MailApiError("not a mailbox address or id: %r" % mailbox[:80])
    return mailbox


def _mailbox_result(mailbox: str, found: dict[str, dict[str, Any]], error: str = "") -> dict[str, Any]:
    matches = sorted(found.values(), key=lambda m: m["received"], reverse=True)
    for match in matches:
        match["matched"].sort()
    return {"mailbox": mailbox, "matches": matches, "error": error}


# ------------------------------------------------------------------- Graph --

def _graph_hits(client: _Client, url: str, params: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    next_url, query = url, dict(params, **{"$top": min(limit, 100)})
    for _ in range(MAX_PAGES):
        if not next_url or len(hits) >= limit:
            break
        page = client.json(next_url, query)
        hits += [item for item in page.get("value") or [] if isinstance(item, dict) and item.get("id")]
        next_url, query = str(page.get("@odata.nextLink") or ""), {}
        if not next_url.startswith(GRAPH + "/"):
            break  # the token goes to Graph and nowhere else
    return hits[:limit]


def _graph_match(item: dict[str, Any]) -> dict[str, Any]:
    sender = ((item.get("from") or {}).get("emailAddress") or {})
    return {"id": str(item["id"]), "message_id": str(item.get("internetMessageId") or ""),
            "received": _iso(str(item.get("receivedDateTime") or "")),
            "from": str(sender.get("address") or "").lower(), "subject": str(item.get("subject") or ""),
            "folder": "", "read": bool(item.get("isRead")), "replied": None, "matched": [],
            "_folder_id": str(item.get("parentFolderId") or ""), "_thread": str(item.get("conversationId") or "")}


def _graph_mailbox(client: _Client, mailbox: str, criteria: Criteria, since: dt.date | None,
                   limit: int) -> dict[str, dict[str, Any]]:
    base = GRAPH + "/me" if mailbox == "me" else "%s/users/%s" % (GRAPH, quote(mailbox, safe="@"))
    url = base + "/messages"
    found: dict[str, dict[str, Any]] = {}
    checks: list[tuple[str, dict[str, Any], Callable[[dict[str, Any]], bool]]] = []
    for message_id in criteria.message_ids:
        checks.append(("message-id " + message_id, {"$filter": "internetMessageId eq " + _odata(message_id)},
                       _field_is("message_id", message_id)))
    for sender in criteria.senders:
        checks.append(("sender " + sender, {"$search": _kql("from:" + sender)}, _field_is("from", sender.lower())))
    for subject in criteria.subjects:
        checks.append(("subject " + subject, {"$search": _kql(subject)}, _subject_is(subject)))
    for label, params, accept in checks:
        for item in _graph_hits(client, url, dict(params, **{"$select": GRAPH_FIELDS}), limit):
            match = _graph_match(item)
            if accept(match) and _since_ok(match["received"], since):
                _merge(found, match, label)
    for domain in criteria.domains:
        params = {"$search": _kql("body:" + domain), "$select": GRAPH_FIELDS + ",body"}
        for item in _graph_hits(client, url, params, limit):
            body = str(((item.get("body") or {}).get("content")) or "").lower()
            match = _graph_match(item)
            if domain.lower() in body and _since_ok(match["received"], since):  # the body is read, never kept
                _merge(found, match, "domain " + domain)
    folders: dict[str, str] = {}
    replies: dict[str, bool | None] = {}
    for match in list(found.values())[:MAX_LOOKUPS]:
        folder_id, thread = match.pop("_folder_id"), match.pop("_thread")
        if folder_id and folder_id not in folders:
            try:
                folder = client.json("%s/mailFolders/%s" % (base, quote(folder_id, safe="")),
                                     {"$select": "displayName"})
                folders[folder_id] = str(folder.get("displayName") or "")
            except MailApiError:
                folders[folder_id] = ""
        match["folder"] = folders.get(folder_id, "")
        if thread and thread not in replies:
            try:
                sent = client.json(base + "/mailFolders/sentitems/messages",
                                   {"$filter": "conversationId eq " + _odata(thread), "$select": "id", "$top": 1})
                replies[thread] = bool(sent.get("value"))
            except MailApiError:
                replies[thread] = None
        match["replied"] = replies.get(thread)
    for match in found.values():
        match.pop("_folder_id", None)
        match.pop("_thread", None)
    return found


def sweep_graph(token: str, mailboxes: list[str], criteria: Criteria, since: dt.date | None = None,
                limit: int = 100, session: Any = None, timeout: float = 30) -> list[dict[str, Any]]:
    client = _Client(ApiSource(token=token, timeout=timeout), "Graph", session)
    results = []
    for mailbox in mailboxes[:MAX_MAILBOXES]:
        try:
            results.append(_mailbox_result(mailbox, _graph_mailbox(client, _checked(mailbox), criteria, since,
                                                                   limit)))
        except MailApiError as exc:
            results.append(_mailbox_result(mailbox, {}, str(exc)))
    return results


# ------------------------------------------------------------------- Gmail --

def _gmail_mailbox(client: _Client, mailbox: str, criteria: Criteria, since: dt.date | None,
                   limit: int) -> dict[str, dict[str, Any]]:
    base = "%s/users/%s" % (GMAIL, quote(mailbox or "me", safe="@"))
    after = " after:%s" % since.strftime("%Y/%m/%d") if since else ""
    searches = [("message-id " + m, "rfc822msgid:" + m.replace(" ", "")) for m in criteria.message_ids]
    searches += [("sender " + s, "from:" + s.replace(" ", "")) for s in criteria.senders]
    searches += [("subject " + s, "subject:" + _gmail_phrase(s)) for s in criteria.subjects]
    searches += [("domain " + d, _gmail_phrase(d)) for d in criteria.domains]
    hits: dict[str, list[str]] = {}
    for label, term in searches:
        params: dict[str, Any] = {"q": "in:anywhere %s%s" % (term, after), "maxResults": min(limit, 500)}
        listed = 0
        for _ in range(MAX_PAGES):
            if listed >= limit:
                break
            page = client.json(base + "/messages", params)
            for item in page.get("messages") or []:
                if isinstance(item, dict) and item.get("id") and listed < limit:
                    hits.setdefault(str(item["id"]), []).append(label)
                    listed += 1
            if not page.get("nextPageToken"):
                break
            params = dict(params, pageToken=str(page["nextPageToken"]))
    found: dict[str, dict[str, Any]] = {}
    replies: dict[str, bool | None] = {}
    for message_id, labels in list(hits.items())[:MAX_LOOKUPS * 5]:
        meta = client.json("%s/messages/%s" % (base, quote(message_id, safe="")),
                           {"format": "metadata", "metadataHeaders": ["From", "Subject", "Date", "Message-ID"]})
        headers = {str(h.get("name", "")).lower(): str(h.get("value", ""))
                   for h in (meta.get("payload") or {}).get("headers") or [] if isinstance(h, dict)}
        tags = [str(tag) for tag in meta.get("labelIds") or []]
        try:
            received = dt.datetime.fromtimestamp(int(meta.get("internalDate") or 0) / 1000, dt.timezone.utc)
            when = received.strftime("%Y-%m-%dT%H:%M:%SZ") if received.year > 1970 else ""
        except (ValueError, OverflowError, OSError):
            when = ""
        match = {"id": message_id, "message_id": headers.get("message-id", ""), "received": when,
                 "from": headers.get("from", ""), "subject": headers.get("subject", ""),
                 "folder": next((name for tag, name in GMAIL_FOLDERS if tag in tags), "Archive"),
                 "read": "UNREAD" not in tags, "replied": None, "matched": []}
        thread = str(meta.get("threadId") or "")
        if thread and thread not in replies and len(replies) < MAX_LOOKUPS:
            try:
                messages = client.json("%s/threads/%s" % (base, quote(thread, safe="")),
                                       {"format": "minimal"}).get("messages") or []
                replies[thread] = any("SENT" in (m.get("labelIds") or []) for m in messages if isinstance(m, dict))
            except MailApiError:
                replies[thread] = None
        match["replied"] = replies.get(thread)
        for label in labels:
            _merge(found, match, label)
    return found


def sweep_gmail(token: str, mailboxes: list[str], criteria: Criteria, since: dt.date | None = None,
                limit: int = 100, session: Any = None, timeout: float = 30) -> list[dict[str, Any]]:
    client = _Client(ApiSource(token=token, timeout=timeout), "Gmail", session)
    results = []
    for mailbox in mailboxes[:MAX_MAILBOXES]:
        try:
            results.append(_mailbox_result(mailbox, _gmail_mailbox(client, _checked(mailbox), criteria, since,
                                                                   limit)))
        except MailApiError as exc:
            results.append(_mailbox_result(mailbox, {}, str(exc)))
    return results
